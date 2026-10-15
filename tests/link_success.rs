#![cfg(target_os = "linux")]

mod common;

use std::{fs, os::unix::fs::PermissionsExt};

use common::toolchain::{
    assemble_object, cargo_linker_with_debug, create_archive, link_executable_input, parse_elf64,
    read_output_bytes, readelf_program_headers, run_executable,
};
use elf::{ElfFileType, ElfMachineType, ElfProgramHeaderType, PF_R, PF_W, PF_X};
use tempfile::tempdir;

#[test]
fn links_single_object_into_exec() {
    let temp = tempdir().unwrap();
    let input = assemble_object(
        &temp,
        "single",
        r#"
.global _start
.text
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
"#,
    );
    let output = temp.path().join("linked_exec");

    cargo_linker_with_debug(0)
        .arg("-o")
        .arg(&output)
        .arg(&input)
        .assert()
        .success();

    let bytes = read_output_bytes(&output);
    let elf = parse_elf64(&bytes);
    let headers = elf.program_headers().collect::<Vec<_>>();
    let load_segments = headers
        .iter()
        .filter(|header| header.segment_type() == ElfProgramHeaderType::PT_LOAD)
        .collect::<Vec<_>>();

    assert_eq!(elf.elf_type(), ElfFileType::ET_EXEC);
    assert_eq!(elf.arch(), ElfMachineType::EM_X86_64);
    assert_eq!(elf.entry(), 0x401000);
    assert!(
        !load_segments.is_empty(),
        "expected at least one PT_LOAD segment"
    );
    assert!(
        load_segments[0].data().is_some_and(|data| !data.is_empty()),
        "expected the first PT_LOAD segment to contain bytes",
    );
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o7777,
        0o755
    );
    run_executable(&output).success();
}

#[test]
fn links_cross_file_call_relocation() {
    let temp = tempdir().unwrap();
    let start = assemble_object(
        &temp,
        "a",
        r#"
.global _start
.text
_start:
    call foo
    mov $60, %rax
    xor %rdi, %rdi
    syscall
"#,
    );
    let callee = assemble_object(
        &temp,
        "b",
        r#"
.global foo
.text
foo:
    ret
"#,
    );
    let output = temp.path().join("relocated_exec");

    cargo_linker_with_debug(0)
        .arg("-o")
        .arg(&output)
        .arg(&start)
        .arg(&callee)
        .assert()
        .success();

    let bytes = read_output_bytes(&output);
    let elf = parse_elf64(&bytes);
    let headers = elf.program_headers().collect::<Vec<_>>();
    let text_segment = headers
        .iter()
        .find(|header| {
            header.segment_type() == ElfProgramHeaderType::PT_LOAD
                && header.flags() == (PF_R | PF_X)
                && header.data().is_some_and(|data| !data.is_empty())
        })
        .expect("expected a readable and executable load segment");
    let data = text_segment.data().unwrap();

    assert_eq!(data.first().copied(), Some(0xE8), "expected a call rel32");

    let displacement = i32::from_le_bytes(data[1..5].try_into().unwrap());
    let target = (text_segment.vaddr() + 5)
        .checked_add_signed(i64::from(displacement))
        .expect("call target address overflowed");
    let target_offset = usize::try_from(
        target
            .checked_sub(text_segment.vaddr())
            .expect("call target before text segment"),
    )
    .unwrap();

    assert_eq!(
        data.get(target_offset),
        Some(&0xC3),
        "call target {target:#x} should land on foo's ret instruction",
    );
    run_executable(&output).success();
}

#[test]
fn links_object_from_archive_input() {
    let temp = tempdir().unwrap();
    let start = assemble_object(
        &temp,
        "start",
        r#"
.global _start
.text
_start:
    call foo
    mov $60, %rax
    mov $37, %rdi
    syscall
"#,
    );
    let callee = assemble_object(
        &temp,
        "callee",
        r#"
.global foo
.text
foo:
    ret
"#,
    );
    let archive = create_archive(&temp, "libcallee", &[callee.as_path()]);
    let output = temp.path().join("archive_exec");

    cargo_linker_with_debug(0)
        .arg("-o")
        .arg(&output)
        .arg(&start)
        .arg(&archive)
        .assert()
        .success();

    let bytes = read_output_bytes(&output);
    let elf = parse_elf64(&bytes);
    let headers = elf.program_headers().collect::<Vec<_>>();
    let text_segment = headers
        .iter()
        .find(|header| {
            header.segment_type() == ElfProgramHeaderType::PT_LOAD
                && header.flags() == (PF_R | PF_X)
                && header.data().is_some_and(|data| !data.is_empty())
        })
        .expect("expected a readable and executable load segment");
    let data = text_segment.data().unwrap();

    assert_eq!(data.first().copied(), Some(0xE8), "expected a call rel32");

    let displacement = i32::from_le_bytes(data[1..5].try_into().unwrap());
    let target = (text_segment.vaddr() + 5)
        .checked_add_signed(i64::from(displacement))
        .expect("call target address overflowed");
    let target_offset = usize::try_from(
        target
            .checked_sub(text_segment.vaddr())
            .expect("call target before text segment"),
    )
    .unwrap();

    assert_eq!(
        data.get(target_offset),
        Some(&0xC3),
        "call target {target:#x} should land on foo's ret instruction",
    );
    run_executable(&output).code(37);
}

#[test]
fn links_text_data_rodata_bss_into_expected_segments() {
    let temp = tempdir().unwrap();
    let input = assemble_object(
        &temp,
        "sections",
        r#"
.global _start
.text
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall

.data
.align 8
writable_value:
    .quad 0x1122334455667788

.section .rodata
message:
    .asciz "hello"

.bss
.align 8
zero_slot:
    .skip 16
"#,
    );
    let output = temp.path().join("segmented_exec");

    cargo_linker_with_debug(0)
        .arg("-o")
        .arg(&output)
        .arg(&input)
        .assert()
        .success();

    let bytes = read_output_bytes(&output);
    let elf = parse_elf64(&bytes);
    let headers = elf.program_headers().collect::<Vec<_>>();
    let load_segments = headers
        .iter()
        .filter(|header| header.segment_type() == ElfProgramHeaderType::PT_LOAD)
        .collect::<Vec<_>>();

    assert_eq!(
        load_segments.len(),
        4,
        "expected PT_LOAD groups for headers, text, rodata, and combined data/bss",
    );
    assert!(
        load_segments
            .iter()
            .any(|header| header.flags() == (PF_R | PF_X) && header.file_size() > 0),
        "expected a readable and executable text segment",
    );
    assert!(
        load_segments.iter().any(|header| {
            header.flags() == PF_R && header.offset() != 0 && header.file_size() > 0
        }),
        "expected a readable rodata segment",
    );
    assert!(
        load_segments
            .iter()
            .any(|header| header.flags() == (PF_R | PF_W) && header.mem_size() > header.file_size()),
        "expected a bss-like segment with mem_size > file_size",
    );
    let reference = link_executable_input(&temp, "gnu_segmented_exec", &[&input]);
    let structure = |path: &std::path::Path| {
        readelf_program_headers(path)
            .lines()
            .filter_map(|line| {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                (fields.first() == Some(&"LOAD")).then(|| {
                    (
                        fields[6..fields.len() - 1].join(" "),
                        fields.last().unwrap().to_string(),
                    )
                })
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(structure(&output), structure(&reference));
    assert_eq!(
        structure(&output),
        vec![
            ("R".to_string(), "0x1000".to_string()),
            ("R E".to_string(), "0x1000".to_string()),
            ("R".to_string(), "0x1000".to_string()),
            ("RW".to_string(), "0x1000".to_string()),
        ]
    );
    for pair in load_segments.windows(2) {
        assert!(
            pair[1].vaddr() / 0x1000 >= (pair[0].vaddr() + pair[0].mem_size()).div_ceil(0x1000)
        );
    }
    run_executable(&output).success();
}

#[test]
fn maps_elf_and_program_headers_in_read_only_load_segment() {
    let temp = tempdir().unwrap();
    let input = assemble_object(
        &temp,
        "mapped_headers",
        r#"
.global _start
.text
_start:
    # Skip argc, argv, and the environment to find the auxiliary vector.
    mov (%rsp), %rcx
    lea 16(%rsp, %rcx, 8), %rsi
skip_env:
    cmpq $0, (%rsi)
    lea 8(%rsi), %rsi
    jne skip_env
find_phdr:
    mov (%rsi), %rax
    test %rax, %rax
    je failed
    cmp $3, %rax                 # AT_PHDR
    je check_phdr
    add $16, %rsi
    jmp find_phdr
check_phdr:
    mov 8(%rsi), %rax
    cmpl $1, (%rax)              # First program header is PT_LOAD.
    jne failed
    cmpl $0x464c457f, -64(%rax)   # ELF magic immediately before the table.
    jne failed
    movzwl -8(%rax), %ecx        # e_phnum at ELF header offset 56.
    dec %ecx
    imul $56, %rcx, %rcx
    cmpl $0x6474e551, (%rax, %rcx) # Last program header is PT_GNU_STACK.
    jne failed
    xor %edi, %edi
    jmp exit
failed:
    mov $1, %edi
exit:
    mov $60, %eax
    syscall
"#,
    );
    let output = temp.path().join("mapped_headers_exec");

    cargo_linker_with_debug(0)
        .arg("-o")
        .arg(&output)
        .arg(&input)
        .assert()
        .success();

    let bytes = read_output_bytes(&output);
    let elf = parse_elf64(&bytes);
    let headers = elf.program_headers().collect::<Vec<_>>();
    let first_load = headers
        .iter()
        .find(|header| header.segment_type() == ElfProgramHeaderType::PT_LOAD)
        .unwrap();
    let phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
    let ehsize = u16::from_le_bytes(bytes[52..54].try_into().unwrap());
    let phentsize = u16::from_le_bytes(bytes[54..56].try_into().unwrap());
    let headers_end = phoff + u64::from(phentsize) * u64::from(elf.program_header_count());

    assert_eq!(first_load.offset(), 0);
    assert_eq!(first_load.vaddr(), 0x400000);
    assert_eq!(first_load.flags(), PF_R);
    assert!(first_load.file_size() >= u64::from(ehsize));
    assert!(first_load.file_size() >= headers_end);
    assert!(first_load.mem_size() >= headers_end);
    assert!(elf.entry() >= (first_load.vaddr() + headers_end).next_multiple_of(0x1000));
    assert_eq!(
        &first_load.data().unwrap()[..usize::from(ehsize)],
        &bytes[..usize::from(ehsize)]
    );

    let stacks = headers
        .iter()
        .filter(|header| header.segment_type() == ElfProgramHeaderType::PT_GNU_STACK)
        .collect::<Vec<_>>();
    assert_eq!(stacks.len(), 1);
    assert_eq!(stacks[0].flags(), PF_R | PF_W);
    assert_eq!(stacks[0].file_size(), 0);
    assert_eq!(stacks[0].mem_size(), 0);

    run_executable(&output).success();
}
