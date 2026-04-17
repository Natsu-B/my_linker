#![cfg(target_os = "linux")]

mod common;

use common::toolchain::{
    assemble_object, cargo_linker_with_debug, create_archive, parse_elf64, read_output_bytes,
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
    assert_eq!(elf.entry(), 0x400000);
    assert!(
        !load_segments.is_empty(),
        "expected at least one PT_LOAD segment"
    );
    assert!(
        load_segments[0].data().is_some_and(|data| !data.is_empty()),
        "expected the first PT_LOAD segment to contain bytes",
    );
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
    xor %rdi, %rdi
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

    assert!(
        load_segments.len() >= 4,
        "expected distinct PT_LOAD segments for text, data, rodata, and bss",
    );
    assert!(
        load_segments
            .iter()
            .any(|header| header.flags() == (PF_R | PF_X) && header.file_size() > 0),
        "expected a readable and executable text segment",
    );
    assert!(
        load_segments.iter().any(|header| {
            header.flags() == (PF_R | PF_W)
                && header.file_size() > 0
                && header.mem_size() == header.file_size()
        }),
        "expected a readable and writable data segment",
    );
    assert!(
        load_segments
            .iter()
            .any(|header| header.flags() == PF_R && header.file_size() > 0),
        "expected a readable rodata segment",
    );
    assert!(
        load_segments
            .iter()
            .any(|header| header.flags() == (PF_R | PF_W) && header.mem_size() > header.file_size()),
        "expected a bss-like segment with mem_size > file_size",
    );
}
