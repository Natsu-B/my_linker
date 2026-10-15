#![cfg(target_os = "linux")]

mod common;

use std::fs;

use common::toolchain::{
    assemble_object, cargo_linker_with_debug, create_archive, parse_elf64, read_output_bytes,
    run_executable,
};
use elf::x86_64::X86_64RelocationType;
use tempfile::tempdir;

#[test]
fn loads_through_all_gotpcrel_encodings_without_relaxation() {
    let temp = tempdir().unwrap();
    let input = assemble_object(
        &temp,
        "got_loads",
        r#"
.global _start
.text
_start:
    movq foo@GOTPCREL(%rip), %rax
    mov (%rax), %edi
    # No REX prefix: this indirect call uses GOTPCRELX.
    call *increment@GOTPCREL(%rip)
    # Explicit plain GOTPCREL on a second movq instruction.
    .byte 0x48, 0x8b, 0x05
plain_displacement:
    .long 0
    .reloc plain_displacement, R_X86_64_GOTPCREL, foo-4
    add (%rax), %edi
    mov $60, %eax
    syscall
increment:
    inc %edi
    ret
.data
.balign 8
foo:
    .quad 20
"#,
    );
    let object_bytes = read_output_bytes(&input);
    let object = parse_elf64(&object_bytes);
    let relocation_types = object
        .sections()
        .find(|section| section.name().unwrap() == ".rela.text")
        .unwrap()
        .rela()
        .unwrap()
        .map(|relocation| X86_64RelocationType::try_from(relocation.info()).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        relocation_types,
        vec![
            X86_64RelocationType::RexGotPcRelX,
            X86_64RelocationType::GotPcRelX,
            X86_64RelocationType::GotPcRel,
        ]
    );
    let output = temp.path().join("got_loads_exec");
    cargo_linker_with_debug(0)
        .arg("-o")
        .arg(&output)
        .arg(&input)
        .assert()
        .success();
    let bytes = read_output_bytes(&output);
    let elf = parse_elf64(&bytes);
    let text = elf
        .program_headers()
        .find(|header| header.flags() == elf::PF_R | elf::PF_X)
        .unwrap();
    assert_eq!(&text.data().unwrap()[..3], &[0x48, 0x8b, 0x05]);
    run_executable(&output).code(41);
}

#[test]
fn weak_undefined_reference_does_not_extract_archive_member() {
    let temp = tempdir().unwrap();
    let input = assemble_object(
        &temp,
        "weak_reference",
        r#"
.global _start
.weak optional
.text
_start:
    movq optional@GOTPCREL(%rip), %rdi
    mov $60, %eax
    syscall
"#,
    );
    let member = assemble_object(
        &temp,
        "optional",
        r#"
.global optional
.text
optional:
    call missing_dependency
    ret
"#,
    );
    let archive = create_archive(&temp, "liboptional", &[&member]);
    let output = temp.path().join("weak_reference_exec");
    cargo_linker_with_debug(0)
        .arg("-o")
        .arg(&output)
        .arg(&input)
        .arg(&archive)
        .assert()
        .success();
    run_executable(&output).success();
}

#[test]
fn got_uses_script_mapping_and_script_defined_targets() {
    let temp = tempdir().unwrap();
    let input = assemble_object(
        &temp,
        "script_got",
        r#"
.global _start
.text
_start:
    movq answer@GOTPCREL(%rip), %rdi
    movq got_address@GOTPCREL(%rip), %rax
    cmp $0x603010, %rax
    jne failed
    mov $60, %eax
    syscall
failed:
    mov $1, %edi
    mov $60, %eax
    syscall
"#,
    );
    let script = temp.path().join("got.ld");
    fs::write(
        &script,
        r#"
ENTRY(_start)
SECTIONS {
    . = 0x600000 + SIZEOF_HEADERS;
    .text 0x601000 : { *(.text) }
    .storage 0x603000 : {
        . = . + 16;
        PROVIDE_HIDDEN(_GLOBAL_OFFSET_TABLE_ = .);
        PROVIDE_HIDDEN(got_address = .);
        *(.got)
    }
    answer = 42;
}
"#,
    )
    .unwrap();
    let output = temp.path().join("script_got_exec");
    cargo_linker_with_debug(0)
        .arg("-T")
        .arg(&script)
        .arg("-o")
        .arg(&output)
        .arg(&input)
        .assert()
        .success();
    let bytes = read_output_bytes(&output);
    let elf = parse_elf64(&bytes);
    let storage = elf
        .program_headers()
        .find(|header| header.vaddr() == 0x603000)
        .unwrap();
    assert_eq!(storage.flags(), elf::PF_R | elf::PF_W);
    assert_eq!(storage.mem_size(), 32);
    assert_eq!(storage.file_size(), 32);
    assert_eq!(storage.align(), 0x1000);
    assert_eq!(&storage.data().unwrap()[16..24], &42u64.to_le_bytes());
    assert_eq!(&storage.data().unwrap()[24..], &0x603010u64.to_le_bytes());
    run_executable(&output).code(42);
}

#[test]
fn got_references_in_weak_definitions_use_the_strong_definition() {
    let temp = tempdir().unwrap();
    let weak = assemble_object(
        &temp,
        "weak_definition",
        r#"
.global _start
.weak foo
.text
_start:
    movq foo@GOTPCREL(%rip), %rax
    mov (%rax), %edi
    mov $60, %eax
    syscall
.data
foo:
    .quad 1
"#,
    );
    let strong = assemble_object(
        &temp,
        "strong_definition",
        r#"
.global foo
.data
foo:
    .quad 42
"#,
    );
    for inputs in [[&weak, &strong], [&strong, &weak]] {
        let output = temp.path().join("strong_got_exec");
        cargo_linker_with_debug(0)
            .arg("-o")
            .arg(&output)
            .args(inputs)
            .assert()
            .success();
        run_executable(&output).code(42);
    }
}
