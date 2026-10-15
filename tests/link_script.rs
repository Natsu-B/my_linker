#![cfg(target_os = "linux")]

mod common;

use std::fs;

use elf::ElfProgramHeaderType;
use predicates::str::contains;
use tempfile::tempdir;

use common::toolchain::{
    assemble_object, cargo_linker_with_debug, create_archive, parse_elf64, read_output_bytes,
    run_executable,
};

#[test]
fn custom_script_sets_entry_and_base_address() {
    let temp = tempdir().unwrap();
    let input = assemble_object(
        &temp,
        "custom_entry",
        r#"
.global _start, boot
.text
_start:
    mov $60, %eax
    mov $1, %edi
    syscall
boot:
    mov $60, %eax
    xor %edi, %edi
    syscall
"#,
    );
    let script = temp.path().join("custom.ld");
    fs::write(
        &script,
        r#"
ENTRY(boot)
SECTIONS {
    . = SEGMENT_START("text-segment", 0x600000) + SIZEOF_HEADERS;
    .text : { *(.text .text.*) }
}
"#,
    )
    .unwrap();

    for option in ["-T", "--script"] {
        let output = temp.path().join(format!("custom_{option}"));
        cargo_linker_with_debug(0)
            .arg(option)
            .arg(&script)
            .arg("-o")
            .arg(&output)
            .arg(&input)
            .assert()
            .success();

        let bytes = read_output_bytes(&output);
        let elf = parse_elf64(&bytes);
        let header_load = elf
            .program_headers()
            .find(|header| header.segment_type() == ElfProgramHeaderType::PT_LOAD)
            .unwrap();
        assert_eq!(header_load.vaddr(), 0x600000);
        assert_eq!(header_load.offset(), 0);
        assert!(elf.entry() >= 0x601000);
        run_executable(&output).success();
    }
}

#[test]
fn entry_symbol_extracts_an_archive_member() {
    let temp = tempdir().unwrap();
    let input = assemble_object(
        &temp,
        "archive_entry",
        r#"
.global boot
.text
boot:
    mov $60, %eax
    xor %edi, %edi
    syscall
"#,
    );
    let archive = create_archive(&temp, "libentry", &[&input]);
    let script = temp.path().join("entry.ld");
    fs::write(
        &script,
        "ENTRY(boot) SECTIONS { . = 0x400000; .text : { *(.text) } }",
    )
    .unwrap();
    let output = temp.path().join("archive_entry_exec");
    cargo_linker_with_debug(0)
        .arg("-T")
        .arg(&script)
        .arg("-o")
        .arg(&output)
        .arg(&archive)
        .assert()
        .success();
    run_executable(&output).success();
}

#[test]
fn invalid_script_is_reported_before_opening_inputs() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("unsupported.ld");
    fs::write(&script, "/* unsupported */\n  MEMORY {}\n").unwrap();
    cargo_linker_with_debug(0)
        .arg("-T")
        .arg(&script)
        .arg("-o")
        .arg(temp.path().join("out"))
        .arg(temp.path().join("missing.o"))
        .assert()
        .failure()
        .stderr(contains("unsupported.ld"))
        .stderr(contains("2:3: unsupported linker script command MEMORY"));
}
