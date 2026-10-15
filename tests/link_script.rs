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

#[test]
fn walks_init_array_in_priority_order_without_crt() {
    let temp = tempdir().unwrap();
    let input = assemble_object(
        &temp,
        "constructors",
        r#"
.global _start
.text
_start:
    lea __init_array_start(%rip), %r12
    lea __init_array_end(%rip), %r13
1:
    cmp %r13, %r12
    je 2f
    call *(%r12)
    add $8, %r12
    jmp 1b
2:
    mov result(%rip), %edi
    mov $60, %eax
    syscall
first:
    movl $1, result(%rip)
    ret
second:
    imull $10, result(%rip), %eax
    add $2, %eax
    mov %eax, result(%rip)
    ret
last:
    imull $10, result(%rip), %eax
    add $3, %eax
    mov %eax, result(%rip)
    ret
.section .init_array.200,"aw",@init_array
.balign 8
.quad second
.section .init_array.100,"aw",@init_array
.balign 8
.quad first
.section .init_array,"aw",@init_array
.balign 8
.quad last
.bss
.balign 4
result:
    .skip 4
"#,
    );
    let output = temp.path().join("constructors_exec");
    cargo_linker_with_debug(0)
        .arg("-o")
        .arg(&output)
        .arg(&input)
        .assert()
        .success();
    run_executable(&output).code(123);
}

#[test]
fn explicit_output_address_and_script_symbols_are_used_by_code() {
    let temp = tempdir().unwrap();
    let input = assemble_object(
        &temp,
        "explicit_address",
        r#"
.global _start
.text
_start:
    lea value(%rip), %rax
    cmp $value_address, %rax
    jne failed
    cmpb $42, (%rax)
    jne failed
    mov $answer, %edi
    jmp exit
failed:
    mov $1, %edi
exit:
    mov $60, %eax
    syscall
.section .special,"a"
value:
    .byte 42
"#,
    );
    let script = temp.path().join("explicit.ld");
    fs::write(
        &script,
        r#"
ENTRY(_start)
answer = 6 * 7;
SECTIONS {
    . = 0x600000 + SIZEOF_HEADERS;
    .text 0x601000 : { *(.text) }
    .special 0x602000 : { value_address = .; *(.special) }
    /DISCARD/ : { *(.note*) }
}
"#,
    )
    .unwrap();
    let output = temp.path().join("explicit_exec");
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
    assert_eq!(elf.entry(), 0x601000);
    let special = elf
        .program_headers()
        .find(|header| header.vaddr() == 0x602000)
        .unwrap();
    assert_eq!(special.data().unwrap(), &[42]);
    assert_eq!(elf.program_headers().next().unwrap().vaddr(), 0x600000);
    run_executable(&output).code(42);
}

#[test]
fn init_fragments_are_contiguous_in_input_order() {
    let temp = tempdir().unwrap();
    let first = assemble_object(
        &temp,
        "init_first",
        r#"
.global _start, initialize
.section .init,"ax"
initialize:
    mov $17, %edi
.text
_start:
    call initialize
    mov $60, %eax
    syscall
"#,
    );
    let last = assemble_object(
        &temp,
        "init_last",
        r#"
.section .init,"ax"
    add $25, %edi
    ret
.text
    ud2
"#,
    );
    let output = temp.path().join("init_fragments_exec");
    cargo_linker_with_debug(0)
        .arg("-o")
        .arg(&output)
        .arg(&first)
        .arg(&last)
        .assert()
        .success();
    let bytes = read_output_bytes(&output);
    let elf = parse_elf64(&bytes);
    let code = elf
        .program_headers()
        .find(|header| header.flags() == elf::PF_R | elf::PF_X)
        .unwrap();
    assert_eq!(
        &code.data().unwrap()[..9],
        &[0xbf, 17, 0, 0, 0, 0x83, 0xc7, 25, 0xc3]
    );
    run_executable(&output).code(42);
}

#[test]
fn provide_respects_input_definitions_and_weak_references() {
    let temp = tempdir().unwrap();
    let input = assemble_object(
        &temp,
        "provide",
        r#"
.global _start, from_input
.set from_input, 20
.weak from_script
.text
_start:
    mov $from_input, %edi
    add $from_script, %edi
    mov $60, %eax
    syscall
"#,
    );
    let script = temp.path().join("provide.ld");
    fs::write(
        &script,
        r#"
ENTRY(_start)
PROVIDE(from_input = missing);
PROVIDE(unreferenced = missing);
PROVIDE_HIDDEN(from_script = 22);
SECTIONS { . = 0x400000 + SIZEOF_HEADERS; .text : { *(.text) } }
"#,
    )
    .unwrap();
    let output = temp.path().join("provide_exec");
    cargo_linker_with_debug(0)
        .arg("-T")
        .arg(&script)
        .arg("-o")
        .arg(&output)
        .arg(&input)
        .assert()
        .success();
    run_executable(&output).code(42);

    fs::write(
        &script,
        "from_input = 3; SECTIONS { . = 0x401000; .text : { *(.text) } }",
    )
    .unwrap();
    cargo_linker_with_debug(0)
        .arg("-T")
        .arg(&script)
        .arg("-o")
        .arg(&output)
        .arg(&input)
        .assert()
        .failure()
        .stderr(contains("multiple definition of symbol: from_input"));
}

#[test]
fn real_header_size_and_leading_read_only_section_share_first_load() {
    let temp = tempdir().unwrap();
    let input = assemble_object(
        &temp,
        "header_size",
        r#"
.global _start
.section .leading,"a"
.balign 8
.quad 0x1122334455667788
.text
_start:
    mov $header_size, %edi
    cmp $232, %edi
    jne exit
    xor %edi, %edi
exit:
    mov $60, %eax
    syscall
"#,
    );
    let script = temp.path().join("headers.ld");
    fs::write(
        &script,
        r#"
ENTRY(_start)
SECTIONS {
    . = 0x400000 + SIZEOF_HEADERS;
    header_size = SIZEOF_HEADERS;
    /DISCARD/ : { *(.note*) }
    .leading : { *(.leading) }
    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .text : { *(.text) }
}
"#,
    )
    .unwrap();
    let output = temp.path().join("header_size_exec");
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
    let headers = elf.program_headers().collect::<Vec<_>>();
    assert_eq!(headers.len(), 3);
    assert_eq!(headers[0].offset(), 0);
    assert_eq!(headers[0].vaddr(), 0x400000);
    assert_eq!(headers[0].file_size(), 232 + 8);
    assert_eq!(
        &headers[0].data().unwrap()[232..240],
        &0x1122334455667788u64.to_le_bytes()
    );
    assert_eq!(headers[1].vaddr(), 0x401000);
    assert_eq!(
        headers[2].segment_type(),
        ElfProgramHeaderType::PT_GNU_STACK
    );
    run_executable(&output).success();
}
