#![cfg(target_os = "linux")]

#[allow(dead_code)]
mod common;

use std::{fs, process::Command};

use common::toolchain::{
    assemble_object, cargo_linker_with_debug, parse_elf64, read_output_bytes, run_executable,
};
use elf::{
    Elf64SectionType, Elf64SymbolBinding, Elf64SymbolInfo, Elf64SymbolSectionIdx, Elf64SymbolType,
    ElfProgramHeaderType,
};
use tempfile::tempdir;

#[test]
fn sections_and_symbols_describe_the_loaded_image() {
    let temp = tempdir().unwrap();
    let first = assemble_object(
        &temp,
        "first",
        r#"
.text
.global _start
.type _start,@function
_start:
    mov $60, %eax
    mov $42, %edi
    syscall
.size _start, .-_start
.type helper,@function
helper: ret
.size helper, .-helper
.data
.weak selected
.type selected,@object
selected: .byte 1
.size selected, .-selected
.quad hidden_marker
.weak optional
.quad optional
.section .tdata,"awT",@progbits
.balign 64
.global initialized
.type initialized,@tls_object
initialized: .long 17
.size initialized, .-initialized
.type local_tls,@tls_object
local_tls: .long 23
.size local_tls, .-local_tls
.section .tbss,"awT",@nobits
.balign 16
.global zero_initialized
.type zero_initialized,@tls_object
zero_initialized: .zero 4
.size zero_initialized, .-zero_initialized
.bss
.balign 32
.global buffer
.type buffer,@object
buffer: .zero 32
.size buffer, .-buffer
"#,
    );
    let second = assemble_object(
        &temp,
        "second",
        r#"
.text
.type helper,@function
helper: nop; ret
.size helper, .-helper
.data
.global selected
.hidden selected
.type selected,@object
selected: .quad 123
.size selected, .-selected
.weak weak_definition
.type weak_definition,@object
weak_definition: .long 7
.size weak_definition, .-weak_definition
"#,
    );
    let script = temp.path().join("metadata.ld");
    fs::write(
        &script,
        r#"
ENTRY(_start)
absolute = 42;
literal_address = 0x401000;
SECTIONS {
  . = 0x401000;
  .text : {
    text_start = .;
    PROVIDE_HIDDEN(hidden_marker = .);
    *(.text)
    text_end = .;
  }
  alias = text_start;
  span = text_end - text_start;
  .data : { *(.data) }
  .tdata : { *(.tdata) }
  .tbss : { *(.tbss) }
  .bss : { *(.bss) }
}
"#,
    )
    .unwrap();
    let output = temp.path().join("metadata");
    cargo_linker_with_debug(0)
        .arg("-T")
        .arg(&script)
        .arg("-o")
        .arg(&output)
        .args([first, second])
        .assert()
        .success();
    run_executable(&output).code(42);
    let bytes = read_output_bytes(&output);
    let elf = parse_elf64(&bytes);
    let sections = elf.sections().collect::<Vec<_>>();
    for section in sections
        .iter()
        .filter(|section| section.flags().get(elf::Elf64SectionFlags::SHF_ALLOC) != 0)
    {
        let load = elf
            .program_headers()
            .find(|header| {
                header.segment_type() == ElfProgramHeaderType::PT_LOAD
                    && section.address() >= header.vaddr()
                    && section.address() + section.size() <= header.vaddr() + header.mem_size()
            })
            .unwrap();
        assert_eq!(
            section.offset(),
            load.offset() + section.address() - load.vaddr()
        );
        assert_eq!(section.address() % section.align(), 0);
        if section.section_type() != Elf64SectionType::SHT_NOBITS {
            assert_eq!(section.data().unwrap().len() as u64, section.size());
        }
    }
    let symtab = sections
        .iter()
        .find(|section| section.name().unwrap() == ".symtab")
        .unwrap();
    let symbols = symtab.symbols().unwrap().collect::<Vec<_>>();
    assert_eq!(symtab.entry_size(), 24);
    assert_eq!(sections[symtab.link() as usize].name().unwrap(), ".strtab");
    assert_eq!(symbols[0].name().unwrap(), "");
    for (index, symbol) in symbols.iter().enumerate() {
        assert_eq!(
            symbol.info().get_enum(Elf64SymbolInfo::st_bind) == Some(Elf64SymbolBinding::STB_LOCAL),
            index < symtab.info() as usize
        );
    }
    let named = |name: &str| {
        symbols
            .iter()
            .find(|symbol| symbol.name().unwrap() == name)
            .unwrap()
    };
    let text = sections
        .iter()
        .find(|section| section.name().unwrap() == ".text")
        .unwrap();
    for name in ["_start", "text_start", "text_end", "alias", "hidden_marker"] {
        assert_eq!(
            named(name).section_idx(),
            Elf64SymbolSectionIdx::Index(text.idx())
        );
    }
    for name in ["absolute", "literal_address", "span"] {
        assert_eq!(
            named(name).section_idx(),
            Elf64SymbolSectionIdx::AbsoluteSymbols
        );
    }
    assert_eq!(named("span").value(), text.size());
    assert_eq!(named("_start").size(), 12);
    assert_eq!(named("selected").size(), 8);
    assert_eq!(named("selected").other(), 2);
    assert_eq!(
        named("weak_definition")
            .info()
            .get_enum(Elf64SymbolInfo::st_bind),
        Some(Elf64SymbolBinding::STB_WEAK)
    );
    assert_eq!(
        named("optional").section_idx(),
        Elf64SymbolSectionIdx::Undefined
    );
    let helpers = symbols
        .iter()
        .filter(|symbol| symbol.name().unwrap() == "helper")
        .collect::<Vec<_>>();
    assert_eq!(helpers.len(), 2);
    assert_ne!(helpers[0].value(), helpers[1].value());
    let tls = elf
        .program_headers()
        .find(|header| header.segment_type() == ElfProgramHeaderType::PT_TLS)
        .unwrap();
    for name in ["initialized", "local_tls", "zero_initialized"] {
        let symbol = named(name);
        assert_eq!(
            symbol.info().get_enum(Elf64SymbolInfo::st_type),
            Some(Elf64SymbolType::STT_TLS)
        );
        let Elf64SymbolSectionIdx::Index(index) = symbol.section_idx() else {
            panic!()
        };
        let section = &sections[index as usize];
        assert!(symbol.value() + tls.vaddr() >= section.address());
        assert!(symbol.value() + tls.vaddr() + symbol.size() <= section.address() + section.size());
    }
    assert_eq!(named("initialized").value(), 0);
    assert_eq!(named("zero_initialized").value(), 16);
    for (tool, flag) in [
        ("readelf", "-SW"),
        ("readelf", "-sW"),
        ("readelf", "-rW"),
        ("nm", "-a"),
        ("objdump", "-d"),
    ] {
        let result = Command::new(tool).arg(flag).arg(&output).output().unwrap();
        assert!(result.status.success());
        assert!(
            result.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        if tool == "objdump" {
            assert!(String::from_utf8_lossy(&result.stdout).contains("<_start>:"));
        }
    }
}

#[test]
fn merge_orphan_stays_beside_rodata_before_writable_loads() {
    let temp = tempdir().unwrap();
    let input = assemble_object(
        &temp,
        "orphan",
        r#"
.global _start
.text
_start: mov $60, %eax; xor %edi, %edi; syscall
.section .rodata
.byte 1
.section rodata.cst32,"aM",@progbits,32
.balign 32
.zero 32
.data
.byte 2
.bss
.zero 16
.section .tbss.extra,"awT",@nobits
.zero 8
"#,
    );
    let output = temp.path().join("orphan");
    cargo_linker_with_debug(0)
        .arg("-o")
        .arg(&output)
        .arg(input)
        .assert()
        .success();
    let bytes = read_output_bytes(&output);
    let elf = parse_elf64(&bytes);
    let sections = elf.sections().collect::<Vec<_>>();
    let rodata = sections
        .iter()
        .find(|section| section.name().unwrap() == ".rodata")
        .unwrap();
    let orphan = &sections[rodata.idx() as usize + 1];
    assert_eq!(orphan.name().unwrap(), "rodata.cst32");
    assert_eq!(orphan.entry_size(), 32);
    assert_eq!(orphan.flags().get(elf::Elf64SectionFlags::SHF_ALLOC), 1);
    assert_eq!(orphan.flags().get(elf::Elf64SectionFlags::SHF_MERGE), 1);
    assert_eq!(orphan.flags().get(elf::Elf64SectionFlags::SHF_WRITE), 0);
    let loads = elf
        .program_headers()
        .filter(|header| header.segment_type() == ElfProgramHeaderType::PT_LOAD)
        .collect::<Vec<_>>();
    assert_eq!(
        loads.iter().map(|load| load.flags()).collect::<Vec<_>>(),
        vec![4, 5, 4, 6]
    );
    assert!(orphan.address() >= loads[2].vaddr());
    assert!(orphan.address() + orphan.size() <= loads[2].vaddr() + loads[2].file_size());
    run_executable(&output).success();
}

#[test]
fn empty_sections_keep_marker_values_and_use_adjacent_section_indices() {
    let temp = tempdir().unwrap();
    let input = assemble_object(
        &temp,
        "empty",
        r#"
.global _start
.text
_start: mov $60, %eax; xor %edi, %edi; syscall
.data
.byte 1
"#,
    );
    let script = temp.path().join("empty.ld");
    fs::write(
        &script,
        r#"
ENTRY(_start)
SECTIONS {
  /DISCARD/ : { *(.note.gnu.property) }
  . = 0x401000;
  .leading : { leading = .; }
  .text : { *(.text) }
  .middle : { middle = .; }
  .data 0x402000 : { *(.data) }
  .trailing : { trailing = .; }
}
"#,
    )
    .unwrap();
    let output = temp.path().join("empty");
    let baseline = temp.path().join("empty_ld");
    cargo_linker_with_debug(0)
        .arg("-T")
        .arg(&script)
        .arg("-o")
        .arg(&output)
        .arg(&input)
        .assert()
        .success();
    let result = Command::new("ld")
        .arg("-static")
        .arg("-T")
        .arg(&script)
        .arg("-o")
        .arg(&baseline)
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let markers = |path: &std::path::Path| {
        let bytes = read_output_bytes(path);
        let elf = parse_elf64(&bytes);
        let sections = elf.sections().collect::<Vec<_>>();
        assert!(
            sections
                .iter()
                .filter(|section| section.flags().get(elf::Elf64SectionFlags::SHF_ALLOC) != 0)
                .all(|section| section.size() != 0)
        );
        let table = sections
            .iter()
            .find(|section| section.name().unwrap() == ".symtab")
            .unwrap();
        table
            .symbols()
            .unwrap()
            .filter(|symbol| ["leading", "middle", "trailing"].contains(&symbol.name().unwrap()))
            .map(|symbol| {
                let Elf64SymbolSectionIdx::Index(index) = symbol.section_idx() else {
                    panic!()
                };
                (
                    symbol.name().unwrap().to_string(),
                    (
                        symbol.value(),
                        sections[index as usize].name().unwrap().to_string(),
                    ),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let actual = markers(&output);
    assert_eq!(actual, markers(&baseline));
    assert_eq!(actual["leading"], (0x401000, ".text".to_string()));
    assert_eq!(actual["middle"], (0x401009, ".data".to_string()));
    assert_eq!(actual["trailing"], (0x402001, ".data".to_string()));
    run_executable(&output).success();
}

#[test]
fn unreferenced_got_base_is_not_added_to_the_symbol_table() {
    let temp = tempdir().unwrap();
    let input = assemble_object(
        &temp,
        "unreferenced_got",
        r#"
.global _start, resolver
.type resolver,@gnu_indirect_function
.text
_start: mov $60, %eax; xor %edi, %edi; syscall
resolver: xor %eax, %eax; ret
.data
.quad resolver
"#,
    );
    let output = temp.path().join("unreferenced_got");
    cargo_linker_with_debug(0)
        .arg("-o")
        .arg(&output)
        .arg(input)
        .assert()
        .success();
    let bytes = read_output_bytes(&output);
    let elf = parse_elf64(&bytes);
    assert!(
        elf.sections()
            .any(|section| section.name().unwrap() == ".got")
    );
    let table = elf
        .sections()
        .find(|section| section.name().unwrap() == ".symtab")
        .unwrap();
    assert!(
        !table
            .symbols()
            .unwrap()
            .any(|symbol| symbol.name().unwrap() == "_GLOBAL_OFFSET_TABLE_")
    );
    run_executable(&output).success();
}
