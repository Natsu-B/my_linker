#![cfg(target_os = "linux")]

mod common;

use std::fs;

use common::toolchain::{
    assemble_object, cargo_linker_with_debug, create_archive, parse_elf64, read_output_bytes,
    run_executable,
};
use elf::x86_64::X86_64RelocationType;
use tempfile::tempdir;

const START: &str = r#"
.global _start, selector, resolver_calls
.type foo,@function
.text
_start:
    cmpq $0, resolver_calls(%rip)
    jne failed
    # Choose an implementation at runtime, before applying IRELATIVE.
    movb $1, selector(%rip)
    lea __rela_iplt_start(%rip), %r12
    lea __rela_iplt_end(%rip), %r13
    mov %r13, %rax
    sub %r12, %rax
    cmp $72, %rax                 # Three IFUNCs, one record each.
    jne failed
apply_irelative:
    cmp %r13, %r12
    je resolved
    cmpq $37, 8(%r12)             # R_X86_64_IRELATIVE, symbol index zero.
    jne failed
    mov (%r12), %r14
    cmpq $0, (%r14)               # No resolver was run by the linker.
    jne failed
    call *16(%r12)
    mov %rax, (%r14)
    add $24, %r12
    jmp apply_irelative
resolved:
    cmpq $3, resolver_calls(%rip)
    jne failed
    call foo                     # PLT32 from an undefined STT_FUNC reference.
    cmp $42, %eax
    jne failed
    lea foo(%rip), %r15           # PC32 gives the canonical stub address.
    cmp absolute_foo(%rip), %r15  # R_X86_64_64 gives the same address.
    jne failed
    mov $foo, %rax                # R_X86_64_32S
    cmp %r15, %rax
    jne failed
    mov $foo, %eax                # R_X86_64_32
    cmp %r15, %rax
    jne failed
    lea 3(%r15), %rax
    cmp absolute_with_addend(%rip), %rax
    jne failed
    call *%r15
    cmp $42, %eax
    jne failed
    mov foo@GOTPCREL(%rip), %rbx   # REX_GOTPCRELX uses the resolved GOT slot.
    call *%rbx
    cmp $42, %eax
    jne failed
    call *foo@GOTPCREL(%rip)      # GOTPCRELX shares that slot.
    cmp $42, %eax
    jne failed
    .byte 0x48, 0x8b, 0x05
plain_displacement:
    .long 0
    .reloc plain_displacement, R_X86_64_GOTPCREL, foo-4
    cmp %rbx, %rax
    jne failed
    call *got_only@GOTPCREL(%rip)
    cmp $7, %eax
    jne failed
    call *absolute_only_pointer(%rip)
    cmp $42, %eax
    jne failed
    cmpq $3, resolver_calls(%rip)  # Calls never run a resolver again.
    jne failed
    mov %eax, %edi
    mov $60, %eax
    syscall
failed:
    mov $1, %edi
    mov $60, %eax
    syscall
.data
.balign 8
absolute_foo:
    .quad foo
absolute_with_addend:
    .quad foo+3
absolute_only_pointer:
    .quad absolute_only
resolver_calls:
    .quad 0
selector:
    .byte 0
"#;

const RESOLVERS: &str = r#"
.global foo, got_only, absolute_only
.type foo,@gnu_indirect_function
.type got_only,@gnu_indirect_function
.type absolute_only,@gnu_indirect_function
.text
foo:
    incq resolver_calls(%rip)
    lea implementation_7(%rip), %rax
    cmpb $0, selector(%rip)
    je done
    lea implementation_42(%rip), %rax
done:
    ret
got_only:
    incq resolver_calls(%rip)
    lea implementation_7(%rip), %rax
    ret
absolute_only:
    incq resolver_calls(%rip)
    lea implementation_42(%rip), %rax
    ret
implementation_7:
    mov $7, %eax
    ret
implementation_42:
    mov $42, %eax
    ret
"#;

#[test]
fn applies_irelative_and_uses_canonical_ifunc_addresses() {
    let temp = tempdir().unwrap();
    let start = assemble_object(&temp, "start", START);
    let resolvers = assemble_object(&temp, "resolvers", RESOLVERS);
    let archive = create_archive(&temp, "libresolvers", &[&resolvers]);
    let bytes = read_output_bytes(&start);
    let object = parse_elf64(&bytes);
    let types = object
        .sections()
        .filter(|section| section.section_type() == elf::Elf64SectionType::SHT_RELA)
        .flat_map(|section| {
            section
                .rela()
                .unwrap()
                .map(|relocation| X86_64RelocationType::try_from(relocation.info()).unwrap())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    for ty in [
        X86_64RelocationType::Plt32,
        X86_64RelocationType::Pc32,
        X86_64RelocationType::Rel64,
        X86_64RelocationType::Rel32,
        X86_64RelocationType::Rel32S,
        X86_64RelocationType::GotPcRel,
        X86_64RelocationType::GotPcRelX,
        X86_64RelocationType::RexGotPcRelX,
    ] {
        assert!(types.contains(&ty), "missing {ty:?} in IFUNC fixture");
    }
    let script = temp.path().join("ifunc.ld");
    fs::write(
        &script,
        r#"
ENTRY(_start)
SECTIONS {
    . = 0x600000 + SIZEOF_HEADERS;
    .records 0x601000 : {
        . = . + 8;
        PROVIDE_HIDDEN(__rela_iplt_start = .);
        *(.rela.iplt)
        PROVIDE_HIDDEN(__rela_iplt_end = .);
    }
    .dispatch 0x603000 : { . = . + 16; *(.iplt) }
    .text 0x604000 : { *(.text) }
    .storage 0x607000 : {
        . = . + 24;
        PROVIDE_HIDDEN(_GLOBAL_OFFSET_TABLE_ = .);
        *(.got)
    }
    .data : { *(.data) }
    .bss : { *(.bss) }
}
"#,
    )
    .unwrap();
    for custom_script in [false, true] {
        let output = temp.path().join("ifunc_exec");
        let mut command = cargo_linker_with_debug(0);
        if custom_script {
            command.arg("-T").arg(&script);
        }
        command
            .arg("-o")
            .arg(&output)
            .arg(&start)
            .arg(if custom_script { &archive } else { &resolvers })
            .assert()
            .success();
        if custom_script {
            let bytes = read_output_bytes(&output);
            let executable = parse_elf64(&bytes);
            let records = executable
                .program_headers()
                .find(|header| header.flags() == elf::PF_R)
                .unwrap();
            let offset = (0x601008 - records.vaddr()) as usize;
            let records = &records.data().unwrap()[offset..offset + 72];
            for record in records.chunks_exact(24) {
                let slot = u64::from_le_bytes(record[..8].try_into().unwrap());
                assert!((0x607018..0x607030).contains(&slot));
                assert_eq!(slot % 8, 0);
                assert_eq!(u64::from_le_bytes(record[8..16].try_into().unwrap()), 37);
                let resolver = u64::from_le_bytes(record[16..].try_into().unwrap());
                assert!((0x604000..0x605000).contains(&resolver));
            }
            let text = executable
                .program_headers()
                .find(|header| header.flags() == elf::PF_R | elf::PF_X)
                .unwrap();
            assert_eq!(text.vaddr(), 0x603000);
            assert_eq!(&text.data().unwrap()[16..18], &[0xff, 0x25]);
        }
        run_executable(&output).code(42);
    }
}
