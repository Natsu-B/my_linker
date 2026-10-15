#![cfg(target_os = "linux")]

mod common;

use common::toolchain::{
    assemble_object, cargo_linker_with_debug, parse_elf64, read_output_bytes, run_executable,
};
use elf::{ElfProgramHeaderType, x86_64::X86_64RelocationType};
use predicates::str::contains;
use tempfile::tempdir;

#[test]
fn local_and_initial_exec_tls_work_with_a_manually_initialized_thread_pointer() {
    let temp = tempdir().unwrap();
    let input = assemble_object(
        &temp,
        "tls",
        r#"
.global _start
.weak optional
.type optional,@tls_object
.text
_start:
    cld
    # Skip argc, argv (including its terminator), and envp to reach auxv.
    mov (%rsp), %rax
    lea 16(%rsp,%rax,8), %rsi
skip_env:
    lodsq
    test %rax, %rax
    jne skip_env
    xor %r8d, %r8d
    xor %r9d, %r9d
    xor %r10d, %r10d
read_aux:
    lodsq
    mov %rax, %rdx
    lodsq
    test %rdx, %rdx
    je find_tls
    cmp $3, %rdx                  # AT_PHDR
    cmove %rax, %r8
    cmp $4, %rdx                  # AT_PHENT
    cmove %rax, %r10
    cmp $5, %rdx                  # AT_PHNUM
    cmove %rax, %r9
    jmp read_aux
find_tls:
    test %r8, %r8
    je failed
    cmp $56, %r10
    jne failed
next_phdr:
    test %r9, %r9
    je failed
    cmpl $7, (%r8)                # PT_TLS
    je setup_tls
    add %r10, %r8
    dec %r9
    jmp next_phdr
setup_tls:
    # This test reserves 256 bytes, aligned to 64, for TLS and the TCB.
    mov 48(%r8), %rdx             # p_align
    test %rdx, %rdx
    je failed
    cmp $64, %rdx
    ja failed
    mov 40(%r8), %rax             # p_memsz
    cmp $128, %rax
    ja failed
    mov 32(%r8), %rcx             # p_filesz
    cmp %rax, %rcx
    ja failed
    lea -1(%rax,%rdx), %rax
    neg %rdx
    and %rdx, %rax                # align_up(p_memsz, p_align)
    mov %rax, %r13
    lea tls_block(%rip), %rdi
    lea (%rdi,%rax), %r12         # TP follows the TLS block (variant II).
    mov %r12, (%r12)              # TCB self-pointer
    mov 16(%r8), %rsi             # p_vaddr, the mapped .tdata image
    rep movsb                    # .tbss is already zero in tls_block.
    mov $158, %eax                # arch_prctl(ARCH_SET_FS, TP)
    mov $0x1002, %edi
    mov %r12, %rsi
    syscall
    test %rax, %rax
    jne failed
    cmp %r12, %fs:0
    jne failed

    # Undefined weak TLS references use S = 0, like GNU ld.
    mov $optional@tpoff, %rax
    mov optional@gottpoff(%rip), %rdx
    cmp %rax, %rdx
    jne failed
    mov 16(%r8), %rcx
    add %r13, %rcx
    neg %rcx
    cmp %rcx, %rax
    jne failed

    mov %fs:value@tpoff, %rdi     # Local-exec
    cmp $20, %rdi
    jne failed
    mov value@gottpoff(%rip), %rax
    mov %fs:(%rax), %rax          # Initial-exec, without relaxation
    cmp %rdi, %rax
    jne failed
    add %rax, %rdi
    mov value@gottpoff(%rip), %rax # Repeated references share one slot.
    add $3, %rax
    cmp offset64(%rip), %rax      # TPOFF64 includes its explicit addend.
    jne failed
    cmpq $7, %fs:value@tpoff+8    # TPOFF32 also includes its addend.
    jne failed
    cmpq $0, %fs:zero_value@tpoff
    jne failed
    mov zero_value@gottpoff(%rip), %rax
    cmpq $0, %fs:(%rax)
    jne failed
    movq $2, %fs:(%rax)
    add %fs:zero_value@tpoff, %rdi
    # Initialized RW data following .tbss must retain its contents.
    cmpq $0x12345678, sentinel(%rip)
    jne failed
    mov $60, %eax
    syscall
failed:
    mov $1, %edi
    mov $60, %eax
    syscall

.section .tdata,"awT",@progbits
.balign 8
.type value,@tls_object
value:
    .quad 20, 7
.size value, .-value
.section .tbss,"awT",@nobits
.balign 32
    .zero 8
.type zero_value,@tls_object
zero_value:
    .zero 8
.size zero_value, .-zero_value
    .zero 1
.data
sentinel:
    .quad 0x12345678
offset64:
    .quad value@tpoff+3
.bss
.balign 64
tls_block:
    .zero 256
"#,
    );
    let bytes = read_output_bytes(&input);
    let object = parse_elf64(&bytes);
    let relocations = object
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
        X86_64RelocationType::TpOff32,
        X86_64RelocationType::TpOff64,
        X86_64RelocationType::GotTpOff,
    ] {
        assert!(relocations.contains(&ty), "missing {ty:?} in TLS fixture");
    }
    let output = temp.path().join("tls_exec");
    cargo_linker_with_debug(0)
        .arg("-o")
        .arg(&output)
        .arg(&input)
        .assert()
        .success();
    let bytes = read_output_bytes(&output);
    let elf = parse_elf64(&bytes);
    let tls = elf
        .program_headers()
        .find(|header| header.segment_type() == ElfProgramHeaderType::PT_TLS)
        .unwrap();
    assert_eq!(tls.file_size(), 16);
    assert_eq!(tls.mem_size(), 49);
    assert_eq!(tls.align(), 32);
    assert_eq!(tls.vaddr() % tls.align(), 0);
    run_executable(&output).code(42);
}

#[test]
fn rejects_unsupported_tls_models() {
    let temp = tempdir().unwrap();
    for ty in [
        "TLSGD",
        "TLSLD",
        "DTPMOD64",
        "DTPOFF32",
        "DTPOFF64",
        "GOTPC32_TLSDESC",
        "TLSDESC_CALL",
        "TLSDESC",
    ] {
        let input = assemble_object(
            &temp,
            ty,
            &format!(
                r#"
.global _start
.text
_start:
    .quad 0
    .reloc _start, R_X86_64_{ty}, value
.section .tdata,"awT",@progbits
.type value,@tls_object
value:
    .quad 1
"#
            ),
        );
        cargo_linker_with_debug(0)
            .arg("-o")
            .arg(temp.path().join("unsupported"))
            .arg(input)
            .assert()
            .failure()
            .stderr(contains("unsupported TLS model"));
    }
}

#[test]
fn rejects_non_tls_relocations_to_tls_symbols() {
    let temp = tempdir().unwrap();
    for ty in ["64", "PC32", "GOTPCREL", "GOTPCRELX", "REX_GOTPCRELX"] {
        let input = assemble_object(
            &temp,
            ty,
            &format!(
                r#"
.global _start
.text
_start:
    .quad 0
    .reloc _start, R_X86_64_{ty}, value
.section .tdata,"awT",@progbits
.type value,@tls_object
value:
    .quad 1
"#
            ),
        );
        cargo_linker_with_debug(0)
            .arg("-o")
            .arg(temp.path().join("non_tls"))
            .arg(input)
            .assert()
            .failure()
            .stderr(contains("non-TLS relocation"))
            .stderr(contains("TLS symbol: value"));
    }
}

#[test]
fn rejects_tpoff32_overflow() {
    let temp = tempdir().unwrap();
    let input = assemble_object(
        &temp,
        "overflow",
        r#"
.global _start
.text
_start:
    .long 0
    .reloc _start, R_X86_64_TPOFF32, value+0x80000008
.section .tdata,"awT",@progbits
.balign 8
.type value,@tls_object
value:
    .quad 1
"#,
    );
    cargo_linker_with_debug(0)
        .arg("-o")
        .arg(temp.path().join("overflow"))
        .arg(input)
        .assert()
        .failure()
        .stderr(contains("relocation TpOff32"))
        .stderr(contains("symbol 'value' at 0x401000"))
        .stderr(contains("overflows Signed Bits32 field"));
}
