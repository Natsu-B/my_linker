#![cfg(target_os = "linux")]

mod common;

use std::{path::Path, process::Command as StdCommand};

use common::toolchain::{
    cargo_linker_with_debug, compile_c_object, glibc_static_toolchain, parse_elf64,
    read_output_bytes,
};
use elf::{ElfFileType, ElfMachineType};
use tempfile::tempdir;

const HELLO_SOURCE: &str = r#"
#include <stdio.h>

int main(void) {
    puts("hello, glibc");
    return 0;
}
"#;

const HELLO_STDOUT: &str = "hello, glibc\n";

fn run_and_assert_hello(executable: &Path) {
    let output = StdCommand::new(executable).output().unwrap_or_else(|err| {
        panic!("failed to run {}: {err}", executable.display());
    });

    assert!(
        output.status.success(),
        "{} exited with {}\nstderr:\n{}",
        executable.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), HELLO_STDOUT);
}

/// Sanity check for the toolchain itself: GNU ld must be able to link the same inputs.
#[test]
fn gnu_ld_links_static_glibc_hello_world() {
    let temp = tempdir().unwrap();
    let toolchain = glibc_static_toolchain();
    let main = compile_c_object(&temp, "main", HELLO_SOURCE);
    let output = temp.path().join("hello_ld");

    let mut command = StdCommand::new("ld");
    command.arg("-static").arg("-o").arg(&output);
    for input in toolchain.link_inputs(&[main.as_path()]) {
        command.arg(input);
    }
    let rendered = format!("{command:?}");
    let result = command.output().unwrap_or_else(|err| {
        panic!("failed to spawn {rendered}: {err}");
    });
    assert!(
        result.status.success(),
        "ld failed\ncommand: {rendered}\nstderr:\n{}",
        String::from_utf8_lossy(&result.stderr),
    );

    run_and_assert_hello(&output);
}

#[test]
#[ignore = "my_linker does not yet support static glibc (TLS/IFUNC/GOT relocations)"]
fn links_static_glibc_hello_world() {
    let temp = tempdir().unwrap();
    let toolchain = glibc_static_toolchain();
    let main = compile_c_object(&temp, "main", HELLO_SOURCE);
    let output = temp.path().join("hello");

    let mut command = cargo_linker_with_debug(1);
    command.arg("-o").arg(&output);
    for input in toolchain.link_inputs(&[main.as_path()]) {
        command.arg(input);
    }
    command.assert().success();

    let bytes = read_output_bytes(&output);
    let elf = parse_elf64(&bytes);
    assert_eq!(elf.elf_type(), ElfFileType::ET_EXEC);
    assert_eq!(elf.arch(), ElfMachineType::EM_X86_64);

    run_and_assert_hello(&output);
}
