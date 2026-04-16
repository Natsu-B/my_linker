use std::{
    fs,
    path::{Path, PathBuf},
    process::Command as StdCommand,
};

use assert_cmd::Command;
use elf::Elf64;
use tempfile::TempDir;

pub fn assert_linux_host() {
    assert_eq!(
        std::env::consts::OS,
        "linux",
        "GNU as/ld based integration tests require Linux",
    );
}

pub fn write_asm_source(dir: &TempDir, file_name: &str, source: &str) -> PathBuf {
    let path = dir.path().join(file_name);
    fs::write(&path, source).unwrap_or_else(|err| {
        panic!("failed to write assembly source {}: {err}", path.display());
    });
    path
}

pub fn assemble_object(dir: &TempDir, stem: &str, source: &str) -> PathBuf {
    assert_linux_host();

    let asm_path = write_asm_source(dir, &format!("{stem}.s"), source);
    let object_path = dir.path().join(format!("{stem}.o"));

    let mut command = StdCommand::new("as");
    command
        .arg("--64")
        .arg("-o")
        .arg(&object_path)
        .arg(&asm_path);
    run_tool(command, &format!("assemble {}", object_path.display()));

    object_path
}

#[allow(dead_code)]
pub fn link_executable_input(dir: &TempDir, output_name: &str, inputs: &[&Path]) -> PathBuf {
    assert_linux_host();

    let output_path = dir.path().join(output_name);

    let mut command = StdCommand::new("ld");
    command
        .arg("-o")
        .arg(&output_path)
        .arg("-e")
        .arg("_start")
        .arg("-no-pie");
    for input in inputs {
        command.arg(input);
    }
    run_tool(command, &format!("link {}", output_path.display()));

    output_path
}

pub fn cargo_linker() -> Command {
    let mut command = Command::cargo_bin("my_linker").unwrap_or_else(|err| {
        panic!("failed to locate my_linker test binary: {err}");
    });
    command.env("NO_COLOR", "1");
    command.env("RAYON_NUM_THREADS", "1");
    command
}

pub fn cargo_linker_with_debug(debug: u8) -> Command {
    let mut command = cargo_linker();
    command.arg("--debug").arg(debug.to_string());
    command
}

pub fn read_output_bytes(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|err| {
        panic!("failed to read output file {}: {err}", path.display());
    })
}

pub fn parse_elf64<'a>(bytes: &'a [u8]) -> Elf64<'a> {
    Elf64::new(bytes).unwrap_or_else(|err| {
        panic!("failed to parse ELF output: {err:#}");
    })
}

fn run_tool(mut command: StdCommand, action: &str) {
    let rendered = format!("{command:?}");
    let output = command.output().unwrap_or_else(|err| {
        panic!("failed to spawn {action} with {rendered}: {err}");
    });

    if !output.status.success() {
        panic!(
            "{action} failed\ncommand: {rendered}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
