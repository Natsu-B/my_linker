pub(crate) mod archive;
mod file_id;
pub(crate) mod object;
mod open;

use anyhow::{Result, ensure};
use memmap2::Mmap;
use rayon::prelude::*;

pub(crate) use file_id::FileId;

pub(crate) enum InputFile<'a> {
    Object(object::ObjectFile<'a>),
    Archive(archive::index::ArchiveState<'a>),
}

/// Own the mappings separately so parsed sections and names can borrow them.
#[derive(Default)]
pub(crate) struct MappedFiles {
    mappings: Vec<Mmap>,
}

pub(crate) struct LoadedInputs<'a> {
    pub(crate) files: Vec<InputFile<'a>>,
}

pub(crate) fn load<'a>(paths: &[String], storage: &'a mut MappedFiles) -> Result<LoadedInputs<'a>> {
    let opened = paths.par_iter().map(open::open_file_and_mmap).collect();
    storage.mappings = collect_results(opened, paths, "open")?;
    let parsed = storage
        .mappings
        .par_iter()
        .zip(paths.par_iter())
        .enumerate()
        .map(|(input_index, (bytes, path))| {
            if elf::Elf64::check_elf_magic(bytes) {
                object::parse(bytes, path.clone(), FileId::InputObject { input_index })
                    .map(InputFile::Object)
            } else {
                archive::index::index_archive(bytes, path.clone(), input_index)
                    .map(InputFile::Archive)
            }
        })
        .collect();
    Ok(LoadedInputs {
        files: collect_results(parsed, paths, "parse")?,
    })
}

fn collect_results<T>(results: Vec<Result<T>>, paths: &[String], action: &str) -> Result<Vec<T>> {
    let mut values = Vec::with_capacity(results.len());
    let mut errors = 0;
    for (result, path) in results.into_iter().zip(paths) {
        match result {
            Ok(value) => values.push(value),
            Err(error) => {
                debugs_or!(
                    pr_err!("file:{path}: {error:?}"),
                    pr_err!("file:{path}: {error}")
                );
                errors += 1;
            }
        }
    }
    ensure!(errors == 0, "{errors} file(s) failed to {action}");
    Ok(values)
}
