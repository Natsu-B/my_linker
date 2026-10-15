pub(crate) mod archive;
mod file_id;
pub(crate) mod object;
pub(crate) mod open;

pub(crate) use file_id::FileId;

pub(crate) enum InputFile<'a> {
    Object(object::ObjectFile<'a>),
    Archive(archive::index::ArchiveState<'a>),
}
