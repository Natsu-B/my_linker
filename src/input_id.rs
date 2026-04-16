use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileId {
    Object(usize),
    ArchiveMember {
        archive_idx: usize,
        member_idx: usize,
    },
}

impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Object(idx) => write!(f, "object[{idx}]"),
            Self::ArchiveMember {
                archive_idx,
                member_idx,
            } => {
                write!(f, "archive[{archive_idx}] member[{member_idx}]")
            }
        }
    }
}
