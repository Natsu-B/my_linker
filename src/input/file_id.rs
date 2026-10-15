use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FileId {
    InputObject {
        input_index: usize,
    },
    ArchiveMember {
        archive_index: usize,
        member_index: usize,
    },
    LinkerGenerated,
}

impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputObject { input_index } => write!(f, "input[{input_index}] (object)"),
            Self::LinkerGenerated => write!(f, "<linker>"),
            Self::ArchiveMember {
                archive_index,
                member_index,
            } => {
                write!(f, "input[{archive_index}] (archive member[{member_index}])")
            }
        }
    }
}
