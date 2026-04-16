use std::{cell::OnceCell, mem::size_of};

use anyhow::{Context, Result, bail, ensure};

const AR_MAGIC: &[u8; 8] = b"!<arch>\n";
const THIN_MAGIC: &[u8; 8] = b"!<thin>\n";
pub(crate) const AR_FMAG: [u8; 2] = *b"`\n";
const AR_NAME_OFFSET: usize = std::mem::offset_of!(archive_member, ar_name);
const AR_NAME_LEN: usize = size_of::<[u8; 16]>();
const AR_SIZE_OFFSET: usize = std::mem::offset_of!(archive_member, ar_size);
const AR_SIZE_LEN: usize = size_of::<[u8; 10]>();
const AR_FMAG_OFFSET: usize = std::mem::offset_of!(archive_member, ar_fmag);
const AR_FMAG_LEN: usize = size_of::<[u8; 2]>();

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct archive_member {
    ar_name: [u8; 16],
    ar_date: [u8; 12],
    ar_uid: [u8; 6],
    ar_gid: [u8; 6],
    ar_mode: [u8; 8],
    ar_size: [u8; 10],
    ar_fmag: [u8; 2],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberName<'a> {
    SymbolTable,
    SymbolTable64,
    LongNameTable,
    Short(&'a str),
    LongNameOffset(usize),
    BsdExtended(usize),
}

#[derive(Debug, Clone, Copy)]
struct MemberSlice {
    offset: usize,
    size: usize,
}

pub fn check_magic(data: &[u8]) -> bool {
    data.starts_with(AR_MAGIC)
}

#[derive(Debug)]
pub struct ArchiveReader<'a> {
    data: &'a [u8],
    long_name_table: OnceCell<Option<MemberSlice>>,
    symbol_table: OnceCell<Option<MemberSlice>>,
}

impl<'a> ArchiveReader<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self> {
        if data.starts_with(THIN_MAGIC) {
            bail!("thin archives are unsupported");
        }
        ensure!(
            check_magic(data),
            "invalid archive format: missing magic header"
        );

        Ok(Self {
            data,
            long_name_table: OnceCell::new(),
            symbol_table: OnceCell::new(),
        })
    }

    pub fn iter(&self) -> ArchiveIter<'_, 'a> {
        ArchiveIter {
            reader: self,
            offset: AR_MAGIC.len(),
        }
    }

    pub fn object_members(&self) -> ArchiveObjectIter<'_, 'a> {
        ArchiveObjectIter { inner: self.iter() }
    }

    pub fn long_name_table(&self) -> Result<Option<&'a [u8]>> {
        self.cached_special_member(&self.long_name_table, SpecialMemberKind::LongNameTable)
    }

    pub fn symbol_table(&self) -> Result<Option<&'a [u8]>> {
        self.cached_special_member(&self.symbol_table, SpecialMemberKind::SymbolTable)
    }

    fn cached_special_member(
        &self,
        cache: &OnceCell<Option<MemberSlice>>,
        kind: SpecialMemberKind,
    ) -> Result<Option<&'a [u8]>> {
        if let Some(cached) = cache.get() {
            return Ok((*cached).map(|slice| self.slice(slice)));
        }

        let found = self.find_special_member(kind)?;
        let _ = cache.set(found);
        Ok(found.map(|slice| self.slice(slice)))
    }

    fn find_special_member(&self, kind: SpecialMemberKind) -> Result<Option<MemberSlice>> {
        for member in self.iter() {
            let member = member?;
            if kind.matches(member.member_name()?) {
                return Ok(Some(MemberSlice {
                    offset: member.payload_offset(),
                    size: member.size()?,
                }));
            }
        }

        Ok(None)
    }

    fn slice(&self, slice: MemberSlice) -> &'a [u8] {
        &self.data[slice.offset..slice.offset + slice.size]
    }
}

#[derive(Debug, Clone, Copy)]
enum SpecialMemberKind {
    LongNameTable,
    SymbolTable,
}

impl SpecialMemberKind {
    fn matches(self, name: MemberName<'_>) -> bool {
        match self {
            Self::LongNameTable => matches!(name, MemberName::LongNameTable),
            Self::SymbolTable => {
                matches!(name, MemberName::SymbolTable | MemberName::SymbolTable64)
            }
        }
    }
}

#[derive(Debug)]
pub struct ArchiveMember<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> ArchiveMember<'a> {
    pub fn header(&self) -> archive_member {
        debug_assert!(self.offset + size_of::<archive_member>() <= self.data.len());

        // Safety: the byte range is bounds-checked above and `archive_member` is `Copy`.
        unsafe { std::ptr::read_unaligned(self.header_bytes().as_ptr().cast::<archive_member>()) }
    }

    pub fn size(&self) -> Result<usize> {
        Ok(to_decimal(self.header_field(AR_SIZE_OFFSET, AR_SIZE_LEN))? as usize)
    }

    pub fn payload_offset(&self) -> usize {
        self.offset + size_of::<archive_member>()
    }

    pub fn payload(&self) -> Result<&'a [u8]> {
        let start = self.payload_offset();
        let end = start
            .checked_add(self.size()?)
            .context("member payload end overflowed usize")?;

        self.data
            .get(start..end)
            .context("archive member payload is out of bounds")
    }

    pub fn next_offset(&self) -> Result<usize> {
        let size = self.size()?;
        let payload_end = self
            .payload_offset()
            .checked_add(size)
            .context("member next offset overflowed usize")?;
        let padding = size % 2;

        payload_end
            .checked_add(padding)
            .context("member padding overflowed usize")
    }

    pub fn member_name(&'a self) -> Result<MemberName<'a>> {
        let raw_name = std::str::from_utf8(self.header_field(AR_NAME_OFFSET, AR_NAME_LEN))
            .context("archive member name is not valid UTF-8")?;
        let raw_name = raw_name.trim_end_matches(' ');

        match raw_name {
            "/" => Ok(MemberName::SymbolTable),
            "/SYM64/" => Ok(MemberName::SymbolTable64),
            "//" => Ok(MemberName::LongNameTable),
            _ => {
                if let Some(offset) = raw_name.strip_prefix('/') {
                    ensure!(
                        !offset.is_empty() && offset.bytes().all(|byte| byte.is_ascii_digit()),
                        "invalid long-name reference: {raw_name:?}"
                    );
                    return Ok(MemberName::LongNameOffset(offset.parse()?));
                }

                if let Some(len) = raw_name.strip_prefix("#1/") {
                    ensure!(
                        !len.is_empty() && len.bytes().all(|byte| byte.is_ascii_digit()),
                        "invalid BSD extended name: {raw_name:?}"
                    );
                    return Ok(MemberName::BsdExtended(len.parse()?));
                }

                if let Some(short_name) = raw_name.strip_suffix('/') {
                    ensure!(!short_name.is_empty(), "archive member name is empty");
                    return Ok(MemberName::Short(short_name));
                }

                bail!("unsupported archive member name format: {raw_name:?}")
            }
        }
    }

    pub fn resolved_name(&self, long_names: Option<&[u8]>) -> Result<String> {
        match self.member_name()? {
            MemberName::Short(name) => Ok(name.to_string()),
            MemberName::LongNameOffset(offset) => {
                let long_names =
                    long_names.context("archive member refers to a missing long-name table")?;
                resolve_long_name(long_names, offset)
            }
            MemberName::BsdExtended(len) => {
                let payload = self.payload()?;
                ensure!(
                    len <= payload.len(),
                    "BSD extended name length {len} exceeds payload size {}",
                    payload.len()
                );
                let name = std::str::from_utf8(&payload[..len])
                    .context("BSD extended member name is not valid UTF-8")?;
                Ok(name.trim_end_matches('\0').to_string())
            }
            MemberName::SymbolTable | MemberName::SymbolTable64 | MemberName::LongNameTable => {
                bail!("special archive member does not have an object member name")
            }
        }
    }

    pub fn object_bytes(&self) -> Result<&'a [u8]> {
        let payload = self.payload()?;

        match self.member_name()? {
            MemberName::BsdExtended(len) => {
                ensure!(
                    len <= payload.len(),
                    "BSD extended name length {len} exceeds payload size {}",
                    payload.len()
                );
                Ok(&payload[len..])
            }
            MemberName::SymbolTable | MemberName::SymbolTable64 | MemberName::LongNameTable => {
                bail!("special archive member does not contain an ELF object")
            }
            MemberName::Short(_) | MemberName::LongNameOffset(_) => Ok(payload),
        }
    }

    fn is_special(&self) -> Result<bool> {
        Ok(matches!(
            self.member_name()?,
            MemberName::SymbolTable | MemberName::SymbolTable64 | MemberName::LongNameTable
        ))
    }

    fn header_bytes(&self) -> &'a [u8] {
        &self.data[self.offset..self.offset + size_of::<archive_member>()]
    }

    fn header_field(&self, offset: usize, len: usize) -> &'a [u8] {
        let start = self.offset + offset;
        &self.data[start..start + len]
    }
}

#[derive(Debug, Clone)]
pub struct ArchiveIter<'reader, 'data> {
    reader: &'reader ArchiveReader<'data>,
    offset: usize,
}

impl<'reader, 'data> Iterator for ArchiveIter<'reader, 'data> {
    type Item = Result<ArchiveMember<'data>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.reader.data.len() {
            return None;
        }

        if self.offset + size_of::<archive_member>() > self.reader.data.len() {
            self.offset = self.reader.data.len();
            return Some(Err(anyhow::anyhow!(
                "invalid archive format: incomplete member header"
            )));
        }

        let member = ArchiveMember {
            data: self.reader.data,
            offset: self.offset,
        };

        if member.header_field(AR_FMAG_OFFSET, AR_FMAG_LEN) != AR_FMAG.as_slice() {
            self.offset = self.reader.data.len();
            return Some(Err(anyhow::anyhow!(
                "invalid archive format: invalid member trailer"
            )));
        }

        let next_offset = match member.next_offset() {
            Ok(next_offset) => next_offset,
            Err(err) => {
                self.offset = self.reader.data.len();
                return Some(Err(err));
            }
        };

        self.offset = next_offset;
        Some(Ok(member))
    }
}

pub struct ArchiveObjectIter<'reader, 'data> {
    inner: ArchiveIter<'reader, 'data>,
}

impl<'reader, 'data> Iterator for ArchiveObjectIter<'reader, 'data> {
    type Item = Result<ArchiveMember<'data>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let member = self.inner.next()?;
            match member {
                Ok(member) => match member.is_special() {
                    Ok(true) => continue,
                    Ok(false) => return Some(Ok(member)),
                    Err(err) => return Some(Err(err)),
                },
                Err(err) => return Some(Err(err)),
            }
        }
    }
}

pub fn resolve_long_name(long_names: &[u8], offset: usize) -> Result<String> {
    ensure!(
        offset < long_names.len(),
        "long-name table offset out of bounds: {offset}"
    );

    let tail = &long_names[offset..];
    let end = tail
        .windows(2)
        .position(|window| window == b"/\n")
        .context("unterminated long-name table entry")?;

    Ok(std::str::from_utf8(&tail[..end])
        .context("long-name table entry is not valid UTF-8")?
        .to_string())
}

fn to_decimal(bytes: &[u8]) -> Result<u64> {
    let trimmed = std::str::from_utf8(bytes)
        .context("archive decimal field is not valid UTF-8")?
        .trim();
    Ok(trimmed.parse::<u64>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TestSymbol, build_archive, build_rel_object};
    use elf::{Elf64SymbolBinding, Elf64SymbolType};

    #[test]
    fn check_magic_only_accepts_archive_magic() {
        assert!(check_magic(AR_MAGIC));
        assert!(!check_magic(THIN_MAGIC));
        assert!(!check_magic(b"\x7FELF"));
    }

    #[test]
    fn short_name_member_resolves() {
        let payload = [1u8, 2, 3];
        let archive = build_archive(&[("foo.o/", &payload)]);
        let reader = ArchiveReader::new(&archive).unwrap();
        let member = reader.object_members().next().unwrap().unwrap();

        assert_eq!(member.member_name().unwrap(), MemberName::Short("foo.o"));
        assert_eq!(member.resolved_name(None).unwrap(), "foo.o");
        assert_eq!(member.object_bytes().unwrap(), payload);
    }

    #[test]
    fn odd_sized_member_skips_padding() {
        let first = [1u8, 2, 3];
        let second = [4u8, 5, 6, 7];
        let archive = build_archive(&[("one.o/", &first), ("two.o/", &second)]);
        let reader = ArchiveReader::new(&archive).unwrap();
        let mut members = reader.object_members();

        let first_member = members.next().unwrap().unwrap();
        let second_member = members.next().unwrap().unwrap();

        assert_eq!(first_member.object_bytes().unwrap(), first);
        assert_eq!(second_member.resolved_name(None).unwrap(), "two.o");
        assert_eq!(second_member.object_bytes().unwrap(), second);
        assert!(members.next().is_none());
    }

    #[test]
    fn long_name_table_resolves_offsets() {
        let long_names = b"very_long_member_name.o/\n";
        let object = build_rel_object(
            &[TestSymbol {
                name: "foo",
                binding: Elf64SymbolBinding::STB_GLOBAL,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 0,
                size: 5,
            }],
            &[],
        );
        let archive = build_archive(&[("//", long_names), ("/0", &object)]);
        let reader = ArchiveReader::new(&archive).unwrap();
        let member = reader.object_members().next().unwrap().unwrap();

        assert_eq!(reader.long_name_table().unwrap().unwrap(), long_names);
        assert_eq!(
            member
                .resolved_name(reader.long_name_table().unwrap())
                .unwrap(),
            "very_long_member_name.o"
        );
    }

    #[test]
    fn bsd_extended_name_resolves() {
        let object = build_rel_object(
            &[TestSymbol {
                name: "foo",
                binding: Elf64SymbolBinding::STB_GLOBAL,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 0,
                size: 5,
            }],
            &[],
        );
        let name = b"bsd_member_name.o";
        let mut payload = name.to_vec();
        payload.extend_from_slice(&object);

        let archive = build_archive(&[("#1/17", &payload)]);
        let reader = ArchiveReader::new(&archive).unwrap();
        let member = reader.object_members().next().unwrap().unwrap();

        assert_eq!(member.resolved_name(None).unwrap(), "bsd_member_name.o");
        assert_eq!(member.object_bytes().unwrap(), object);
    }

    #[test]
    fn special_members_are_skipped_from_object_iteration() {
        let object = build_rel_object(
            &[TestSymbol {
                name: "foo",
                binding: Elf64SymbolBinding::STB_GLOBAL,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 0,
                size: 5,
            }],
            &[],
        );
        let archive = build_archive(&[
            ("/", b"symtab"),
            ("/SYM64/", b"symtab64"),
            ("//", b"foo.o/\n"),
            ("foo.o/", &object),
        ]);
        let reader = ArchiveReader::new(&archive).unwrap();
        let members = reader
            .object_members()
            .map(|member| {
                member
                    .unwrap()
                    .resolved_name(reader.long_name_table().unwrap())
                    .unwrap()
            })
            .collect::<Vec<_>>();

        assert_eq!(members, vec!["foo.o".to_string()]);
        assert_eq!(reader.symbol_table().unwrap().unwrap(), b"symtab");
        assert_eq!(reader.long_name_table().unwrap().unwrap(), b"foo.o/\n");
    }

    #[test]
    fn invalid_trailer_is_rejected() {
        let object = build_rel_object(
            &[TestSymbol {
                name: "foo",
                binding: Elf64SymbolBinding::STB_GLOBAL,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 0,
                size: 5,
            }],
            &[],
        );
        let mut archive = Vec::from(AR_MAGIC.as_slice());
        push_member_with_trailer(&mut archive, "foo.o/", &object, *b"!!");
        let reader = ArchiveReader::new(&archive).unwrap();
        let err = reader.iter().next().unwrap().unwrap_err();

        assert!(err.to_string().contains("invalid member trailer"));
    }

    fn push_field(out: &mut Vec<u8>, width: usize, value: &[u8]) {
        assert!(value.len() <= width);
        out.extend_from_slice(value);
        out.resize(out.len() + (width - value.len()), b' ');
    }

    fn push_member_with_trailer(out: &mut Vec<u8>, name: &str, payload: &[u8], trailer: [u8; 2]) {
        push_field(out, 16, name.as_bytes());
        push_field(out, 12, b"0");
        push_field(out, 6, b"0");
        push_field(out, 6, b"0");
        push_field(out, 8, b"100644");
        push_field(out, 10, payload.len().to_string().as_bytes());
        out.extend_from_slice(&trailer);
        out.extend_from_slice(payload);
        if payload.len() % 2 != 0 {
            out.push(b'\n');
        }
    }
}
