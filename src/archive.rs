use std::{cell::OnceCell, collections::HashMap, mem::size_of};

use anyhow::{Context, Result, bail, ensure};
use elf::{Elf64SymbolBinding, Elf64SymbolInfo, Elf64SymbolSectionIdx, Elf64SymbolType};

use crate::parse;

const AR_MAGIC: &[u8; 8] = b"!<arch>\n";
const THIN_MAGIC: &[u8; 8] = b"!<thin>\n";
const AR_FMAG: [u8; 2] = *b"`\n";

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
            data.starts_with(AR_MAGIC),
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

    pub fn collect_member_infos(&self) -> Result<Vec<MemberInfo<'a>>> {
        let long_names = self.long_name_table()?;
        let mut infos = Vec::new();

        for (file_idx, member) in self.object_members().enumerate() {
            let member = member?;
            let name = member.resolved_name(long_names)?;
            let bytes = member.object_bytes().with_context(|| {
                format!("failed to read object bytes for archive member {name}")
            })?;
            let object = parse::parse(bytes, name.clone(), file_idx)
                .with_context(|| format!("failed to parse archive member {name}"))?;
            let (defined, undefined) = collect_symbols(&object);

            infos.push(MemberInfo {
                name,
                bytes,
                defined,
                undefined,
            });
        }

        Ok(infos)
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
    pub fn header(&'a self) -> &'a archive_member {
        debug_assert!(self.offset + size_of::<archive_member>() <= self.data.len());

        let bytes = &self.data[self.offset..self.offset + size_of::<archive_member>()];
        unsafe { &*bytes.as_ptr().cast::<archive_member>() }
    }

    pub fn size(&self) -> Result<usize> {
        Ok(to_decimal(&self.header().ar_size)? as usize)
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
        let payload_end = self
            .payload_offset()
            .checked_add(self.size()?)
            .context("member next offset overflowed usize")?;
        let padding = self.size()? % 2;

        payload_end
            .checked_add(padding)
            .context("member padding overflowed usize")
    }

    pub fn member_name(&'a self) -> Result<MemberName<'a>> {
        let raw_name = std::str::from_utf8(&self.header().ar_name)
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
        let header = member.header();

        if header.ar_fmag != AR_FMAG {
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

#[derive(Debug)]
pub struct MemberInfo<'a> {
    pub name: String,
    pub bytes: &'a [u8],
    pub defined: Vec<&'a str>,
    pub undefined: Vec<&'a str>,
}

pub fn build_symbol_index<'a>(
    infos: Vec<MemberInfo<'a>>,
) -> Result<(Vec<MemberInfo<'a>>, HashMap<&'a str, usize>)> {
    let mut index = HashMap::new();

    for (member_idx, info) in infos.iter().enumerate() {
        for &symbol in &info.defined {
            if let Some(existing_idx) = index.insert(symbol, member_idx) {
                bail!(
                    "duplicate defined symbol: {symbol} in members {} and {}",
                    infos[existing_idx].name,
                    info.name
                );
            }
        }
    }

    Ok((infos, index))
}

fn collect_symbols<'a>(object: &parse::ObjectFile<'a>) -> (Vec<&'a str>, Vec<&'a str>) {
    let mut defined = Vec::new();
    let mut undefined = Vec::new();

    for symbol in &object.symbols {
        if symbol.name.is_empty() {
            continue;
        }

        if matches!(
            symbol.info.get_enum(Elf64SymbolInfo::st_type),
            Some(Elf64SymbolType::STT_FILE | Elf64SymbolType::STT_SECTION)
        ) {
            continue;
        }

        match symbol.section_idx {
            Elf64SymbolSectionIdx::Undefined => undefined.push(symbol.name),
            _ => {
                if matches!(
                    symbol.info.get_enum(Elf64SymbolInfo::st_bind),
                    Some(Elf64SymbolBinding::STB_GLOBAL | Elf64SymbolBinding::STB_WEAK)
                ) {
                    defined.push(symbol.name);
                }
            }
        }
    }

    (defined, undefined)
}

fn resolve_long_name(long_names: &[u8], offset: usize) -> Result<String> {
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
    use elf::{Elf64SectionType, Elf64SymbolBinding, Elf64SymbolType, ElfFileType, ElfMachineType};

    #[derive(Clone, Copy)]
    struct TestSymbol<'a> {
        name: &'a str,
        binding: Elf64SymbolBinding,
        ty: Elf64SymbolType,
        section_idx: u16,
        value: u64,
        size: u64,
    }

    fn write_u16(out: &mut [u8], offset: usize, value: u16) {
        out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(out: &mut [u8], offset: usize, value: u32) {
        out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(out: &mut [u8], offset: usize, value: u64) {
        out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn build_rel_object(symbols: &[TestSymbol<'_>]) -> Vec<u8> {
        const ELF_HEADER_SIZE: usize = 64;
        const SECTION_HEADER_SIZE: usize = 64;
        const SYMBOL_SIZE: usize = 24;

        let shstrtab = b"\0.shstrtab\0.text\0.symtab\0.strtab\0";
        let text = [0x90, 0x90, 0xC3];

        let mut symbols = symbols.to_vec();
        symbols.sort_by_key(|symbol| usize::from(symbol.binding != Elf64SymbolBinding::STB_LOCAL));

        let mut strtab = vec![0];
        let mut name_offsets = Vec::with_capacity(symbols.len());
        for symbol in &symbols {
            if symbol.name.is_empty() {
                name_offsets.push(0);
            } else {
                let offset = strtab.len() as u32;
                strtab.extend_from_slice(symbol.name.as_bytes());
                strtab.push(0);
                name_offsets.push(offset);
            }
        }

        let local_count = symbols
            .iter()
            .take_while(|symbol| symbol.binding == Elf64SymbolBinding::STB_LOCAL)
            .count();
        let shstrtab_offset = ELF_HEADER_SIZE;
        let text_offset = shstrtab_offset + shstrtab.len();
        let symtab_offset = text_offset + text.len();
        let symtab_size = SYMBOL_SIZE * (symbols.len() + 1);
        let strtab_offset = symtab_offset + symtab_size;
        let shoff = strtab_offset + strtab.len();
        let file_size = shoff + SECTION_HEADER_SIZE * 5;

        let mut out = vec![0u8; file_size];

        out[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        out[4] = 2;
        out[5] = 1;
        out[6] = 1;

        write_u16(&mut out, 16, ElfFileType::ET_REL.raw());
        write_u16(&mut out, 18, ElfMachineType::EM_X86_64.raw());
        write_u32(&mut out, 20, 1);
        write_u64(&mut out, 24, 0);
        write_u64(&mut out, 32, 0);
        write_u64(&mut out, 40, shoff as u64);
        write_u32(&mut out, 48, 0);
        write_u16(&mut out, 52, ELF_HEADER_SIZE as u16);
        write_u16(&mut out, 54, 0);
        write_u16(&mut out, 56, 0);
        write_u16(&mut out, 58, SECTION_HEADER_SIZE as u16);
        write_u16(&mut out, 60, 5);
        write_u16(&mut out, 62, 1);

        out[shstrtab_offset..shstrtab_offset + shstrtab.len()].copy_from_slice(shstrtab);
        out[text_offset..text_offset + text.len()].copy_from_slice(&text);
        out[strtab_offset..strtab_offset + strtab.len()].copy_from_slice(&strtab);

        for (i, symbol) in symbols.iter().enumerate() {
            let entry = symtab_offset + SYMBOL_SIZE * (i + 1);
            write_u32(&mut out, entry, name_offsets[i]);
            out[entry + 4] = ((symbol.binding as u8) << 4) | (symbol.ty as u8);
            out[entry + 5] = 0;
            write_u16(&mut out, entry + 6, symbol.section_idx);
            write_u64(&mut out, entry + 8, symbol.value);
            write_u64(&mut out, entry + 16, symbol.size);
        }

        let mut sh = shoff;

        sh += SECTION_HEADER_SIZE;

        write_u32(&mut out, sh, 1);
        write_u32(&mut out, sh + 4, Elf64SectionType::SHT_STRTAB.raw());
        write_u64(&mut out, sh + 24, shstrtab_offset as u64);
        write_u64(&mut out, sh + 32, shstrtab.len() as u64);
        write_u64(&mut out, sh + 48, 1);
        sh += SECTION_HEADER_SIZE;

        write_u32(&mut out, sh, 11);
        write_u32(&mut out, sh + 4, Elf64SectionType::SHT_PROGBITS.raw());
        write_u64(&mut out, sh + 8, 0x6);
        write_u64(&mut out, sh + 24, text_offset as u64);
        write_u64(&mut out, sh + 32, text.len() as u64);
        write_u64(&mut out, sh + 48, 16);
        sh += SECTION_HEADER_SIZE;

        write_u32(&mut out, sh, 17);
        write_u32(&mut out, sh + 4, Elf64SectionType::SHT_SYMTAB.raw());
        write_u64(&mut out, sh + 24, symtab_offset as u64);
        write_u64(&mut out, sh + 32, symtab_size as u64);
        write_u32(&mut out, sh + 40, 4);
        write_u32(&mut out, sh + 44, (local_count + 1) as u32);
        write_u64(&mut out, sh + 48, 8);
        write_u64(&mut out, sh + 56, SYMBOL_SIZE as u64);
        sh += SECTION_HEADER_SIZE;

        write_u32(&mut out, sh, 25);
        write_u32(&mut out, sh + 4, Elf64SectionType::SHT_STRTAB.raw());
        write_u64(&mut out, sh + 24, strtab_offset as u64);
        write_u64(&mut out, sh + 32, strtab.len() as u64);
        write_u64(&mut out, sh + 48, 1);

        out
    }

    fn push_field(out: &mut Vec<u8>, width: usize, value: &[u8]) {
        assert!(value.len() <= width);
        out.extend_from_slice(value);
        out.resize(out.len() + (width - value.len()), b' ');
    }

    fn push_member(out: &mut Vec<u8>, name: &str, payload: &[u8]) {
        push_member_with_trailer(out, name, payload, AR_FMAG);
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

    fn build_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::from(AR_MAGIC.as_slice());
        for &(name, payload) in members {
            push_member(&mut out, name, payload);
        }
        out
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
        let object = build_rel_object(&[TestSymbol {
            name: "foo",
            binding: Elf64SymbolBinding::STB_GLOBAL,
            ty: Elf64SymbolType::STT_FUNC,
            section_idx: 2,
            value: 0,
            size: 3,
        }]);
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
        let object = build_rel_object(&[TestSymbol {
            name: "foo",
            binding: Elf64SymbolBinding::STB_GLOBAL,
            ty: Elf64SymbolType::STT_FUNC,
            section_idx: 2,
            value: 0,
            size: 3,
        }]);
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
        let object = build_rel_object(&[TestSymbol {
            name: "foo",
            binding: Elf64SymbolBinding::STB_GLOBAL,
            ty: Elf64SymbolType::STT_FUNC,
            section_idx: 2,
            value: 0,
            size: 3,
        }]);
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
    fn build_symbol_map_reuses_undefined_list_contents() {
        let object = build_rel_object(&[
            TestSymbol {
                name: "",
                binding: Elf64SymbolBinding::STB_LOCAL,
                ty: Elf64SymbolType::STT_SECTION,
                section_idx: 2,
                value: 0,
                size: 0,
            },
            TestSymbol {
                name: "member.c",
                binding: Elf64SymbolBinding::STB_LOCAL,
                ty: Elf64SymbolType::STT_FILE,
                section_idx: 0xFFF1,
                value: 0,
                size: 0,
            },
            TestSymbol {
                name: "local_only",
                binding: Elf64SymbolBinding::STB_LOCAL,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 1,
                size: 1,
            },
            TestSymbol {
                name: "foo",
                binding: Elf64SymbolBinding::STB_GLOBAL,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 0,
                size: 3,
            },
            TestSymbol {
                name: "bar",
                binding: Elf64SymbolBinding::STB_WEAK,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 0,
                size: 3,
            },
            TestSymbol {
                name: "baz",
                binding: Elf64SymbolBinding::STB_GLOBAL,
                ty: Elf64SymbolType::STT_NOTYPE,
                section_idx: 0,
                value: 0,
                size: 0,
            },
        ]);
        let archive = build_archive(&[("multi.o/", &object)]);
        let reader = ArchiveReader::new(&archive).unwrap();
        let infos = reader.collect_member_infos().unwrap();
        let map = build_symbol_map(&infos).unwrap();

        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].defined, vec!["foo", "bar"]);
        assert_eq!(infos[0].undefined, vec!["baz"]);
        assert_eq!(map.get("foo").unwrap().0, infos[0].bytes);
        assert_eq!(map.get("foo").unwrap().1, vec!["baz"]);
        assert_eq!(map.get("bar").unwrap().0, infos[0].bytes);
        assert_eq!(map.get("bar").unwrap().1, vec!["baz"]);

        let (infos, index) = build_symbol_index(infos).unwrap();
        assert_eq!(index["foo"], 0);
        assert_eq!(index["bar"], 0);
        assert_eq!(infos[index["foo"]].undefined, vec!["baz"]);
    }

    #[test]
    fn duplicate_symbol_is_an_error() {
        let first = build_rel_object(&[TestSymbol {
            name: "dup",
            binding: Elf64SymbolBinding::STB_GLOBAL,
            ty: Elf64SymbolType::STT_FUNC,
            section_idx: 2,
            value: 0,
            size: 3,
        }]);
        let second = build_rel_object(&[TestSymbol {
            name: "dup",
            binding: Elf64SymbolBinding::STB_GLOBAL,
            ty: Elf64SymbolType::STT_FUNC,
            section_idx: 2,
            value: 0,
            size: 3,
        }]);
        let archive = build_archive(&[("one.o/", &first), ("two.o/", &second)]);
        let reader = ArchiveReader::new(&archive).unwrap();
        let infos = reader.collect_member_infos().unwrap();

        assert!(build_symbol_map(&infos).is_err());
        assert!(build_symbol_index(infos).is_err());
    }

    #[test]
    fn invalid_trailer_is_rejected() {
        let object = build_rel_object(&[TestSymbol {
            name: "foo",
            binding: Elf64SymbolBinding::STB_GLOBAL,
            ty: Elf64SymbolType::STT_FUNC,
            section_idx: 2,
            value: 0,
            size: 3,
        }]);
        let mut archive = Vec::from(AR_MAGIC.as_slice());
        push_member_with_trailer(&mut archive, "foo.o/", &object, *b"!!");
        let reader = ArchiveReader::new(&archive).unwrap();
        let err = reader.iter().next().unwrap().unwrap_err();

        assert!(err.to_string().contains("invalid member trailer"));
    }
}
