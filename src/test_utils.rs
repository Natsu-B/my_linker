use elf::{Elf64SectionType, Elf64SymbolBinding, Elf64SymbolType, ElfFileType, ElfMachineType};

use crate::archive::AR_FMAG;

const ELF_HEADER_SIZE: usize = 64;
const SECTION_HEADER_SIZE: usize = 64;
const SYMBOL_SIZE: usize = 24;
const RELA_SIZE: usize = 24;
const AR_MAGIC: &[u8; 8] = b"!<arch>\n";

#[derive(Clone, Copy)]
pub(crate) struct TestSymbol<'a> {
    pub(crate) name: &'a str,
    pub(crate) binding: Elf64SymbolBinding,
    pub(crate) ty: Elf64SymbolType,
    pub(crate) section_idx: u16,
    pub(crate) value: u64,
    pub(crate) size: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct TestRelocation {
    pub(crate) offset: u64,
    pub(crate) sym: u32,
    pub(crate) ty: u32,
    pub(crate) addend: i64,
}

pub(crate) fn build_rel_object(
    symbols: &[TestSymbol<'_>],
    relocations: &[TestRelocation],
) -> Vec<u8> {
    let shstrtab = b"\0.shstrtab\0.text\0.rela.text\0.symtab\0.strtab\0";
    let text = [0x90u8, 0x90, 0x90, 0x90, 0xC3];

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
    let has_relocations = !relocations.is_empty();
    let section_count = if has_relocations { 6 } else { 5 };
    let symtab_section_idx = if has_relocations { 4 } else { 3 };
    let strtab_section_idx = if has_relocations { 5 } else { 4 };

    let shstrtab_offset = ELF_HEADER_SIZE;
    let text_offset = shstrtab_offset + shstrtab.len();
    let rela_offset = text_offset + text.len();
    let rela_size = RELA_SIZE * relocations.len();
    let symtab_offset = rela_offset + rela_size;
    let symtab_size = SYMBOL_SIZE * (symbols.len() + 1);
    let strtab_offset = symtab_offset + symtab_size;
    let shoff = strtab_offset + strtab.len();
    let file_size = shoff + SECTION_HEADER_SIZE * section_count;

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
    write_u16(&mut out, 60, section_count as u16);
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

    for (i, relocation) in relocations.iter().enumerate() {
        let entry = rela_offset + RELA_SIZE * i;
        write_u64(&mut out, entry, relocation.offset);
        write_u64(
            &mut out,
            entry + 8,
            (u64::from(relocation.sym) << 32) | u64::from(relocation.ty),
        );
        write_i64(&mut out, entry + 16, relocation.addend);
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

    if has_relocations {
        write_u32(&mut out, sh, 17);
        write_u32(&mut out, sh + 4, Elf64SectionType::SHT_RELA.raw());
        write_u64(&mut out, sh + 24, rela_offset as u64);
        write_u64(&mut out, sh + 32, rela_size as u64);
        write_u32(&mut out, sh + 40, symtab_section_idx);
        write_u32(&mut out, sh + 44, 2);
        write_u64(&mut out, sh + 48, 8);
        write_u64(&mut out, sh + 56, RELA_SIZE as u64);
        sh += SECTION_HEADER_SIZE;
    }

    write_u32(&mut out, sh, 28);
    write_u32(&mut out, sh + 4, Elf64SectionType::SHT_SYMTAB.raw());
    write_u64(&mut out, sh + 24, symtab_offset as u64);
    write_u64(&mut out, sh + 32, symtab_size as u64);
    write_u32(&mut out, sh + 40, strtab_section_idx);
    write_u32(&mut out, sh + 44, (local_count + 1) as u32);
    write_u64(&mut out, sh + 48, 8);
    write_u64(&mut out, sh + 56, SYMBOL_SIZE as u64);
    sh += SECTION_HEADER_SIZE;

    write_u32(&mut out, sh, 36);
    write_u32(&mut out, sh + 4, Elf64SectionType::SHT_STRTAB.raw());
    write_u64(&mut out, sh + 24, strtab_offset as u64);
    write_u64(&mut out, sh + 32, strtab.len() as u64);
    write_u64(&mut out, sh + 48, 1);

    out
}

pub(crate) fn build_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::from(AR_MAGIC.as_slice());
    for &(name, payload) in members {
        push_member(&mut out, name, payload);
    }
    out
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

fn write_i64(out: &mut [u8], offset: usize, value: i64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn push_field(out: &mut Vec<u8>, width: usize, value: &[u8]) {
    assert!(value.len() <= width);
    out.extend_from_slice(value);
    out.resize(out.len() + (width - value.len()), b' ');
}

fn push_member(out: &mut Vec<u8>, name: &str, payload: &[u8]) {
    push_field(out, 16, name.as_bytes());
    push_field(out, 12, b"0");
    push_field(out, 6, b"0");
    push_field(out, 6, b"0");
    push_field(out, 8, b"100644");
    push_field(out, 10, payload.len().to_string().as_bytes());
    out.extend_from_slice(&AR_FMAG);
    out.extend_from_slice(payload);
    if payload.len() % 2 != 0 {
        out.push(b'\n');
    }
}
