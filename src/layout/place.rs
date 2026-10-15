use std::{cell::OnceCell, collections::HashMap};

use anyhow::{Context, Result, ensure};
use elf::{Elf64ProgramHeaderFlags, Elf64SymbolSectionIdx, PF_R};

use super::{OutputSection, PAGE_SIZE};
use crate::{
    input::FileId,
    script::{
        ast::*,
        eval,
        mapping::{MappedItem, MappedStatement, MappingInput},
    },
    symbols::{Definition, ResolvedSymbol, SymbolTable},
};

pub(super) struct SectionPlacer<'s> {
    context: eval::Context,
    symbols: &'s SymbolTable,
    section_symbols: HashMap<(FileId, u16), Vec<&'s ResolvedSymbol>>,
    pub(super) script_symbols: HashMap<String, u64>,
    pub(super) script_symbol_sections: HashMap<String, usize>,
    symbol_sections: HashMap<String, usize>,
    current_section: Option<usize>,
    dot_section: Option<usize>,
    pub(super) header_vaddr: Option<u64>,
}

impl<'s> SectionPlacer<'s> {
    pub(super) fn new(symbols: &'s SymbolTable, sizeof_headers: u64) -> Self {
        let mut section_symbols: HashMap<_, Vec<_>> = HashMap::new();
        let mut context = eval::Context {
            sizeof_headers,
            ..Default::default()
        };
        for symbol in symbols.named_symbols() {
            if let Definition::Input {
                file_id,
                section_idx,
                value,
            } = symbol.definition
            {
                match section_idx {
                    Elf64SymbolSectionIdx::Index(idx) => {
                        section_symbols
                            .entry((file_id, idx))
                            .or_default()
                            .push(symbol);
                    }
                    Elf64SymbolSectionIdx::AbsoluteSymbols => {
                        context.symbols.insert(symbol.name.clone(), value);
                    }
                    _ => {}
                }
            }
        }
        Self {
            context,
            symbols,
            section_symbols,
            script_symbols: HashMap::new(),
            script_symbol_sections: HashMap::new(),
            symbol_sections: HashMap::new(),
            current_section: None,
            dot_section: None,
            header_vaddr: None,
        }
    }

    fn assign(&mut self, assignment: &Assignment) -> Result<()> {
        if !self.symbols.should_assign(assignment) {
            return Ok(());
        }
        let value = eval::evaluate(&assignment.value, &self.context)?;
        if assignment.name == "." {
            self.context.dot = value;
        } else {
            // Section identity cannot be reconstructed from an address: an
            // absolute constant may equal an address, and end symbols lie on
            // boundaries. Carry the association alongside the numeric value.
            let section = self
                .current_section
                .or(self.expression_section(&assignment.value)?);
            if let Some(section) = section {
                self.script_symbol_sections
                    .insert(assignment.name.clone(), section);
                self.symbol_sections
                    .insert(assignment.name.clone(), section);
            } else {
                self.script_symbol_sections.remove(&assignment.name);
                self.symbol_sections.remove(&assignment.name);
            }
            self.context.symbols.insert(assignment.name.clone(), value);
            self.script_symbols.insert(assignment.name.clone(), value);
        }
        Ok(())
    }

    fn expression_section(&self, expr: &Expr) -> Result<Option<usize>> {
        Ok(match &expr.kind {
            ExprKind::Dot => self.dot_section,
            ExprKind::Symbol(name) => self.symbol_sections.get(name).copied(),
            ExprKind::Binary(op, left, right) => {
                let left = self.expression_section(left)?;
                let right = self.expression_section(right)?;
                match op {
                    BinaryOp::Add => left.or(right),
                    BinaryOp::Subtract if right.is_none() => left,
                    _ => None,
                }
            }
            ExprKind::Conditional(condition, yes, no) => {
                self.expression_section(if eval::evaluate(condition, &self.context)? != 0 {
                    yes
                } else {
                    no
                })?
            }
            ExprKind::Call(Function::Align, args) => {
                if args.len() == 1 {
                    self.dot_section
                } else {
                    self.expression_section(&args[0])?
                }
            }
            ExprKind::Call(Function::DataSegmentRelroEnd, args) => {
                self.expression_section(&args[1])?
            }
            ExprKind::Call(Function::DataSegmentEnd, args) => self.expression_section(&args[0])?,
            _ => None,
        })
    }

    pub(super) fn place<'a>(
        &mut self,
        items: &[MappedItem],
        inputs: &[MappingInput<'a>],
    ) -> Result<Vec<OutputSection<'a>>> {
        let mut sections = Vec::new();
        let mut previous_flags = Elf64ProgramHeaderFlags::from_bits(PF_R);
        let mut previous_end = 0;
        let tls_align = items
            .iter()
            .filter_map(|item| match item {
                MappedItem::Output(output) if output.is_tls() => Some(output.align),
                _ => None,
            })
            .max()
            .unwrap_or(1);
        let mut tls_started = false;
        for (item_index, item) in items.iter().enumerate() {
            self.context.next_section_alignment = items[item_index + 1..]
                .iter()
                .find_map(|item| match item {
                    MappedItem::Output(output) if output.has_contents(inputs) => Some(output.align),
                    _ => None,
                })
                .unwrap_or(1);
            match item {
                MappedItem::Assignment(assignment) => self.assign(assignment)?,
                MappedItem::Output(output) => {
                    let mut output_align = output.align;
                    if !tls_started && output.is_tls() && output.has_contents(inputs) {
                        output_align = output_align.max(tls_align);
                        tls_started = true;
                    }
                    let mut address = match output.address {
                        Some(address) => eval::evaluate(address, &self.context)?,
                        None => align(self.context.dot, output_align)?,
                    };
                    if output.statements.is_empty() {
                        continue;
                    }
                    if self.header_vaddr.is_none() {
                        let first_address = if self.context.dot >= self.context.sizeof_headers {
                            self.context.dot.min(address)
                        } else {
                            address
                        };
                        let base = first_address
                            .checked_sub(self.context.sizeof_headers)
                            .context(
                                "no space for mapped ELF headers before the first output section",
                            )?
                            / PAGE_SIZE
                            * PAGE_SIZE;
                        self.header_vaddr = Some(base);
                        previous_end = base + self.context.sizeof_headers;
                    }
                    let flags = output.permissions();
                    if output.has_contents(inputs) {
                        let minimum = if flags == previous_flags {
                            previous_end
                        } else {
                            align(previous_end, PAGE_SIZE)?
                        };
                        if output.address.is_some() {
                            ensure!(
                                address >= minimum,
                                "output section {} at {address:#x} overlaps a previous section or shares a page with different permissions",
                                output.name
                            );
                        } else {
                            address = align(address.max(minimum), output_align)?;
                        }
                    }
                    self.context.dot = address;
                    self.current_section = Some(sections.len());
                    self.dot_section = self.current_section;
                    let mut section = OutputSection {
                        name: output.name.clone(),
                        flags,
                        size: 0,
                        align: output_align,
                        address: OnceCell::from(address),
                        data: None,
                        inputs: Vec::new(),
                    };
                    for statement in &output.statements {
                        match statement {
                            MappedStatement::Assignment(assignment) => {
                                let old_dot = self.context.dot;
                                self.assign(assignment)?;
                                ensure!(
                                    self.context.dot >= old_dot,
                                    "location counter moves backwards in output section {}",
                                    output.name
                                );
                            }
                            MappedStatement::Input(index) => {
                                let input = &inputs[*index].section;
                                self.context.dot = align(self.context.dot, input.align.max(1))?;
                                let offset = self.context.dot - address;
                                if let Some(data) = input.data.as_deref() {
                                    ensure!(
                                        data.len() as u64 == input.size,
                                        "input section {} data length does not match size",
                                        input.name
                                    );
                                    let output_data = section.data.get_or_insert_with(Vec::new);
                                    output_data.resize(
                                        usize::try_from(offset)
                                            .context("output section too large")?,
                                        0,
                                    );
                                    output_data.extend_from_slice(data);
                                }
                                for symbol in self
                                    .section_symbols
                                    .get(&(input.file_id, input.idx))
                                    .into_iter()
                                    .flatten()
                                {
                                    let Definition::Input { value, .. } = symbol.definition else {
                                        unreachable!()
                                    };
                                    self.context.symbols.insert(
                                        symbol.name.clone(),
                                        self.context
                                            .dot
                                            .checked_add(value)
                                            .context("symbol address exceeds u64")?,
                                    );
                                    self.symbol_sections
                                        .insert(symbol.name.clone(), sections.len());
                                }
                                self.context.dot = self
                                    .context
                                    .dot
                                    .checked_add(input.size)
                                    .context("output section address exceeds u64")?;
                                section.inputs.push((input.clone(), offset));
                            }
                        }
                    }
                    section.size = self.context.dot - address;
                    if section.size != 0 {
                        ensure!(
                            address >= previous_end,
                            "output section {} overlaps a previous section",
                            output.name
                        );
                        ensure!(
                            flags == previous_flags || address >= align(previous_end, PAGE_SIZE)?,
                            "output section {} shares a page with different permissions",
                            output.name
                        );
                        previous_end = self.context.dot;
                        previous_flags = flags;
                    }
                    pr_debug!(
                        "Output section {} at {address:#x}, size {:#x}",
                        section.name,
                        section.size
                    );
                    sections.push(section);
                    self.current_section = None;
                }
            }
        }
        Ok(sections)
    }
}

fn align(value: u64, alignment: u64) -> Result<u64> {
    value
        .checked_next_multiple_of(alignment)
        .context("aligned address exceeds u64")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        input::object::InputSection,
        layout::{segments::load_segment_count, tls::TlsSegment},
        script::{
            mapping::{MappedOutputSection, input_name, map_sections},
            parser,
        },
    };
    use elf::Elf64SectionFlags;

    fn input(file: &str, name: &'static str, flags: u64, align: u64) -> MappingInput<'static> {
        MappingInput {
            file_name: input_name(
                file,
                if file.ends_with(')') {
                    FileId::ArchiveMember {
                        archive_index: 0,
                        member_index: 0,
                    }
                } else {
                    FileId::InputObject { input_index: 0 }
                },
            )
            .to_string(),
            section: InputSection {
                file_id: FileId::InputObject { input_index: 0 },
                idx: 1,
                name,
                flags: Elf64SectionFlags::from_bits(flags),
                section_type: elf::Elf64SectionType::SHT_PROGBITS,
                entry_size: 0,
                align,
                data: Some(std::borrow::Cow::Borrowed(&[1])),
                size: 1,
            },
        }
    }

    fn names<'a>(items: &'a [MappedItem<'_>]) -> Vec<&'a str> {
        items
            .iter()
            .filter_map(|item| match item {
                MappedItem::Output(output) => Some(output.name.as_str()),
                _ => None,
            })
            .collect()
    }

    fn members(output: &MappedOutputSection) -> Vec<usize> {
        output
            .statements
            .iter()
            .filter_map(|statement| match statement {
                MappedStatement::Input(index) => Some(*index),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn orphans_follow_the_last_output_with_the_same_flags() {
        let inputs = vec![
            input("a.o", ".text", 6, 16),
            input("a.o", ".rodata", 2, 8),
            input("a.o", ".data", 3, 8),
            input("a.o", ".extra", 6, 32),
            input("b.o", ".extra", 6, 16),
            input("a.o", ".other", 2, 8),
        ];
        let script = parser::parse("SECTIONS { . = 0x400000 + SIZEOF_HEADERS; .text : { *(.text) } .rodata : { *(.rodata) } .data : { *(.data) } }").unwrap();
        let items = map_sections(&script, &inputs).unwrap();
        assert_eq!(
            names(&items),
            vec![".text", ".extra", ".rodata", ".other", ".data"]
        );
        let MappedItem::Output(extra) = &items[2] else {
            panic!()
        };
        assert_eq!(members(extra), vec![3, 4]);
        let symbols = SymbolTable::default();
        let mut layout = SectionPlacer::new(&symbols, 64 + 56 * 5);
        let sections = layout.place(&items, &inputs).unwrap();
        let text = &sections[0];
        let extra = &sections[1];
        let rodata = &sections[2];
        assert_eq!(*extra.address.get().unwrap() % 32, 0);
        assert_eq!(
            *extra.address.get().unwrap(),
            (*text.address.get().unwrap() + 1).next_multiple_of(32)
        );
        assert_eq!(*rodata.address.get().unwrap() % PAGE_SIZE, 0);
        assert_eq!(load_segment_count(&sections), 4);
    }

    #[test]
    fn info_discard_and_nonalloc_outputs_do_not_change_dot() {
        let inputs = vec![
            input("a.o", ".debug_info", 0, 1),
            input("a.o", ".ignored", 2, 1),
            input("a.o", ".drop", 2, 1),
            input("a.o", ".text", 6, 1),
        ];
        let script = parser::parse("SECTIONS { . = 0x401000; .debug_info 0 : { *(.debug_info) } .info 0 (INFO) : { *(.ignored) } /DISCARD/ : { *(.drop) } .text : { *(.text) } }").unwrap();
        let items = map_sections(&script, &inputs).unwrap();
        assert_eq!(names(&items), vec![".text"]);
        let symbols = SymbolTable::default();
        let mut layout = SectionPlacer::new(&symbols, 232);
        let sections = layout.place(&items, &inputs).unwrap();
        assert_eq!(*sections[0].address.get().unwrap(), 0x401000);
    }

    #[test]
    fn rejects_explicit_sections_sharing_a_page_with_different_permissions() {
        let inputs = vec![input("a.o", ".text", 6, 1), input("a.o", ".data", 3, 1)];
        let script = parser::parse("SECTIONS { . = 0x400000 + SIZEOF_HEADERS; .text 0x401000 : { *(.text) } .data 0x401001 : { *(.data) } }").unwrap();
        let items = map_sections(&script, &inputs).unwrap();
        let symbols = SymbolTable::default();
        let mut layout = SectionPlacer::new(&symbols, 232);
        let error = layout.place(&items, &inputs).err().unwrap();
        assert!(
            error
                .to_string()
                .contains("shares a page with different permissions")
        );
    }

    #[test]
    fn next_section_alignment_and_sequential_assignments() {
        let inputs = vec![
            input("a.o", ".rodata", 2, 64),
            input("a.o", ".data", 3, 128),
        ];
        let script = parser::parse("SECTIONS { . = 0x400000 + SIZEOF_HEADERS; before = .; alignment = ALIGNOF(NEXT_SECTION); .rodata : { start = .; next_alignment = ALIGNOF(NEXT_SECTION); *(.rodata) . = ALIGN(16); finish = .; } after = .; .data : { *(.data) } }").unwrap();
        let items = map_sections(&script, &inputs).unwrap();
        let symbols = SymbolTable::default();
        let mut layout = SectionPlacer::new(&symbols, 176);
        let sections = layout.place(&items, &inputs).unwrap();
        assert_eq!(layout.script_symbols["before"], 0x4000b0);
        assert_eq!(layout.script_symbols["alignment"], 64);
        assert_eq!(layout.script_symbols["next_alignment"], 128);
        assert_eq!(layout.script_symbols["start"], 0x4000c0);
        assert_eq!(layout.script_symbols["finish"], 0x4000d0);
        assert_eq!(layout.script_symbols["after"], 0x4000d0);
        assert_eq!(sections[0].size, 16);
    }

    #[test]
    fn tls_start_uses_maximum_alignment_and_tbss_reserves_address_space() {
        let mut inputs = vec![
            input("a.o", ".prefix", 3, 1),
            input("a.o", ".tdata", 0x403, 8),
            input("a.o", ".tbss", 0x403, 32),
            input("a.o", ".data", 3, 8),
        ];
        inputs[2].section.data = None;
        let script = parser::parse(
            "SECTIONS { . = 0x401000; .prefix : { *(.prefix) . = ALIGN(16); } .tdata : { *(.tdata) } .tbss : { *(.tbss) } .data : { *(.data) } }",
        ).unwrap();
        let items = map_sections(&script, &inputs).unwrap();
        let symbols = SymbolTable::default();
        let mut layout = SectionPlacer::new(&symbols, 288);
        let sections = layout.place(&items, &inputs).unwrap();
        assert_eq!(*sections[1].address.get().unwrap(), 0x401020);
        assert_eq!(*sections[2].address.get().unwrap(), 0x401040);
        assert_eq!(*sections[3].address.get().unwrap(), 0x401048);
        assert_eq!(
            TlsSegment::from_sections(&sections).unwrap(),
            Some(TlsSegment {
                vaddr: 0x401020,
                file_size: 1,
                mem_size: 33,
                align: 32,
            })
        );
    }
}
