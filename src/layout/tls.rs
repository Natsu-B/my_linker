use anyhow::{Context, Result, ensure};
use elf::Elf64SectionFlags;

use crate::layout::OutputSection;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TlsSegment {
    pub(crate) vaddr: u64,
    pub(crate) file_size: u64,
    pub(crate) mem_size: u64,
    pub(crate) align: u64,
}

impl TlsSegment {
    pub(crate) fn from_sections(sections: &[OutputSection]) -> Result<Option<Self>> {
        let mut tls: Option<Self> = None;
        let mut finished = false;
        let mut zero_fill = false;
        for section in sections.iter().filter(|section| section.size != 0) {
            let is_tls = section
                .inputs
                .iter()
                .any(|(input, _)| input.flags.get(Elf64SectionFlags::SHF_TLS) != 0);
            if !is_tls {
                finished |= tls.is_some();
                continue;
            }
            ensure!(!finished, "TLS output sections must be contiguous");
            let address = *section
                .address
                .get()
                .context("TLS section has no address")?;
            let segment = tls.get_or_insert(Self {
                vaddr: address,
                file_size: 0,
                mem_size: 0,
                align: 1,
            });
            for (input, offset) in &section.inputs {
                ensure!(
                    input.size == 0 || input.flags.get(Elf64SectionFlags::SHF_TLS) != 0,
                    "output section {} mixes TLS and non-TLS inputs",
                    section.name
                );
                if input.flags.get(Elf64SectionFlags::SHF_TLS) == 0 {
                    continue;
                }
                segment.align = segment.align.max(input.align.max(1));
                if input.size == 0 {
                    continue;
                }
                if input.data.is_some() {
                    ensure!(!zero_fill, "initialized TLS follows zero-fill TLS");
                    segment.file_size = address
                        .checked_add(*offset)
                        .and_then(|address| address.checked_add(input.size))
                        .and_then(|end| end.checked_sub(segment.vaddr))
                        .context("TLS file range exceeds u64")?;
                } else {
                    zero_fill = true;
                }
            }
            // .tbss reserves VMA just like other NOBITS sections. The load
            // writer materializes zeros if initialized RW data follows it.
            segment.mem_size = address
                .checked_add(section.size)
                .and_then(|end| end.checked_sub(segment.vaddr))
                .context("TLS memory range exceeds u64")?;
            if !zero_fill {
                // Include script padding at the end of initialized TLS output
                // sections. The file image must contain these zeros as well.
                segment.file_size = segment.mem_size;
            }
        }
        if let Some(segment) = &tls {
            ensure!(
                segment.vaddr.is_multiple_of(segment.align),
                "TLS start is not aligned to the maximum TLS input alignment"
            );
        }
        Ok(tls)
    }

    pub(crate) fn tpoff(&self, address: u64) -> Result<i64> {
        let size = self
            .mem_size
            .checked_next_multiple_of(self.align)
            .context("aligned TLS size exceeds u64")?;
        // x86-64 TLS variant II: TP follows the aligned static TLS block.
        // An undefined weak TLS symbol keeps S = 0 in this calculation.
        i64::try_from(i128::from(address) - i128::from(self.vaddr) - i128::from(size))
            .context("TLS TP offset exceeds i64")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpoff_uses_the_aligned_memory_size() {
        let tls = TlsSegment {
            vaddr: 0x402000,
            file_size: 0x38,
            mem_size: 0x50,
            align: 32,
        };
        assert_eq!(tls.tpoff(0x402000).unwrap(), -0x60);
        assert_eq!(tls.tpoff(0x402038).unwrap(), -0x28);
        assert_eq!(tls.tpoff(0x402048).unwrap(), -0x18);
        assert_eq!(tls.tpoff(0).unwrap(), -0x402060);
    }

    #[test]
    fn tpoff_checks_alignment_and_signed_overflow() {
        let mut tls = TlsSegment {
            vaddr: 0,
            file_size: 0,
            mem_size: u64::MAX,
            align: 8,
        };
        assert!(
            tls.tpoff(0)
                .unwrap_err()
                .to_string()
                .contains("aligned TLS size")
        );
        tls.align = 1;
        assert!(
            tls.tpoff(0)
                .unwrap_err()
                .to_string()
                .contains("exceeds i64")
        );
    }
}
