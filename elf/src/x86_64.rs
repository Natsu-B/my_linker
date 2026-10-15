use anyhow::{Result, anyhow};

use crate::Elf64RelaInfo;

/// Relocation numbers and calculations from the [AMD64 psABI, section 4.4.1].
///
/// `S` is the symbol value, `A` the explicit addend, `P` the relocation place,
/// `B` the load base, `GOT` the GOT address, `G` a symbol's GOT entry offset,
/// `L` its PLT entry address, and `Z` its size. For TLS, `dtpoff(S)` is the
/// offset within the defining module's TLS block and `tpoff(S)` the offset
/// from the thread pointer. `resolve(address)` calls an IFUNC resolver.
///
/// [AMD64 psABI, section 4.4.1]: https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/master/x86-64-ABI/object-files.tex
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86_64RelocationType {
    /// R_X86_64_NONE: no calculation or write.
    None = 0,
    /// R_X86_64_64: `S + A`.
    R64 = 1,
    /// R_X86_64_PC32: `S + A - P`.
    Pc32 = 2,
    /// R_X86_64_GOT32: `G + A`.
    Got32 = 3,
    /// R_X86_64_PLT32: `L + A - P`.
    Plt32 = 4,
    /// R_X86_64_COPY: runtime copy of symbol data; no arithmetic calculation.
    Copy = 5,
    /// R_X86_64_GLOB_DAT: `S`.
    GlobDat = 6,
    /// R_X86_64_JUMP_SLOT: `S`.
    JumpSlot = 7,
    /// R_X86_64_RELATIVE: `B + A`.
    Relative = 8,
    /// R_X86_64_GOTPCREL: `G + GOT + A - P`.
    GotPcRel = 9,
    /// R_X86_64_32: `S + A`, checked by zero extension from 32 bits.
    R32 = 10,
    /// R_X86_64_32S: `S + A`, checked by sign extension from 32 bits.
    R32S = 11,
    /// R_X86_64_16: `S + A`.
    R16 = 12,
    /// R_X86_64_PC16: `S + A - P`.
    Pc16 = 13,
    /// R_X86_64_8: `S + A`.
    R8 = 14,
    /// R_X86_64_PC8: `S + A - P`.
    Pc8 = 15,
    /// R_X86_64_DTPMOD64: the TLS module ID of the definition of `S`.
    DtpMod64 = 16,
    /// R_X86_64_DTPOFF64: `dtpoff(S) + A`.
    DtpOff64 = 17,
    /// R_X86_64_TPOFF64: `tpoff(S) + A`.
    TpOff64 = 18,
    /// R_X86_64_TLSGD: `G + GOT + A - P` for the symbol's TLS index pair.
    TlsGd = 19,
    /// R_X86_64_TLSLD: `G + GOT + A - P` for the module's TLS index pair.
    TlsLd = 20,
    /// R_X86_64_DTPOFF32: `dtpoff(S) + A`.
    DtpOff32 = 21,
    /// R_X86_64_GOTTPOFF: `G + GOT + A - P` for a GOT slot holding `tpoff(S)`.
    GotTpOff = 22,
    /// R_X86_64_TPOFF32: `tpoff(S) + A`.
    TpOff32 = 23,
    /// R_X86_64_PC64: `S + A - P`.
    Pc64 = 24,
    /// R_X86_64_GOTOFF64: `S + A - GOT`.
    GotOff64 = 25,
    /// R_X86_64_GOTPC32: `GOT + A - P`.
    GotPc32 = 26,
    /// R_X86_64_SIZE32: `Z + A`.
    Size32 = 32,
    /// R_X86_64_SIZE64: `Z + A`.
    Size64 = 33,
    /// R_X86_64_GOTPC32_TLSDESC: `G + GOT + A - P` for the TLS descriptor pair.
    GotPc32TlsDesc = 34,
    /// R_X86_64_TLSDESC_CALL: a resolver call marker; no arithmetic calculation.
    TlsDescCall = 35,
    /// R_X86_64_TLSDESC: a resolver/argument pair computing `tpoff(S) + A`.
    TlsDesc = 36,
    /// R_X86_64_IRELATIVE: `resolve(B + A)`.
    IRelative = 37,
    /// R_X86_64_GOTPCRELX: `G + GOT + A - P` before optional relaxation.
    GotPcRelX = 41,
    /// R_X86_64_REX_GOTPCRELX: `G + GOT + A - P` before optional relaxation.
    RexGotPcRelX = 42,
}

impl TryFrom<u32> for X86_64RelocationType {
    type Error = anyhow::Error;

    fn try_from(ty: u32) -> Result<Self> {
        match ty {
            0 => Ok(Self::None),
            1 => Ok(Self::R64),
            2 => Ok(Self::Pc32),
            3 => Ok(Self::Got32),
            4 => Ok(Self::Plt32),
            5 => Ok(Self::Copy),
            6 => Ok(Self::GlobDat),
            7 => Ok(Self::JumpSlot),
            8 => Ok(Self::Relative),
            9 => Ok(Self::GotPcRel),
            10 => Ok(Self::R32),
            11 => Ok(Self::R32S),
            12 => Ok(Self::R16),
            13 => Ok(Self::Pc16),
            14 => Ok(Self::R8),
            15 => Ok(Self::Pc8),
            16 => Ok(Self::DtpMod64),
            17 => Ok(Self::DtpOff64),
            18 => Ok(Self::TpOff64),
            19 => Ok(Self::TlsGd),
            20 => Ok(Self::TlsLd),
            21 => Ok(Self::DtpOff32),
            22 => Ok(Self::GotTpOff),
            23 => Ok(Self::TpOff32),
            24 => Ok(Self::Pc64),
            25 => Ok(Self::GotOff64),
            26 => Ok(Self::GotPc32),
            32 => Ok(Self::Size32),
            33 => Ok(Self::Size64),
            34 => Ok(Self::GotPc32TlsDesc),
            35 => Ok(Self::TlsDescCall),
            36 => Ok(Self::TlsDesc),
            37 => Ok(Self::IRelative),
            41 => Ok(Self::GotPcRelX),
            42 => Ok(Self::RexGotPcRelX),
            _ => Err(anyhow!("unknown relocation type: {}", ty)),
        }
    }
}

impl TryFrom<Elf64RelaInfo> for X86_64RelocationType {
    type Error = anyhow::Error;

    fn try_from(value: Elf64RelaInfo) -> Result<Self> {
        Self::try_from(value.ty)
    }
}
