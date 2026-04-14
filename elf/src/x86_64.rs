use anyhow::{Result, anyhow};

use crate::Elf64RelaInfo;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86_64RelocationType {
    /// R_X86_64_NONE
    None = 0,
    /// R_X86_64_64
    Rel64 = 1,
    /// R_X86_64_PC32
    Pc32 = 2,
    /// R_X86_64_GOT32
    Got32 = 3,
    /// R_X86_64_PLT32
    Plt32 = 4,
    /// R_X86_64_COPY
    Copy = 5,
    /// R_X86_64_GLOB_DAT
    GlobDat = 6,
    /// R_X86_64_JUMP_SLOT
    JumpSlot = 7,
    /// R_X86_64_RELATIVE
    Relative = 8,
    /// R_X86_64_GOTPCREL
    GotPcRel = 9,
    /// R_X86_64_32
    Rel32 = 10,
    /// R_X86_64_32S
    Rel32S = 11,
    /// R_X86_64_16
    Rel16 = 12,
    /// R_X86_64_PC16
    Pc16 = 13,
    /// R_X86_64_8
    Rel8 = 14,
    /// R_X86_64_PC8
    Pc8 = 15,
    /// R_X86_64_DTPMOD64
    DtpMod64 = 16,
    /// R_X86_64_DTPOFF64
    DtpOff64 = 17,
    /// R_X86_64_TPOFF64
    TpOff64 = 18,
    /// R_X86_64_TLSGD
    TlsGd = 19,
    /// R_X86_64_TLSLD
    TlsLd = 20,
    /// R_X86_64_DTPOFF32
    DtpOff32 = 21,
    /// R_X86_64_GOTTPOFF
    GotTpOff = 22,
    /// R_X86_64_TPOFF32
    TpOff32 = 23,
    /// R_X86_64_PC64
    Pc64 = 24,
    /// R_X86_64_GOTOFF64
    GotOff64 = 25,
    /// R_X86_64_GOTPC32
    GotPc32 = 26,
    /// R_X86_64_SIZE32
    Size32 = 32,
    /// R_X86_64_SIZE64
    Size64 = 33,
    /// R_X86_64_GOTPC32_TLSDESC
    GotPc32TlsDesc = 34,
    /// R_X86_64_TLSDESC_CALL
    TlsDescCall = 35,
    /// R_X86_64_TLSDESC
    TlsDesc = 36,
    /// R_X86_64_IRELATIVE
    IRelative = 37,
}

impl TryFrom<u32> for X86_64RelocationType {
    type Error = anyhow::Error;

    fn try_from(ty: u32) -> Result<Self> {
        match ty {
            0 => Ok(Self::None),
            1 => Ok(Self::Rel64),
            2 => Ok(Self::Pc32),
            3 => Ok(Self::Got32),
            4 => Ok(Self::Plt32),
            5 => Ok(Self::Copy),
            6 => Ok(Self::GlobDat),
            7 => Ok(Self::JumpSlot),
            8 => Ok(Self::Relative),
            9 => Ok(Self::GotPcRel),
            10 => Ok(Self::Rel32),
            11 => Ok(Self::Rel32S),
            12 => Ok(Self::Rel16),
            13 => Ok(Self::Pc16),
            14 => Ok(Self::Rel8),
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
