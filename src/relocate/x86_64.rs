//! Compute relocation values and check that they fit before writing them.
//!
//! [`compute`] takes a kind and [`Operands`] and returns a [`RelocationValue`].
//! Its [`Width`] gives the field size; [`Signedness`] gives the allowed range.
//! [`write_value`] checks that range and the byte-buffer bounds, then writes
//! little-endian bytes. [`RelocationSite`] supplies error details.
//!
//! For example, PC32 stores `S + A - P`: the symbol address plus the addend,
//! minus the patch address. We use a wide integer so a too-large result cannot
//! wrap before we check it. As in GNU ld, 32 and 32S use different range checks.
//!
//! References: AMD64 psABI §4.4.1; ELF gABI "Relocation".

use anyhow::{Context, Result, bail, ensure};
use elf::x86_64::X86_64RelocationType;

/// The psABI field size, including NONE's no-write case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Width {
    None,
    Bits32,
    Bits64,
}

/// Check the value's range before taking its low bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Signedness {
    /// R_X86_64_32 must fit after zero extension.
    Unsigned,
    /// A 64-bit word accepts signed or unsigned values, including `S = 0, A = -8`.
    Either,
    /// PC and TLS offsets, and R_X86_64_32S, must fit after sign extension.
    Signed,
}

/// Keep a wide result with the range rule for the field it will fill.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct RelocationValue {
    pub(super) width: Width,
    pub(super) signedness: Signedness,
    pub(super) value: i128,
}

/// Values used in the psABI formulas; GOT, TLS, and IFUNC values exist only when needed.
pub(super) struct Operands {
    /// S: chosen symbol value, still the resolver address for IFUNC.
    pub(super) symbol: u64,
    /// A: explicit signed addend.
    pub(super) addend: i64,
    /// P: address of the patch field.
    pub(super) place: u64,
    /// G + GOT: the slot's address.
    pub(super) got_slot: Option<u64>,
    /// tpoff(S): signed offset from TP.
    pub(super) tls_offset: Option<i64>,
    /// Use the IFUNC stub in place of S or L for direct references.
    pub(super) iplt_address: Option<u64>,
}

/// Use the AMD64 psABI §4.4.1 formulas for the supported kinds.
///
/// | R_X86_64_ suffix | Value | Field |
/// | --- | --- | --- |
/// | NONE | no write | none |
/// | 64 | S + A | word64, signed or unsigned |
/// | 32 | S + A | unsigned 32 |
/// | 32S | S + A | signed 32 |
/// | PC32 | S + A - P | signed 32 |
/// | PLT32 | L + A - P | signed 32 |
/// | GOTPCREL, GOTPCRELX, REX_GOTPCRELX | G + GOT + A - P | signed 32 |
/// | GOTTPOFF | G + GOT + A - P | signed 32 |
/// | TPOFF32 | tpoff(S) + A | signed 32 |
/// | TPOFF64 | tpoff(S) + A | signed 64 |
///
/// S is the symbol value, A the signed addend, and P the patch address.
/// G is the slot offset from GOT; `got_slot` already adds them. L is the PLT
/// address: S for an ordinary static function, the IPLT stub for an IFUNC.
/// Direct IFUNC references use that stub for S too. tpoff(S) is the offset
/// from the thread pointer. Leave GOTPCRELX instructions unchanged.
pub(super) fn compute(ty: X86_64RelocationType, operands: &Operands) -> Result<RelocationValue> {
    use Signedness::{Either, Signed, Unsigned};
    use Width::{Bits32, Bits64};
    use X86_64RelocationType::*;
    // Direct IFUNC references use the stub so calls and function pointers
    // agree. The caller keeps the resolver address for IRELATIVE.
    let s = i128::from(operands.iplt_address.unwrap_or(operands.symbol));
    let a = i128::from(operands.addend);
    let p = i128::from(operands.place);
    let (width, signedness, value) = match ty {
        None => (Width::None, Unsigned, 0),
        R64 => (Bits64, Either, s + a),
        R32 => (Bits32, Unsigned, s + a),
        R32S => (Bits32, Signed, s + a),
        Pc32 | Plt32 => (Bits32, Signed, s + a - p),
        GotPcRel | GotPcRelX | RexGotPcRelX | GotTpOff => (
            Bits32,
            Signed,
            i128::from(operands.got_slot.context("missing GOT slot address")?) + a - p,
        ),
        TpOff32 | TpOff64 => (
            if ty == TpOff32 { Bits32 } else { Bits64 },
            Signed,
            i128::from(operands.tls_offset.context("missing TLS offset")?) + a,
        ),
        _ => bail!("unsupported relocation type: {ty:?}"),
    };
    Ok(RelocationValue {
        width,
        signedness,
        value,
    })
}

/// Name the kind, symbol, and patch address when a range or bounds check fails.
pub(super) struct RelocationSite<'a> {
    pub(super) ty: X86_64RelocationType,
    pub(super) symbol: &'a str,
    pub(super) place: u64,
}

/// Check the psABI range and buffer bounds before writing any bytes.
///
/// An overflow or bad offset must leave the target unchanged; report the
/// relocation kind, symbol, and address with the error.
pub(super) fn write_value(
    data: &mut [u8],
    offset: u64,
    value: RelocationValue,
    site: &RelocationSite,
) -> Result<()> {
    use Signedness::{Either, Signed, Unsigned};
    use Width::*;
    let (size, minimum, maximum) = match (value.width, value.signedness) {
        (None, _) => return Ok(()),
        (Bits32, Unsigned) => (4, 0, i128::from(u32::MAX)),
        (Bits32, Signed) => (4, i128::from(i32::MIN), i128::from(i32::MAX)),
        (Bits32, Either) => (4, i128::from(i32::MIN), i128::from(u32::MAX)),
        (Bits64, Unsigned) => (8, 0, i128::from(u64::MAX)),
        (Bits64, Either) => (8, i128::from(i64::MIN), i128::from(u64::MAX)),
        (Bits64, Signed) => (8, i128::from(i64::MIN), i128::from(i64::MAX)),
    };
    let diagnostic = || {
        format!(
            "relocation {:?} for symbol '{}' at {:#x}",
            site.ty, site.symbol, site.place
        )
    };
    ensure!(
        (minimum..=maximum).contains(&value.value),
        "{} overflows {:?} {:?} field: value {:#x}",
        diagnostic(),
        value.signedness,
        value.width,
        value.value
    );
    let offset = usize::try_from(offset)
        .with_context(|| format!("{}: write offset exceeds usize", diagnostic()))?;
    let end = offset
        .checked_add(size)
        .with_context(|| format!("{}: write end exceeds usize", diagnostic()))?;
    let target = data.get_mut(offset..end).with_context(|| {
        format!(
            "{}: write out of bounds at offset {offset:#x}",
            diagnostic()
        )
    })?;
    target.copy_from_slice(&value.value.to_le_bytes()[..size]);
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Check psABI formulas and prove that a failed field check writes no bytes.

    use super::*;

    #[test]
    fn checked_writer_accepts_boundaries_and_rejects_truncation_without_writing() {
        use Signedness::{Signed, Unsigned};
        use Width::{Bits32, Bits64};
        use X86_64RelocationType::{R32, R32S, R64, TpOff64};
        for (ty, width, signedness, size, minimum, maximum) in [
            (R32, Bits32, Unsigned, 4, 0, i128::from(u32::MAX)),
            (
                R32S,
                Bits32,
                Signed,
                4,
                i128::from(i32::MIN),
                i128::from(i32::MAX),
            ),
            (R64, Bits64, Unsigned, 8, 0, i128::from(u64::MAX)),
            (
                R64,
                Bits64,
                Signedness::Either,
                8,
                i128::from(i64::MIN),
                i128::from(u64::MAX),
            ),
            (
                TpOff64,
                Bits64,
                Signed,
                8,
                i128::from(i64::MIN),
                i128::from(i64::MAX),
            ),
        ] {
            let site = RelocationSite {
                ty,
                symbol: "target",
                place: 0x401234,
            };
            for value in [minimum, maximum] {
                let mut data = [0xa5; 10];
                write_value(
                    &mut data,
                    1,
                    RelocationValue {
                        width,
                        signedness,
                        value,
                    },
                    &site,
                )
                .unwrap();
                assert_eq!(&data[1..1 + size], &value.to_le_bytes()[..size]);
                assert_eq!(data[0], 0xa5);
                assert!(data[1 + size..].iter().all(|byte| *byte == 0xa5));
            }
            for value in [minimum - 1, maximum + 1] {
                let mut data = [0xa5; 8];
                let error = write_value(
                    &mut data,
                    0,
                    RelocationValue {
                        width,
                        signedness,
                        value,
                    },
                    &site,
                )
                .unwrap_err()
                .to_string();
                assert!(error.contains(&format!("{ty:?}")));
                assert!(error.contains("symbol 'target' at 0x401234"));
                assert!(error.contains("overflows"));
                assert_eq!(data, [0xa5; 8]);
            }
        }
    }

    #[test]
    fn r64_writes_negative_values_as_twos_complement() {
        // An undefined weak symbol has S = 0, so `.quad sym - 8` yields -8.
        let value = compute(
            X86_64RelocationType::R64,
            &Operands {
                symbol: 0,
                addend: -8,
                place: 0x401000,
                got_slot: Option::None,
                tls_offset: Option::None,
                iplt_address: Option::None,
            },
        )
        .unwrap();
        let mut data = [0; 8];
        write_value(
            &mut data,
            0,
            value,
            &RelocationSite {
                ty: X86_64RelocationType::R64,
                symbol: "weak",
                place: 0x401000,
            },
        )
        .unwrap();
        assert_eq!(u64::from_le_bytes(data), (-8i64) as u64);
    }

    #[test]
    fn checked_writer_reports_out_of_bounds_with_relocation_context() {
        let site = RelocationSite {
            ty: X86_64RelocationType::R64,
            symbol: "target",
            place: 0x401234,
        };
        for offset in [1, u64::MAX] {
            let mut data = [0xa5; 8];
            let error = write_value(
                &mut data,
                offset,
                RelocationValue {
                    width: Width::Bits64,
                    signedness: Signedness::Unsigned,
                    value: 0,
                },
                &site,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("relocation R64 for symbol 'target' at 0x401234"));
            assert_eq!(data, [0xa5; 8]);
        }
    }
}
