use anyhow::{Context, Result, bail, ensure};
use elf::x86_64::X86_64RelocationType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Width {
    None,
    Bits32,
    Bits64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Signedness {
    /// The value must fit after zero extension (e.g. R_X86_64_32).
    Unsigned,
    /// The value is two's complement in a 64-bit field (R_X86_64_64): the
    /// psABI word64 accepts both signed and unsigned values, so `S + A` with a
    /// negative result (e.g. undefined weak `S = 0` and `A < 0`) is valid.
    Either,
    Signed,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct RelocationValue {
    pub(super) width: Width,
    pub(super) signedness: Signedness,
    pub(super) value: i128,
}

pub(super) struct Operands {
    pub(super) symbol: u64,
    pub(super) addend: i64,
    pub(super) place: u64,
    pub(super) got_slot: Option<u64>,
    pub(super) tls_offset: Option<i64>,
    pub(super) iplt_address: Option<u64>,
}

/// Calculations for supported relocations (AMD64 psABI, section 4.4.1).
///
/// | R_X86_64_ suffix | Calculation | Field |
/// | --- | --- | --- |
/// | NONE | no write | none |
/// | 64 | S + A | unsigned 64 |
/// | 32 | S + A | unsigned 32 (zero extension) |
/// | 32S | S + A | signed 32 (sign extension) |
/// | PC32 | S + A - P | signed 32 |
/// | PLT32 | L + A - P | signed 32 |
/// | GOTPCREL, GOTPCRELX, REX_GOTPCRELX | G + GOT + A - P | signed 32 |
/// | GOTTPOFF | G + GOT + A - P | signed 32 |
/// | TPOFF32 | tpoff(S) + A | signed 32 |
/// | TPOFF64 | tpoff(S) + A | signed 64 |
///
/// `got_slot` is G + GOT. For static output L is S unless an IFUNC needs an
/// IPLT stub. GOTPCRELX instructions remain unrelaxed. Wide intermediate
/// arithmetic keeps overflow checks separate from these psABI formulas.
pub(super) fn compute(ty: X86_64RelocationType, operands: &Operands) -> Result<RelocationValue> {
    use Signedness::{Either, Signed, Unsigned};
    use Width::{Bits32, Bits64};
    use X86_64RelocationType::*;
    // The IPLT stub is the canonical function address of an IFUNC. Its
    // resolver's S is retained separately for the IRELATIVE relocation.
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

pub(super) struct RelocationSite<'a> {
    pub(super) ty: X86_64RelocationType,
    pub(super) symbol: &'a str,
    pub(super) place: u64,
}

/// Check the psABI's extension rule before writing one little-endian field.
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
