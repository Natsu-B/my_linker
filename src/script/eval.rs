//! Compute script expressions from the layout facts known so far.
//!
//! [`evaluate`] takes an [`Expr`] and [`EvalContext`], then returns a 64-bit
//! unsigned value or an error with its line and column. [`Context`] holds `.`,
//! known symbol values, header size, and alignments. Like GNU ld, arithmetic
//! wraps at 64 bits, and a conditional evaluates only the chosen branch.
//!
//! SIZEOF_HEADERS includes the ELF and program headers. The supported static
//! subset uses 4 KiB page constants, the default SEGMENT_START address, and no
//! RELRO padding. Layout checks address ranges after expression math.
//!
//! References: [GNU ld expressions](https://sourceware.org/binutils/docs/ld/Expressions.html)
//! and [built-ins](https://sourceware.org/binutils/docs/ld/Builtin-Functions.html);
//! ELF gABI "Program Header".

use std::collections::HashMap;

use anyhow::{Result, bail, ensure};

use super::ast::*;

/// Values known in one layout pass; only earlier script values are available.
#[derive(Debug)]
pub(crate) struct Context {
    /// The location counter: the virtual address where the next bytes go.
    pub(crate) dot: u64,
    pub(crate) symbols: HashMap<String, u64>,
    /// ELF header plus the current guess at program-header bytes.
    pub(crate) sizeof_headers: u64,
    pub(crate) max_page_size: u64,
    pub(crate) common_page_size: u64,
    /// Alignment of the next output section with contents.
    pub(crate) next_section_alignment: u64,
}

/// Supply layout facts to expressions without making evaluation depend on the placer.
pub(crate) trait EvalContext {
    fn dot(&self) -> u64;
    fn symbol(&self, name: &str) -> Option<u64>;
    fn sizeof_headers(&self) -> u64;
    fn constant(&self, constant: Constant) -> u64;
    fn next_section_alignment(&self) -> u64;
}

impl Default for Context {
    fn default() -> Self {
        Self {
            dot: 0,
            symbols: HashMap::new(),
            sizeof_headers: 0,
            max_page_size: 0x1000,
            common_page_size: 0x1000,
            next_section_alignment: 1,
        }
    }
}

impl EvalContext for Context {
    fn dot(&self) -> u64 {
        self.dot
    }
    fn symbol(&self, name: &str) -> Option<u64> {
        self.symbols.get(name).copied()
    }
    fn sizeof_headers(&self) -> u64 {
        self.sizeof_headers
    }
    fn constant(&self, constant: Constant) -> u64 {
        match constant {
            Constant::MaxPageSize => self.max_page_size,
            Constant::CommonPageSize => self.common_page_size,
        }
    }
    fn next_section_alignment(&self) -> u64 {
        self.next_section_alignment
    }
}

/// Use 64-bit unsigned math, as GNU ld does, and report errors at the expression.
///
/// Only evaluate the chosen branch of a conditional. A missing symbol, zero
/// divisor, or bad alignment causes an error instead of a guessed value.
pub(crate) fn evaluate(expr: &Expr, context: &impl EvalContext) -> Result<u64> {
    let location = expr.location;
    let eval = |value: &Expr| evaluate(value, context);
    Ok(match &expr.kind {
        ExprKind::Number(value) => *value,
        ExprKind::Dot => context.dot(),
        ExprKind::Symbol(name) => context
            .symbol(name)
            .ok_or_else(|| anyhow::anyhow!("{location}: undefined script symbol {name}"))?,
        ExprKind::String(_) => bail!("{location}: string is not a numeric expression"),
        ExprKind::SizeofHeaders => context.sizeof_headers(),
        ExprKind::Unary(op, value) => {
            let value = eval(value)?;
            match op {
                UnaryOp::Negate => value.wrapping_neg(),
                UnaryOp::BitNot => !value,
                UnaryOp::LogicalNot => u64::from(value == 0),
            }
        }
        ExprKind::Binary(op, left, right) => {
            let left = eval(left)?;
            let right = eval(right)?;
            // GNU ld wraps unsigned expression math; layout checks the final
            // address range when it places sections.
            match op {
                BinaryOp::Add => left.wrapping_add(right),
                BinaryOp::Subtract => left.wrapping_sub(right),
                BinaryOp::Multiply => left.wrapping_mul(right),
                BinaryOp::Divide => {
                    ensure!(right != 0, "{location}: division by zero");
                    left / right
                }
                BinaryOp::BitAnd => left & right,
                BinaryOp::BitOr => left | right,
                BinaryOp::Equal => u64::from(left == right),
                BinaryOp::NotEqual => u64::from(left != right),
                BinaryOp::Less => u64::from(left < right),
                BinaryOp::Greater => u64::from(left > right),
                BinaryOp::LessEqual => u64::from(left <= right),
                BinaryOp::GreaterEqual => u64::from(left >= right),
            }
        }
        ExprKind::Conditional(condition, yes, no) => {
            if eval(condition)? != 0 {
                eval(yes)?
            } else {
                eval(no)?
            }
        }
        ExprKind::Call(function, args) => match function {
            Function::Align => {
                let (value, alignment) = if args.len() == 1 {
                    (context.dot(), eval(&args[0])?)
                } else {
                    (eval(&args[0])?, eval(&args[1])?)
                };
                align(value, alignment, location)?
            }
            Function::Constant => match &args[0].kind {
                ExprKind::Symbol(name) if name == "MAXPAGESIZE" => {
                    context.constant(Constant::MaxPageSize)
                }
                ExprKind::Symbol(name) if name == "COMMONPAGESIZE" => {
                    context.constant(Constant::CommonPageSize)
                }
                _ => bail!("{location}: invalid CONSTANT argument"),
            },
            Function::SegmentStart => eval(&args[1])?,
            Function::AlignOf => context.next_section_alignment(),
            Function::DataSegmentAlign => {
                let max = eval(&args[0])?;
                // Keep the old offset within a max-sized page. This static
                // subset does not use ld's common-page-size optimization.
                align(context.dot(), max, location)?.wrapping_add(context.dot() & (max - 1))
            }
            Function::DataSegmentRelroEnd => eval(&args[1])?,
            Function::DataSegmentEnd => eval(&args[0])?,
        },
    })
}

fn align(value: u64, alignment: u64, location: Location) -> Result<u64> {
    ensure!(alignment != 0, "{location}: alignment must be nonzero");
    let remainder = value % alignment;
    if remainder == 0 {
        return Ok(value);
    }
    value
        .checked_add(alignment - remainder)
        .ok_or_else(|| anyhow::anyhow!("{location}: aligned address exceeds u64"))
}

#[cfg(test)]
mod tests {
    //! Check GNU expression rules and errors with their source positions.

    use super::*;
    use crate::script::parser::parse_expression;

    fn eval(source: &str) -> u64 {
        evaluate(&parse_expression(source).unwrap(), &Context::default()).unwrap()
    }

    #[test]
    fn precedence_and_associativity() {
        for (source, expected) in [
            ("2 + 3 * 4", 14),
            ("(2+3)*4", 20),
            ("20/2/2-1", 4),
            ("8-3-2", 3),
            ("~0 & 7 | 8", 15),
            ("!1 + !0", 1),
            ("-1+2", 1),
            ("2+3 == 5", 1),
            ("1 == 2 < 3", 1),
            ("1 | 2 & 4", 1),
            ("4 & 2 == 0", 0),
            ("1 < 2", 1),
            ("1 > 2", 0),
            ("2 <= 2", 1),
            ("2 >= 3", 0),
            ("3 != 4", 1),
            ("3 == 4", 0),
            ("1+2*3 == 7 ? 11 : 22", 11),
            ("0 ? 11 : 1 ? 22 : 33", 22),
            ("1 ? 0 ? 11 : 22 : 33", 22),
            ("1 ? 42 : missing/0", 42),
            ("0 ? 1/0 : 9", 9),
        ] {
            assert_eq!(eval(source), expected, "{source}");
        }
    }

    #[test]
    fn numbers_and_suffixes() {
        for (source, expected) in [
            ("123", 123),
            ("0xff", 255),
            ("0XFF", 255),
            ("010", 8),
            ("4K", 4096),
            ("2m", 2 * 1024 * 1024),
            ("0x10K", 16384),
            ("1M", 1024 * 1024),
            ("1k", 1024),
        ] {
            assert_eq!(eval(source), expected, "{source}");
        }
        for source in [
            "0x",
            "0xGG",
            "123abc",
            "18446744073709551616",
            "18446744073709551615K",
        ] {
            assert!(
                parse_expression(source)
                    .unwrap_err()
                    .to_string()
                    .contains("1:1:")
            );
        }
    }

    #[test]
    fn functions_and_context() {
        let context = Context {
            dot: 0x1234,
            symbols: HashMap::from([("foo".into(), 7)]),
            sizeof_headers: 400,
            max_page_size: 0x200000,
            common_page_size: 0x1000,
            next_section_alignment: 64,
        };
        for (source, expected) in [
            (". + foo + SIZEOF_HEADERS", 0x1234 + 7 + 400),
            ("ALIGN(0x1000)", 0x2000),
            ("ALIGN(17, 8)", 24),
            ("CONSTANT(MAXPAGESIZE)", 0x200000),
            ("CONSTANT(COMMONPAGESIZE)", 0x1000),
            ("SEGMENT_START(\"text-segment\", 0x600000)", 0x600000),
            ("ALIGNOF(NEXT_SECTION)", 64),
            ("DATA_SEGMENT_ALIGN(0x1000, 0x1000)", 0x2234),
            ("DATA_SEGMENT_ALIGN(0x1000, 0)", 0x2234),
            ("DATA_SEGMENT_RELRO_END(0, .)", 0x1234),
            ("DATA_SEGMENT_END(.)", 0x1234),
        ] {
            assert_eq!(
                evaluate(&parse_expression(source).unwrap(), &context).unwrap(),
                expected,
                "{source}"
            );
        }
    }

    #[test]
    fn evaluation_errors_have_locations() {
        for source in [
            "missing",
            "1/0",
            "ALIGN(0)",
            "ALIGN(-1, 8)",
            "DATA_SEGMENT_ALIGN(0, 1)",
        ] {
            let expr = parse_expression(&format!("\n  {source}")).unwrap();
            assert!(
                evaluate(&expr, &Context::default())
                    .unwrap_err()
                    .to_string()
                    .starts_with("2:3:"),
                "{source}"
            );
        }
    }
}
