//! Keep script rules and expressions until the link can use them.
//!
//! The parser returns a [`Script`] of ordered statements. [`OutputSectionRule`]
//! names an output section; [`InputSectionRule`] chooses its inputs. [`Expr`]
//! holds address math, and [`Location`] lets errors point back to the text.
//!
//! Sort and exclusion wrappers keep the scope they have in GNU ld scripts.
//! For example, sorting one list must not sort the next list too. Mapping uses
//! these rules before layout computes their expressions.
//!
//! References: [GNU ld SECTIONS](https://sourceware.org/binutils/docs/ld/SECTIONS.html),
//! input-section descriptions, and expressions; ELF gABI "Sections" and "Symbol Table".

use std::fmt;

/// Keep source order: assignments and section rules can depend on earlier ones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Script {
    pub(crate) statements: Vec<Statement>,
}

/// One-based line and column for script errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Location {
    pub(crate) line: usize,
    pub(crate) column: usize,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.line, self.column)
    }
}

/// Commands outside an output section, including whole SECTIONS blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Statement {
    Entry(String),
    Sections(Vec<SectionStatement>),
    Assignment(Assignment),
    Ignored(IgnoredCommand),
}

/// Accept these GNU commands without acting on them in this fixed-target linker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IgnoredCommand {
    OutputFormat,
    OutputArch,
    Constructors,
    LinkerVersion,
}

/// Rules and assignments between output sections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SectionStatement {
    Assignment(Assignment),
    Output(OutputSectionRule),
}

/// A symbol or dot expression, with the rule for deciding whether to define it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Assignment {
    /// `.` changes the location counter rather than defining a symbol.
    pub(crate) name: String,
    pub(crate) value: Expr,
    pub(crate) kind: AssignmentKind,
    /// Tell separate PROVIDE assignments for the same name apart.
    pub(crate) location: Location,
}

/// A plain definition always runs; PROVIDE runs only for a needed, otherwise undefined name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AssignmentKind {
    Define,
    Provide,
    /// Apply PROVIDE's rule and write the static symbol as local.
    ProvideHidden,
}

/// A script rule before mapping picks its inputs or layout sets its address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OutputSectionRule {
    /// `/DISCARD/` drops the matched inputs.
    pub(crate) name: String,
    pub(crate) address: Option<Expr>,
    pub(crate) constraint: Option<SectionConstraint>,
    /// `(INFO)` keeps this rule out of allocated memory.
    pub(crate) info: bool,
    pub(crate) statements: Vec<OutputStatement>,
    pub(crate) location: Location,
}

/// GNU ld ONLY_IF_RO/ONLY_IF_RW checks on the chosen output's write flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SectionConstraint {
    ReadOnly,
    ReadWrite,
}

/// Keep input choices and assignments in the order the script gives them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OutputStatement {
    Assignment(Assignment),
    Input(InputSectionRule),
    Ignored(IgnoredCommand),
}

/// Keep wrapper scope so one sort or exclusion cannot affect a neighboring rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InputSectionRule {
    File {
        pattern: String,
        sections: Vec<SectionPattern>,
    },
    /// Keep the GNU syntax; this linker keeps all chosen inputs without garbage collection.
    Keep(Box<InputSectionRule>),
    Sort(SortKind, Box<InputSectionRule>),
    ExcludeFile(Vec<String>, Box<InputSectionRule>),
}

/// Patterns within one file selector; an exclusion affects the patterns that follow it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SectionPattern {
    Glob(String),
    /// Accept the script keyword, but let resolution reject actual COMMON storage.
    Common,
    Sort(SortKind, Vec<SectionPattern>),
    ExcludeFile(Vec<String>),
}

/// GNU ld's order for input sections; equal keys keep input order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SortKind {
    Name,
    None,
    /// Use numeric constructor priority, including the reversed legacy .ctors/.dtors numbering.
    InitPriority,
}

/// An expression with a source location for errors; layout computes its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Expr {
    pub(crate) kind: ExprKind,
    pub(crate) location: Location,
}

/// Address math with symbol names, the location counter, and built-in calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ExprKind {
    Number(u64),
    Dot,
    Symbol(String),
    String(String),
    SizeofHeaders,
    Unary(UnaryOp, Box<Expr>),
    Binary(BinaryOp, Box<Expr>, Box<Expr>),
    /// Evaluate only the chosen branch; an unused branch may refer to a missing symbol.
    Conditional(Box<Expr>, Box<Expr>, Box<Expr>),
    Call(Function, Vec<Expr>),
}

/// Unary operations on 64-bit unsigned values; negation wraps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnaryOp {
    Negate,
    BitNot,
    LogicalNot,
}

/// Use GNU ld's 64-bit unsigned math; add, subtract, and multiply wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BinaryOp {
    Add,
    Subtract,
    Multiply,
    Divide,
    BitAnd,
    BitOr,
    Equal,
    NotEqual,
    Less,
    Greater,
    LessEqual,
    GreaterEqual,
}

/// Built-ins accepted by the parser; evaluation supports the static subset below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Function {
    Align,
    Constant,
    /// Use the default address; command-line segment overrides are not supported.
    SegmentStart,
    /// Accept ALIGNOF(NEXT_SECTION); placement supplies the next section's alignment.
    AlignOf,
    /// Use ALIGN(max) plus the old offset within a max-sized page.
    DataSegmentAlign,
    /// Return the address argument; this linker adds no RELRO padding.
    DataSegmentRelroEnd,
    /// Return the address argument.
    DataSegmentEnd,
}

/// Page sizes used by script expressions; both default to 4 KiB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Constant {
    MaxPageSize,
    CommonPageSize,
}
