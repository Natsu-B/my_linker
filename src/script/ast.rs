use std::fmt;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Script {
    pub(crate) statements: Vec<Statement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Statement {
    Entry(String),
    Sections(Vec<SectionStatement>),
    Assignment(Assignment),
    Ignored(IgnoredCommand),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IgnoredCommand {
    OutputFormat,
    OutputArch,
    Constructors,
    LinkerVersion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SectionStatement {
    Assignment(Assignment),
    Output(OutputSectionRule),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Assignment {
    pub(crate) name: String,
    pub(crate) value: Expr,
    pub(crate) kind: AssignmentKind,
    pub(crate) location: Location,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AssignmentKind {
    Define,
    Provide,
    ProvideHidden,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OutputSectionRule {
    pub(crate) name: String,
    pub(crate) address: Option<Expr>,
    pub(crate) constraint: Option<SectionConstraint>,
    pub(crate) info: bool,
    pub(crate) statements: Vec<OutputStatement>,
    pub(crate) location: Location,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SectionConstraint {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OutputStatement {
    Assignment(Assignment),
    Input(InputSectionRule),
    Ignored(IgnoredCommand),
}

// Keep the wrappers in the tree so layout can apply sorting and exclusions
// at the scope where they appeared in the script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InputSectionRule {
    File {
        pattern: String,
        sections: Vec<SectionPattern>,
    },
    Keep(Box<InputSectionRule>),
    Sort(SortKind, Box<InputSectionRule>),
    ExcludeFile(Vec<String>, Box<InputSectionRule>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SectionPattern {
    Glob(String),
    Common,
    Sort(SortKind, Vec<SectionPattern>),
    // Applies to subsequent patterns in this list, including nested sorts.
    ExcludeFile(Vec<String>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SortKind {
    Name,
    None,
    InitPriority,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Expr {
    pub(crate) kind: ExprKind,
    pub(crate) location: Location,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ExprKind {
    Number(u64),
    Dot,
    Symbol(String),
    String(String),
    SizeofHeaders,
    Unary(UnaryOp, Box<Expr>),
    Binary(BinaryOp, Box<Expr>, Box<Expr>),
    Conditional(Box<Expr>, Box<Expr>, Box<Expr>),
    Call(Function, Vec<Expr>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnaryOp {
    Negate,
    BitNot,
    LogicalNot,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Function {
    Align,
    Constant,
    SegmentStart,
    AlignOf,
    DataSegmentAlign,
    DataSegmentRelroEnd,
    DataSegmentEnd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Constant {
    MaxPageSize,
    CommonPageSize,
}
