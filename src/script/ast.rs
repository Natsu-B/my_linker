use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Location {
    pub line: usize,
    pub column: usize,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.line, self.column)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Script {
    pub statements: Vec<Statement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Statement {
    Entry(String),
    Sections(Vec<SectionStatement>),
    Assignment(Assignment),
    Ignored(IgnoredCommand),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IgnoredCommand {
    OutputFormat,
    OutputArch,
    Constructors,
    LinkerVersion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SectionStatement {
    Assignment(Assignment),
    Output(OutputSection),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
    pub name: String,
    pub value: Expr,
    pub kind: AssignmentKind,
    pub location: Location,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssignmentKind {
    Define,
    Provide,
    ProvideHidden,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputSection {
    pub name: String,
    pub address: Option<Expr>,
    pub constraint: Option<SectionConstraint>,
    pub info: bool,
    pub statements: Vec<OutputStatement>,
    pub location: Location,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionConstraint {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputStatement {
    Assignment(Assignment),
    Input(InputSection),
    Ignored(IgnoredCommand),
}

// Keep the wrappers in the tree so layout can apply sorting and exclusions
// at the scope where they appeared in the script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputSection {
    File {
        pattern: String,
        sections: Vec<SectionPattern>,
    },
    Keep(Box<InputSection>),
    Sort(SortKind, Box<InputSection>),
    ExcludeFile(Vec<String>, Box<InputSection>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SectionPattern {
    Glob(String),
    Common,
    Sort(SortKind, Vec<SectionPattern>),
    // Applies to subsequent patterns in this list, including nested sorts.
    ExcludeFile(Vec<String>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortKind {
    Name,
    None,
    InitPriority,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expr {
    pub kind: ExprKind,
    pub location: Location,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExprKind {
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
pub enum UnaryOp {
    Negate,
    BitNot,
    LogicalNot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryOp {
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
pub enum Function {
    Align,
    Constant,
    SegmentStart,
    AlignOf,
    DataSegmentAlign,
    DataSegmentRelroEnd,
    DataSegmentEnd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Constant {
    MaxPageSize,
    CommonPageSize,
}
