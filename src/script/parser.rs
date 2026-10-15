//! Turn script text into rules and expression trees.
//!
//! [`parse`] takes text and returns a [`Script`]. The private `Parser` checks
//! syntax, operator order, and built-in arguments. Errors include the text's
//! line and column; unsupported commands fail instead of silently changing layout.
//!
//! We follow the supported GNU ld syntax. OUTPUT_FORMAT and OUTPUT_ARCH are
//! accepted but do not choose a target: input checks and output already fix
//! little-endian x86-64.
//!
//! References: [GNU ld script format](https://sourceware.org/binutils/docs/ld/Script-Format.html),
//! SECTIONS, and expressions; ELF gABI "Sections" and "Symbol Table".

use anyhow::{Result, bail, ensure};

use super::{
    ast::*,
    lexer::{Token, TokenKind, lex},
};

/// Parse the full script; reject unsupported commands with their line and column.
pub(crate) fn parse(source: &str) -> Result<Script> {
    Parser::new(source)?.script()
}

/// Parse a whole expression for tests, rejecting trailing text.
#[cfg(test)]
pub(crate) fn parse_expression(source: &str) -> Result<Expr> {
    let mut parser = Parser::new(source)?;
    let expr = parser.expression(0)?;
    parser.expect_eof()?;
    Ok(expr)
}

struct Parser<'a> {
    source: &'a str,
    tokens: Vec<Token>,
    index: usize,
}

impl<'a> Parser<'a> {
    fn new(source: &'a str) -> Result<Self> {
        Ok(Self {
            source,
            tokens: lex(source)?,
            index: 0,
        })
    }

    fn token(&self) -> &Token {
        &self.tokens[self.index]
    }

    fn at(&self, ch: char) -> bool {
        self.token().kind == TokenKind::Punct(ch)
    }

    fn word(&self, name: &str) -> bool {
        matches!(&self.token().kind, TokenKind::Word(word) if word == name)
    }

    fn take(&mut self, ch: char) -> bool {
        if self.at(ch) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, ch: char) -> Result<()> {
        ensure!(
            self.take(ch),
            "{}: expected {ch:?}, found {:?}",
            self.token().location,
            self.token().kind
        );
        Ok(())
    }

    #[cfg(test)]
    fn expect_eof(&self) -> Result<()> {
        ensure!(
            self.token().kind == TokenKind::Eof,
            "{}: unexpected token {:?}",
            self.token().location,
            self.token().kind
        );
        Ok(())
    }

    fn unsupported(&self) -> Result<()> {
        if let TokenKind::Word(name) = &self.token().kind {
            ensure!(
                !matches!(
                    name.as_str(),
                    "MEMORY"
                        | "PHDRS"
                        | "OVERLAY"
                        | "AT"
                        | "INCLUDE"
                        | "INPUT"
                        | "GROUP"
                        | "AS_NEEDED"
                        | "ASSERT"
                ),
                "{}: unsupported linker script command {name}",
                self.token().location
            );
        }
        ensure!(
            !self.at('>'),
            "{}: unsupported linker script region assignment (>region)",
            self.token().location
        );
        Ok(())
    }

    fn script(&mut self) -> Result<Script> {
        let mut statements = Vec::new();
        while self.token().kind != TokenKind::Eof {
            if self.take(';') {
                continue;
            }
            self.unsupported()?;
            if self.word("ENTRY") {
                self.index += 1;
                self.expect('(')?;
                let name = self.pattern()?;
                self.expect(')')?;
                statements.push(Statement::Entry(name));
            } else if self.word("SECTIONS") {
                self.index += 1;
                self.expect('{')?;
                let mut sections = Vec::new();
                while !self.take('}') {
                    if self.take(';') {
                        continue;
                    }
                    self.unsupported()?;
                    sections.push(if self.is_assignment() {
                        SectionStatement::Assignment(self.assignment()?)
                    } else {
                        SectionStatement::Output(self.output_section()?)
                    });
                }
                statements.push(Statement::Sections(sections));
            } else if self.word("OUTPUT_FORMAT") || self.word("OUTPUT_ARCH") {
                statements.push(Statement::Ignored(self.output_metadata()?));
            } else if self.is_assignment() {
                statements.push(Statement::Assignment(self.assignment()?));
            } else {
                bail!(
                    "{}: expected ENTRY, SECTIONS, or assignment, found {:?}",
                    self.token().location,
                    self.token().kind
                );
            }
        }
        Ok(Script { statements })
    }

    fn output_metadata(&mut self) -> Result<IgnoredCommand> {
        let location = self.token().location;
        let format = self.word("OUTPUT_FORMAT");
        self.index += 1;
        self.expect('(')?;
        let mut args = Vec::new();
        loop {
            let value = if let TokenKind::String(value) = &self.token().kind {
                let value = value.clone();
                self.index += 1;
                value
            } else {
                let mut value = self.pattern()?;
                if !format && self.take(':') {
                    value.push(':');
                    value.push_str(&self.pattern()?);
                }
                value
            };
            args.push(value);
            if !self.take(',') {
                break;
            }
        }
        self.expect(')')?;
        if format {
            ensure!(
                (args.len() == 1 || args.len() == 3)
                    && args.iter().all(|arg| arg == "elf64-x86-64"),
                "{location}: unsupported OUTPUT_FORMAT (expected elf64-x86-64)"
            );
            Ok(IgnoredCommand::OutputFormat)
        } else {
            ensure!(
                args == ["i386:x86-64"],
                "{location}: unsupported OUTPUT_ARCH (expected i386:x86-64)"
            );
            Ok(IgnoredCommand::OutputArch)
        }
    }

    fn is_assignment(&self) -> bool {
        self.word("PROVIDE")
            || self.word("PROVIDE_HIDDEN")
            || matches!(self.token().kind, TokenKind::Word(_))
                && self
                    .tokens
                    .get(self.index + 1)
                    .is_some_and(|token| token.kind == TokenKind::Punct('='))
    }

    fn assignment(&mut self) -> Result<Assignment> {
        let location = self.token().location;
        let kind = if self.word("PROVIDE") {
            AssignmentKind::Provide
        } else if self.word("PROVIDE_HIDDEN") {
            AssignmentKind::ProvideHidden
        } else {
            AssignmentKind::Define
        };
        if kind != AssignmentKind::Define {
            self.index += 1;
            self.expect('(')?;
        }
        let name = self.identifier()?;
        ensure!(
            name != "." || kind == AssignmentKind::Define,
            "{location}: PROVIDE cannot assign the location counter"
        );
        self.expect('=')?;
        let value = self.expression(0)?;
        if kind != AssignmentKind::Define {
            self.expect(')')?;
        }
        self.expect(';')?;
        Ok(Assignment {
            name,
            value,
            kind,
            location,
        })
    }

    fn identifier(&mut self) -> Result<String> {
        let token = self.token();
        let TokenKind::Word(word) = &token.kind else {
            bail!(
                "{}: expected identifier, found {:?}",
                token.location,
                token.kind
            );
        };
        ensure!(
            !word.starts_with(|ch: char| ch.is_ascii_digit()),
            "{}: expected identifier, found {word}",
            token.location
        );
        let word = word.clone();
        self.index += 1;
        Ok(word)
    }

    fn info(&self) -> bool {
        self.at('(')
            && self
                .tokens
                .get(self.index + 1)
                .is_some_and(|token| token.kind == TokenKind::Word("INFO".into()))
    }

    fn output_section(&mut self) -> Result<OutputSectionRule> {
        let location = self.token().location;
        let name = self.pattern()?;
        self.unsupported()?;
        let address = if self.at(':') || self.info() {
            None
        } else {
            Some(self.expression(0)?)
        };
        let info = self.info();
        if info {
            self.expect('(')?;
            self.index += 1;
            self.expect(')')?;
        }
        self.unsupported()?;
        self.expect(':')?;
        self.unsupported()?;
        let constraint = if self.word("ONLY_IF_RO") {
            self.index += 1;
            Some(SectionConstraint::ReadOnly)
        } else if self.word("ONLY_IF_RW") {
            self.index += 1;
            Some(SectionConstraint::ReadWrite)
        } else {
            None
        };
        self.expect('{')?;
        let mut statements = Vec::new();
        while !self.take('}') {
            if self.take(';') {
                continue;
            }
            self.unsupported()?;
            statements.push(if self.is_assignment() {
                OutputStatement::Assignment(self.assignment()?)
            } else if self.word("LINKER_VERSION") {
                self.index += 1;
                OutputStatement::Ignored(IgnoredCommand::LinkerVersion)
            } else if self.word("SORT")
                && self
                    .tokens
                    .get(self.index + 2)
                    .is_some_and(|token| token.kind == TokenKind::Word("CONSTRUCTORS".into()))
            {
                self.index += 1;
                self.expect('(')?;
                self.index += 1;
                self.expect(')')?;
                OutputStatement::Ignored(IgnoredCommand::Constructors)
            } else {
                OutputStatement::Input(self.input_section()?)
            });
        }
        self.unsupported()?;
        Ok(OutputSectionRule {
            name,
            address,
            info,
            constraint,
            statements,
            location,
        })
    }

    fn sort_kind(&self) -> Option<SortKind> {
        match &self.token().kind {
            TokenKind::Word(name) => match name.as_str() {
                "SORT" | "SORT_BY_NAME" => Some(SortKind::Name),
                "SORT_NONE" => Some(SortKind::None),
                "SORT_BY_INIT_PRIORITY" => Some(SortKind::InitPriority),
                _ => None,
            },
            _ => None,
        }
    }

    fn input_section(&mut self) -> Result<InputSectionRule> {
        self.unsupported()?;
        if self.word("KEEP") {
            self.index += 1;
            self.expect('(')?;
            let input = self.input_section()?;
            self.expect(')')?;
            return Ok(InputSectionRule::Keep(Box::new(input)));
        }
        if let Some(kind) = self.sort_kind() {
            self.index += 1;
            self.expect('(')?;
            let input = self.input_section()?;
            self.expect(')')?;
            return Ok(InputSectionRule::Sort(kind, Box::new(input)));
        }
        if self.word("EXCLUDE_FILE") {
            let files = self.excluded_files()?;
            return Ok(InputSectionRule::ExcludeFile(
                files,
                Box::new(self.input_section()?),
            ));
        }
        let pattern = self.pattern()?;
        self.expect('(')?;
        let sections = self.section_patterns()?;
        self.expect(')')?;
        Ok(InputSectionRule::File { pattern, sections })
    }

    fn excluded_files(&mut self) -> Result<Vec<String>> {
        self.index += 1;
        self.expect('(')?;
        let mut files = Vec::new();
        while !self.take(')') {
            files.push(self.pattern()?);
            self.take(',');
        }
        Ok(files)
    }

    fn section_patterns(&mut self) -> Result<Vec<SectionPattern>> {
        let mut patterns = Vec::new();
        while !self.at(')') {
            self.unsupported()?;
            if let Some(kind) = self.sort_kind() {
                self.index += 1;
                self.expect('(')?;
                let nested = self.section_patterns()?;
                self.expect(')')?;
                patterns.push(SectionPattern::Sort(kind, nested));
            } else if self.word("EXCLUDE_FILE") {
                patterns.push(SectionPattern::ExcludeFile(self.excluded_files()?));
            } else {
                let pattern = self.pattern()?;
                patterns.push(if pattern == "COMMON" {
                    SectionPattern::Common
                } else {
                    SectionPattern::Glob(pattern)
                });
            }
            self.take(',');
        }
        Ok(patterns)
    }

    // A '*' or '?' can be a pattern or an expression token. Join only
    // adjacent spans here so whitespace still separates script expressions.
    fn pattern(&mut self) -> Result<String> {
        let token = self.token();
        if let TokenKind::String(value) = &token.kind {
            let value = value.clone();
            self.index += 1;
            return Ok(value);
        }
        let location = token.location;
        let start = token.start;
        let mut end = start;
        let mut brackets = 0;
        loop {
            let token = self.token();
            if token.start != end {
                break;
            }
            match token.kind {
                TokenKind::Word(_) | TokenKind::Punct('*' | '?' | '-' | '/' | '$') => {}
                TokenKind::Punct('[') => brackets += 1,
                TokenKind::Punct(']') if brackets > 0 => brackets -= 1,
                TokenKind::Punct('!' | '^') if brackets > 0 => {}
                _ => break,
            }
            end = token.end;
            self.index += 1;
        }
        ensure!(
            end > start,
            "{location}: expected pattern, found {:?}",
            self.token().kind
        );
        ensure!(
            brackets == 0,
            "{location}: unterminated glob character class"
        );
        Ok(self.source[start..end].to_string())
    }

    fn expression(&mut self, minimum: u8) -> Result<Expr> {
        let mut left = self.primary()?;
        loop {
            if minimum == 0 && self.take('?') {
                let yes = self.expression(0)?;
                self.expect(':')?;
                let no = self.expression(0)?;
                let location = left.location;
                left = Expr {
                    kind: ExprKind::Conditional(Box::new(left), Box::new(yes), Box::new(no)),
                    location,
                };
                continue;
            }
            let Some((op, precedence)) = self.binary_op() else {
                break;
            };
            if precedence < minimum {
                break;
            }
            self.index += 1;
            let right = self.expression(precedence + 1)?;
            let location = left.location;
            left = Expr {
                kind: ExprKind::Binary(op, Box::new(left), Box::new(right)),
                location,
            };
        }
        Ok(left)
    }

    fn binary_op(&self) -> Option<(BinaryOp, u8)> {
        Some(match self.token().kind {
            TokenKind::Punct('|') => (BinaryOp::BitOr, 1),
            TokenKind::Punct('&') => (BinaryOp::BitAnd, 2),
            TokenKind::Equal => (BinaryOp::Equal, 3),
            TokenKind::NotEqual => (BinaryOp::NotEqual, 3),
            TokenKind::Punct('<') => (BinaryOp::Less, 4),
            TokenKind::Punct('>') => (BinaryOp::Greater, 4),
            TokenKind::LessEqual => (BinaryOp::LessEqual, 4),
            TokenKind::GreaterEqual => (BinaryOp::GreaterEqual, 4),
            TokenKind::Punct('+') => (BinaryOp::Add, 5),
            TokenKind::Punct('-') => (BinaryOp::Subtract, 5),
            TokenKind::Punct('*') => (BinaryOp::Multiply, 6),
            TokenKind::Punct('/') => (BinaryOp::Divide, 6),
            _ => return None,
        })
    }

    fn primary(&mut self) -> Result<Expr> {
        self.unsupported()?;
        let location = self.token().location;
        let unary = match self.token().kind {
            TokenKind::Punct('-') => Some(UnaryOp::Negate),
            TokenKind::Punct('~') => Some(UnaryOp::BitNot),
            TokenKind::Punct('!') => Some(UnaryOp::LogicalNot),
            _ => None,
        };
        let kind = if let Some(op) = unary {
            self.index += 1;
            ExprKind::Unary(op, Box::new(self.primary()?))
        } else if self.take('(') {
            let expr = self.expression(0)?;
            self.expect(')')?;
            return Ok(expr);
        } else {
            let token = self.token().clone();
            self.index += 1;
            match token.kind {
                TokenKind::Word(word) if word.starts_with(|ch: char| ch.is_ascii_digit()) => {
                    ExprKind::Number(number(&word, location)?)
                }
                TokenKind::Word(word) if self.at('(') => self.function(&word, location)?,
                TokenKind::Word(word) => match word.as_str() {
                    "." => ExprKind::Dot,
                    "SIZEOF_HEADERS" => ExprKind::SizeofHeaders,
                    _ => ExprKind::Symbol(word),
                },
                _ => bail!("{location}: expected expression, found {:?}", token.kind),
            }
        };
        Ok(Expr { kind, location })
    }

    fn function(&mut self, name: &str, location: Location) -> Result<ExprKind> {
        let function = match name {
            "ALIGN" => Function::Align,
            "CONSTANT" => Function::Constant,
            "SEGMENT_START" => Function::SegmentStart,
            "ALIGNOF" => Function::AlignOf,
            "DATA_SEGMENT_ALIGN" => Function::DataSegmentAlign,
            "DATA_SEGMENT_RELRO_END" => Function::DataSegmentRelroEnd,
            "DATA_SEGMENT_END" => Function::DataSegmentEnd,
            _ => bail!("{location}: unsupported linker script function {name}"),
        };
        self.expect('(')?;
        let mut args = Vec::new();
        if !self.at(')') {
            loop {
                if function == Function::SegmentStart && args.is_empty() {
                    let token = self.token().clone();
                    let TokenKind::String(value) = token.kind else {
                        bail!(
                            "{}: SEGMENT_START expects a quoted segment name",
                            token.location
                        );
                    };
                    self.index += 1;
                    args.push(Expr {
                        kind: ExprKind::String(value),
                        location: token.location,
                    });
                } else {
                    args.push(self.expression(0)?);
                }
                if !self.take(',') {
                    break;
                }
            }
        }
        self.expect(')')?;
        let valid_count = match function {
            Function::Align => (1..=2).contains(&args.len()),
            Function::Constant | Function::AlignOf | Function::DataSegmentEnd => args.len() == 1,
            _ => args.len() == 2,
        };
        ensure!(
            valid_count,
            "{location}: invalid number of arguments to {name}"
        );
        if function == Function::Constant {
            ensure!(
                matches!(&args[0].kind, ExprKind::Symbol(name) if name == "MAXPAGESIZE" || name == "COMMONPAGESIZE"),
                "{location}: CONSTANT expects MAXPAGESIZE or COMMONPAGESIZE"
            );
        }
        if function == Function::AlignOf {
            ensure!(
                matches!(&args[0].kind, ExprKind::Symbol(name) if name == "NEXT_SECTION"),
                "{location}: ALIGNOF only supports NEXT_SECTION"
            );
        }
        Ok(ExprKind::Call(function, args))
    }
}

fn number(text: &str, location: Location) -> Result<u64> {
    let (digits, multiplier) = match text.as_bytes().last() {
        Some(b'k' | b'K') => (&text[..text.len() - 1], 1024),
        Some(b'm' | b'M') => (&text[..text.len() - 1], 1024 * 1024),
        _ => (text, 1),
    };
    let value = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else if digits.len() > 1 && digits.starts_with('0') {
        // GNU ld reads a leading zero as octal.
        u64::from_str_radix(&digits[1..], 8)
    } else {
        digits.parse::<u64>()
    };
    let value =
        value.map_err(|err| anyhow::anyhow!("{location}: invalid number {text:?}: {err}"))?;
    value
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow::anyhow!("{location}: number {text:?} exceeds u64"))
}

#[cfg(test)]
mod tests {
    //! Check the accepted GNU script subset and errors for unsupported commands.

    use super::*;

    fn output(source: &str) -> OutputSectionRule {
        let script = parse(&format!("SECTIONS {{ {source} }}")).unwrap();
        let Statement::Sections(statements) = &script.statements[0] else {
            panic!("expected SECTIONS")
        };
        let SectionStatement::Output(section) = &statements[0] else {
            panic!("expected output section")
        };
        section.clone()
    }

    #[test]
    fn parses_builtin_and_gnu_static_scripts() {
        let builtin = parse(crate::script::DEFAULT_SCRIPT).unwrap();
        let gnu = parse(include_str!("../../tests/fixtures/gnu_ld_static.ld")).unwrap();
        for script in [builtin, gnu] {
            assert_eq!(script.entry_name(), "_start");
        }
    }

    #[test]
    fn entries_assignments_and_output_sections() {
        let script = parse(
            r#"
            OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
            OUTPUT_ARCH(i386:x86-64)
            ENTRY(first) ENTRY(boot);
            base = 0x600000;
            SECTIONS {
                . = SEGMENT_START("text-segment", base) + SIZEOF_HEADERS;
                PROVIDE(a = .);
                PROVIDE_HIDDEN(b = ALIGN(8));
                .text 0x601000 : ONLY_IF_RO {
                    begin = .;
                    *(.text .text.*)
                    PROVIDE(end = .);
                }
                .data : ONLY_IF_RW { *(.data) }
            }
        "#,
        )
        .unwrap();
        assert_eq!(script.entry_name(), "boot");
        let Statement::Assignment(base) = &script.statements[4] else {
            panic!("expected base assignment")
        };
        assert_eq!(base.kind, AssignmentKind::Define);
        let Statement::Sections(statements) = &script.statements[5] else {
            panic!("expected SECTIONS")
        };
        let SectionStatement::Assignment(provide) = &statements[1] else {
            panic!("expected PROVIDE")
        };
        assert_eq!(provide.kind, AssignmentKind::Provide);
        let SectionStatement::Assignment(hidden) = &statements[2] else {
            panic!("expected PROVIDE_HIDDEN")
        };
        assert_eq!(hidden.kind, AssignmentKind::ProvideHidden);
        let SectionStatement::Output(section) = &statements[3] else {
            panic!("expected output section")
        };
        assert_eq!(section.name, ".text");
        assert_eq!(
            section.address.as_ref().unwrap().kind,
            ExprKind::Number(0x601000)
        );
        assert_eq!(section.constraint, Some(SectionConstraint::ReadOnly));
        assert_eq!(section.statements.len(), 3);
        let SectionStatement::Output(section) = &statements[4] else {
            panic!("expected output section")
        };
        assert_eq!(section.constraint, Some(SectionConstraint::ReadWrite));
    }

    #[test]
    fn patterns_wrappers_and_exclusions_preserve_scope() {
        let section = output(
            r#".ctors : {
            KEEP(*crtbegin?.o(.ctors))
            KEEP(*(EXCLUDE_FILE(*crtend.o *crtend?.o) .ctors))
            *(.init_array SORT_BY_INIT_PRIORITY(.init_array.*)
              SORT_BY_NAME(SORT_NONE(.text.[a-z]?)) COMMON)
            SORT(*crt*.o(.text))
            EXCLUDE_FILE(foo.o) *(.data)
            "/path with spaces/foo.o"(.rodata)
        }"#,
        );
        assert_eq!(
            section.statements[0],
            OutputStatement::Input(InputSectionRule::Keep(Box::new(InputSectionRule::File {
                pattern: "*crtbegin?.o".into(),
                sections: vec![SectionPattern::Glob(".ctors".into())]
            })))
        );
        assert_eq!(
            section.statements[1],
            OutputStatement::Input(InputSectionRule::Keep(Box::new(InputSectionRule::File {
                pattern: "*".into(),
                sections: vec![
                    SectionPattern::ExcludeFile(vec!["*crtend.o".into(), "*crtend?.o".into()]),
                    SectionPattern::Glob(".ctors".into()),
                ]
            })))
        );
        assert_eq!(
            section.statements[2],
            OutputStatement::Input(InputSectionRule::File {
                pattern: "*".into(),
                sections: vec![
                    SectionPattern::Glob(".init_array".into()),
                    SectionPattern::Sort(
                        SortKind::InitPriority,
                        vec![SectionPattern::Glob(".init_array.*".into())]
                    ),
                    SectionPattern::Sort(
                        SortKind::Name,
                        vec![SectionPattern::Sort(
                            SortKind::None,
                            vec![SectionPattern::Glob(".text.[a-z]?".into())]
                        ),]
                    ),
                    SectionPattern::Common,
                ],
            })
        );
        assert_eq!(
            section.statements[3],
            OutputStatement::Input(InputSectionRule::Sort(
                SortKind::Name,
                Box::new(InputSectionRule::File {
                    pattern: "*crt*.o".into(),
                    sections: vec![SectionPattern::Glob(".text".into())]
                })
            ))
        );
        assert!(
            matches!(&section.statements[4], OutputStatement::Input(InputSectionRule::ExcludeFile(files, _)) if files == &["foo.o"])
        );
        assert!(
            matches!(&section.statements[5], OutputStatement::Input(InputSectionRule::File { pattern, .. }) if pattern == "/path with spaces/foo.o")
        );
    }

    #[test]
    fn ignored_constructs_and_discard() {
        let section =
            output(".comment 0 (INFO) : { *(.comment); LINKER_VERSION; SORT(CONSTRUCTORS) }");
        assert!(section.info);
        assert_eq!(section.address.unwrap().kind, ExprKind::Number(0));
        assert_eq!(
            section.statements[1],
            OutputStatement::Ignored(IgnoredCommand::LinkerVersion)
        );
        assert_eq!(
            section.statements[2],
            OutputStatement::Ignored(IgnoredCommand::Constructors)
        );
        let section = output("/DISCARD/ : { *(.note.GNU-stack) }");
        assert_eq!(section.name, "/DISCARD/");
        let section = output(".debug_info 0 : { *(.debug_info .gnu.linkonce.wi.*) }");
        assert_eq!(section.address.unwrap().kind, ExprKind::Number(0));
        parse("OUTPUT_FORMAT(elf64-x86-64) OUTPUT_ARCH(\"i386:x86-64\")").unwrap();
    }

    #[test]
    fn unsupported_commands_report_their_locations() {
        for command in [
            "MEMORY",
            "PHDRS",
            "OVERLAY",
            "AT",
            "INCLUDE",
            "INPUT",
            "GROUP",
            "AS_NEEDED",
            "ASSERT",
        ] {
            let error = parse(&format!("/* comment */\n  {command}(x)"))
                .unwrap_err()
                .to_string();
            assert!(
                error.starts_with("2:3: unsupported linker script command"),
                "{error}"
            );
            assert!(error.contains(command), "{error}");
        }
        for (source, message) in [
            ("SECTIONS { .text : AT(0) { *(.text) } }", "command AT"),
            (
                "SECTIONS { .text : { *(.text) } >ram }",
                "region assignment",
            ),
            ("SECTIONS { OVERLAY 0 : {} }", "command OVERLAY"),
            ("SECTIONS { .text : { ASSERT(0, bad) } }", "command ASSERT"),
            ("OUTPUT_ARCH(aarch64)", "unsupported OUTPUT_ARCH"),
            ("OUTPUT_FORMAT(elf32-i386)", "unsupported OUTPUT_FORMAT"),
        ] {
            let error = parse(source).unwrap_err().to_string();
            assert!(error.contains(message), "{source}: {error}");
        }
    }

    #[test]
    fn invalid_syntax_and_functions_are_errors() {
        for source in [
            "ENTRY(foo",
            "SECTIONS {",
            "SECTIONS { .text : { *(.text) }",
            "SECTIONS { .text : { *(.text[ab) } }",
            "foo = 1",
            "PROVIDE(. = 0);",
        ] {
            let error = parse(source).unwrap_err().to_string();
            assert!(error.contains(':'), "{source}: {error}");
        }
        for source in [
            "ALIGN()",
            "ALIGN(1,2,3)",
            "CONSTANT(OTHER)",
            "ALIGNOF(.text)",
            "SEGMENT_START(text, 0)",
            "SEGMENT_START(\"text\")",
            "UNKNOWN(1)",
            "DATA_SEGMENT_ALIGN(1)",
            "DATA_SEGMENT_RELRO_END(1)",
            "DATA_SEGMENT_END(1,2)",
            "1 << 2",
            "1 && 2",
            "1 || 2",
            "1 % 2",
            "\"text\"",
        ] {
            let error = parse_expression(source).unwrap_err().to_string();
            assert!(error.contains(':'), "{source}: {error}");
        }
    }
}
