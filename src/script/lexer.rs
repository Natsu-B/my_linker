//! Split script text into tokens for the parser.
//!
//! [`lex`] returns [`Token`] records with a [`TokenKind`], [`Location`], and
//! byte range. It handles comments and quoted strings but leaves names and
//! numbers for the parser to interpret.
//!
//! The byte ranges let the parser tell adjacent filename or glob pieces from
//! separate expression tokens. A `*` can mean a wildcard or multiplication;
//! the GNU ld script rule around it decides which.
//!
//! Reference: [GNU ld script format](https://sourceware.org/binutils/docs/ld/Script-Format.html)
//! and expressions. [`super::mapping`] later gives section names their ELF meaning.

use anyhow::{Result, bail};

use super::ast::Location;

/// Keep words unsplit until the parser knows whether they name a file or an expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum TokenKind {
    Word(String),
    String(String),
    Punct(char),
    Equal,
    NotEqual,
    LessEqual,
    GreaterEqual,
    Eof,
}

/// Keep line and column for errors and byte offsets for pattern joins.
#[derive(Clone, Debug)]
pub(super) struct Token {
    pub(crate) kind: TokenKind,
    pub(crate) location: Location,
    /// First byte in the source; adjacent spans can form one filename or glob.
    pub(crate) start: usize,
    /// First byte after the token.
    pub(crate) end: usize,
}

/// Read comments, strings, and tokens, then add an EOF token with the final position.
pub(super) fn lex(source: &str) -> Result<Vec<Token>> {
    let mut lexer = Lexer {
        source,
        offset: 0,
        line: 1,
        column: 1,
    };
    let mut tokens = Vec::new();
    while let Some(ch) = lexer.peek() {
        if ch.is_whitespace() {
            lexer.bump();
            continue;
        }
        let start = lexer.offset;
        let location = lexer.location();
        if lexer.rest().starts_with("/*") {
            lexer.bump();
            lexer.bump();
            while !lexer.rest().starts_with("*/") {
                if lexer.bump().is_none() {
                    bail!("{location}: unterminated comment");
                }
            }
            lexer.bump();
            lexer.bump();
            continue;
        }
        let kind = if ch == '"' {
            lexer.bump();
            let mut value = String::new();
            loop {
                match lexer.bump() {
                    Some('"') => break,
                    Some('\\') => match lexer.bump() {
                        Some(ch) => value.push(ch),
                        None => bail!("{location}: unterminated string"),
                    },
                    Some(ch) => value.push(ch),
                    None => bail!("{location}: unterminated string"),
                }
            }
            TokenKind::String(value)
        } else if ch.is_ascii_alphanumeric() || "_.$".contains(ch) {
            while lexer
                .peek()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || "_.$".contains(ch))
            {
                lexer.bump();
            }
            TokenKind::Word(source[start..lexer.offset].to_string())
        } else {
            lexer.bump();
            match (ch, lexer.peek()) {
                ('=', Some('=')) => {
                    lexer.bump();
                    TokenKind::Equal
                }
                ('!', Some('=')) => {
                    lexer.bump();
                    TokenKind::NotEqual
                }
                ('<', Some('=')) => {
                    lexer.bump();
                    TokenKind::LessEqual
                }
                ('>', Some('=')) => {
                    lexer.bump();
                    TokenKind::GreaterEqual
                }
                _ if "{}():;,=+-*/&|~!<>?[]^".contains(ch) => TokenKind::Punct(ch),
                _ => bail!("{location}: unexpected character {ch:?}"),
            }
        };
        tokens.push(Token {
            kind,
            location,
            start,
            end: lexer.offset,
        });
    }
    tokens.push(Token {
        kind: TokenKind::Eof,
        location: lexer.location(),
        start: source.len(),
        end: source.len(),
    });
    Ok(tokens)
}

struct Lexer<'a> {
    source: &'a str,
    offset: usize,
    line: usize,
    column: usize,
}

impl Lexer<'_> {
    fn rest(&self) -> &str {
        &self.source[self.offset..]
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.offset += ch.len_utf8();
        if ch == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(ch)
    }

    fn location(&self) -> Location {
        Location {
            line: self.line,
            column: self.column,
        }
    }
}

#[cfg(test)]
mod tests {
    //! Check where tokens start and end around comments and strings.

    use super::*;

    #[test]
    fn comments_strings_and_locations() {
        let tokens = lex("/* x\ny */\n  SEGMENT_START(\"text-segment\", 0x400000)").unwrap();
        assert_eq!(tokens[0].location, Location { line: 3, column: 3 });
        assert_eq!(tokens[2].kind, TokenKind::String("text-segment".into()));
        assert_eq!(
            lex("\n /*").unwrap_err().to_string(),
            "2:2: unterminated comment"
        );
        assert_eq!(
            lex("\n \"").unwrap_err().to_string(),
            "2:2: unterminated string"
        );
        assert!(lex("\n @").unwrap_err().to_string().starts_with("2:2:"));
    }
}
