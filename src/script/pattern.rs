//! Match a script's file or section pattern against a name.
//!
//! [`matches()`] takes a glob and a name and returns whether they match.
//! A glob is a name pattern: `*` matches any run of characters, `?` matches one,
//! and brackets select a character class. [`super::mapping`] uses these GNU ld
//! patterns to pick input sections; this code does not search the filesystem.
//!
//! References: [GNU ld input wildcards](https://sourceware.org/binutils/docs/ld/Input-Section-Wildcards.html);
//! ELF gABI "Sections".

pub(crate) fn matches(pattern: &str, name: &str) -> bool {
    let pattern = pattern.as_bytes();
    let name = name.as_bytes();
    let (mut p, mut n) = (0, 0);
    let mut star = None;
    while n < name.len() {
        if pattern.get(p) == Some(&b'*') {
            star = Some((p + 1, n));
            p += 1;
            continue;
        }
        if let Some(length) = component(&pattern[p..], name[n]) {
            p += length;
            n += 1;
        } else if let Some((after_star, consumed)) = star {
            n = consumed + 1;
            p = after_star;
            star = Some((after_star, n));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|byte| *byte == b'*')
}

fn component(pattern: &[u8], byte: u8) -> Option<usize> {
    match pattern.first()? {
        b'?' => Some(1),
        b'[' => {
            let negated = matches!(pattern.get(1), Some(b'!' | b'^'));
            let mut index = if negated { 2 } else { 1 };
            let start = index;
            let mut found = false;
            // A closing bracket at the start of a class is a literal bracket.
            if pattern.get(index) == Some(&b']') {
                found = byte == b']';
                index += 1;
            }
            while let Some(&first) = pattern.get(index) {
                if first == b']' {
                    return (index > start && found != negated).then_some(index + 1);
                }
                if pattern.get(index + 1) == Some(&b'-')
                    && let Some(&last) = pattern.get(index + 2)
                    && last != b']'
                {
                    found |= (first..=last).contains(&byte);
                    index += 3;
                } else {
                    found |= first == byte;
                    index += 1;
                }
            }
            (byte == b'[').then_some(1)
        }
        literal => (*literal == byte).then_some(1),
    }
}

#[cfg(test)]
mod tests {
    //! Check wildcard matches, including bracket classes and literal brackets.

    use super::matches;

    #[test]
    fn section_and_file_globs() {
        for (pattern, name, expected) in [
            (".text.*", ".text.hot", true),
            (".text.*", ".text", false),
            ("*crtbegin?.o", "crtbeginT.o", true),
            ("*crtbegin?.o", "crtbegin.o", false),
            (".init_array.[0-9]*", ".init_array.00100", true),
            ("[!a-c]?", "d0", true),
            ("[^a-c]?", "b0", false),
            ("[]a]", "]", true),
            ("[abc", "[abc", true),
            ("*ab*cd", "aabababcd", true),
            ("*ab*cd", "aabababc", false),
            ("*", "", true),
            ("?", "", false),
        ] {
            assert_eq!(matches(pattern, name), expected, "{pattern} vs {name}");
        }
    }
}
