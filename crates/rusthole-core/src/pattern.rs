//! Regex rules.
//!
//! rusthole uses the `regex` crate. Its match time is linear in the input, so a bad pattern
//! cannot cause a `ReDoS`. Each match is case-insensitive (decision D4). A size limit stops
//! a pattern that compiles to a very large program (amendment A8).

use regex::{Regex, RegexBuilder};

/// Maximum length of a regex pattern in characters of text.
pub const MAX_PATTERN_LEN: usize = 1024;
/// Maximum size of one compiled regex program, in bytes.
pub const REGEX_SIZE_LIMIT: usize = 256 * 1024;
/// Maximum size of the lazy DFA cache of one regex, in bytes.
pub const REGEX_DFA_SIZE_LIMIT: usize = 256 * 1024;

/// Why a regex rule cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PatternError {
    #[error("the pattern is empty")]
    Empty,
    #[error("the pattern is longer than {MAX_PATTERN_LEN} characters")]
    TooLong,
    #[error("the pattern does not compile: {0}")]
    Compile(String),
}

/// Compiles a rule pattern: case-insensitive, with the size limits above.
pub fn compile_rule_regex(pattern: &str) -> Result<Regex, PatternError> {
    if pattern.is_empty() {
        return Err(PatternError::Empty);
    }
    if pattern.len() > MAX_PATTERN_LEN {
        return Err(PatternError::TooLong);
    }
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
        .build()
        .map_err(|e| PatternError::Compile(first_line(&e.to_string())))
}

/// The regex crate gives multi-line errors with a caret diagram. Keep the last useful line.
fn first_line(text: &str) -> String {
    text.lines()
        .rev()
        .find(|l| l.trim_start().starts_with("error:"))
        .or_else(|| text.lines().next())
        .unwrap_or_default()
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn pihole_style_patterns_compile() {
        let r = compile_rule_regex(r"(\.|^)example\.com$").unwrap();
        assert!(r.is_match("ads.EXAMPLE.com"));
        assert!(r.is_match("example.com"));
        assert!(!r.is_match("notexample.com"));
        let r = compile_rule_regex(r"ads\d+\.example").unwrap();
        assert!(r.is_match("ADS12.example.net"));
    }

    #[test]
    fn rejects_bad_patterns() {
        assert_eq!(compile_rule_regex("").err(), Some(PatternError::Empty));
        assert_eq!(
            compile_rule_regex(&"a".repeat(MAX_PATTERN_LEN + 1)).err(),
            Some(PatternError::TooLong)
        );
        assert!(matches!(
            compile_rule_regex("(unclosed"),
            Err(PatternError::Compile(_))
        ));
        // Look-around is not in the regex crate.
        assert!(compile_rule_regex("(?!ads)example").is_err());
        // A huge counted repeat goes over the size limit.
        assert!(compile_rule_regex(r"\w{1000}\w{1000}\w{1000}").is_err());
    }

    proptest! {
        #[test]
        fn never_panics(s in "\\PC{0,64}") {
            let _ = compile_rule_regex(&s);
        }
    }
}
