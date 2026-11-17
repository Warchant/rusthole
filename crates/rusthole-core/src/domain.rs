//! Normalized DNS domain names.
//!
//! A [`DomainName`] is lowercase ASCII, has no trailing dot, and obeys the DNS length limits.
//! Blocklists in the wild contain underscores, so `_` is a valid label character.

use std::fmt;

/// Maximum length of a domain name in text form, without the trailing dot (RFC 1035).
pub const MAX_NAME_LEN: usize = 253;
/// Maximum length of one label (RFC 1035).
pub const MAX_LABEL_LEN: usize = 63;

/// Why a string is not a valid domain name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    #[error("domain name is empty")]
    Empty,
    #[error("domain name is longer than {MAX_NAME_LEN} characters")]
    TooLong,
    #[error("label {index} is empty")]
    EmptyLabel { index: usize },
    #[error("label {index} is longer than {MAX_LABEL_LEN} characters")]
    LabelTooLong { index: usize },
    #[error("character {ch:?} is not valid in a domain name")]
    BadChar { ch: char },
}

/// A normalized domain name. See the module documentation for the rules.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainName(Box<str>);

impl DomainName {
    /// Parses and normalizes `input`.
    ///
    /// The function removes one trailing dot and changes ASCII letters to lowercase.
    /// The root name (`.` or an empty string) is not a valid `DomainName`.
    pub fn parse(input: &str) -> Result<Self, DomainError> {
        let trimmed = input.strip_suffix('.').unwrap_or(input);
        if trimmed.is_empty() {
            return Err(DomainError::Empty);
        }
        if trimmed.len() > MAX_NAME_LEN {
            return Err(DomainError::TooLong);
        }
        for (index, label) in trimmed.split('.').enumerate() {
            if label.is_empty() {
                return Err(DomainError::EmptyLabel { index });
            }
            if label.len() > MAX_LABEL_LEN {
                return Err(DomainError::LabelTooLong { index });
            }
            if let Some(ch) = label.chars().find(|c| !is_label_char(*c)) {
                return Err(DomainError::BadChar { ch });
            }
        }
        Ok(Self(trimmed.to_ascii_lowercase().into_boxed_str()))
    }

    /// The name as text, lowercase, without a trailing dot.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The labels from the most specific to the least specific (`a.b.c` gives `a`, `b`, `c`).
    pub fn labels(&self) -> impl DoubleEndedIterator<Item = &str> {
        self.0.split('.')
    }

    /// The name and each parent name, from the most specific to the top-level label.
    /// For `a.b.c` this gives `a.b.c`, `b.c`, `c`.
    pub fn self_and_parents(&self) -> impl Iterator<Item = &str> {
        let s: &str = &self.0;
        std::iter::once(s).chain(
            s.match_indices('.')
                .filter_map(move |(i, _)| s.get(i + 1..)),
        )
    }

    /// True when `self` is `other` or a subdomain of `other`.
    pub fn is_same_or_subdomain_of(&self, other: &DomainName) -> bool {
        self.self_and_parents().any(|p| p == other.as_str())
    }
}

fn is_label_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DomainName({:?})", &*self.0)
    }
}

impl std::str::FromStr for DomainName {
    type Err = DomainError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn normalizes_case_and_trailing_dot() {
        let d = DomainName::parse("Ads.Example.COM.").unwrap();
        assert_eq!(d.as_str(), "ads.example.com");
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(DomainName::parse(""), Err(DomainError::Empty));
        assert_eq!(DomainName::parse("."), Err(DomainError::Empty));
        assert_eq!(
            DomainName::parse("a..b"),
            Err(DomainError::EmptyLabel { index: 1 })
        );
        assert_eq!(
            DomainName::parse("a b"),
            Err(DomainError::BadChar { ch: ' ' })
        );
        assert!(matches!(
            DomainName::parse(&"a".repeat(64)),
            Err(DomainError::LabelTooLong { index: 0 })
        ));
    }

    #[test]
    fn accepts_underscore_and_digits() {
        assert!(DomainName::parse("_dmarc.0-1.example").is_ok());
    }

    #[test]
    fn parents() {
        let d = DomainName::parse("a.b.c").unwrap();
        let v: Vec<_> = d.self_and_parents().collect();
        assert_eq!(v, ["a.b.c", "b.c", "c"]);
        let parent = DomainName::parse("b.c").unwrap();
        assert!(d.is_same_or_subdomain_of(&parent));
        assert!(!parent.is_same_or_subdomain_of(&d));
        let lookalike = DomainName::parse("xb.c").unwrap();
        assert!(!lookalike.is_same_or_subdomain_of(&parent));
    }

    fn label() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9_-]{1,63}"
    }

    fn name() -> impl Strategy<Value = String> {
        prop::collection::vec(label(), 1..6)
            .prop_map(|v| v.join("."))
            .prop_filter("length limit", |s| s.len() <= MAX_NAME_LEN)
    }

    proptest! {
        #[test]
        fn valid_names_parse(s in name()) {
            prop_assert!(DomainName::parse(&s).is_ok());
        }

        #[test]
        fn parse_is_idempotent(s in name()) {
            let a = DomainName::parse(&s).unwrap();
            let b = DomainName::parse(a.as_str()).unwrap();
            prop_assert_eq!(a, b);
        }

        #[test]
        fn case_and_trailing_dot_do_not_matter(s in name()) {
            let lower = DomainName::parse(&s.to_ascii_lowercase()).unwrap();
            let upper_dot = DomainName::parse(&format!("{}.", s.to_ascii_uppercase())).unwrap();
            prop_assert_eq!(lower, upper_dot);
        }

        #[test]
        fn output_obeys_limits(s in ".{0,300}") {
            if let Ok(d) = DomainName::parse(&s) {
                prop_assert!(d.as_str().len() <= MAX_NAME_LEN);
                prop_assert!(d.labels().all(|l| !l.is_empty() && l.len() <= MAX_LABEL_LEN));
                prop_assert!(d.as_str().chars().all(|c| is_label_char(c) && !c.is_ascii_uppercase()));
            }
        }

        #[test]
        fn self_and_parents_ends_with_tld(s in name()) {
            let d = DomainName::parse(&s).unwrap();
            let parents: Vec<_> = d.self_and_parents().collect();
            prop_assert_eq!(parents.len(), d.labels().count());
            prop_assert_eq!(parents[0], d.as_str());
            prop_assert_eq!(*parents.last().unwrap(), d.labels().last().unwrap());
        }
    }
}
