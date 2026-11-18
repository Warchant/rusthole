//! The registrable domain (eTLD+1) of a name (docs/API.md section 1.5).
//!
//! The Public Suffix List is in the `psl` crate (compiled into the code, no file at run
//! time). The store keeps full names. The grouping happens at query time.

/// The registrable domain of `name`: one label below the public suffix.
///
/// A name with no registrable domain is its own base: a single label, a public suffix (for
/// example `co.uk`), the root name, and each name in the `arpa` zone (reverse zones).
pub fn registrable(name: &str) -> &str {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() {
        return name;
    }
    // Names are lowercase here, so a case-sensitive test is correct.
    #[allow(clippy::case_sensitive_file_extension_comparisons)] // A DNS label, not a file.
    let in_arpa = trimmed == "arpa" || trimmed.ends_with(".arpa");
    if in_arpa {
        return trimmed;
    }
    psl::domain_str(trimmed).unwrap_or(trimmed)
}

#[cfg(test)]
mod tests {
    use super::registrable;

    #[test]
    fn known_suffixes() {
        assert_eq!(registrable("cdn.example.co.uk"), "example.co.uk");
        assert_eq!(registrable("www.example.com"), "example.com");
        assert_eq!(registrable("example.com"), "example.com");
        assert_eq!(registrable("a.b.c.example.net"), "example.net");
    }

    #[test]
    fn names_without_a_registrable_domain_are_their_own_base() {
        assert_eq!(registrable("co.uk"), "co.uk");
        assert_eq!(registrable("com"), "com");
        assert_eq!(registrable("localhost"), "localhost");
        assert_eq!(registrable("."), ".");
        assert_eq!(registrable(""), "");
        assert_eq!(
            registrable("10.2.0.192.in-addr.arpa"),
            "10.2.0.192.in-addr.arpa"
        );
        assert_eq!(registrable("arpa"), "arpa");
    }

    #[test]
    fn unknown_suffix_uses_the_default_rule() {
        // The PSL default rule "*": an unknown TLD is a public suffix.
        assert_eq!(registrable("printer.home.lan"), "home.lan");
        assert_eq!(registrable("example.lan"), "example.lan");
    }

    #[test]
    fn trailing_dot_is_removed() {
        assert_eq!(registrable("www.example.com."), "example.com");
    }
}
