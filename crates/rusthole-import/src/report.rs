//! The import report: one line for each item.

use std::fmt;

/// What the import did with each item. Each entry is one line of text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// Items that are now in the rusthole config.
    pub translated: Vec<String>,
    /// Items that rusthole does not need. No action is necessary.
    pub ignored: Vec<String>,
    /// Items that need your attention: rusthole cannot translate them, or it changed them.
    pub reported: Vec<String>,
}

/// Replaces each control character of `line` with its escape (`\u{1b}`, `\n`, ...).
///
/// A report line can hold text from the export (a zip entry name, a TOML key). The report
/// goes to a terminal, so a raw control character could hide or fake output.
fn clean(line: impl Into<String>) -> String {
    let line = line.into();
    if !line.chars().any(char::is_control) {
        return line;
    }
    let mut out = String::with_capacity(line.len() + 8);
    for c in line.chars() {
        if c.is_control() {
            out.extend(c.escape_debug());
        } else {
            out.push(c);
        }
    }
    out
}

impl ImportReport {
    /// Adds a translated item. Control characters are escaped.
    pub fn translate(&mut self, line: impl Into<String>) {
        self.translated.push(clean(line));
    }

    /// Adds an ignored item. Control characters are escaped.
    pub fn ignore(&mut self, line: impl Into<String>) {
        self.ignored.push(clean(line));
    }

    /// Adds an item that needs attention. Control characters are escaped.
    pub fn report(&mut self, line: impl Into<String>) {
        self.reported.push(clean(line));
    }

    /// All lines of all three sections.
    pub fn all_lines(&self) -> impl Iterator<Item = &str> {
        self.translated
            .iter()
            .chain(&self.ignored)
            .chain(&self.reported)
            .map(String::as_str)
    }
}

impl fmt::Display for ImportReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sections = [
            ("Translated", &self.translated),
            ("Ignored (no action needed)", &self.ignored),
            ("Needs your attention", &self.reported),
        ];
        for (title, lines) in sections {
            writeln!(f, "{title} ({}):", lines.len())?;
            for line in lines {
                writeln!(f, "  - {line}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_are_escaped() {
        let mut r = ImportReport::default();
        r.translate("a\u{1b}[2Jb");
        r.ignore("zip entry x\ny: not used");
        r.report("tab\there\u{7f}");
        assert_eq!(r.translated, [r"a\u{1b}[2Jb"]);
        assert_eq!(r.ignored, [r"zip entry x\ny: not used"]);
        assert_eq!(r.reported, [r"tab\there\u{7f}"]);
        assert!(!r.to_string().chars().any(|c| c.is_control() && c != '\n'));
    }
}
