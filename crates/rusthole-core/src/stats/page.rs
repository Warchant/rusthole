//! Keyset pages for long collections (docs/API.md section 1.2).
//!
//! Each item has a [`SortKey`]. The keys are unique (the `tie` field is a unique id) and
//! give a total order. The cursor is the encoded key of the last item of a page; the next
//! page holds the items after it. So an item never shows on two pages, and an item is never
//! lost, also when other items are added between two requests.
//!
//! The cursor comes from the network. [`decode`] checks it and returns an error; it never
//! panics.

/// The largest page size.
pub const MAX_LIMIT: usize = 500;
/// The longest cursor that [`decode`] accepts, in bytes.
pub const MAX_CURSOR_LEN: usize = 2048;

const PREFIX: &str = "c1";

/// The sort key of one item. Items sort by `num`, then `text`, then `tie`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SortKey {
    /// A number (negate it for "high to low").
    pub num: i64,
    /// A text (for "by name" orders).
    pub text: String,
    /// A unique id of the item.
    pub tie: String,
}

/// One page of a collection.
#[derive(Debug, Clone, PartialEq)]
pub struct Page<T> {
    /// The items of the page.
    pub items: Vec<T>,
    /// The cursor of the next page, or `None` on the last page.
    pub next_cursor: Option<String>,
}

/// A cursor that is not valid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the cursor is not valid")]
pub struct CursorError;

/// Encodes a sort key as an opaque cursor.
pub fn encode(key: &SortKey) -> String {
    format!(
        "{PREFIX}.{}.{}.{}",
        key.num,
        hex(key.text.as_bytes()),
        hex(key.tie.as_bytes())
    )
}

/// Decodes a cursor from [`encode`].
pub fn decode(cursor: &str) -> Result<SortKey, CursorError> {
    if cursor.len() > MAX_CURSOR_LEN {
        return Err(CursorError);
    }
    let mut parts = cursor.split('.');
    let (Some(PREFIX), Some(num), Some(text), Some(tie), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Err(CursorError);
    };
    Ok(SortKey {
        num: num.parse().map_err(|_| CursorError)?,
        text: unhex(text)?,
        tie: unhex(tie)?,
    })
}

/// Sorts `items` by key and returns the page after `cursor` with at most `limit` items.
/// `limit` is clamped to `1..=MAX_LIMIT`.
pub fn paginate<T>(
    mut items: Vec<(SortKey, T)>,
    cursor: Option<&str>,
    limit: usize,
) -> Result<Page<T>, CursorError> {
    let after = cursor.map(decode).transpose()?;
    let limit = limit.clamp(1, MAX_LIMIT);
    items.sort_by(|a, b| a.0.cmp(&b.0));
    let mut rest = items
        .into_iter()
        .filter(|(k, _)| after.as_ref().is_none_or(|a| k > a));
    let mut page = Vec::with_capacity(limit.min(64));
    let mut last: Option<SortKey> = None;
    for (k, item) in rest.by_ref().take(limit) {
        page.push(item);
        last = Some(k);
    }
    let next_cursor = match (rest.next(), last) {
        (Some(_), Some(last)) => Some(encode(&last)),
        _ => None,
    };
    Ok(Page {
        items: page,
        next_cursor,
    })
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(
            DIGITS.get(usize::from(b >> 4)).copied().unwrap_or(b'0'),
        ));
        s.push(char::from(
            DIGITS.get(usize::from(b & 0x0f)).copied().unwrap_or(b'0'),
        ));
    }
    s
}

fn unhex(s: &str) -> Result<String, CursorError> {
    fn digit(c: u8) -> Result<u8, CursorError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(CursorError),
        }
    }
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(CursorError);
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for [hi, lo] in bytes.as_chunks::<2>().0 {
        out.push((digit(*hi)? << 4) | digit(*lo)?);
    }
    String::from_utf8(out).map_err(|_| CursorError)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(num: i64, text: &str, tie: &str) -> SortKey {
        SortKey {
            num,
            text: text.to_owned(),
            tie: tie.to_owned(),
        }
    }

    #[test]
    fn cursor_round_trip() {
        let k = key(-42, "name.example", "02:00:00:00:00:01");
        assert_eq!(decode(&encode(&k)), Ok(k));
        let k = key(i64::MIN, "", "");
        assert_eq!(decode(&encode(&k)), Ok(k));
    }

    #[test]
    fn bad_cursors_are_errors() {
        for bad in [
            "", "c1", "c1.1.2", "c2.1..", "c1.x..", "c1.1.0..", "c1.1.zz.", "c1.1...", "c1.1.ff.",
        ] {
            assert_eq!(decode(bad), Err(CursorError), "{bad:?}");
        }
        assert_eq!(decode(&"a".repeat(MAX_CURSOR_LEN + 1)), Err(CursorError));
    }

    #[test]
    fn pages_cover_all_items_once() {
        let items: Vec<(SortKey, u32)> = (0..23u32)
            .map(|i| (key(-i64::from(i % 5), "", &format!("{i:03}")), i))
            .collect();
        let mut seen = Vec::new();
        let mut cursor = None;
        for _ in 0..30 {
            let page = paginate(items.clone(), cursor.as_deref(), 4).unwrap();
            seen.extend(page.items);
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        seen.sort_unstable();
        assert_eq!(seen, (0..23).collect::<Vec<_>>());
    }
}
