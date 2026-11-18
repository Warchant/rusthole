//! Compact set of domain names. Each name has a set of list elements.
//!
//! Layout (see docs/POLICY.md):
//!
//! - The names are in byte buffers. A name is one length byte and the name bytes. A buffer is
//!   the entry buffer of a [`ParsedList`](crate::lists::ParsedList) that the set takes over (no
//!   copy), or a chunk of [`CHUNK_BYTES`] for names that the set copies. A name has one
//!   logical 32-bit offset over all buffers.
//! - Each unique name has one [`Slot`]: its offset and its element set (8 bytes).
//! - An open-addressing hash table maps a name to its slot. A table entry is 4 bytes: 24 bits
//!   of slot index and 8 bits of the hash, so most probes do not read the name.
//! - The hash is SipHash-1-3 with a secret key for each set ([`HashKey`]). List text comes
//!   from the network, so a list author must not know the hash. Else the author can make
//!   names that fill one part of the table (hash flooding).
//! - An insert probes at most [`MAX_PROBE`] entries. When a name needs more, the set takes a
//!   new key and builds the table again (at most [`MAX_REHASH`] times in one build). A lookup
//!   probes at most the longest probe of an insert plus one.
//! - An element is `list_index << 2 | subtree << 1 | allow`. Most names are in one list, so
//!   a slot holds one element inline. A name in more lists points to an interned element set.
//!
//! The set does not allocate on lookup.

use std::collections::HashMap;
use std::hash::Hasher;

use siphasher::sip::SipHasher13;

use crate::lists::{FLAG_ALLOW, FLAG_SUBTREE, ParsedList, read_raw_entry};

/// Size of one chunk for copied names, in bytes.
pub(crate) const CHUNK_BYTES: usize = 1 << 20;
/// Maximum number of unique names (24-bit slot index; the top value marks an empty entry).
pub(crate) const MAX_UNIQUE: usize = (1 << 24) - 1;
/// Maximum number of lists (the list index uses 16 bits of an element).
pub(crate) const MAX_LISTS: usize = 1 << 16;
/// Maximum logical size of all name buffers.
const MAX_ARENA: u64 = u32::MAX as u64;
/// Maximum probe length of an insert (entries after the home entry). With a secret key and a
/// load factor of at most 3/4, the longest probe of 16M random names is much shorter.
pub const MAX_PROBE: usize = 1024;
/// Maximum number of new keys in one build. After that, an insert has no probe limit.
pub const MAX_REHASH: u32 = 4;

const EMPTY: u32 = u32::MAX;
/// Marks a slot set that holds one element inline.
const INLINE: u32 = 1 << 31;
const ELEM_SUBTREE: u32 = 2;
const ELEM_ALLOW: u32 = 1;

/// One element: a list index and two flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Elem(u32);

impl Elem {
    pub(crate) fn new(list: u16, subtree: bool, allow: bool) -> Self {
        let mut v = u32::from(list) << 2;
        if subtree {
            v |= ELEM_SUBTREE;
        }
        if allow {
            v |= ELEM_ALLOW;
        }
        Self(v)
    }

    pub(crate) fn list(self) -> usize {
        // At most 16 bits after the shift, so the value fits in usize.
        usize::try_from(self.0 >> 2).unwrap_or(usize::MAX)
    }

    pub(crate) fn subtree(self) -> bool {
        self.0 & ELEM_SUBTREE != 0
    }

    pub(crate) fn allow(self) -> bool {
        self.0 & ELEM_ALLOW != 0
    }
}

#[derive(Debug, Clone, Copy)]
struct Slot {
    off: u32,
    set: u32,
}

/// Why a list could not go into the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SetFull {
    /// More than [`MAX_UNIQUE`] names.
    TooManyNames,
    /// The name buffers are larger than 4 GiB.
    ArenaFull,
}

/// Result of adding one list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct AddStats {
    /// Entries in the list.
    pub(crate) entries: usize,
    /// Names that were not in the set before.
    pub(crate) new_names: usize,
    /// `@@` entries of a block-kind list. They are not used (see docs/POLICY.md).
    pub(crate) ignored_allow: usize,
}

/// The secret key of the name hash. The shell gives a seed from the OS random source, so a
/// list author cannot make names that collide in the table. The same seed gives the same set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct HashKey {
    k0: u64,
    k1: u64,
}

impl HashKey {
    pub(crate) fn new(seed: [u64; 2]) -> Self {
        let [k0, k1] = seed;
        Self { k0, k1 }
    }

    /// SipHash-1-3 of `name` with this key.
    pub(crate) fn hash(self, name: &[u8]) -> u64 {
        let mut h = SipHasher13::new_with_keys(self.k0, self.k1);
        h.write(name);
        h.finish()
    }

    /// The key after a rehash. It comes from this key, so it is secret when this key is
    /// secret, and the build stays repeatable.
    fn next(self) -> Self {
        Self {
            k0: self.hash(b"rusthole rehash k0"),
            k1: self.hash(b"rusthole rehash k1"),
        }
    }
}

fn tag_of(hash: u64) -> u32 {
    u32::from((hash >> 56) as u8)
}

/// Name buffers with logical offsets.
#[derive(Debug, Default)]
struct Arena {
    bufs: Vec<Vec<u8>>,
    /// Logical start of each buffer.
    starts: Vec<u32>,
    /// Logical end of the last buffer.
    end: u64,
    /// Index of the open chunk, if any. Only the last buffer can be open.
    open: Option<usize>,
}

impl Arena {
    /// The name at logical offset `off` (the offset of its length byte).
    fn name(&self, off: u32) -> Option<&[u8]> {
        let i = self.starts.partition_point(|s| *s <= off).checked_sub(1)?;
        let buf = self.bufs.get(i)?;
        let pos = usize::try_from(off - *self.starts.get(i)?).ok()?;
        let len = usize::from(*buf.get(pos)?);
        buf.get(pos + 1..pos + 1 + len)
    }

    /// Takes over a list buffer. Returns the logical start of the buffer.
    fn donate(&mut self, data: Vec<u8>) -> Option<u32> {
        let start = u32::try_from(self.end).ok()?;
        let len = u64::try_from(data.len()).ok()?;
        if self.end + len > MAX_ARENA {
            return None;
        }
        self.close_open_chunk();
        self.bufs.push(data);
        self.starts.push(start);
        self.end += len;
        Some(start)
    }

    /// Copies one name into the open chunk. Returns its logical offset.
    fn copy_name(&mut self, name: &[u8]) -> Option<u32> {
        let len_byte = u8::try_from(name.len()).ok()?;
        let need = name.len() + 1;
        let fits = self
            .open
            .and_then(|i| self.bufs.get(i))
            .is_some_and(|b| b.capacity() - b.len() >= need);
        if !fits {
            self.close_open_chunk();
            let start = u32::try_from(self.end).ok()?;
            if self.end + (CHUNK_BYTES as u64) > MAX_ARENA {
                return None;
            }
            self.bufs.push(Vec::with_capacity(CHUNK_BYTES));
            self.starts.push(start);
            self.open = Some(self.bufs.len() - 1);
        }
        let i = self.open?;
        let start = *self.starts.get(i)?;
        let buf = self.bufs.get_mut(i)?;
        let off = start.checked_add(u32::try_from(buf.len()).ok()?)?;
        buf.push(len_byte);
        buf.extend_from_slice(name);
        self.end += need as u64;
        Some(off)
    }

    /// Fixes the size of the open chunk, so that a later buffer can follow it.
    fn close_open_chunk(&mut self) {
        if let Some(buf) = self.open.take().and_then(|i| self.bufs.get_mut(i)) {
            buf.shrink_to_fit();
        }
    }

    fn heap_bytes(&self) -> usize {
        self.bufs.iter().map(Vec::capacity).sum::<usize>()
            + self.bufs.capacity() * std::mem::size_of::<Vec<u8>>()
            + self.starts.capacity() * 4
    }
}

/// Open-addressing hash table with linear probing. An entry is `slot << 8 | tag`.
#[derive(Debug, Default)]
struct Table {
    entries: Vec<u32>,
    /// The longest probe of an insert (entries after the home entry).
    max_probe: usize,
}

/// Result of [`Table::insert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Insert {
    Done,
    /// The probe is longer than the limit. The table did not change.
    TooLong,
    /// No empty entry. This does not occur, because the table is sized for its names.
    Full,
}

impl Table {
    fn with_size(size: usize) -> Self {
        Self {
            entries: vec![EMPTY; size],
            max_probe: 0,
        }
    }

    fn mask(&self) -> usize {
        self.entries.len().saturating_sub(1)
    }

    /// Finds the slot of `name`. `name_of` reads the name of a slot.
    fn find<'a>(
        &self,
        name: &[u8],
        hash: u64,
        name_of: impl Fn(usize) -> Option<&'a [u8]>,
    ) -> Option<usize> {
        if self.entries.is_empty() {
            return None;
        }
        let mask = self.mask();
        let tag = tag_of(hash);
        let mut i = start_index(hash, mask);
        // Bounded: each name in the table is at most `max_probe` entries after its home
        // entry, so a longer probe cannot find the name. `max_probe` is less than the table
        // size.
        for _ in 0..=self.max_probe {
            let e = *self.entries.get(i)?;
            if e == EMPTY {
                return None;
            }
            if e & 0xff == tag {
                let slot = usize::try_from(e >> 8).ok()?;
                if name_of(slot) == Some(name) {
                    return Some(slot);
                }
            }
            i = (i + 1) & mask;
        }
        None
    }

    /// Inserts a slot that is not in the table. With `limit`, the insert stops when the probe
    /// is longer than `limit` entries.
    fn insert(&mut self, slot: usize, hash: u64, limit: Option<usize>) -> Insert {
        let Ok(slot32) = u32::try_from(slot) else {
            return Insert::Full;
        };
        let mask = self.mask();
        let mut i = start_index(hash, mask);
        // Bounded by the table size.
        for probe in 0..self.entries.len() {
            if limit.is_some_and(|l| probe > l) {
                return Insert::TooLong;
            }
            match self.entries.get_mut(i) {
                Some(e) if *e == EMPTY => {
                    *e = slot32 << 8 | tag_of(hash);
                    self.max_probe = self.max_probe.max(probe);
                    return Insert::Done;
                }
                Some(_) => i = (i + 1) & mask,
                None => return Insert::Full,
            }
        }
        Insert::Full
    }
}

fn start_index(hash: u64, mask: usize) -> usize {
    // Keep the low bits; the tag uses the high bits.
    usize::try_from(hash & (mask as u64)).unwrap_or(0)
}

/// Table size for `n` names: a power of two with a load factor of at most 3/4.
fn table_size(n: usize) -> usize {
    (n.saturating_mul(4) / 3 + 1).next_power_of_two().max(16)
}

/// Builds a [`DomainSet`] one list at a time. Each list buffer is dropped or taken over
/// after it is added.
#[derive(Debug)]
pub(crate) struct DomainSetBuilder {
    arena: Arena,
    slots: Vec<Slot>,
    table: Table,
    key: HashKey,
    /// New keys in this build (at most [`MAX_REHASH`]).
    rehashes: u32,
    /// Extra elements for names in more than one list: (slot, element).
    extra: Vec<(u32, u32)>,
    has_subtree: bool,
    peak: usize,
}

impl DomainSetBuilder {
    pub(crate) fn new(key: HashKey) -> Self {
        Self {
            arena: Arena::default(),
            slots: Vec::new(),
            table: Table::default(),
            key,
            rehashes: 0,
            extra: Vec::new(),
            has_subtree: false,
            peak: 0,
        }
    }

    /// The probe limit of an insert. When the rehash budget is spent, there is no limit.
    fn limit(&self) -> Option<usize> {
        (self.rehashes < MAX_REHASH).then_some(MAX_PROBE)
    }

    /// Takes the next key. The caller then builds the table again.
    fn new_key(&mut self) {
        self.rehashes += 1;
        self.key = self.key.next();
        tracing::warn!(
            rehashes = self.rehashes,
            names = self.slots.len(),
            "domain set: a name probed more than {MAX_PROBE} table entries; new hash key"
        );
        if self.rehashes >= MAX_REHASH {
            tracing::error!(
                rehashes = self.rehashes,
                "domain set: the rehash budget is spent; inserts have no probe limit now"
            );
        }
    }

    /// Makes a new table of `size` entries with all slots. When a name probes more than
    /// [`MAX_PROBE`] entries, it takes a new key and starts again.
    fn rebuild(&mut self, size: usize) {
        // Bounded: each failed try takes one new key. When the budget is spent, the limit is
        // off and a try cannot fail. Thus at most MAX_REHASH + 1 tries.
        for _ in 0..=MAX_REHASH {
            let limit = self.limit();
            let mut table = Table::with_size(size);
            let mut too_long = false;
            for (i, slot) in self.slots.iter().enumerate() {
                let Some(name) = self.arena.name(slot.off) else {
                    continue;
                };
                match table.insert(i, self.key.hash(name), limit) {
                    Insert::Done => {}
                    Insert::TooLong => {
                        too_long = true;
                        break;
                    }
                    Insert::Full => {
                        tracing::error!(size, slot = i, "domain set: the new table is full");
                    }
                }
            }
            if !too_long {
                self.table = table;
                return;
            }
            self.new_key();
        }
        // Not reached (see the bound above). The old table stays; a later insert that does
        // not fit fails with `TooManyNames`.
        tracing::error!(size, "domain set: the table rebuild did not end");
    }

    /// Puts slot `idx` with the name `name` into the table. A rehash can change the key, so
    /// this function hashes the name again on each try.
    fn place(&mut self, idx: usize, name: &[u8]) -> Result<(), SetFull> {
        // Bounded: each `TooLong` takes one new key. When the budget is spent, the limit is
        // off and `TooLong` cannot occur. Thus at most MAX_REHASH + 1 tries.
        for _ in 0..=MAX_REHASH {
            match self.table.insert(idx, self.key.hash(name), self.limit()) {
                Insert::Done => return Ok(()),
                Insert::Full => return Err(SetFull::TooManyNames),
                Insert::TooLong => {
                    self.new_key();
                    let size = self.table.entries.len();
                    self.rebuild(size);
                }
            }
        }
        tracing::error!("domain set: the insert did not end");
        Err(SetFull::TooManyNames)
    }

    fn find(&self, name: &[u8], hash: u64) -> Option<usize> {
        let slots = &self.slots;
        let arena = &self.arena;
        self.table.find(name, hash, |s| {
            slots.get(s).and_then(|slot| arena.name(slot.off))
        })
    }

    fn heap_bytes(&self) -> usize {
        self.arena.heap_bytes()
            + self.slots.capacity() * std::mem::size_of::<Slot>()
            + self.table.entries.capacity() * 4
            + self.extra.capacity() * 8
    }

    fn note_peak(&mut self, extra: usize) {
        self.peak = self.peak.max(self.heap_bytes() + extra);
    }

    /// Grows the table so that `n` names fit.
    fn reserve_names(&mut self, n: usize) {
        let want = table_size(n);
        if want <= self.table.entries.len() {
            return;
        }
        self.rebuild(want);
    }

    /// Adds every entry of one list. `allow_kind` is true for an allow-kind list: then each
    /// entry allows.
    pub(crate) fn add_list(
        &mut self,
        list: u16,
        allow_kind: bool,
        parsed: ParsedList,
    ) -> Result<AddStats, SetFull> {
        let input = parsed.heap_bytes();
        self.note_peak(input);
        // Pass 1: count the new names. A list with mostly new names gives its buffer to the
        // arena, so its names are not copied.
        let mut entries = 0usize;
        let mut new = 0usize;
        let mut pos = 0;
        let mut ignored = 0usize;
        while let Some((flags, name, next)) = read_raw_entry(parsed.data(), pos) {
            entries += 1;
            if !allow_kind && flags & FLAG_ALLOW != 0 {
                ignored += 1;
            } else if self.find(name, self.key.hash(name)).is_none() {
                new += 1;
            }
            pos = next;
        }
        if self.slots.len() + new > MAX_UNIQUE {
            return Err(SetFull::TooManyNames);
        }
        self.reserve_names(self.slots.len() + new);
        self.slots.reserve_exact(new);
        self.note_peak(input);

        let donate = new > 0 && new.saturating_mul(4) >= entries.saturating_mul(3);
        let mut stats = AddStats {
            entries,
            new_names: 0,
            ignored_allow: ignored,
        };
        if donate {
            let Some(start) = self.arena.donate(parsed.into_data()) else {
                return Err(SetFull::ArenaFull);
            };
            let buf = self.arena.bufs.len() - 1;
            let mut pos = 0;
            let mut name = [0u8; 256];
            // Copy each name out of the arena, so that the set can change while it is read.
            while let Some((flags, len, next)) = self
                .arena
                .bufs
                .get(buf)
                .and_then(|b| read_raw_entry(b, pos))
                .and_then(|(f, n, next)| {
                    name.get_mut(..n.len())?.copy_from_slice(n);
                    Some((f, n.len(), next))
                })
            {
                // The length byte follows the flags byte.
                let off = u32::try_from(pos + 1)
                    .ok()
                    .and_then(|p| start.checked_add(p))
                    .ok_or(SetFull::ArenaFull)?;
                let n = name.get(..len).unwrap_or_default();
                self.add_entry(list, allow_kind, flags, n, Some(off), &mut stats)?;
                pos = next;
            }
        } else {
            let data = parsed.into_data();
            let mut pos = 0;
            while let Some((flags, n, next)) = read_raw_entry(&data, pos) {
                self.add_entry(list, allow_kind, flags, n, None, &mut stats)?;
                pos = next;
            }
            self.note_peak(data.capacity());
        }
        self.note_peak(0);
        Ok(stats)
    }

    /// Adds one entry. `donated_off` is the offset of the name when its buffer is in the
    /// arena already; otherwise the name is copied into a chunk.
    fn add_entry(
        &mut self,
        list: u16,
        allow_kind: bool,
        flags: u8,
        name: &[u8],
        donated_off: Option<u32>,
        stats: &mut AddStats,
    ) -> Result<(), SetFull> {
        if !allow_kind && flags & FLAG_ALLOW != 0 {
            // An `@@` entry of a block-kind list: not used, counted in pass 1.
            return Ok(());
        }
        let subtree = flags & FLAG_SUBTREE != 0;
        // In an allow-kind list each entry allows; in a block-kind list each used entry denies.
        let elem = Elem::new(list, subtree, allow_kind);
        self.has_subtree |= subtree;
        if let Some(slot) = self.find(name, self.key.hash(name)) {
            self.add_elem(slot, elem);
            return Ok(());
        }
        if self.slots.len() >= MAX_UNIQUE {
            return Err(SetFull::TooManyNames);
        }
        if table_size(self.slots.len() + 1) > self.table.entries.len() {
            // Pass 1 reserves room for every new name, so this does not occur. A rehash here
            // is safe, because all names are in the arena.
            self.reserve_names(self.slots.len() + 1);
        }
        let off = match donated_off {
            Some(off) => off,
            None => self.arena.copy_name(name).ok_or(SetFull::ArenaFull)?,
        };
        let idx = self.slots.len();
        self.place(idx, name)?;
        self.slots.push(Slot {
            off,
            set: INLINE | elem.0,
        });
        stats.new_names += 1;
        Ok(())
    }

    fn add_elem(&mut self, slot: usize, elem: Elem) {
        let Some(s) = self.slots.get(slot) else {
            return;
        };
        if s.set == INLINE | elem.0 {
            return;
        }
        if let Ok(slot32) = u32::try_from(slot) {
            self.extra.push((slot32, elem.0));
        }
    }

    /// Finishes the set: interns the element sets and shrinks the buffers.
    pub(crate) fn finish(mut self) -> DomainSet {
        self.arena.close_open_chunk();
        self.extra.sort_unstable();
        self.extra.dedup();
        let mut set_starts: Vec<u32> = vec![0];
        let mut set_elems: Vec<u32> = Vec::new();
        let mut interned: HashMap<Vec<u32>, u32> = HashMap::new();
        let mut group: Vec<u32> = Vec::new();
        let mut i = 0;
        while let Some(&(slot, _)) = self.extra.get(i) {
            group.clear();
            let slot_idx = usize::try_from(slot).unwrap_or(usize::MAX);
            let Some(s) = self.slots.get_mut(slot_idx) else {
                i += 1;
                continue;
            };
            group.push(s.set & !INLINE);
            while let Some(&(sl, e)) = self.extra.get(i) {
                if sl != slot {
                    break;
                }
                group.push(e);
                i += 1;
            }
            group.sort_unstable();
            group.dedup();
            if let [only] = group.as_slice() {
                s.set = INLINE | *only;
                continue;
            }
            let id = if let Some(id) = interned.get(&group) {
                *id
            } else {
                let Ok(id) = u32::try_from(set_starts.len() - 1) else {
                    continue;
                };
                set_elems.extend_from_slice(&group);
                set_starts.push(u32::try_from(set_elems.len()).unwrap_or(u32::MAX));
                interned.insert(group.clone(), id);
                id
            };
            s.set = id;
        }
        self.note_peak(interned.len() * 64);
        drop(interned);
        self.extra = Vec::new();
        self.slots.shrink_to_fit();
        // Shrink the table when it is more than twice the size it needs.
        if self.table.entries.len() > 2 * table_size(self.slots.len()) {
            self.table = Table::default();
            self.reserve_names(self.slots.len());
        }
        set_elems.shrink_to_fit();
        set_starts.shrink_to_fit();
        self.note_peak(0);
        DomainSet {
            arena: self.arena,
            slots: self.slots,
            table: self.table,
            key: self.key,
            rehashes: self.rehashes,
            set_starts,
            set_elems,
            has_subtree: self.has_subtree,
            peak: self.peak,
        }
    }
}

/// The finished, immutable set.
#[derive(Default)]
pub(crate) struct DomainSet {
    arena: Arena,
    slots: Vec<Slot>,
    table: Table,
    key: HashKey,
    rehashes: u32,
    set_starts: Vec<u32>,
    set_elems: Vec<u32>,
    has_subtree: bool,
    peak: usize,
}

impl std::fmt::Debug for DomainSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainSet")
            .field("names", &self.slots.len())
            .field("sets", &self.set_starts.len().saturating_sub(1))
            .field("heap_bytes", &self.heap_bytes())
            .finish_non_exhaustive()
    }
}

/// Iterator over the elements of one name. It does not allocate.
#[derive(Debug, Clone)]
pub(crate) enum Elems<'a> {
    One(Option<u32>),
    Many(std::slice::Iter<'a, u32>),
}

impl Iterator for Elems<'_> {
    type Item = Elem;

    fn next(&mut self) -> Option<Elem> {
        match self {
            Self::One(v) => v.take().map(Elem),
            Self::Many(it) => it.next().copied().map(Elem),
        }
    }
}

impl DomainSet {
    /// The elements of `name`, or `None` when the set does not hold the name.
    pub(crate) fn get(&self, name: &str) -> Option<Elems<'_>> {
        let bytes = name.as_bytes();
        let slot = self.table.find(bytes, self.key.hash(bytes), |s| {
            self.slots.get(s).and_then(|slot| self.arena.name(slot.off))
        })?;
        let set = self.slots.get(slot)?.set;
        if set & INLINE != 0 {
            return Some(Elems::One(Some(set & !INLINE)));
        }
        let id = usize::try_from(set).ok()?;
        let from = usize::try_from(*self.set_starts.get(id)?).ok()?;
        let to = usize::try_from(*self.set_starts.get(id + 1)?).ok()?;
        Some(Elems::Many(self.set_elems.get(from..to)?.iter()))
    }

    /// True when at least one element is a subtree element.
    pub(crate) fn has_subtree(&self) -> bool {
        self.has_subtree
    }

    /// Number of unique names.
    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }

    /// Heap bytes of the set.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.arena.heap_bytes()
            + self.slots.capacity() * std::mem::size_of::<Slot>()
            + self.table.entries.capacity() * 4
            + self.set_starts.capacity() * 4
            + self.set_elems.capacity() * 4
    }

    /// The estimated peak heap use of the build, in bytes.
    pub(crate) fn peak_build_bytes(&self) -> usize {
        self.peak
    }

    /// New hash keys that the build took because a probe was too long.
    pub(crate) fn rehashes(&self) -> u32 {
        self.rehashes
    }

    /// The longest probe in the table. A lookup probes at most this plus one entries.
    pub(crate) fn max_probe(&self) -> usize {
        self.table.max_probe
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DomainName;
    use crate::lists::{EntryAction, MatchKind};

    const KEY: HashKey = HashKey { k0: 1, k1: 2 };

    /// `n` names whose home entry in a table of `size` entries is one of the first `window`
    /// entries under `hash`. A list author who knows the hash can make such names.
    fn crafted(n: usize, size: usize, window: u64, hash: impl Fn(&[u8]) -> u64) -> Vec<String> {
        let mask = (size - 1) as u64;
        let mut out = Vec::with_capacity(n);
        let mut i = 0u64;
        while out.len() < n {
            let name = format!("c{i}.example");
            if hash(name.as_bytes()) & mask < window {
                out.push(name);
            }
            i += 1;
        }
        out
    }

    fn deny_list(names: &[String]) -> ParsedList {
        let mut l = ParsedList::new();
        for n in names {
            l.push(
                &DomainName::parse(n).unwrap(),
                MatchKind::Exact,
                EntryAction::Deny,
            )
            .unwrap();
        }
        l
    }

    /// Names that fill one part of the table under the key of the build.
    fn flood(key: HashKey) -> Vec<String> {
        let n = 1500;
        let size = table_size(n);
        assert_eq!(size, 2048);
        // 1500 names in 32 home entries: without a probe limit, the longest probe is about
        // 1470 entries.
        crafted(n, size, 32, |b| key.hash(b))
    }

    #[test]
    fn probe_limit_takes_a_new_key() {
        let names = flood(KEY);
        let mut b = DomainSetBuilder::new(KEY);
        b.add_list(0, false, deny_list(&names)).unwrap();
        let set = b.finish();
        assert!(set.rehashes() >= 1, "the crafted names must force a rehash");
        assert!(set.rehashes() < MAX_REHASH);
        assert!(
            set.max_probe() <= MAX_PROBE,
            "max probe {}",
            set.max_probe()
        );
        // The new key spreads the names.
        assert!(set.max_probe() < 100, "max probe {}", set.max_probe());
        assert_eq!(set.len(), names.len());
        for n in &names {
            assert!(set.get(n).is_some(), "{n}");
        }
        assert!(set.get("c-missing.example").is_none());
    }

    #[test]
    fn spent_rehash_budget_still_finds_every_name() {
        // With the budget spent, the insert has no limit. The build ends, and a lookup finds
        // names with a probe longer than MAX_PROBE.
        let names = flood(KEY);
        let mut b = DomainSetBuilder::new(KEY);
        b.rehashes = MAX_REHASH;
        b.add_list(0, false, deny_list(&names)).unwrap();
        let set = b.finish();
        assert_eq!(set.rehashes(), MAX_REHASH);
        assert!(set.max_probe() > MAX_PROBE, "max probe {}", set.max_probe());
        assert!(set.max_probe() < 2048);
        for n in &names {
            assert!(set.get(n).is_some(), "{n}");
        }
        assert!(set.get("c-missing.example").is_none());

        // With one try left, the build takes exactly one new key.
        let mut b = DomainSetBuilder::new(KEY);
        b.rehashes = MAX_REHASH - 1;
        b.add_list(0, false, deny_list(&names)).unwrap();
        let set = b.finish();
        assert_eq!(set.rehashes(), MAX_REHASH);
        assert!(set.max_probe() < 100, "max probe {}", set.max_probe());
    }

    #[test]
    fn names_that_collide_under_the_old_fixed_key_do_not_cluster() {
        // The old hash was `DefaultHasher::new()`: SipHash-1-3 with the public key (0, 0).
        let old = |b: &[u8]| {
            let mut h = std::hash::DefaultHasher::new();
            h.write(b);
            h.finish()
        };
        let n = 2000;
        let size = table_size(n);
        assert_eq!(size, 4096);
        let names = crafted(n, size, 64, old);
        let mut b = DomainSetBuilder::new(HashKey::new([0x5eed, 0xcafe]));
        b.add_list(0, false, deny_list(&names)).unwrap();
        let set = b.finish();
        assert_eq!(set.rehashes(), 0);
        assert!(set.max_probe() < 100, "max probe {}", set.max_probe());
        for n in &names {
            assert!(set.get(n).is_some(), "{n}");
        }
    }

    #[test]
    fn hash_depends_on_the_key() {
        let a = HashKey::new([1, 2]);
        let b = HashKey::new([1, 3]);
        assert_eq!(a.hash(b"a.example"), a.hash(b"a.example"));
        assert_ne!(a.hash(b"a.example"), b.hash(b"a.example"));
        assert_ne!(a.next(), a);
        assert_eq!(a.next(), HashKey::new([1, 2]).next());
    }

    fn list(names: &[(&str, bool, bool)]) -> ParsedList {
        let mut l = ParsedList::new();
        for (n, subtree, allow) in names {
            l.push(
                &DomainName::parse(n).unwrap(),
                if *subtree {
                    MatchKind::Subtree
                } else {
                    MatchKind::Exact
                },
                if *allow {
                    EntryAction::Allow
                } else {
                    EntryAction::Deny
                },
            )
            .unwrap();
        }
        l
    }

    fn elems(set: &DomainSet, name: &str) -> Vec<(usize, bool, bool)> {
        set.get(name).map_or_else(Vec::new, |e| {
            e.map(|e| (e.list(), e.subtree(), e.allow())).collect()
        })
    }

    #[test]
    fn merges_lists_and_interns_sets() {
        let mut b = DomainSetBuilder::new(KEY);
        b.add_list(
            0,
            false,
            list(&[("a.example", false, false), ("b.example", true, false)]),
        )
        .unwrap();
        // Mostly duplicates: copied, not donated.
        b.add_list(
            1,
            true,
            list(&[
                ("a.example", false, false),
                ("b.example", true, false),
                ("c.example", false, false),
                ("a.example", false, false),
            ]),
        )
        .unwrap();
        let st = b
            .add_list(
                2,
                false,
                list(&[("b.example", true, true), ("b.example", true, false)]),
            )
            .unwrap();
        assert_eq!(st.ignored_allow, 1);
        let set = b.finish();
        assert_eq!(set.len(), 3);
        assert_eq!(
            elems(&set, "a.example"),
            [(0, false, false), (1, false, true)]
        );
        assert_eq!(
            elems(&set, "b.example"),
            [(0, true, false), (1, true, true), (2, true, false)]
        );
        assert_eq!(elems(&set, "c.example"), [(1, false, true)]);
        assert!(set.get("d.example").is_none());
        assert!(set.get("example").is_none());
        assert!(set.has_subtree());
    }

    #[test]
    fn many_names_across_chunks_and_donations() {
        let mut b = DomainSetBuilder::new(KEY);
        let names: Vec<String> = (0..20_000).map(|i| format!("host-{i}.example")).collect();
        // List 0: a small list (donated). List 1: all names, mostly new (donated).
        // List 2: the same names again (copied path, all duplicates).
        let mut l0 = ParsedList::new();
        for n in names.iter().take(10) {
            l0.push(
                &DomainName::parse(n).unwrap(),
                MatchKind::Exact,
                EntryAction::Deny,
            )
            .unwrap();
        }
        b.add_list(0, false, l0).unwrap();
        let mut l1 = ParsedList::new();
        for n in &names {
            l1.push(
                &DomainName::parse(n).unwrap(),
                MatchKind::Exact,
                EntryAction::Deny,
            )
            .unwrap();
        }
        b.add_list(1, false, l1.clone()).unwrap();
        b.add_list(2, false, l1).unwrap();
        // List 3: names that need chunks (copied: a few new names among many old ones).
        let mut l3 = ParsedList::new();
        for n in names.iter().take(100) {
            l3.push(
                &DomainName::parse(n).unwrap(),
                MatchKind::Exact,
                EntryAction::Deny,
            )
            .unwrap();
        }
        l3.push(
            &DomainName::parse("new.example").unwrap(),
            MatchKind::Exact,
            EntryAction::Deny,
        )
        .unwrap();
        b.add_list(3, false, l3).unwrap();
        let set = b.finish();
        assert_eq!(set.len(), 20_001);
        assert_eq!(elems(&set, "host-5.example").len(), 4);
        assert_eq!(
            elems(&set, "host-19999.example"),
            [(1, false, false), (2, false, false)]
        );
        assert_eq!(elems(&set, "new.example"), [(3, false, false)]);
        for n in &names {
            assert!(set.get(n).is_some(), "{n}");
        }
        assert!(set.get("host-20000.example").is_none());
        assert!(!set.has_subtree());
        assert!(set.heap_bytes() > 0);
        assert!(set.peak_build_bytes() >= set.heap_bytes());
    }

    #[test]
    fn empty_set() {
        let set = DomainSetBuilder::new(KEY).finish();
        assert!(set.get("a.example").is_none());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn elem_encoding() {
        let e = Elem::new(u16::MAX, true, false);
        assert_eq!(e.list(), 65_535);
        assert!(e.subtree());
        assert!(!e.allow());
        assert_eq!(e.0 & INLINE, 0);
    }
}
