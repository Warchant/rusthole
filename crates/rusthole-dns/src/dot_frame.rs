//! The frame reader for DNS over TCP and DNS over TLS: a 2-byte length, then the message
//! (RFC 1035 section 4.2.2, RFC 7858 section 3.3). Pure: no I/O.
//!
//! The reader takes bytes in chunks of any size and gives whole messages. Its buffer never
//! holds more than [`MAX_BUFFER`] bytes, so a peer cannot make it grow without a limit.

use crate::wire::HEADER_LEN;

/// The largest DNS message (the 2-byte length).
pub const MAX_FRAME: usize = 65_535;
/// The largest chunk that [`FrameReader::push`] takes at one time.
pub const MAX_CHUNK: usize = 16 * 1024;
/// The largest buffer: one full frame with its length, plus one chunk.
pub const MAX_BUFFER: usize = MAX_FRAME + 2 + MAX_CHUNK;

/// Why the stream cannot go on. The caller closes the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// A frame is shorter than a DNS header.
    #[error("a frame is shorter than a DNS header")]
    TooShort,
    /// A chunk is longer than [`MAX_CHUNK`], or the buffer would be longer than
    /// [`MAX_BUFFER`]. The caller did not take the frames out.
    #[error("the frame buffer is full")]
    Overflow,
}

/// Collects bytes and gives whole frames.
#[derive(Debug, Default)]
pub struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    /// An empty reader.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes in the buffer.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Adds bytes from the stream. Take the frames out with [`FrameReader::next_frame`]
    /// after each push, so the buffer stays small.
    pub fn push(&mut self, data: &[u8]) -> Result<(), FrameError> {
        if data.len() > MAX_CHUNK || self.buf.len().saturating_add(data.len()) > MAX_BUFFER {
            return Err(FrameError::Overflow);
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }

    /// The next whole frame, or `None` when more bytes are necessary.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        let Some(&[a, b]) = self.buf.get(..2) else {
            return Ok(None);
        };
        let len = usize::from(u16::from_be_bytes([a, b]));
        if len < HEADER_LEN {
            return Err(FrameError::TooShort);
        }
        let Some(frame) = self.buf.get(2..2 + len) else {
            return Ok(None);
        };
        let frame = frame.to_vec();
        self.buf.drain(..2 + len);
        Ok(Some(frame))
    }
}

/// Adds the 2-byte length to `msg`. `None` when `msg` is longer than [`MAX_FRAME`].
pub fn frame(msg: &[u8]) -> Option<Vec<u8>> {
    let len = u16::try_from(msg.len()).ok()?;
    let mut out = Vec::with_capacity(msg.len() + 2);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(msg);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn frames_across_chunks() {
        let a = frame(&[1; 12]).unwrap();
        let b = frame(&[2; 40]).unwrap();
        let mut stream = a.clone();
        stream.extend_from_slice(&b);
        let mut r = FrameReader::new();
        r.push(&stream[..5]).unwrap();
        assert_eq!(r.next_frame().unwrap(), None);
        r.push(&stream[5..20]).unwrap();
        assert_eq!(r.next_frame().unwrap(), Some(vec![1; 12]));
        assert_eq!(r.next_frame().unwrap(), None);
        r.push(&stream[20..]).unwrap();
        assert_eq!(r.next_frame().unwrap(), Some(vec![2; 40]));
        assert_eq!(r.next_frame().unwrap(), None);
        assert_eq!(r.buffered(), 0);
    }

    #[test]
    fn short_frame_is_an_error() {
        let mut r = FrameReader::new();
        r.push(&[0, 11]).unwrap();
        assert_eq!(r.next_frame(), Err(FrameError::TooShort));
        let mut r = FrameReader::new();
        r.push(&[0, 0]).unwrap();
        assert_eq!(r.next_frame(), Err(FrameError::TooShort));
    }

    #[test]
    fn buffer_is_bounded() {
        let mut r = FrameReader::new();
        assert_eq!(r.push(&vec![0; MAX_CHUNK + 1]), Err(FrameError::Overflow));
        // A partial maximum frame, then chunks until the limit.
        r.push(&[0xff, 0xff]).unwrap();
        let chunk = vec![0u8; MAX_CHUNK];
        let mut pushed = 2;
        while r.push(&chunk).is_ok() {
            pushed += MAX_CHUNK;
            assert!(r.buffered() <= MAX_BUFFER);
        }
        assert!(pushed <= MAX_BUFFER);
        assert!(r.next_frame().unwrap().is_some());
    }

    #[test]
    fn frame_rejects_long_messages() {
        assert!(frame(&vec![0; MAX_FRAME]).is_some());
        assert!(frame(&vec![0; MAX_FRAME + 1]).is_none());
    }

    proptest! {
        /// Frames split at arbitrary points come back unchanged and in order.
        #[test]
        fn split_stream_round_trip(
            msgs in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 12..300), 1..8),
            cuts in proptest::collection::vec(1usize..64, 1..64),
        ) {
            let mut stream = Vec::new();
            for m in &msgs {
                stream.extend_from_slice(&frame(m).unwrap());
            }
            let mut r = FrameReader::new();
            let mut out = Vec::new();
            let mut pos = 0;
            let mut i = 0;
            while pos < stream.len() {
                let step = cuts[i % cuts.len()].min(stream.len() - pos);
                r.push(&stream[pos..pos + step]).unwrap();
                pos += step;
                i += 1;
                while let Some(f) = r.next_frame().unwrap() {
                    out.push(f);
                }
            }
            prop_assert_eq!(out, msgs);
            prop_assert_eq!(r.buffered(), 0);
        }

        /// Arbitrary bytes never panic, and the buffer stays within its limit.
        #[test]
        fn arbitrary_bytes_are_bounded(chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..2000), 0..40)) {
            let mut r = FrameReader::new();
            for c in &chunks {
                if r.push(c).is_err() {
                    break;
                }
                let mut stop = false;
                for _ in 0..=c.len() {
                    match r.next_frame() {
                        Ok(Some(f)) => prop_assert!(f.len() >= HEADER_LEN),
                        Ok(None) => break,
                        Err(_) => { stop = true; break; }
                    }
                }
                prop_assert!(r.buffered() <= MAX_BUFFER);
                if stop {
                    break;
                }
            }
        }
    }
}
