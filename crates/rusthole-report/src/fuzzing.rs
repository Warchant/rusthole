//! Entry points for the fuzz targets (`fuzz/`). Each must never panic on any input.

/// Runs the RDAP parsers on arbitrary bytes. The first byte picks the parser.
pub fn rdap_json(data: &[u8]) {
    let Some((sel, body)) = data.split_first() else {
        return;
    };
    if sel % 2 == 0 {
        if let Ok(b) = crate::rdap::parse_bootstrap(body) {
            let _ = b.server_for("www.example.com");
            let _ = b.server_for("a.b.c.d.e");
        }
    } else if let Ok(v) = crate::rdap::parse_domain(body) {
        assert!(v.is_object());
        let n = v
            .get("status")
            .and_then(|x| x.as_array())
            .map_or(0, Vec::len);
        assert!(n <= crate::rdap::MAX_ITEMS);
    }
}

/// Runs the certificate parser on arbitrary bytes (one DER certificate).
pub fn cert_chain(data: &[u8]) {
    if let Ok(v) = crate::tls::cert_json(data, 0) {
        let n = v
            .get("names")
            .and_then(|x| x.as_array())
            .map_or(0, Vec::len);
        assert!(n <= crate::tls::MAX_SANS);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        super::rdap_json(b"");
        super::rdap_json(&[0]);
        let mut d = vec![0u8];
        d.extend_from_slice(crate::rdap::tests::BOOT.as_bytes());
        super::rdap_json(&d);
        let mut d = vec![1u8];
        d.extend_from_slice(crate::rdap::tests::DOMAIN.as_bytes());
        super::rdap_json(&d);
        super::cert_chain(b"");
        super::cert_chain(&[0x30, 0x82, 0x01]);
    }
}
