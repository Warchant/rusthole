#![no_main]
//! Fuzz the TLS PEM loader: arbitrary bytes as the certificate PEM and the key PEM go
//! through `load_pem_pair`. It returns Ok or Err and never panics. The certificate bytes
//! also go to the DER certificate parser (`cert_facts`).
//!
//! The first two bytes give the split point between the certificate and the key.

use libfuzzer_sys::fuzz_target;
use rustls_pki_types::CertificateDer;

fuzz_target!(|data: &[u8]| {
    let Some((head, rest)) = data.split_first_chunk::<2>() else {
        return;
    };
    let split = usize::from(u16::from_le_bytes(*head)) % (rest.len() + 1);
    let (cert, key) = rest.split_at(split);
    let provider = rusthole_tls::provider();
    let _ = rusthole_tls::load_pem_pair(cert, key, &provider);
    let _ = rusthole_tls::pem::cert_facts(&CertificateDer::from(cert), "fuzz");
});
