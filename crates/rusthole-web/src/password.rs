//! Argon2id password hashes (decision D10).
//!
//! Parameters for new hashes (OWASP password storage cheat sheet, Argon2id option 2):
//! memory 19 MiB (`m=19456`), 2 iterations (`t=2`), 1 lane (`p=1`), 16-byte random salt,
//! 32-byte output. A check uses the parameters of the stored PHC string, with an upper
//! limit (see [`MAX_M_COST`]) so that a bad config value cannot use all memory.

use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};

/// The shortest password that `rusthole passwd` accepts.
pub const MIN_PASSWORD_LEN: usize = 10;
/// The longest password (bytes). A longer one is refused before the hash.
pub const MAX_PASSWORD_LEN: usize = 1024;
/// The highest memory cost (KiB) of a stored hash that rusthole checks: 256 MiB.
pub const MAX_M_COST: u32 = 256 * 1024;
/// The highest time cost of a stored hash that rusthole checks.
pub const MAX_T_COST: u32 = 16;

/// Why a hash cannot be made.
#[derive(Debug, thiserror::Error)]
pub enum HashError {
    /// The password is too short or too long.
    #[error("the password must have {MIN_PASSWORD_LEN} to {MAX_PASSWORD_LEN} bytes")]
    Length,
    /// The OS random source failed.
    #[error("the OS random source failed")]
    Random,
    /// The hash failed.
    #[error("the Argon2id hash failed")]
    Hash,
}

fn hasher() -> Result<Argon2<'static>, HashError> {
    let params = Params::new(Params::DEFAULT_M_COST, Params::DEFAULT_T_COST, 1, Some(32))
        .map_err(|_| HashError::Hash)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Makes an Argon2id PHC string for `password`.
pub fn hash_password(password: &str) -> Result<String, HashError> {
    if password.len() < MIN_PASSWORD_LEN || password.len() > MAX_PASSWORD_LEN {
        return Err(HashError::Length);
    }
    let salt = crate::util::random_bytes::<16>().map_err(|_| HashError::Random)?;
    let hash = hasher()?
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map_err(|_| HashError::Hash)?;
    Ok(hash.to_string())
}

/// True when `password` matches the PHC string `phc`. A bad string, an algorithm other
/// than Argon2id or too high costs give false. Blocks for the time of one hash: call it on a
/// blocking thread.
pub fn verify_password(password: &str, phc: &str) -> bool {
    if phc.is_empty() || password.len() > MAX_PASSWORD_LEN {
        return false;
    }
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    if parsed.algorithm.as_str() != "argon2id" {
        return false;
    }
    let Ok(params) = Params::try_from(&parsed) else {
        return false;
    };
    if params.m_cost() > MAX_M_COST || params.t_cost() > MAX_T_COST {
        tracing::error!("the stored password hash has too high costs; the check is refused");
        return false;
    }
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{h}");
        assert!(rusthole_core::config::is_argon2id_phc(&h));
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("correct horse batterz", &h));
        assert!(!verify_password("correct horse battery", ""));
        assert!(!verify_password("x", "not a hash"));
        // Two hashes of one password differ (random salt).
        assert_ne!(h, hash_password("correct horse battery").unwrap());
    }

    #[test]
    fn length_limits() {
        assert!(matches!(hash_password("short"), Err(HashError::Length)));
        let long = "a".repeat(MAX_PASSWORD_LEN + 1);
        assert!(matches!(hash_password(&long), Err(HashError::Length)));
    }

    #[test]
    fn too_high_costs_are_refused() {
        let h = "$argon2id$v=19$m=4194304,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhcw";
        assert!(!verify_password("whatever-password", h));
    }
}
