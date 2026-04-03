//! Shared utilities for TLS course lessons
//!
//! This library provides common functionality used across all lessons:
//! - Logging configuration with detailed TLS information
//! - Certificate generation and management
//! - Common TLS configuration helpers
//! - Debug utilities for protocol analysis

pub mod certgen;
pub mod logging;

use std::io::Seek;
use std::path::Path;

use anyhow::Result;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Re-export commonly used types
pub use rustls;
pub use rustls_ring;
pub use tracing;

/// Load certificates from a PEM file
pub fn load_certs(path: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>> {
    let certfile = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(certfile);

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut reader)
            .filter_map(|cert| cert.ok())
            .collect();

    Ok(certs)
}

/// Load private key from a PEM file (supports PKCS#8 and RSA)
pub fn load_private_key(path: impl AsRef<Path>) -> Result<PrivateKeyDer<'static>> {
    let keyfile = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(keyfile);

    // Try PKCS#8 first
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .filter_map(|key| key.ok())
        .next()
    {
        return Ok(PrivateKeyDer::try_from(key)?);
    }

    // Reset reader and try RSA
    reader.rewind()?;
    if let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader)
        .filter_map(|key| key.ok())
        .next()
    {
        return Ok(PrivateKeyDer::try_from(key)?);
    }

    anyhow::bail!("No private key found in file")
}

/// Generate a unique connection ID for logging
pub fn generate_conn_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);

    format!("conn-{}", COUNTER.fetch_add(1, Ordering::SeqCst))
}
