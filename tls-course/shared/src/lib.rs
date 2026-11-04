//! Shared utilities for TLS course lessons
//!
//! This library provides common functionality used across all lessons:
//! - Logging configuration with detailed TLS information
//! - Certificate generation and management
//! - Common TLS configuration helpers
//! - Debug utilities for protocol analysis

pub mod certgen;
pub mod logging;

/// Blocking TLS stream helpers
///
/// `rustls::Stream`（借用式）在课时代码里会与后续的连接查询产生借用冲突，
/// 这里改用拥有式的 `rustls::StreamOwned` 封装，并提供 `conn()` 访问器，
/// 便于握手完成后查询协商结果（套件、版本、对端证书等）。
pub mod util {
    use std::io::{Read, Write};
    use std::ops::{Deref, DerefMut};

    use rustls::{ConnectionCommon, SideData};

    /// 拥有底层连接与套接字的阻塞 TLS 流
    pub struct Stream<C, T>
    where
        C: Sized,
        T: Read + Write + Sized,
    {
        inner: rustls::StreamOwned<C, T>,
    }

    impl<C, T, S> Stream<C, T>
    where
        C: DerefMut + Deref<Target = ConnectionCommon<S>>,
        T: Read + Write,
        S: SideData,
    {
        /// 以连接和套接字构造（转移所有权）
        pub fn new(conn: C, stream: T) -> Self {
            Self {
                inner: rustls::StreamOwned::new(conn, stream),
            }
        }

        /// 只读访问底层连接（查询协商结果等）
        pub fn conn(&self) -> &C {
            &self.inner.conn
        }

        /// 可变访问底层连接
        pub fn conn_mut(&mut self) -> &mut C {
            &mut self.inner.conn
        }
    }

    impl<C, T, S> Read for Stream<C, T>
    where
        C: DerefMut + Deref<Target = ConnectionCommon<S>>,
        T: Read + Write,
        S: SideData,
    {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(buf)
        }
    }

    impl<C, T, S> Write for Stream<C, T>
    where
        C: DerefMut + Deref<Target = ConnectionCommon<S>>,
        T: Read + Write,
        S: SideData,
    {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.inner.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    /// `Stream` 的别名（lesson01 使用）
    pub type TlsStream<C, T> = Stream<C, T>;
}


use std::io::Seek;
use std::path::Path;

use anyhow::Result;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Re-export commonly used types
pub use rustls;
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
