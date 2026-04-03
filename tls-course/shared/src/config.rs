//! TLS configuration helpers
//!
//! Provides pre-configured ClientConfig and ServerConfig builders
//! with sensible defaults for learning purposes.

use std::sync::Arc;

use anyhow::Result;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ClientConfig, RootCertStore, ServerConfig,
};
use rustls_ring::DEFAULT_PROVIDER;

/// Create a basic client configuration with webpki roots
pub fn create_basic_client_config() -> ClientConfig {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

/// Create a basic server configuration
pub fn create_basic_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> ServerConfig {
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("cert and key should be valid")
}
