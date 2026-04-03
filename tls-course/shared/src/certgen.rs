//! Certificate generation utilities
//!
//! Provides functions to generate test certificates, CA chains,
//! and self-signed certificates for TLS development.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};

/// CA configuration for certificate generation
pub struct CaConfig {
    pub cn: String,
    pub validity_days: i64,
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            cn: "Test CA".to_string(),
            validity_days: 365 * 10, // 10 years
        }
    }
}

/// Server certificate configuration
pub struct ServerCertConfig {
    pub cn: String,
    pub sans: Vec<String>,
    pub validity_days: i64,
}

impl Default for ServerCertConfig {
    fn default() -> Self {
        Self {
            cn: "localhost".to_string(),
            sans: vec!["localhost".to_string(), "127.0.0.1".to_string()],
            validity_days: 365, // 1 year
        }
    }
}

/// Client certificate configuration
pub struct ClientCertConfig {
    pub cn: String,
    pub validity_days: i64,
}

impl Default for ClientCertConfig {
    fn default() -> Self {
        Self {
            cn: "test-client".to_string(),
            validity_days: 365,
        }
    }
}

/// Generate a self-signed CA certificate
pub fn generate_ca(config: &CaConfig) -> Result<(Certificate, KeyPair)> {
    let mut params = CertificateParams::new(vec![config.cn.clone()])?;

    let now = std::time::SystemTime::now();
    params.not_before = now.into();
    params.not_after = (now + std::time::Duration::from_secs(config.validity_days as u64 * 24 * 60 * 60)).into();

    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, &config.cn);
    params.distinguished_name.push(DnType::OrganizationName, "TLS Course Test");
    params.distinguished_name.push(DnType::CountryName, "CN");

    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    Ok((cert, key_pair))
}

/// Generate a server certificate signed by a CA
pub fn generate_server_cert(
    ca_cert: &Certificate,
    ca_key: &KeyPair,
    config: &ServerCertConfig,
) -> Result<(Certificate, KeyPair)> {
    let mut params = CertificateParams::new(vec![config.cn.clone()])?;

    let now = std::time::SystemTime::now();
    params.not_before = now.into();
    params.not_after = (now + std::time::Duration::from_secs(config.validity_days as u64 * 24 * 60 * 60)).into();

    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, &config.cn);
    params.distinguished_name.push(DnType::OrganizationName, "TLS Course Test");

    // Add Subject Alternative Names
    for san in &config.sans {
        if let Ok(ip) = san.parse::<std::net::IpAddr>() {
            params.subject_alt_names.push(SanType::IpAddress(ip));
        } else {
            params.subject_alt_names.push(SanType::DnsName(san.parse()?));
        }
    }

    params.is_ca = IsCa::NoCa;

    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];

    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
    ];

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, ca_cert, ca_key)?;

    Ok((cert, key_pair))
}

/// Generate a client certificate signed by a CA
pub fn generate_client_cert(
    ca_cert: &Certificate,
    ca_key: &KeyPair,
    config: &ClientCertConfig,
) -> Result<(Certificate, KeyPair)> {
    let mut params = CertificateParams::new(vec![config.cn.clone()])?;

    let now = std::time::SystemTime::now();
    params.not_before = now.into();
    params.not_after = (now + std::time::Duration::from_secs(config.validity_days as u64 * 24 * 60 * 60)).into();

    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, &config.cn);
    params.distinguished_name.push(DnType::OrganizationName, "TLS Course Test");

    params.is_ca = IsCa::NoCa;

    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];

    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
    ];

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, ca_cert, ca_key)?;

    Ok((cert, key_pair))
}

/// Write certificate and key to files
pub fn write_cert_files(
    base_path: impl AsRef<Path>,
    cert: &Certificate,
    key: &KeyPair,
) -> Result<(PathBuf, PathBuf)> {
    let base = base_path.as_ref();
    fs::create_dir_all(base)?;

    let cert_path = base.join("cert.pem");
    let key_path = base.join("key.pem");

    fs::write(&cert_path, cert.pem())?;
    fs::write(&key_path, key.serialize_pem())?;

    Ok((cert_path, key_path))
}

/// Generate a complete certificate chain for testing
pub fn generate_test_certs(output_dir: impl AsRef<Path>) -> Result<TestCerts> {
    let output = output_dir.as_ref();
    fs::create_dir_all(output)?;

    // Generate CA
    let ca_config = CaConfig::default();
    let (ca_cert, ca_key) = generate_ca(&ca_config)?;

    // Generate server cert
    let server_config = ServerCertConfig::default();
    let (server_cert, server_key) =
        generate_server_cert(&ca_cert, &ca_key, &server_config)?;

    // Generate client cert
    let client_config = ClientCertConfig::default();
    let (client_cert, client_key) =
        generate_client_cert(&ca_cert, &ca_key, &client_config)?;

    // Write files
    let ca_path = output.join("ca");
    fs::create_dir_all(&ca_path)?;
    fs::write(ca_path.join("ca-cert.pem"), ca_cert.pem())?;
    fs::write(ca_path.join("ca-key.pem"), ca_key.serialize_pem())?;

    let server_paths = write_cert_files(output.join("server"), &server_cert, &server_key)?;
    let client_paths = write_cert_files(output.join("client"), &client_cert, &client_key)?;

    // Create server fullchain
    let fullchain_path = output.join("server").join("fullchain.pem");
    let fullchain = format!("{}{}", server_cert.pem(), ca_cert.pem());
    fs::write(&fullchain_path, fullchain)?;

    Ok(TestCerts {
        ca_cert_path: ca_path.join("ca-cert.pem"),
        ca_key_path: ca_path.join("ca-key.pem"),
        server_cert_path: server_paths.0,
        server_key_path: server_paths.1,
        server_fullchain_path: fullchain_path,
        client_cert_path: client_paths.0,
        client_key_path: client_paths.1,
    })
}

/// Paths to generated test certificates
pub struct TestCerts {
    pub ca_cert_path: PathBuf,
    pub ca_key_path: PathBuf,
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,
    pub server_fullchain_path: PathBuf,
    pub client_cert_path: PathBuf,
    pub client_key_path: PathBuf,
}

/// Generate expired certificate for testing
pub fn generate_expired_cert(ca_cert: &Certificate, ca_key: &KeyPair) -> Result<(Certificate, KeyPair)> {
    let mut params = CertificateParams::new(vec!["expired.example.com".to_string()])?;

    let now = std::time::SystemTime::now();
    // Set validity in the past
    params.not_before = (now - std::time::Duration::from_secs(30 * 24 * 60 * 60)).into();
    params.not_after = (now - std::time::Duration::from_secs(1 * 24 * 60 * 60)).into();

    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, "expired.example.com");
    params.distinguished_name.push(DnType::OrganizationName, "TLS Course Test");

    params.is_ca = IsCa::NoCa;

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, ca_cert, ca_key)?;

    Ok((cert, key_pair))
}

/// Generate certificate with specific key type (for testing different algorithms)
pub fn generate_cert_with_key_type(
    ca_cert: &Certificate,
    ca_key: &KeyPair,
    cn: &str,
) -> Result<(Certificate, KeyPair)> {
    let mut params = CertificateParams::new(vec![cn.to_string()])?;

    let now = std::time::SystemTime::now();
    params.not_before = now.into();
    params.not_after = (now + std::time::Duration::from_secs(365 * 24 * 60 * 60)).into();

    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, cn);

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, ca_cert, ca_key)?;

    Ok((cert, key_pair))
}
