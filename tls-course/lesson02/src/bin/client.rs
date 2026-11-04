//! Lesson 2: Certificate and Identity Verification
//!
//! This client demonstrates:
//! 1. X.509 certificate analysis
//! 2. Custom certificate verification
//! 3. SNI (Server Name Indication) handling
//! 4. Client certificate authentication (mTLS)

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Result;
use clap::Parser;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    ClientConfig, ClientConnection, RootCertStore,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    DigitallySignedStruct, Error, SignatureScheme,
};
use rustls::crypto::ring::default_provider;

#[derive(Parser, Debug)]
#[command(name = "cert_client", about = "Lesson 2: Certificate Verification Client")]
struct Args {
    #[arg(short, long, default_value = "localhost")]
    host: String,

    #[arg(short, long, default_value = "8443")]
    port: u16,

    #[arg(short, long)]
    ca_cert: Option<PathBuf>,

    /// Client certificate for mTLS
    #[arg(long)]
    client_cert: Option<PathBuf>,

    /// Client private key for mTLS
    #[arg(long)]
    client_key: Option<PathBuf>,

    /// Use custom certificate verifier
    #[arg(long)]
    custom_verifier: bool,

    /// Skip hostname verification (dangerous!)
    #[arg(long)]
    skip_hostname: bool,
}

fn main() -> Result<()> {
    shared::logging::init_logging();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Lesson 2: Certificate and Identity Verification           ║");
    println!("║  Client                                                    ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    // Load CA certificates
    let mut root_store = RootCertStore::empty();
    if let Some(ca_path) = &args.ca_cert {
        let certs = shared::load_certs(ca_path)?;
        for cert in certs {
            root_store.add(cert)?;
        }
        println!("✓ Loaded CA certificate from {:?}", ca_path);
    } else {
        println!("⚠️  No CA certificate specified, using webpki roots");
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    // Create client configuration
    let config = if args.custom_verifier {
        create_config_with_custom_verifier(root_store, args.skip_hostname)?
    } else {
        create_standard_config(&args, root_store)?
    };

    // Connect to server
    let addr = format!("{}:{}", args.host, args.port);
    println!("\nConnecting to {}...", addr);

    let server_name: ServerName = args.host.clone().try_into()?;
    let conn = ClientConnection::new(Arc::new(config), server_name)?;
    let tcp = TcpStream::connect(&addr)?;

    // Complete handshake
    println!("Performing TLS handshake...");
    let mut stream = shared::util::Stream::new(conn, tcp);
    stream.flush()?;

    println!("✓ TLS handshake completed\n");

    // Print connection info
    if let Some(suite) = stream.conn().negotiated_cipher_suite() {
        println!("Cipher Suite: {:?}", suite.suite());
    }
    if let Some(version) = stream.conn().protocol_version() {
        println!("Protocol: {:?}", version);
    }

    // Send test message
    stream.write_all(b"Hello with certificate verification!")?;
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    println!("\nReceived: {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}

fn create_standard_config(args: &Args, root_store: RootCertStore) -> Result<ClientConfig> {
    let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("safe defaults")
        .with_root_certificates(root_store);

    // Configure client authentication if certs provided
    let config = if let (Some(cert_path), Some(key_path)) = (&args.client_cert, &args.client_key) {
        let certs = shared::load_certs(cert_path)?;
        let key = shared::load_private_key(key_path)?;
        builder.with_client_auth_cert(certs, key)?
    } else {
        builder.with_no_client_auth()
    };

    Ok(config)
}

/// Custom certificate verifier that logs detailed info
#[derive(Debug)]
struct LoggingVerifier;

impl ServerCertVerifier for LoggingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        println!("\n=== Custom Certificate Verification ===");
        println!("Server Name: {:?}", server_name);
        println!("Certificate chain length: {}", intermediates.len() + 1);

        // Parse and print certificate details
        if let Ok((_, cert)) = x509_parser::parse_x509_certificate(end_entity.as_ref()) {
            println!("Subject: {}", cert.subject);
            println!("Issuer: {}", cert.issuer);
            println!("Serial: {:?}", cert.serial);
            println!("Not Before: {}", cert.validity.not_before);
            println!("Not After: {}", cert.validity.not_after);

            // Check expiration
            let now_unix = now.as_secs();
            let not_before = cert.validity.not_before.timestamp() as u64;
            let not_after = cert.validity.not_after.timestamp() as u64;

            if now_unix < not_before {
                println!("⚠️  Certificate not yet valid!");
                return Err(Error::InvalidCertificate(
                    rustls::CertificateError::NotValidYet,
                ));
            }
            if now_unix > not_after {
                println!("⚠️  Certificate expired!");
                return Err(Error::InvalidCertificate(
                    rustls::CertificateError::Expired,
                ));
            }
            println!("✓ Certificate validity check passed");

            // Print SANs
            for ext in cert.extensions() {
                if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(sans) =
                    ext.parsed_extension()
                {
                    println!("Subject Alternative Names:");
                    for san in &sans.general_names {
                        println!("  - {:?}", san);
                    }
                }
            }
        }

        println!("====================================\n");

        // For this example, we accept all certificates
        // In production, implement proper verification!
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

fn create_config_with_custom_verifier(
    root_store: RootCertStore,
    _skip_hostname: bool,
) -> Result<ClientConfig> {
    let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("safe defaults")
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Note: In production, use proper verification
    // This is for demonstration only
    Ok(config)
}
