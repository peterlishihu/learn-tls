//! Lesson 2: Certificate Analyzer
//!
//! This tool analyzes X.509 certificates and displays detailed information
//! about their structure, extensions, and validity.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use x509_parser::prelude::*;
use rustls::crypto::ring::default_provider;

#[derive(Parser, Debug)]
#[command(name = "cert_analyzer", about = "X.509 Certificate Analyzer")]
struct Args {
    /// Certificate file to analyze (PEM or DER)
    #[arg(short, long)]
    cert: Option<PathBuf>,

    /// Remote host to fetch certificate from
    #[arg(short, long)]
    host: Option<String>,

    /// Port for remote connection
    #[arg(short, long, default_value = "443")]
    port: u16,

    /// Detailed analysis
    #[arg(short, long)]
    detailed: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║           X.509 Certificate Analyzer                       ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    let cert_data = if let Some(cert_path) = args.cert {
        std::fs::read(&cert_path)?
    } else if let Some(host) = args.host {
        fetch_remote_cert(&host, args.port)?
    } else {
        anyhow::bail!("Must specify --cert or --host");
    };

    analyze_certificate(&cert_data, args.detailed)?;

    Ok(())
}

fn fetch_remote_cert(host: &str, port: u16) -> Result<Vec<u8>> {
    use std::io::Write;
    use std::net::TcpStream;
    use std::sync::Arc;

    println!("Fetching certificate from {}:{}...", host, port);

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder_with_provider(
        Arc::new(default_provider()),
    )
    .with_safe_default_protocol_versions()
    .expect("safe defaults")
    .with_root_certificates(root_store)
    .with_no_client_auth();

    // ServerName<'static>：从 String 转换，避免借用生命周期问题
    let server_name: rustls::pki_types::ServerName =
        rustls::pki_types::ServerName::try_from(host.to_string())?;
    let addr = format!("{}:{}", host, port);

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;
    let mut sock = TcpStream::connect(&addr)?;

    // Perform handshake
    while conn.is_handshaking() {
        while conn.wants_write() {
            conn.write_tls(&mut sock)?;
        }
        sock.flush()?;

        if conn.wants_read() {
            match conn.read_tls(&mut sock) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
            conn.process_new_packets()
                .map_err(|e| anyhow::anyhow!("TLS error: {}", e))?;
        }
    }

    // Get peer certificates
    if let Some(certs) = conn.peer_certificates() {
        if let Some(first) = certs.first() {
            return Ok(first.as_ref().to_vec());
        }
    }

    anyhow::bail!("No certificate received from server");
}

fn analyze_certificate(data: &[u8], detailed: bool) -> Result<()> {
    // Try PEM format first
    let der_data = if data.starts_with(b"-----BEGIN") {
        // Parse PEM
        let mut reader = std::io::BufReader::new(data);
        let certs: Vec<_> = rustls_pemfile::certs(&mut reader).filter_map(|c| c.ok()).collect();
        if certs.is_empty() {
            anyhow::bail!("No certificates found in PEM file");
        }
        certs[0].as_ref().to_vec()
    } else {
        data.to_vec()
    };

    let (_, cert) = X509Certificate::from_der(&der_data)?;

    // Basic info
    println!("\n=== Certificate Overview ===");
    println!("Subject: {}", cert.subject);
    println!("Issuer: {}", cert.issuer);
    println!("Serial Number: {:?}", cert.serial);
    println!("Version: V{:?}", cert.version);

    // Validity
    println!("\n=== Validity Period ===");
    println!("Not Before: {}", cert.validity.not_before);
    println!("Not After: {}", cert.validity.not_after);

    let now = std::time::SystemTime::now();
    let not_before = std::time::UNIX_EPOCH + std::time::Duration::from_secs(cert.validity.not_before.timestamp() as u64);
    let not_after = std::time::UNIX_EPOCH + std::time::Duration::from_secs(cert.validity.not_after.timestamp() as u64);

    if now < not_before {
        println!("⚠️  Status: NOT YET VALID");
    } else if now > not_after {
        println!("⚠️  Status: EXPIRED");
    } else {
        println!("✓ Status: VALID");
    }

    // Signature
    println!("\n=== Signature ===");
    println!("Algorithm: {:?}", cert.signature_algorithm);

    // Public Key
    println!("\n=== Public Key ===");
    println!("Algorithm: {:?}", cert.signature_algorithm);
    println!("Key Size: {} bits", cert.public_key().raw.len() * 8);

    // Extensions
    println!("\n=== Extensions ===");
    for ext in cert.extensions() {
        print_extension(ext)?;
    }

    if detailed {
        println!("\n=== Raw Certificate (Hex) ===");
        let hex_str = hex::encode(&der_data);
        for chunk in hex_str.as_bytes().chunks(64) {
            println!("{}", std::str::from_utf8(chunk).unwrap_or("???"));
        }
    }

    Ok(())
}

fn print_extension(ext: &X509Extension) -> Result<()> {
    let oid = &ext.oid;
    let name = match oid.to_string().as_str() {
        "2.5.29.14" => "Subject Key Identifier",
        "2.5.29.15" => "Key Usage",
        "2.5.29.17" => "Subject Alternative Name",
        "2.5.29.19" => "Basic Constraints",
        "2.5.29.31" => "CRL Distribution Points",
        "2.5.29.32" => "Certificate Policies",
        "2.5.29.35" => "Authority Key Identifier",
        "2.5.29.37" => "Extended Key Usage",
        "1.3.6.1.5.5.7.1.1" => "Authority Information Access",
        "1.3.6.1.4.1.11129.2.4.2" => "Signed Certificate Timestamp (SCT)",
        _ => &oid.to_string(),
    };

    println!("\n  [{}] {}", name, oid);
    println!("      Critical: {}", ext.critical);

    // x509-parser 0.16: parsed_extension() 直接返回 &ParsedExtension（不再是 Result）
    match ext.parsed_extension() {
        ParsedExtension::SubjectAlternativeName(san) => {
            for gn in &san.general_names {
                match gn {
                    GeneralName::DNSName(dns) => println!("      DNS: {}", dns),
                    GeneralName::IPAddress(ip) => println!("      IP: {:?}", ip),
                    GeneralName::RFC822Name(email) => println!("      Email: {}", email),
                    _ => println!("      {:?}", gn),
                }
            }
        }
        ParsedExtension::BasicConstraints(bc) => {
            println!("      CA: {}", bc.ca);
            if let Some(path_len) = bc.path_len_constraint {
                println!("      Path Length Constraint: {}", path_len);
            }
        }
        ParsedExtension::KeyUsage(ku) => {
            println!("      Usage: {:?}", ku);
        }
        // x509-parser 0.16: 常见 EKU 已解析为 bool 字段，其余 OID 在 other 中
        ParsedExtension::ExtendedKeyUsage(eku) => {
            if eku.any { println!("      Any"); }
            if eku.server_auth { println!("      Server Authentication"); }
            if eku.client_auth { println!("      Client Authentication"); }
            if eku.code_signing { println!("      Code Signing"); }
            if eku.email_protection { println!("      Email Protection"); }
            if eku.time_stamping { println!("      Time Stamping"); }
            if eku.ocsp_signing { println!("      OCSP Signing"); }
            for oid in &eku.other {
                println!("      Other: {}", oid);
            }
        }
        _ => {
            println!("      Raw data: {} bytes", ext.value.len());
        }
    }

    Ok(())
}
