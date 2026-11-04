//! Lesson 2: Certificate and Identity Verification - Server
//!
//! This server demonstrates:
//! 1. Server certificate presentation
//! 2. Client certificate verification (mTLS)
//! 3. Certificate chain validation

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use rustls::{
    pki_types::CertificateDer,
    ServerConfig, ServerConnection,
};
use rustls::crypto::ring::default_provider;

#[derive(Parser, Debug)]
#[command(name = "cert_server", about = "Lesson 2: Certificate Verification Server")]
struct Args {
    #[arg(short, long, required = true)]
    cert: PathBuf,

    #[arg(short, long, required = true)]
    key: PathBuf,

    #[arg(short, long, default_value = "8443")]
    port: u16,

    /// CA certificate for client verification
    #[arg(long)]
    ca_cert: Option<PathBuf>,

    /// Require client certificate (mTLS)
    #[arg(long)]
    require_client_cert: bool,
}

fn main() -> Result<()> {
    shared::logging::init_logging();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Lesson 2: Certificate and Identity Verification           ║");
    println!("║  Server                                                    ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    // Load certificates
    let certs = shared::load_certs(&args.cert)?;
    let key = shared::load_private_key(&args.key)?;

    println!("✓ Loaded {} server certificate(s)", certs.len());

    /// 接受任意客户端证书的验证器（仅用于教学演示！生产环境必须校验）
    ///
    /// rustls 0.23 中 `server::Acceptor` 不是 ClientCertVerifier，
    /// "要求提供但不校验客户端证书"需要自定义验证器实现。
    #[derive(Debug)]
    struct AcceptAnyClientCert;

    impl rustls::server::danger::ClientCertVerifier for AcceptAnyClientCert {
        fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
            &[]
        }

        fn verify_client_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
            println!("⚠️  Client certificate accepted without verification (demo only)");
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    // Build server config
    let config_builder = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("safe defaults");

    // Configure client authentication
    let config = if args.require_client_cert {
        if let Some(ca_path) = args.ca_cert {
            let ca_certs = shared::load_certs(&ca_path)?;
            let mut roots = rustls::RootCertStore::empty();
            for cert in ca_certs {
                roots.add(cert).unwrap();
            }
            println!("✓ Client certificate verification enabled");
            config_builder.with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder(roots.into())
                    .build()
                    .unwrap(),
            )
        } else {
            println!("⚠️  No CA cert provided, accepting any client certificate");
            config_builder.with_client_cert_verifier(Arc::new(AcceptAnyClientCert))
        }
    } else {
        config_builder.with_no_client_auth()
    }
    .with_single_cert(certs, key)?;

    // Listen and accept connections
    let addr = format!("[::]:{}", args.port);
    let listener = TcpListener::bind(&addr)?;
    println!("\nServer listening on {}", addr);
    println!("mTLS enabled: {}\n", args.require_client_cert);

    for stream in listener.incoming() {
        let mut stream = stream?;
        let peer = stream.peer_addr()?;
        println!("Connection from {}", peer);

        let mut conn = ServerConnection::new(Arc::new(config.clone()))?;

        // Complete handshake
        if let Err(e) = complete_handshake(&mut conn, &mut stream) {
            eprintln!("  Handshake failed: {}", e);
            continue;
        }
        println!("  ✓ Handshake successful");

        // Check client certificate if mTLS
        if args.require_client_cert {
            if let Some(certs) = conn.peer_certificates() {
                println!("  Client presented {} certificate(s)", certs.len());
                for (i, cert) in certs.iter().enumerate() {
                    if let Ok((_, parsed)) = x509_parser::parse_x509_certificate(cert.as_ref()) {
                        println!("    [{}] Subject: {}", i, parsed.subject);
                    }
                }
            } else {
                println!("  ⚠️  No client certificate presented");
            }
        }

        // Handle client
        handle_client(&mut conn, &mut stream)?;
        println!("  Connection closed\n");
    }

    Ok(())
}

fn complete_handshake(conn: &mut ServerConnection, stream: &mut std::net::TcpStream) -> Result<()> {
    loop {
        while conn.wants_write() {
            conn.write_tls(stream)?;
        }
        stream.flush()?;

        if !conn.is_handshaking() {
            break;
        }

        if conn.wants_read() {
            match conn.read_tls(stream) {
                Ok(0) => anyhow::bail!("Connection closed during handshake"),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
            conn.process_new_packets()
                .map_err(|e| anyhow::anyhow!("TLS error: {}", e))?;
        }
    }
    Ok(())
}

fn handle_client(conn: &mut ServerConnection, stream: &mut std::net::TcpStream) -> Result<()> {
    let mut buf = [0u8; 1024];

    loop {
        while conn.wants_read() {
            match conn.read_tls(stream) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            }
            conn.process_new_packets()
                .map_err(|e| anyhow::anyhow!("TLS error: {}", e))?;
        }

        match conn.reader().read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                let msg = String::from_utf8_lossy(&buf[..n]);
                println!("  Received: {}", msg.trim());

                let reply = format!("Server received: {}\r\n", msg.trim());
                conn.writer().write_all(reply.as_bytes())?;

                while conn.wants_write() {
                    conn.write_tls(stream)?;
                }
                stream.flush()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }
}
