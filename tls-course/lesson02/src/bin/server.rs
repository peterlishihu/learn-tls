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
    server::{ClientCertVerified, ClientCertVerifier},
};
use rustls_ring::DEFAULT_PROVIDER;

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

    // Build server config
    let mut config = ServerConfig::builder_with_provider(Arc::new(DEFAULT_PROVIDER))
        .with_safe_default_protocol_versions()
        .expect("safe defaults");

    // Configure client authentication
    config = if args.require_client_cert {
        if let Some(ca_path) = args.ca_cert {
            let ca_certs = shared::load_certs(&ca_path)?;
            let mut roots = rustls::RootCertStore::empty();
            for cert in ca_certs {
                roots.add(cert).unwrap();
            }
            println!("✓ Client certificate verification enabled");
            config.with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder(roots.into())
                    .build()
                    .unwrap(),
            )
        } else {
            println!("⚠️  No CA cert provided, using self-signed verifier");
            config.with_client_cert_verifier(rustls::server::Acceptor::default())
        }
    } else {
        config.with_no_client_auth()
    };

    let config = config.with_single_cert(certs, key)?;

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
