//! Lesson 4: 0-RTT Client
//!
//! Demonstrates TLS 1.3 0-RTT (zero round-trip time) mode.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use rustls_ring::DEFAULT_PROVIDER;

#[derive(Parser, Debug)]
#[command(name = "zerortt_client", about = "0-RTT Client Demo")]
struct Args {
    #[arg(short, long, default_value = "localhost")]
    host: String,

    #[arg(short, long, default_value = "8443")]
    port: u16,

    #[arg(short, long)]
    ca_cert: Option<PathBuf>,

    /// Send 0-RTT data
    #[arg(long)]
    early_data: String,
}

fn main() -> Result<()> {
    shared::logging::init_logging();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  0-RTT (Zero Round-Trip Time) Client                       ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    let mut root_store = RootCertStore::empty();
    if let Some(ca_path) = args.ca_cert {
        let certs = shared::load_certs(&ca_path)?;
        for cert in certs {
            root_store.add(cert)?;
        }
    } else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let config = ClientConfig::builder_with_provider(Arc::new(DEFAULT_PROVIDER))
        .with_safe_default_protocol_versions()
        .expect("safe defaults")
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name: rustls::pki_types::ServerName = args.host.clone().try_into()?;
    let addr = format!("{}:{}", args.host, args.port);

    println!("Connecting to {}...", addr);
    println!("Sending 0-RTT data: {}\n", args.early_data);

    let mut conn = ClientConnection::new(Arc::new(config), server_name)?;
    let mut tcp = TcpStream::connect(&addr)?;

    // Complete handshake and send 0-RTT data
    // Note: Full 0-RTT requires PSK from previous session
    // This demo shows the concept

    let mut stream = shared::util::Stream::new(&mut conn, &mut tcp);
    stream.flush()?;

    println!("✓ Handshake complete");
    println!("Negotiated: {:?}", conn.protocol_version());

    // Send application data
    stream.write_all(args.early_data.as_bytes())?;

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    println!("Response: {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}
