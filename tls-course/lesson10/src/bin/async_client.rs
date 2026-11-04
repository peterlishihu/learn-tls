//! Lesson 10: Async TLS Client
//!
//! Demonstrates async/await usage with tokio-rustls.

use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use rustls::{ClientConfig, RootCertStore};
use rustls::crypto::ring::default_provider;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Parser, Debug)]
#[command(name = "async_client", about = "Async TLS Client")]
struct Args {
    #[arg(short, long, default_value = "localhost")]
    host: String,

    #[arg(short, long, default_value = "8443")]
    port: u16,

    #[arg(short, long)]
    ca_cert: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    shared::logging::init_logging();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Async TLS Client (tokio-rustls)                           ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    // Create TLS config
    let mut root_store = RootCertStore::empty();
    if let Some(ca_path) = args.ca_cert {
        let certs = shared::load_certs(&ca_path)?;
        for cert in certs {
            root_store.add(cert)?;
        }
    } else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("safe defaults")
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    // Connect
    let addr = format!("{}:{}", args.host, args.port);
    println!("Connecting to {}...", addr);

    let stream = TcpStream::connect(&addr).await?;
    let server_name: rustls::pki_types::ServerName = args.host.clone().try_into()?;

    let start = std::time::Instant::now();
    let mut tls_stream = connector.connect(server_name, stream).await?;
    let elapsed = start.elapsed();

    println!("✓ TLS handshake completed in {:?}", elapsed);

    // Send data
    let msg = "Hello from async client!";
    tls_stream.write_all(msg.as_bytes()).await?;
    println!("→ Sent: {}", msg);

    // Read response
    let mut buf = [0u8; 1024];
    let n = tls_stream.read(&mut buf).await?;
    println!("← Received: {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}
