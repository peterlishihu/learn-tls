//! Lesson 10: Async TLS Server
//!
//! Demonstrates async server with tokio-rustls.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use rustls::{ServerConfig, ServerConnection};
use rustls_ring::DEFAULT_PROVIDER;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

#[derive(Parser, Debug)]
#[command(name = "async_server", about = "Async TLS Server")]
struct Args {
    #[arg(short, long, required = true)]
    cert: PathBuf,

    #[arg(short, long, required = true)]
    key: PathBuf,

    #[arg(short, long, default_value = "8443")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    shared::logging::init_logging();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Async TLS Server (tokio-rustls)                           ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    // Load certificates
    let certs = shared::load_certs(&args.cert)?;
    let key = shared::load_private_key(&args.key)?;

    let config = ServerConfig::builder_with_provider(Arc::new(DEFAULT_PROVIDER))
        .with_safe_default_protocol_versions()
        .expect("safe defaults")
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let acceptor = TlsAcceptor::from(Arc::new(config));

    // Listen
    let addr = format!("[::]:{}", args.port);
    let listener = TcpListener::bind(&addr).await?;
    println!("Server listening on {}\n", addr);

    // Accept connections
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client(acceptor, stream, peer).await {
                eprintln!("Error handling {}: {}", peer, e);
            }
        });
    }
}

async fn handle_client(
    acceptor: TlsAcceptor,
    stream: TcpStream,
    peer: std::net::SocketAddr,
) -> Result<()> {
    println!("Connection from {}", peer);

    let start = std::time::Instant::now();
    let mut tls_stream = acceptor.accept(stream).await?;
    let elapsed = start.elapsed();

    println!("  ✓ TLS handshake completed in {:?}", elapsed);

    let mut buf = [0u8; 1024];
    loop {
        match tls_stream.read(&mut buf).await {
            Ok(0) => {
                println!("  Client disconnected");
                break;
            }
            Ok(n) => {
                let msg = String::from_utf8_lossy(&buf[..n]);
                println!("  ← Received: {}", msg.trim());

                let reply = format!("Server received: {}\n", msg.trim());
                tls_stream.write_all(reply.as_bytes()).await?;
            }
            Err(e) => {
                eprintln!("  Read error: {}", e);
                break;
            }
        }
    }

    Ok(())
}
