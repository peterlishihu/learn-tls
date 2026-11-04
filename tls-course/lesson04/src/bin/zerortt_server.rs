//! Lesson 4: 0-RTT Server
//!
//! Demonstrates TLS 1.3 0-RTT server-side handling.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use rustls::{ServerConfig, ServerConnection};
use rustls::crypto::ring::default_provider;

#[derive(Parser, Debug)]
#[command(name = "zerortt_server", about = "0-RTT Server Demo")]
struct Args {
    #[arg(short, long, required = true)]
    cert: PathBuf,

    #[arg(short, long, required = true)]
    key: PathBuf,

    #[arg(short, long, default_value = "8443")]
    port: u16,
}

fn main() -> Result<()> {
    shared::logging::init_logging();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  0-RTT (Zero Round-Trip Time) Server                       ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    let certs = shared::load_certs(&args.cert)?;
    let key = shared::load_private_key(&args.key)?;

    let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("safe defaults")
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let addr = format!("[::]:{}", args.port);
    let listener = TcpListener::bind(&addr)?;

    println!("Server listening on {}\n", addr);
    println!("Note: 0-RTT requires previous session ticket.");
    println!("First connection will be full handshake.\n");

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

        println!("  ✓ Handshake complete");
        println!("  Protocol: {:?}", conn.protocol_version());

        // Handle 0-RTT data if present
        // rustls 0.23：ServerConnection 没有 is_early_data_accepted()，
        // 通过 early_data() 是否返回 Some 判断 0-RTT 是否被接受
        if conn.early_data().is_some() {
            println!("  ✓ 0-RTT data accepted");
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

                let reply = "Server received 0-RTT data!\r\n";
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
