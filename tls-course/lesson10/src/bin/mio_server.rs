//! Lesson 10: MIO-based TLS Server
//!
//! Demonstrates low-level async I/O with mio.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Token};
use rustls::{ServerConfig, ServerConnection};
use rustls_ring::DEFAULT_PROVIDER;

const SERVER: Token = Token(0);

#[derive(Parser, Debug)]
#[command(name = "mio_server", about = "MIO TLS Server")]
struct Args {
    #[arg(short, long, required = true)]
    cert: PathBuf,

    #[arg(short, long, required = true)]
    key: PathBuf,

    #[arg(short, long, default_value = "8443")]
    port: u16,
}

struct Client {
    conn: ServerConnection,
    stream: TcpStream,
    addr: SocketAddr,
}

fn main() -> Result<()> {
    shared::logging::init_logging();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  MIO TLS Server                                            ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    // Load certificates
    let certs = shared::load_certs(&args.cert)?;
    let key = shared::load_private_key(&args.key)?;

    let config = ServerConfig::builder_with_provider(Arc::new(DEFAULT_PROVIDER))
        .with_safe_default_protocol_versions()
        .expect("safe defaults")
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let config = Arc::new(config);

    // Create poll and listener
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1024);

    let addr = format!("[::]:{}", args.port).parse()?;
    let mut listener = TcpListener::bind(addr)?;
    poll.registry()
        .register(&mut listener, SERVER, Interest::READABLE)?;

    println!("Server listening on {}\n", addr);

    let mut clients: HashMap<Token, Client> = HashMap::new();
    let mut next_token = 1;

    loop {
        poll.poll(&mut events, None)?;

        for event in events.iter() {
            match event.token() {
                SERVER => {
                    // Accept new connections
                    while let Ok((mut stream, addr)) = listener.accept() {
                        let token = Token(next_token);
                        next_token += 1;

                        println!("New connection from {} (token {:?})", addr, token);

                        poll.registry()
                            .register(&mut stream, token, Interest::READABLE | Interest::WRITABLE)?;

                        let conn = ServerConnection::new(config.clone())?;
                        clients.insert(token, Client { conn, stream, addr });
                    }
                }
                token => {
                    if let Some(client) = clients.get_mut(&token) {
                        if let Err(e) = handle_client(client) {
                            println!("  Error from {}: {}", client.addr, e);
                            clients.remove(&token);
                        } else if client.conn.is_handshaking() {
                            // Still handshaking, keep connection
                        }
                    }
                }
            }
        }
    }
}

fn handle_client(client: &mut Client) -> Result<()> {
    // Read TLS data
    if client.conn.wants_read() {
        match client.conn.read_tls(&mut client.stream) {
            Ok(0) => anyhow::bail!("Connection closed"),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }

        client.conn.process_new_packets()
            .map_err(|e| anyhow::anyhow!("TLS error: {}", e))?;
    }

    // Write TLS data
    while client.conn.wants_write() {
        client.conn.write_tls(&mut client.stream)?;
    }

    // Handle application data
    if !client.conn.is_handshaking() {
        let mut buf = [0u8; 1024];
        match client.conn.reader().read(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                let msg = String::from_utf8_lossy(&buf[..n]);
                println!("  ← From {}: {}", client.addr, msg.trim());

                let reply = format!("Server got: {}\n", msg.trim());
                client.conn.writer().write_all(reply.as_bytes())?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}
