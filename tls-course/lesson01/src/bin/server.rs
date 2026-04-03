//! Lesson 1: TLS Handshake Explorer - Server
//!
//! This server demonstrates:
//! 1. Detailed logging of the TLS handshake process
//! 2. Server-side handshake handling
//! 3. Certificate loading and presentation
//! 4. Client connection analysis
//!
//! # TLS Handshake Overview (Server Perspective)
//!
//! ```text
//! 1. CLIENT: Send ClientHello
//!    (received by server)
//!
//! 2. SERVER: Parse ClientHello
//!    - Check supported versions
//!    - Select cipher suite
//!    - Process extensions (SNI, ALPN, etc.)
//!
//! 3. SERVER: Send ServerHello
//!    - Selected version
//!    - Selected cipher suite
//!    - Server random
//!
//! 4. SERVER: Send Certificate chain
//!    - Server certificate
//!    - Intermediate CAs
//!
//! 5. [TLS 1.2] SERVER: Send ServerKeyExchange
//!    - Ephemeral public key
//!    - Signature
//!
//! 6. [TLS 1.2] SERVER: Send ServerHelloDone
//!
//! 7. SERVER: Wait for Client response
//!    - Certificate (if client auth required)
//!    - ClientKeyExchange
//!    - ChangeCipherSpec
//!    - Finished
//!
//! 8. SERVER: Send ChangeCipherSpec + Finished
//!
//! 9. SERVER: Receive encrypted application data
//! ```

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use rustls::pki_types::CertificateDer;
use rustls::{ServerConfig, ServerConnection};
use rustls_ring::DEFAULT_PROVIDER;

/// Command line arguments for the TLS handshake explorer server
#[derive(Parser, Debug)]
#[command(
    name = "tls_handshake_server",
    about = "TLS Handshake Explorer - Server Example",
    long_about = "Demonstrates TLS handshake from server perspective with detailed logging"
)]
struct Args {
    /// Server certificate file (PEM format)
    #[arg(short, long, required = true)]
    cert: PathBuf,

    /// Server private key file (PEM format)
    #[arg(short, long, required = true)]
    key: PathBuf,

    /// Port to listen on
    #[arg(short, long, default_value = "8443")]
    port: u16,

    /// Require client certificate (mTLS)
    #[arg(long)]
    require_client_cert: bool,

    /// Protocol version (tls12, tls13, or auto)
    #[arg(short, long, default_value = "auto")]
    version: String,

    /// Print detailed handshake analysis
    #[arg(long)]
    analyze: bool,
}

fn main() -> Result<()> {
    // Initialize logging
    shared::logging::init_logging();
    shared::logging::log_key_logging_info();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║       TLS Handshake Explorer - Server                      ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();

    // Load certificates and private key
    println!("[1] Loading server certificates...");
    let certs = load_certificates(&args.cert)?;
    println!("    ✓ Loaded {} certificate(s)", certs.len());

    let key = load_private_key(&args.key)?;
    println!("    ✓ Loaded private key");

    // Create TLS configuration
    let config = create_server_config(&args, certs, key)?;
    print_config_info(&config, &args);

    // Start listening
    let addr = format!("[::]:{}", args.port);
    let listener = TcpListener::bind(&addr)?;
    println!("\n[2] Server listening on {}", addr);
    println!("    Waiting for client connections...");
    println!("    Press Ctrl+C to stop\n");

    // Accept connections
    for (conn_id, stream_result) in listener.incoming().enumerate() {
        let mut stream = match stream_result {
            Ok(s) => s,
            Err(e) => {
                eprintln!("    ✗ Connection error: {}", e);
                continue;
            }
        };

        let peer_addr = stream.peer_addr()?;
        println!("\n╔════════════════════════════════════════════════════════════╗");
        println!("║ Connection #{:<5} from {:<35} ║", conn_id + 1, peer_addr);
        println!("╚════════════════════════════════════════════════════════════╝");

        // Create TLS connection
        let mut conn = ServerConnection::new(Arc::new(config.clone()))?;

        // Handle handshake
        println!("[3] Performing TLS handshake...");
        let start_time = std::time::Instant::now();

        // Complete handshake
        let result = complete_handshake(&mut conn, &mut stream);

        match result {
            Ok(()) => {
                let handshake_time = start_time.elapsed();
                println!("    ✓ TLS handshake completed in {:?}", handshake_time);

                // Print handshake results
                print_handshake_results(&conn);

                // Handle application data
                if args.analyze {
                    analyze_handshake(&conn);
                }

                handle_client(&mut conn, &mut stream)?;
            }
            Err(e) => {
                eprintln!("    ✗ TLS handshake failed: {}", e);
            }
        }

        println!("\n[✓] Connection closed");
    }

    Ok(())
}

/// Load certificates from PEM file
fn load_certificates(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>> {
    let certfile = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(certfile);

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut reader)
            .filter_map(|cert| cert.ok())
            .collect();

    if certs.is_empty() {
        anyhow::bail!("No certificates found in file");
    }

    Ok(certs)
}

/// Load private key from PEM file
fn load_private_key(path: &PathBuf) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let keyfile = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(keyfile);

    // Try PKCS#8 first
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .filter_map(|key| key.ok())
        .next()
    {
        return Ok(rustls::pki_types::PrivateKeyDer::try_from(key)?);
    }

    // Reset reader and try RSA
    reader.rewind()?;
    if let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader)
        .filter_map(|key| key.ok())
        .next()
    {
        return Ok(rustls::pki_types::PrivateKeyDer::try_from(key)?);
    }

    anyhow::bail!("No private key found in file")
}

/// Create server configuration based on arguments
fn create_server_config(
    args: &Args,
    certs: Vec<CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<ServerConfig> {
    let config = match args.version.as_str() {
        "tls13" => {
            println!("[Config] Enforcing TLS 1.3 only");
            ServerConfig::builder_with_provider(Arc::new(DEFAULT_PROVIDER))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_no_client_auth()
                .with_single_cert(certs, key)?
        }
        "tls12" => {
            println!("[Config] Enforcing TLS 1.2 only");
            ServerConfig::builder_with_provider(Arc::new(DEFAULT_PROVIDER))
                .with_protocol_versions(&[&rustls::version::TLS12])?
                .with_no_client_auth()
                .with_single_cert(certs, key)?
        }
        _ => {
            println!("[Config] Auto-negotiating TLS version (1.2 or 1.3)");
            ServerConfig::builder_with_provider(Arc::new(DEFAULT_PROVIDER))
                .with_safe_default_protocol_versions()
                .expect("safe defaults")
                .with_no_client_auth()
                .with_single_cert(certs, key)?
        }
    };

    Ok(config)
}

/// Print server configuration information
fn print_config_info(_config: &ServerConfig, args: &Args) {
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║ Server Configuration                                       ║");
    println!("╠════════════════════════════════════════════════════════════╣");
    println!("║ Certificate: {:?}", args.cert);
    println!("║ Private Key: {:?}", args.key);
    println!("║ Port: {}", args.port);
    println!("║ Client Certificate Required: {}", args.require_client_cert);
    println!("╚════════════════════════════════════════════════════════════╝");
}

/// Complete TLS handshake
fn complete_handshake(
    conn: &mut ServerConnection,
    stream: &mut std::net::TcpStream,
) -> Result<()> {
    // Read ClientHello and send response
    loop {
        // Write any pending TLS data
        while conn.wants_write() {
            conn.write_tls(stream)?;
        }
        stream.flush()?;

        // Check if handshake is complete
        if !conn.is_handshaking() {
            break;
        }

        // Read TLS data from client
        if conn.wants_read() {
            match conn.read_tls(stream) {
                Ok(0) => {
                    anyhow::bail!("Connection closed during handshake");
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => return Err(e.into()),
            }

            // Process TLS messages
            conn.process_new_packets()
                .map_err(|e| anyhow::anyhow!("TLS error: {}", e))?;
        }
    }

    // Final flush
    while conn.wants_write() {
        conn.write_tls(stream)?;
    }
    stream.flush()?;

    Ok(())
}

/// Print handshake results
fn print_handshake_results(conn: &ServerConnection) {
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║ Handshake Results                                          ║");
    println!("╠════════════════════════════════════════════════════════════╣");

    if let Some(version) = conn.protocol_version() {
        let version_str = match version {
            rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2",
            rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3",
            _ => "Unknown",
        };
        println!("║ Protocol Version: {:<38} ║", version_str);
    }

    if let Some(suite) = conn.negotiated_cipher_suite() {
        println!("║ Cipher Suite: {:?}", suite.suite());

        if let Some(tls13) = suite.tls13() {
            println!("║ Key Exchange: {:?}", tls13.key_exchange_algorithm());
        }
    }

    if let Some(alpn) = conn.alpn_protocol() {
        println!("║ ALPN Protocol: {:<39} ║", String::from_utf8_lossy(alpn));
    }

    println!("╚════════════════════════════════════════════════════════════╝");
}

/// Handle client communication
fn handle_client(
    conn: &mut ServerConnection,
    stream: &mut std::net::TcpStream,
) -> Result<()> {
    println!("\n[4] Handling client communication...");

    // Read data from client
    let mut buf = [0u8; 1024];

    loop {
        // Process any pending TLS data
        while conn.wants_read() {
            match conn.read_tls(stream) {
                Ok(0) => {
                    println!("    Client disconnected");
                    return Ok(());
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            }

            conn.process_new_packets()
                .map_err(|e| anyhow::anyhow!("TLS error: {}", e))?;
        }

        // Try to read application data
        match conn.reader().read(&mut buf) {
            Ok(0) => {
                println!("    Client disconnected");
                return Ok(());
            }
            Ok(n) => {
                let received = String::from_utf8_lossy(&buf[..n]);
                println!("    ← Received ({} bytes): {}", n, received.trim());

                // Echo back with a message
                let response = format!(
                    "TLS Server received: {}\r\n",
                    received.trim()
                );
                conn.writer().write_all(response.as_bytes())?;
                println!("    → Sent: {}", response.trim());

                // Flush TLS data
                while conn.wants_write() {
                    conn.write_tls(stream)?;
                }
                stream.flush()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data available, continue
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Perform detailed handshake analysis
fn analyze_handshake(conn: &ServerConnection) {
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║ Detailed Handshake Analysis                                ║");
    println!("╠════════════════════════════════════════════════════════════╣");

    // Print client SNI
    if let Some(sni) = conn.server_name() {
        println!("║ Client SNI: {:?}", sni);
    }

    // Print negotiated parameters
    if let Some(version) = conn.protocol_version() {
        println!("║ Negotiated Version: {:?}", version);
    }

    if let Some(suite) = conn.negotiated_cipher_suite() {
        println!("║ Negotiated Cipher: {:?}", suite.suite());
        println!("║ Suite Strength: {:?} bit", suite.algorithm_key_len());
    }

    // Print client certificate info if available
    if let Some(client_certs) = conn.peer_certificates() {
        println!("║ Client Certificate Chain ({} certificates):", client_certs.len());
        for (i, cert) in client_certs.iter().enumerate() {
            println!("║   [{}] {} bytes", i, cert.len());
        }
    }

    println!("╚════════════════════════════════════════════════════════════╝");
}
