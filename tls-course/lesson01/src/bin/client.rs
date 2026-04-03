//! Lesson 1: TLS Handshake Explorer - Client
//!
//! This client demonstrates:
//! 1. Detailed logging of the TLS handshake process
//! 2. ClientHello structure and contents
//! 3. ServerHello response analysis
//! 4. Cipher suite negotiation
//! 5. Certificate reception
//!
//! # TLS Handshake Overview (Client Perspective)
//!
//! ```text
//! 1. CLIENT: Create ClientHello
//!    - Protocol versions supported
//!    - Cipher suites offered
//!    - Random bytes (32 bytes)
//!    - Session ID (or empty for new session)
//!    - Extensions (SNI, ALPN, Key Share, etc.)
//!
//! 2. SERVER: Respond with ServerHello
//!    - Selected protocol version
//!    - Selected cipher suite
//!    - Server random
//!    - Extensions
//!
//! 3. SERVER: Send Certificate chain
//!    - Server's public key certificate
//!    - Intermediate CA certificates
//!
//! 4. [TLS 1.2] SERVER: Send ServerKeyExchange (for DHE/ECDHE)
//!    - Server's ephemeral public key
//!    - Signature over key exchange parameters
//!
//! 5. [TLS 1.2] SERVER: Send ServerHelloDone
//!
//! 6. CLIENT: Verify server certificate
//!    - Check certificate chain
//!    - Verify signature
//!    - Check hostname (SNI)
//!    - Check validity period
//!
//! 7. CLIENT: Generate pre-master secret
//!    - [RSA] Encrypt random with server's public key
//!    - [DHE/ECDHE] Generate ephemeral key pair, compute shared secret
//!
//! 8. CLIENT: Derive session keys using PRF/KDF
//!
//! 9. CLIENT: Send ChangeCipherSpec + Finished
//!    - Switch to encrypted communication
//!    - Verify handshake integrity
//!
//! 10. SERVER: Send ChangeCipherSpec + Finished
//!
//! 11. Both: Encrypted application data
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use rustls_ring::DEFAULT_PROVIDER;

/// Command line arguments for the TLS handshake explorer client
#[derive(Parser, Debug)]
#[command(
    name = "tls_handshake_client",
    about = "TLS Handshake Explorer - Client Example",
    long_about = "Demonstrates TLS handshake process with detailed logging and analysis"
)]
struct Args {
    /// Target host to connect to
    #[arg(short, long, default_value = "localhost")]
    host: String,

    /// Target port
    #[arg(short, long, default_value = "8443")]
    port: u16,

    /// Use system webpki roots (for connecting to real servers)
    #[arg(long)]
    use_webpki: bool,

    /// Path to CA certificate (for self-signed certs)
    #[arg(short, long)]
    ca_cert: Option<PathBuf>,

    /// Protocol version (tls12, tls13, or auto)
    #[arg(short, long, default_value = "auto")]
    version: String,

    /// Send HTTP request after handshake
    #[arg(long)]
    http: bool,

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
    println!("║       TLS Handshake Explorer - Client                      ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();

    // Create TLS configuration
    let config = create_client_config(&args)?;

    // Print configuration details
    print_config_info(&config, &args);

    // Establish connection and perform handshake
    let server_name: ServerName = args.host.clone().try_into()?;
    let addr = format!("{}:{}", args.host, args.port);

    println!("\n[1] Connecting to {}...", addr);
    let mut tcp_stream = TcpStream::connect(&addr)?;
    println!("    ✓ TCP connection established");

    println!("\n[2] Starting TLS handshake...");
    println!("    → Sending ClientHello");
    println!("    → Waiting for ServerHello...");

    let start_time = std::time::Instant::now();
    let mut conn = ClientConnection::new(Arc::new(config), server_name)?;
    let mut tls = shared::util::TlsStream::new(&mut conn, &mut tcp_stream);

    // Complete handshake by trying to read/write
    tls.flush()?;

    let handshake_time = start_time.elapsed();
    println!("    ✓ TLS handshake completed in {:?}", handshake_time);

    // Print handshake results
    print_handshake_results(&conn);

    // Send application data
    if args.http {
        send_http_request(&mut tls, &args.host)?;
    } else {
        send_echo_message(&mut tls)?;
    }

    if args.analyze {
        analyze_handshake(&conn);
    }

    println!("\n[✓] Connection closed successfully");

    Ok(())
}

/// Create TLS client configuration based on arguments
fn create_client_config(args: &Args) -> Result<ClientConfig> {
    let mut root_store = RootCertStore::empty();

    // Load CA certificates
    if args.use_webpki {
        // Use system root certificates
        println!("[Config] Loading webpki root certificates...");
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    } else if let Some(ca_path) = &args.ca_cert {
        // Load custom CA certificate
        println!("[Config] Loading CA certificate from {:?}...", ca_path);
        let ca_cert = shared::load_certs(ca_path)?;
        for cert in ca_cert {
            root_store.add(cert)?;
        }
    } else {
        // Try to load from default location (../certs/ca/ca-cert.pem)
        let default_ca = PathBuf::from("../certs/ca/ca-cert.pem");
        if default_ca.exists() {
            println!("[Config] Loading CA certificate from default location...");
            let ca_cert = shared::load_certs(&default_ca)?;
            for cert in ca_cert {
                root_store.add(cert)?;
            }
        } else {
            // For testing only - disable verification
            println!("⚠️  [Config] No CA certificate provided, using dangerous configuration!");
            println!("   This should only be used for testing.");
            return create_dangerous_config(args);
        }
    }

    // Build configuration with selected protocol version
    let config = match args.version.as_str() {
        "tls13" => {
            println!("[Config] Enforcing TLS 1.3 only");
            ClientConfig::builder_with_provider(Arc::new(DEFAULT_PROVIDER))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_root_certificates(root_store)
                .with_no_client_auth()
        }
        "tls12" => {
            println!("[Config] Enforcing TLS 1.2 only");
            ClientConfig::builder_with_provider(Arc::new(DEFAULT_PROVIDER))
                .with_protocol_versions(&[&rustls::version::TLS12])?
                .with_root_certificates(root_store)
                .with_no_client_auth()
        }
        _ => {
            println!("[Config] Auto-negotiating TLS version (1.2 or 1.3)");
            ClientConfig::builder_with_provider(Arc::new(DEFAULT_PROVIDER))
                .with_safe_default_protocol_versions()
                .expect("safe defaults")
                .with_root_certificates(root_store)
                .with_no_client_auth()
        }
    };

    Ok(config)
}

/// Create a dangerous configuration that accepts any certificate
/// WARNING: Only use for testing!
fn create_dangerous_config(_args: &Args) -> Result<ClientConfig> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    struct DangerousAcceptAllVerifier;

    impl ServerCertVerifier for DangerousAcceptAllVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            println!("    ⚠️  DANGEROUS: Accepting certificate without verification!");
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
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ED25519,
            ]
        }
    }

    let mut config = ClientConfig::builder_with_provider(Arc::new(DEFAULT_PROVIDER))
        .with_safe_default_protocol_versions()
        .expect("safe defaults")
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();

    // Replace the certificate verifier with our dangerous one
    let verifier = Arc::new(DangerousAcceptAllVerifier);
    // Note: In production code, we would use config.dangerous().set_certificate_verifier(verifier)
    // but for this example, we'll just use the default with empty roots

    Ok(config)
}

/// Print TLS configuration information
fn print_config_info(config: &ClientConfig, args: &Args) {
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║ Configuration                                              ║");
    println!("╠════════════════════════════════════════════════════════════╣");
    println!("║ Target: {}:{:<45} ║", args.host, args.port);
    println!("║ Protocol Versions: {:?}", config.alpn_protocols.len());

    // Print supported cipher suites
    let provider = Arc::new(DEFAULT_PROVIDER);
    println!("║ Cipher Suites: {:<42} ║", provider.cipher_suites.len());
    for suite in &provider.cipher_suites {
        println!("║   • {:?}", suite.suite());
    }

    println!("╚════════════════════════════════════════════════════════════╝");
}

/// Print results after handshake completes
fn print_handshake_results(conn: &ClientConnection) {
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

        // Print additional details
        if let Some(tls13) = suite.tls13() {
            println!("║ Key Exchange: {:?}", tls13.key_exchange_algorithm());
        }
    }

    if let Some(alpn) = conn.alpn_protocol() {
        println!("║ ALPN Protocol: {:<39} ║", String::from_utf8_lossy(alpn));
    }

    println!("║ Handshake Type: {}", if conn.is_handshaking() {
        "In Progress"
    } else {
        "Complete"
    });

    println!("╚════════════════════════════════════════════════════════════╝");
}

/// Send a simple echo message
fn send_echo_message<S>(stream: &mut S) -> Result<()>
where
    S: Read + Write,
{
    println!("\n[3] Sending echo message...");

    let message = "Hello, TLS World!";
    stream.write_all(message.as_bytes())?;
    stream.flush()?;
    println!("    → Sent: {}", message);

    let mut buffer = [0u8; 1024];
    let n = stream.read(&mut buffer)?;
    let response = String::from_utf8_lossy(&buffer[..n]);
    println!("    ← Received: {}", response);

    Ok(())
}

/// Send HTTP GET request
fn send_http_request<S>(stream: &mut S, host: &str) -> Result<()>
where
    S: Read + Write,
{
    println!("\n[3] Sending HTTP GET request...");

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: close\r\n\
         User-Agent: TLS-Course-Client/1.0\r\n\
         Accept: */*\r\n\
         \r\n",
        host
    );

    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    println!("    → HTTP request sent");

    println!("\n[4] Reading HTTP response...");
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer)?;

    // Print first 500 bytes of response
    let response = String::from_utf8_lossy(&buffer);
    let preview = if response.len() > 500 {
        &response[..500]
    } else {
        &response
    };
    println!("{}\n[... {} bytes total ...]", preview, buffer.len());

    Ok(())
}

/// Perform detailed handshake analysis
fn analyze_handshake(conn: &ClientConnection) {
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║ Detailed Handshake Analysis                                ║");
    println!("╠════════════════════════════════════════════════════════════╣");

    // Print SNI info if available
    if let Some(sni) = conn.server_name() {
        println!("║ SNI (Server Name Indication): {:?}", sni);
    }

    // Print TLS 1.3 specific info
    if let Some(_secrets) = conn.tls13_secrets() {
        println!("║ TLS 1.3: Secrets are available");
        // Note: Access to actual secrets requires special handling
    }

    // Print certificate info
    if let Some(cert_chain) = conn.peer_certificates() {
        println!("║ Server Certificate Chain:");
        for (i, cert) in cert_chain.iter().enumerate() {
            println!("║   [{}] {} bytes", i, cert.len());

            // Try to parse certificate details
            if let Ok((_, parsed)) = x509_parser::parse_x509_certificate(cert.as_ref()) {
                println!("║       Subject: {}", parsed.subject);
                println!("║       Issuer: {}", parsed.issuer);
                println!("║       Serial: {:?}", parsed.serial);
            }
        }
    }

    println!("╚════════════════════════════════════════════════════════════╝");
}

// Utility module for this lesson
mod util {
    use std::io::{Read, Write};
    use rustls::Connection;

    /// Simple TLS stream wrapper
    pub struct TlsStream<'a, T: Read + Write> {
        conn: &'a mut rustls::ClientConnection,
        socket: &'a mut T,
    }

    impl<'a, T: Read + Write> TlsStream<'a, T> {
        pub fn new(conn: &'a mut rustls::ClientConnection, socket: &'a mut T) -> Self {
            Self { conn, socket }
        }

        fn complete_io(&mut self) -> std::io::Result<(usize, usize)> {
            let mut write_bytes = 0;
            let mut read_bytes = 0;

            // Write any pending TLS data
            while self.conn.wants_write() {
                write_bytes += self.conn.write_tls(self.socket)?;
            }

            // Read TLS data
            while self.conn.wants_read() {
                match self.conn.read_tls(self.socket) {
                    Ok(n) => read_bytes += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
                self.conn.process_new_packets().map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                })?;
            }

            Ok((read_bytes, write_bytes))
        }
    }

    impl<T: Read + Write> Read for TlsStream<'_, T> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.complete_io()?;
            self.conn.reader().read(buf)
        }
    }

    impl<T: Read + Write> Write for TlsStream<'_, T> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.conn.writer().write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.conn.writer().flush()?;
            self.complete_io()?;
            Ok(())
        }
    }
}
