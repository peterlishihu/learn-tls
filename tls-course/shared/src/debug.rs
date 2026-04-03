//! Debug utilities for TLS protocol analysis
//!
//! Provides helpers for analyzing TLS handshake messages,
/// connection states, and protocol details.

use std::fmt;

/// Pretty print TLS message details
pub fn print_tls_message(label: &str, data: &[u8]) {
    tracing::debug!("{}: {} bytes", label, data.len());

    if data.len() < 5 {
        tracing::debug!("  (message too short for TLS record)");
        return;
    }

    // TLS record header is 5 bytes:
    // - content_type: 1 byte
    // - version: 2 bytes
    // - length: 2 bytes
    let content_type = data[0];
    let version = u16::from_be_bytes([data[1], data[2]]);
    let length = u16::from_be_bytes([data[3], data[4]]) as usize;

    let content_type_str = match content_type {
        20 => "ChangeCipherSpec",
        21 => "Alert",
        22 => "Handshake",
        23 => "ApplicationData",
        24 => "Heartbeat",
        _ => "Unknown",
    };

    tracing::debug!("  Content Type: {} ({})", content_type_str, content_type);
    tracing::debug!("  Version: 0x{:04x}", version);
    tracing::debug!("  Length: {}", length);

    // Parse handshake message if present
    if content_type == 22 && data.len() >= 6 {
        let handshake_type = data[5];
        let handshake_type_str = match handshake_type {
            1 => "ClientHello",
            2 => "ServerHello",
            4 => "NewSessionTicket",
            8 => "EncryptedExtensions",
            11 => "Certificate",
            15 => "CertificateVerify",
            20 => "Finished",
            24 => "KeyUpdate",
            _ => "Unknown",
        };
        tracing::debug!("  Handshake Type: {}", handshake_type_str);
    }
}

/// Print detailed information about supported cipher suites
pub fn print_cipher_suites_info(suites: &[rustls::SupportedCipherSuite]) {
    tracing::info!("Supported Cipher Suites ({}):", suites.len());

    for suite in suites {
        let suite = suite.suite();
        tracing::info!("  - {:?}", suite);
    }
}

/// Compare TLS versions
pub fn compare_tls_versions() {
    tracing::info!("=== TLS Version Comparison ===");

    tracing::info!("\nTLS 1.2:");
    tracing::info!("  - Based on SSL 3.0, many legacy features");
    tracing::info!("  - Multiple round trips for handshake (2-RTT)");
    tracing::info!("  - Many cipher suites, some insecure");
    tracing::info!("  - Static RSA key exchange option (no FS)");
    tracing::info!("  - MAC-then-Encrypt structure");

    tracing::info!("\nTLS 1.3:");
    tracing::info!("  - Complete redesign, removed legacy");
    tracing::info!("  - 1-RTT handshake (0-RTT with PSK)");
    tracing::info!("  - Only AEAD cipher suites");
    tracing::info!("  - All key exchanges provide forward secrecy");
    tracing::info!("  - Encrypt-then-MAC structure");
    tracing::info!("  - Encrypted extensions in handshake");

    tracing::info!("\nKey Differences:");
    tracing::info!("  1. Handshake latency: TLS 1.3 is faster");
    tracing::info!("  2. Security: TLS 1.3 removes many vulnerable features");
    tracing::info!("  3. Privacy: TLS 1.3 encrypts more of handshake");
    tracing::info!("  4. Complexity: TLS 1.3 implementation is simpler");
}

/// Print a summary of TLS handshake state
pub fn print_handshake_summary(is_client: bool, state: &str) {
    let role = if is_client { "Client" } else { "Server" };
    tracing::info!("[{}] Handshake state: {}", role, state);
}

/// Format bytes for display
pub struct BytesFormatter<'a>(pub &'a [u8]);

impl fmt::Display for BytesFormatter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.len() <= 16 {
            // Short: show all hex
            write!(f, "0x")?;
            for byte in self.0 {
                write!(f, "{:02x}", byte)?;
            }
        } else {
            // Long: show first 8 and last 8
            write!(f, "0x")?;
            for byte in &self.0[..8] {
                write!(f, "{:02x}", byte)?;
            }
            write!(f, "...")?;
            for byte in &self.0[self.0.len()-8..] {
                write!(f, "{:02x}", byte)?;
            }
            write!(f, " ({} bytes)", self.0.len())?;
        }
        Ok(())
    }
}

/// Format a duration for display
pub struct DurationFormatter(pub std::time::Duration);

impl fmt::Display for DurationFormatter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0.as_secs();
        let millis = self.0.subsec_millis();
        let micros = self.0.subsec_micros() % 1000;

        if secs > 0 {
            write!(f, "{}.{:03}s", secs, millis)?;
        } else if millis > 0 {
            write!(f, "{}.{:03}ms", millis, micros)?;
        } else {
            write!(f, "{}µs", self.0.as_micros())?;
        }
        Ok(())
    }
}

/// Measure time taken by a closure
pub fn timeit<F, T>(name: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let start = std::time::Instant::now();
    let result = f();
    let duration = start.elapsed();
    tracing::info!("{} took {}", name, DurationFormatter(duration));
    result
}

/// Print a table of TLS extensions
pub fn print_tls_extensions() {
    tracing::info!("=== Common TLS Extensions ===");

    let extensions = vec![
        ("server_name", 0, "SNI - Server Name Indication"),
        ("max_fragment_length", 1, "Max fragment length"),
        ("client_certificate_url", 2, "Client certificate URL"),
        ("trusted_ca_keys", 3, "Trusted CA keys"),
        ("truncated_hmac", 4, "Truncated HMAC"),
        ("status_request", 5, "OCSP status request"),
        ("supported_groups", 10, "Supported groups (curves)"),
        ("ec_point_formats", 11, "EC point formats"),
        ("signature_algorithms", 13, "Signature algorithms"),
        ("use_srtp", 14, "SRTP protection profiles"),
        ("heartbeat", 15, "Heartbeat extension"),
        ("application_layer_protocol_negotiation", 16, "ALPN"),
        ("signed_certificate_timestamp", 18, "SCT (Certificate Transparency)"),
        ("client_certificate_type", 19, "Client certificate type"),
        ("server_certificate_type", 20, "Server certificate type"),
        ("padding", 21, "Extension padding"),
        ("encrypt_then_mac", 22, "Encrypt-then-MAC (TLS 1.2)"),
        ("extended_master_secret", 23, "Extended master secret"),
        ("session_ticket", 35, "Session ticket (TLS 1.2)"),
        ("supported_versions", 43, "Supported versions (TLS 1.3)"),
        ("cookie", 44, "Cookie (TLS 1.3)"),
        ("psk_key_exchange_modes", 45, "PSK key exchange modes"),
        ("certificate_authorities", 47, "Certificate authorities"),
        ("oid_filters", 48, "OID filters"),
        ("post_handshake_auth", 49, "Post-handshake auth (TLS 1.3)"),
        ("signature_algorithms_cert", 50, "Signature algorithms for certificates"),
        ("key_share", 51, "Key share (TLS 1.3)"),
    ];

    for (name, id, description) in extensions {
        tracing::info!("  {:>3}: {:<35} - {}", id, name, description);
    }
}
