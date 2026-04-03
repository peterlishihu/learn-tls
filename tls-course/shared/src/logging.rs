//! Logging configuration for TLS debugging
//!
//! Provides detailed logging setup for TLS handshake analysis,
//! including key logging for Wireshark decryption.

use std::env;
use std::path::PathBuf;

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialize tracing with TLS-specific configuration
///
/// # Environment Variables
/// - `RUST_LOG`: Standard tracing log level (default: info)
/// - `SSLKEYLOGFILE`: Path to save TLS key log for Wireshark (optional)
///
/// # Example
/// ```
/// export RUST_LOG=debug
/// export SSLKEYLOGFILE=/tmp/tls-keys.log
/// cargo run --bin client
/// ```
pub fn init_logging() {
    let filter = EnvFilter::from_default_env()
        .add_directive("rustls=debug".parse().unwrap())
        .add_directive("shared=debug".parse().unwrap());

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(true).with_thread_ids(true))
        .init();
}

/// Initialize logging with custom filter
pub fn init_logging_with_filter(filter_str: &str) {
    let filter = EnvFilter::new(filter_str)
        .add_directive("rustls=debug".parse().unwrap())
        .add_directive("shared=debug".parse().unwrap());

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(true).with_thread_ids(true))
        .init();
}

/// Check if key logging is enabled
pub fn is_key_logging_enabled() -> bool {
    env::var("SSLKEYLOGFILE").is_ok()
}

/// Get the key log file path if set
pub fn key_log_file_path() -> Option<PathBuf> {
    env::var("SSLKEYLOGFILE").ok().map(PathBuf::from)
}

/// Log information about SSLKEYLOGFILE setup
pub fn log_key_logging_info() {
    if let Some(path) = key_log_file_path() {
        tracing::info!(
            "SSLKEYLOGFILE is set: {}",
            path.display()
        );
        tracing::info!(
            "Wireshark can decrypt this traffic using: Edit -> Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename"
        );
    } else {
        tracing::debug!("SSLKEYLOGFILE not set - Wireshark decryption disabled");
    }
}

/// Pretty print a hex buffer with offset
pub fn hex_dump(data: &[u8], label: &str) {
    const BYTES_PER_LINE: usize = 16;

    tracing::debug!("{} ({} bytes):", label, data.len());

    for (i, chunk) in data.chunks(BYTES_PER_LINE).enumerate() {
        let offset = i * BYTES_PER_LINE;
        let hex_part: String = chunk
            .iter()
            .map(|b| format!("{:02x} ", b))
            .collect();

        let ascii_part: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();

        tracing::debug!(
            "  {:04x} | {:<48} | {}",
            offset,
            hex_part,
            ascii_part
        );
    }
}
