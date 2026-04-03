//! Lesson 12: Debugging Tools
//!
//! Demonstrates TLS debugging techniques.

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "debug_tools", about = "Lesson 12: Debugging Tools")]
struct Args {
    /// Explain debugging techniques
    #[arg(long)]
    explain: bool,
}

fn main() -> Result<()> {
    shared::logging::init_logging();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Lesson 12: Debugging and Contribution                     ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    if args.explain {
        explain_debugging();
    } else {
        print_all_info();
    }

    Ok(())
}

fn explain_debugging() {
    println!("\n=== Wireshark TLS Decryption ===\n");

    println!("Prerequisites:");
    println!("  1. SSLKEYLOGFILE environment variable set");
    println!("  2. Application supports key logging");
    println!("  3. Wireshark configured with key log file\n");

    println!("Steps:");
    println!("  # 1. Set environment variable");
    println!("  export SSLKEYLOGFILE=/tmp/tls-keys.log\n");

    println!("  # 2. Run your TLS application");
    println!("  cargo run --bin client\n");

    println!("  # 3. Capture traffic (or use Wireshark GUI)");
    println!("  sudo tcpdump -i any -w capture.pcap port 443\n");

    println!("  # 4. In Wireshark:");
    println!("  # Edit → Preferences → Protocols → TLS");
    println!("  # Set '(Pre)-Master-Secret log filename' to /tmp/tls-keys.log\n");

    println!("=== Common TLS Issues ===\n");

    println!("1. Certificate Verification Failed");
    println!("   Causes:");
    println!("     - Missing root certificate");
    println!("     - Certificate expired");
    println!("     - Hostname mismatch (SNI)");
    println!("     - Self-signed certificate\n");

    println!("   Solutions:");
    println!("     - Check system time");
    println!("     - Verify certificate chain");
    println!("     - Use correct hostname\n");

    println!("2. Handshake Failure");
    println!("   Causes:");
    println!("     - No common protocol version");
    println!("     - No common cipher suite");
    println!("     - Client requires mTLS but server doesn't support\n");

    println!("   Solutions:");
    println!("     - Check protocol version compatibility");
    println!("     - Enable common cipher suites");
    println!("     - Configure client authentication\n");

    println!("3. Connection Reset");
    println!("   Causes:");
    println!("     - Alert sent by peer");
    println!("     - Timeout");
    println!("     - Network issue\n");

    println!("   Solutions:");
    println!("     - Check server logs for alerts");
    println!("     - Increase timeout values");
    println!("     - Verify network connectivity\n");

    println!("=== rustls Debugging Features ===\n");

    println!("1. Tracing");
    println!("   RUST_LOG=debug cargo run");
    println!("   Shows detailed protocol flow\n");

    println!("2. Key Logging");
    println!("   export SSLKEYLOGFILE=/tmp/keys.log");
    println!("   Enables Wireshark decryption\n");

    println!("3. Error Messages");
    println!("   rustls provides detailed error types");
    println!("   Check rustls::Error variants\n");

    println!("=== Testing ===\n");

    println!("Test Suites:");
    println!("  - Unit tests: cargo test");
    println!("  - Bogo tests: TLS compliance tests");
    println!("  - Integration tests: cargo test --test api\n");

    println!("Fuzzing:");
    println!("  cargo fuzz run fuzz_target_name");
    println!("  Uses rustls-fuzzing-provider for coverage-guided fuzzing\n");

    println!("Performance:");
    println!("  cargo bench");
    println!("  Measures handshake and throughput performance");
}

fn print_all_info() {
    explain_debugging();

    println!("\n=== Contributing to rustls ===\n");

    println!("1. Find an Issue");
    println!("   - Check GitHub issues labeled 'good first issue'");
    println!("   - Ask in Discord if unsure\n");

    println!("2. Set Up Development Environment");
    println!("   git clone https://github.com/rustls/rustls.git");
    println!("   cd rustls");
    println!("   cargo test  # Ensure tests pass\n");

    println!("3. Make Changes");
    println!("   - Create feature branch");
    println!("   - Write code with tests");
    println!("   - Follow existing code style\n");

    println!("4. Test Thoroughly");
    println!("   cargo test");
    println!("   cargo clippy");
    println!("   cargo fmt --check\n");

    println!("5. Submit PR");
    println!("   - Clear description");
    println!("   - Link related issues");
    println!("   - Respond to review feedback\n");

    println!("=== Code Quality ===\n");

    println!("rustls requirements:");
    println!("  ✓ No unsafe code (by default)");
    println!("  ✓ Comprehensive tests");
    println!("  ✓ Documentation");
    println!("  ✓ Clippy clean");
    println!("  ✓ Formatted with rustfmt");
}
