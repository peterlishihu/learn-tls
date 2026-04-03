//! Lesson 8: rustls Architecture Explorer
//!
//! Explores the internal architecture of rustls.

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "architecture_explorer", about = "Lesson 8: rustls Architecture")]
struct Args {
    /// Explain architecture
    #[arg(long)]
    explain: bool,

    /// Show state machine
    #[arg(long)]
    state_machine: bool,
}

fn main() -> Result<()> {
    shared::logging::init_logging();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Lesson 8: rustls Architecture Deep Dive                   ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    if args.explain {
        explain_architecture();
    } else if args.state_machine {
        show_state_machine();
    } else {
        print_all_info();
    }

    Ok(())
}

fn explain_architecture() {
    println!("\n=== rustls Architecture Overview ===\n");

    println!("rustls is organized in layers:\n");

    println!("1. Public API Layer");
    println!("   - ClientConfig, ServerConfig: Configuration builders");
    println!("   - ClientConnection, ServerConnection: TLS connections");
    println!("   - Stream: Higher-level I/O abstraction");
    println!("   - RootCertStore, CertificateDer: Certificate types\n");

    println!("2. Connection State Layer");
    println!("   - ConnectionCommon: Shared between client and server");
    println!("   - CommonState: Handshake and encryption state");
    println!("   - DataState: Read/write buffers");
    println!("   - StateMachine: Current handshake state\n");

    println!("3. Protocol Logic Layer");
    println!("   - tls12/: TLS 1.2 specific implementation");
    println!("   - tls13/: TLS 1.3 specific implementation");
    println!("   - msgs/: TLS message encoding/decoding");
    println!("   - verify/: Certificate verification\n");

    println!("4. Crypto Abstraction Layer");
    println!("   - crypto::CryptoProvider: Pluggable crypto");
    println!("   - rustls-aws-lc-rs: AWS libcrypto provider");
    println!("   - rustls-ring: Ring crypto provider\n");

    println!("=== Design Principles ===\n");

    println!("1. Zero-Copy Where Possible");
    println!("   - Messages parsed in-place");
    println!("   - Buffers reused across operations\n");

    println!("2. Type Safety");
    println!("   - State encoded in types (State<T>)");
    println!("   - Invalid state transitions prevented at compile time\n");

    println!("3. Modularity");
    println!("   - TLS 1.2 and 1.3 separated");
    println!("   - Crypto provider is pluggable");
    println!("   - Platform-specific code isolated\n");

    println!("4. Safety First");
    println!("   - No unsafe code by default");
    println!("   - Bounds checking");
    println!("   - Constant-time operations for crypto");
}

fn show_state_machine() {
    println!("\n=== TLS 1.3 Client State Machine ===\n");

    println!("  ┌───────────────────────────────────────┐");
    println!("  │           ExpectClientHello           │");
    println!("  └─────────────────┬─────────────────────┘");
    println!("                    │");
    println!("                    ▼");
    println!("  ┌───────────────────────────────────────┐");
    println!("  │  ExpectClientHelloOrHelloRetryRequest │");
    println!("  └─────────────────┬─────────────────────┘");
    println!("                    │");
    println!("                    ▼");
    println!("  ┌───────────────────────────────────────┐");
    println!("  │           ExpectFinished              │");
    println!("  └─────────────────┬─────────────────────┘");
    println!("                    │");
    println!("                    ▼");
    println!("  ┌───────────────────────────────────────┐");
    println!("  │              Traffic                  │");
    println!("  │    (Application data phase)           │");
    println!("  └───────────────────────────────────────┘");

    println!("\n=== TLS 1.3 Server State Machine ===\n");

    println!("  ┌───────────────────────────────────────┐");
    println!("  │           ExpectServerHello           │");
    println!("  └─────────────────┬─────────────────────┘");
    println!("                    │");
    println!("                    ▼");
    println!("  ┌───────────────────────────────────────┐");
    println!("  │       ExpectEncryptedExtensions       │");
    println!("  └─────────────────┬─────────────────────┘");
    println!("                    │");
    println!("                    ▼");
    println!("  ┌───────────────────────────────────────┐");
    println!("  │   ExpectCertificateOrCertReq          │");
    println!("  └─────────────────┬─────────────────────┘");
    println!("                    │");
    println!("                    ▼");
    println!("  ┌───────────────────────────────────────┐");
    println!("  │       ExpectCertificateVerify         │");
    println!("  └─────────────────┬─────────────────────┘");
    println!("                    │");
    println!("                    ▼");
    println!("  ┌───────────────────────────────────────┐");
    println!("  │           ExpectFinished              │");
    println!("  └─────────────────┬─────────────────────┘");
    println!("                    │");
    println!("                    ▼");
    println!("  ┌───────────────────────────────────────┐");
    println!("  │              Traffic                  │");
    println!("  └───────────────────────────────────────┘");
}

fn print_all_info() {
    explain_architecture();
    println!();
    show_state_machine();

    println!("\n=== ConnectionCommon ===\n");

    println!("ConnectionCommon is the shared structure between ClientConnection");
    println!("and ServerConnection. It contains:\n");

    println!("Core Components:");
    println!("  - common_state: CommonState");
    println!("    - negotiated version");
    println!("    - negotiated cipher suite");
    println!("    - handshake complete flag");
    println!("  - data: DataState");
    println!("    - read buffer");
    println!("    - write buffer");
    println!("  - state: Option<State>");
    println!("    - current handshake state machine\n");

    println!("=== Config Builders ===\n");

    println!("ClientConfig builder pattern:");
    println!("  ConfigBuilder");
    println!("    .with_root_certificates()");
    println!("    .with_client_auth_cert() / .with_no_client_auth()");
    println!("    → ClientConfig\n");

    println!("ServerConfig builder pattern:");
    println!("  ConfigBuilder");
    println!("    .with_client_cert_verifier() / .with_no_client_auth()");
    println!("    .with_single_cert()");
    println!("    → ServerConfig");
}
