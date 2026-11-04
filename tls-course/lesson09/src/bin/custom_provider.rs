//! Lesson 9: Crypto Provider Implementation
//!
//! Demonstrates how to implement a custom CryptoProvider.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use rustls::crypto::ring::default_provider;

#[derive(Parser, Debug)]
#[command(name = "custom_provider", about = "Lesson 9: Crypto Provider")]
struct Args {
    /// Explain CryptoProvider trait
    #[arg(long)]
    explain: bool,

    /// List available algorithms
    #[arg(long)]
    list: bool,
}

fn main() -> Result<()> {
    shared::logging::init_logging();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Lesson 9: Crypto Provider Implementation                  ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    if args.explain {
        explain_provider();
    } else if args.list {
        list_algorithms();
    } else {
        print_all_info();
    }

    Ok(())
}

fn explain_provider() {
    println!("\n=== CryptoProvider Trait ===\n");

    println!("CryptoProvider defines the cryptographic operations for rustls:");
    println!("\npub struct CryptoProvider {{");
    println!("    pub cipher_suites: Vec<SupportedCipherSuite>,");
    println!("    pub kx_groups: &[&'static dyn SupportedKxGroup],");
    println!("    pub signature_verification_algorithms: SignatureVerificationAlgorithms,");
    println!("    pub secure_random: Arc<dyn SecureRandom>,");
    println!("    pub key_provider: Arc<dyn KeyProvider>,");
    println!("}}\n");

    println!("Components:");
    println!("\n1. Cipher Suites");
    println!("   Define encryption + authentication algorithm combinations");
    println!("   Each suite implements the CipherSuite trait\n");

    println!("2. Key Exchange Groups");
    println!("   Define elliptic curves or DH groups for key exchange");
    println!("   Implement the SupportedKxGroup trait\n");

    println!("3. Signature Verification");
    println!("   Algorithms for verifying certificates");
    println!("   ECDSA, Ed25519, RSA\n");

    println!("4. Secure Random");
    println!("   Cryptographically secure random number generator\n");

    println!("5. Key Provider");
    println!("   Generates key pairs for key exchange\n");

    println!("=== Implementing Custom Provider ===\n");

    println!("Steps:");
    println!("  1. Create struct implementing CryptoProvider");
    println!("  2. Implement each crypto trait");
    println!("  3. Register provider with rustls");
    println!("  4. Use with ClientConfig/ServerConfig\n");

    println!("Example:");
    println!("  let provider = Arc::new(MyCustomProvider::new());");
    println!("  let config = ClientConfig::builder_with_provider(provider)");
    println!("      .with_safe_default_protocol_versions()?");
    println!("      .with_root_certificates(roots)");
    println!("      .with_no_client_auth();");
}

fn list_algorithms() {
    let provider = Arc::new(default_provider());

    println!("\n=== Available Cipher Suites ===\n");

    for (i, suite) in provider.cipher_suites.iter().enumerate() {
        let s = suite.suite();
        println!("{}. {:?}", i + 1, s);

        // SupportedCipherSuite::tls13() 返回 Option<&Tls13CipherSuite>
        if let Some(tls13) = suite.tls13() {
            println!("   TLS 1.3 (hash: {:?})", tls13.common.hash_provider.algorithm());
        }
        // rustls 0.23 没有 tls12() 访问器，直接模式匹配枚举
        if let rustls::SupportedCipherSuite::Tls12(tls12) = suite {
            println!("   TLS 1.2 (hash: {:?})", tls12.common.hash_provider.algorithm());
        }
        println!();
    }

    println!("\n=== Available Key Exchange Groups ===\n");

    for (i, kx) in provider.kx_groups.iter().enumerate() {
        println!("{}. {:?}", i + 1, kx.name());
    }
}

fn print_all_info() {
    explain_provider();
    println!();
    list_algorithms();

    println!("\n=== Use Cases ===\n");

    println!("1. FIPS Compliance");
    println!("   - Use only FIPS-approved algorithms");
    println!("   - Required for government/military use\n");

    println!("2. Hardware Acceleration");
    println!("   - Use HSM (Hardware Security Module)");
    println!("   - Offload crypto operations to dedicated hardware\n");

    println!("3. Post-Quantum Crypto");
    println!("   - Add quantum-resistant algorithms");
    println!("   - Prepare for quantum computing threats\n");

    println!("4. Embedded Systems");
    println!("   - Use minimal crypto implementations");
    println!("   - Reduce code size and memory usage\n");

    println!("5. Custom Requirements");
    println!("   - Specific compliance requirements");
    println!("   - Proprietary algorithms");
}
