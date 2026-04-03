//! Lesson 3: Key Exchange Mechanisms Demo
//!
//! Demonstrates differences between RSA and ECDHE key exchange,
//! forward secrecy concepts, and TLS 1.2 vs 1.3 differences.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use rustls_ring::DEFAULT_PROVIDER;

#[derive(Parser, Debug)]
#[command(name = "key_exchange_demo", about = "Lesson 3: Key Exchange Mechanisms")]
struct Args {
    /// List supported key exchange groups
    #[arg(long)]
    list_groups: bool,

    /// Compare TLS 1.2 vs 1.3
    #[arg(long)]
    compare: bool,

    /// Show forward secrecy explanation
    #[arg(long)]
    explain_fs: bool,
}

fn main() -> Result<()> {
    shared::logging::init_logging();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Lesson 3: Key Exchange Mechanisms                         ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    if args.list_groups {
        list_key_exchange_groups();
    } else if args.compare {
        compare_tls_versions();
    } else if args.explain_fs {
        explain_forward_secrecy();
    } else {
        print_all_info();
    }

    Ok(())
}

fn list_key_exchange_groups() {
    println!("\n=== Supported Key Exchange Groups ===\n");

    let provider = Arc::new(DEFAULT_PROVIDER);

    println!("TLS 1.3 Key Exchange Groups:");
    if let Some(kx) = provider.key_exchange {
        println!("  Available: {:?}", kx);
    }

    println!("\nCommon Groups:");
    println!("  X25519     - Curve25519 ECDH (recommended)");
    println!("  X448       - Curve448 ECDH");
    println!("  P-256      - NIST secp256r1");
    println!("  P-384      - NIST secp384r1");
    println!("  P-521      - NIST secp521r1");
    println!("  FFDHE2048  - Finite Field DH");
}

fn compare_tls_versions() {
    println!("\n=== TLS 1.2 vs TLS 1.3 Key Exchange ===\n");

    println!("TLS 1.2 (ECDHE with separate messages):");
    println!("  1. ClientHello");
    println!("  2. ServerHello");
    println!("  3. Certificate");
    println!("  4. ServerKeyExchange  <- Contains ephemeral public key");
    println!("  5. ServerHelloDone");
    println!("  6. ClientKeyExchange  <- Contains ephemeral public key");
    println!("  7. [ChangeCipherSpec]");
    println!("  8. Finished");
    println!("  Total: 2-RTT\n");

    println!("TLS 1.3 (1-RTT with KeyShare):");
    println!("  1. ClientHello + KeyShare");
    println!("  2. ServerHello");
    println!("  3. {{EncryptedExtensions}}");
    println!("  4. {{Certificate}}");
    println!("  5. {{CertificateVerify}}");
    println!("  6. {{Finished}}");
    println!("  Total: 1-RTT\n");

    println!("Key Differences:");
    println!("  ✓ TLS 1.3: Key exchange in first flight");
    println!("  ✓ TLS 1.3: All handshake after ServerHello encrypted");
    println!("  ✓ TLS 1.3: No separate key exchange messages");
    println!("  ✓ TLS 1.3: Faster by 1 RTT");
}

fn explain_forward_secrecy() {
    println!("\n=== Forward Secrecy (FS) Explained ===\n");

    println!("PROBLEM: Long-term key compromise");
    println!("  If an attacker records all traffic and later");
    println!("  steals the server's private key...\n");

    println!("WITHOUT Forward Secrecy (RSA):");
    println!("  ❌ Attacker can decrypt ALL past sessions!");
    println!("  ❌ Session keys were encrypted with long-term RSA key");
    println!("  ❌ All history is compromised\n");

    println!("WITH Forward Secrecy (ECDHE):");
    println!("  ✓ Each session uses ephemeral key pair");
    println!("  ✓ Ephemeral private key destroyed after session");
    println!("  ✓ Attacker can only compromise future sessions");
    println!("  ✓ Past sessions remain secure\n");

    println!("Implementation:");
    println!("  1. Generate ephemeral key pair (X25519, P-256)");
    println!("  2. Exchange public keys");
    println!("  3. Compute shared secret");
    println!("  4. Derive session keys from shared secret");
    println!("  5. DELETE ephemeral private key!");
    println!("  6. Long-term key used only for authentication");
}

fn print_all_info() {
    list_key_exchange_groups();
    println!();
    compare_tls_versions();
    println!();
    explain_forward_secrecy();
}
