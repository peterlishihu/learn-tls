//! Lesson 11: Security Extensions
//!
//! Explains SCT, OCSP Stapling, and ECH.

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "security_extensions", about = "Lesson 11: Security Extensions")]
struct Args {
    /// Explain security extensions
    #[arg(long)]
    explain: bool,
}

fn main() -> Result<()> {
    shared::logging::init_logging();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Lesson 11: Security Extensions                            ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    if args.explain {
        explain_extensions();
    } else {
        print_all_info();
    }

    Ok(())
}

fn explain_extensions() {
    println!("\n=== Certificate Transparency (CT) ===\n");

    println!("Problem:");
    println!("  A malicious CA could issue certificates for any domain");
    println!("  without the domain owner's knowledge.\n");

    println!("Solution: Certificate Transparency");
    println!("  All certificates must be logged in public CT logs");
    println!("  Logs are append-only and cryptographically verifiable\n");

    println!("SCT (Signed Certificate Timestamp):");
    println!("  Cryptographic proof that certificate was logged");
    println!("  Can be embedded in certificate or stapled\n");

    println!("CT Logs:");
    println!("  - Google (multiple logs)");
    println!("  - Cloudflare");
    println!("  - Let's Encrypt");
    println!("  - Many others\n");

    println!("=== OCSP (Online Certificate Status Protocol) ===\n");

    println!("Traditional OCSP:");
    println!("  1. Client receives certificate");
    println!("  2. Client queries OCSP responder");
    println!("  3. Responder returns certificate status");
    println!("  Problems:");
    println!("    - Adds latency (extra round trip)");
    println!("    - Privacy leak (responder knows what sites you visit)");
    println!("    - OCSP responder can be a single point of failure\n");

    println!("OCSP Stapling:");
    println!("  1. Server periodically queries OCSP responder");
    println!("  2. Server receives signed OCSP response");
    println!("  3. Server staples (includes) response in TLS handshake");
    println!("  Benefits:");
    println!("    - No extra round trip for client");
    println!("    - Privacy preserved (no client→OCSP query)");
    println!("    - Better availability\n");

    println!("OCSP Must-Staple:");
    println!("  Certificate extension that requires stapling");
    println!("  If server doesn't staple, client must reject\n");

    println!("=== Encrypted Client Hello (ECH) ===\n");

    println!("Problem:");
    println!("  SNI (Server Name Indication) in ClientHello reveals");
    println!("  which website you're connecting to - even with HTTPS!\n");

    println!("Example:");
    println!("  Even though content is encrypted, SNI shows:");
    println!("    'blog.example.com' or 'secret.example.com'\n");

    println!("Solution: ECH");
    println!("  Encrypt the entire ClientHello including SNI\n");

    println!("ECH Flow:");
    println!("  1. DNS returns HTTPS record with ECHConfig");
    println!("     (public key for encryption)");
    println!("  2. Client generates ClientHelloInner (with real SNI)");
    println!("  3. Client encrypts it using ECH public key");
    println!("  4. Client sends ClientHelloOuter with dummy SNI");
    println!("  5. Only server with ECH private key can decrypt");
    println!("  6. Server processes inner ClientHello normally\n");

    println!("Security:");
    println!("  - Network observers only see dummy SNI");
    println!("  - Real destination hidden");
    println!("  - Similar to ESNI (Encrypted SNI) but encrypts more\n");

    println!("Deployment:");
    println!("  - Requires DNS-over-HTTPS (to hide ECHConfig lookup)");
    println!("  - Supported by Cloudflare, Fastly, etc.");
    println!("  - Firefox, Chrome implementing");
}

fn print_all_info() {
    explain_extensions();

    println!("\n=== Extension Comparison ===\n");

    println!("┌──────────────────┬─────────────┬──────────────────┬────────────┐");
    println!("│ Extension        │ TLS Version │ Server Support   │ Client     │");
    println!("├──────────────────┼─────────────┼──────────────────┼────────────┤");
    println!("│ SCT              │ 1.0+        │ CA embeds        │ Required   │");
    println!("│ OCSP Stapling    │ 1.0+        │ Recommended      │ Supported  │");
    println!("│ OCSP Must-Staple │ 1.0+        │ Optional         │ Required   │");
    println!("│ ECH              │ 1.3         │ CDN support      │ Emerging   │");
    println!("└──────────────────┴─────────────┴──────────────────┴────────────┘");

    println!("\n=== Implementation in rustls ===\n");

    println!("rustls supports:");
    println!("  ✓ SCT validation via webpki");
    println!("  ✓ OCSP stapling (server-side)");
    println!("  ✓ ECH (experimental, via rustls-post-quantum)");

    println!("\nConfiguring:");
    println!("  // Enable OCSP stapling");
    println!("  config.enable_sct = true;");
    println!("  config.ocsp_response = Some(response);");
}
