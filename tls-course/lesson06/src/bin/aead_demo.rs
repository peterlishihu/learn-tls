//! Lesson 6: AEAD (Authenticated Encryption) Demo
//!
//! Demonstrates AES-GCM and ChaCha20-Poly1305 encryption.

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "aead_demo", about = "Lesson 6: AEAD Encryption")]
struct Args {
    /// Show AEAD explanation
    #[arg(long)]
    explain: bool,

    /// Show algorithm comparison
    #[arg(long)]
    compare: bool,
}

fn main() -> Result<()> {
    shared::logging::init_logging();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Lesson 6: Symmetric Encryption and AEAD                   ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    if args.explain {
        explain_aead();
    } else if args.compare {
        compare_algorithms();
    } else {
        print_all_info();
    }

    Ok(())
}

fn explain_aead() {
    println!("\n=== AEAD (Authenticated Encryption with Associated Data) ===\n");

    println!("What is AEAD?");
    println!("  AEAD provides both:");
    println!("    1. Confidentiality (encryption)");
    println!("    2. Integrity (authentication)\n");

    println!("AEAD Interface:");
    println!("┌─────────────────────────────────────────────────────┐");
    println!("│ encrypt(key, nonce, plaintext, associated_data)     │");
    println!("│   → (ciphertext, tag)                               │");
    println!("│                                                     │");
    println!("│ decrypt(key, nonce, ciphertext, tag, associated_data)│");
    println!("│   → plaintext (or error if authentication fails)    │");
    println!("└─────────────────────────────────────────────────────┘\n");

    println!("Components:");
    println!("  Key: Symmetric encryption key (128/256 bits)");
    println!("  Nonce: Number used once - must be unique per key");
    println!("  Plaintext: Data to encrypt");
    println!("  Associated Data: Authenticated but not encrypted");
    println!("  Tag: Authentication tag (128 bits)\n");

    println!("⚠️  Critical: Nonce must NEVER repeat for same key!");
    println!("   If nonce repeats, security is completely broken.\n");

    println!("=== AES-GCM (Galois/Counter Mode) ===\n");

    println!("AES-GCM combines:");
    println!("  - AES-CTR: Counter mode for encryption");
    println!("  - GHASH: Galois field multiplication for authentication\n");

    println!("Encryption Process:");
    println!("  1. Generate counter blocks from nonce");
    println!("  2. Encrypt counter blocks with AES");
    println!("  3. XOR with plaintext → ciphertext");
    println!("  4. Compute GHASH over associated data + ciphertext");
    println!("  5. Encrypt final block → authentication tag\n");

    println!("Security:");
    println!("  ✓ Proven secure (with unique nonces)");
    println!("  ✓ Parallelizable");
    println!("  ✓ Hardware acceleration (AES-NI)\n");

    println!("Limitations:");
    println!("  ✗ 64-bit IV limits messages to 2^64 - 2^32 blocks");
    println!("  ✗ Weak keys possible (rare)");
    println!("  ✗ Timing side-channel without hardware support\n");

    println!("=== ChaCha20-Poly1305 ===\n");

    println!("ChaCha20:");
    println!("  - Stream cipher designed by Daniel Bernstein");
    println!("  - 256-bit key, 96-bit nonce");
    println!("  - 20 rounds of ARX (Add-Rotate-XOR) operations");
    println!("  - Designed to be fast in software\n");

    println!("Poly1305:");
    println!("  - Message authentication code");
    println!("  - 128-bit authentication tag");
    println!("  - Fast, constant-time implementation\n");

    println!("Combined Mode:");
    println!("  1. Derive one-time Poly1305 key from ChaCha20");
    println!("  2. Encrypt plaintext with ChaCha20");
    println!("  3. Compute Poly1305 MAC over AD + ciphertext + padding\n");

    println!("Advantages over AES-GCM:");
    println!("  ✓ Faster in software (no AES-NI needed)");
    println!("  ✓ Constant-time implementation");
    println!("  ✓ Simpler design, easier to verify");
    println!("  ✓ No weak keys\n");

    println!("TLS 1.3 Cipher Suites:");
    println!("  TLS_AES_128_GCM_SHA256");
    println!("  TLS_AES_256_GCM_SHA384");
    println!("  TLS_CHACHA20_POLY1305_SHA256");
    println!("  TLS_AES_128_CCM_SHA256 (for constrained devices)");
}

fn compare_algorithms() {
    println!("\n=== Algorithm Comparison ===\n");

    println!("┌─────────────────────┬────────────────┬─────────────────────┐");
    println!("│ Feature             │ AES-256-GCM    │ ChaCha20-Poly1305   │");
    println!("├─────────────────────┼────────────────┼─────────────────────┤");
    println!("│ Key Size            │ 256 bits       │ 256 bits            │");
    println!("│ Nonce Size          │ 96 bits        │ 96 bits             │");
    println!("│ Tag Size            │ 128 bits       │ 128 bits            │");
    println!("│ Rounds/Operations   │ 10 (AES)       │ 20 (ChaCha)         │");
    println!("│ Hardware Support    │ AES-NI (x86)   │ None required       │");
    println!("│ SW Performance      │ Slow without   │ Fast                │");
    println!("│                     │ AES-NI         │                     │");
    println!("│ Timing Safe         │ Needs care     │ Natural             │");
    println!("│ Design Complexity   │ Moderate       │ Simple              │");
    println!("│ Standardization     │ NIST           │ IETF (RFC 8439)     │");
    println!("└─────────────────────┴────────────────┴─────────────────────┘");

    println!("\nPerformance on Modern x86 (cycles/byte):");
    println!("  AES-128-GCM with AES-NI:  ~1.0");
    println!("  AES-256-GCM with AES-NI:  ~1.3");
    println!("  ChaCha20-Poly1305:        ~1.5");
    println!("  AES-256-GCM (software):   ~20+\n");

    println!("Recommendation:");
    println!("  - x86_64 with AES-NI: Use AES-GCM");
    println!("  - ARM/mobile devices: ChaCha20-Poly1305 or AES");
    println!("  - Embedded systems: AES-CCM (smaller code)");
}

fn print_all_info() {
    explain_aead();
    println!();
    compare_algorithms();

    println!("\n=== Nonce Management in TLS 1.3 ===\n");

    println!("Problem:");
    println!("  - AEAD requires unique nonce for each message");
    println!("  - Transmitting full nonce wastes bandwidth");
    println!("  - Need to handle packet loss/reordering\n");

    println!("TLS 1.3 Solution:");
    println!("  1. Derive base IV from handshake secrets");
    println!("  2. XOR base IV with 64-bit sequence number");
    println!("  3. Result is unique nonce for each record");
    println!("  4. No nonce transmitted (saves 8 bytes)\n");

    println!("  Nonce = Base_IV XOR Sequence_Number");
    println!("\n  Sequence numbers:");
    println!("    - Monotonically increasing");
    println!("    - Separate counters for read/write");
    println!("    - 64-bit prevents overflow");
    println!("    - Detects replay attacks");
}
