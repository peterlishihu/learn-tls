//! Lesson 5: TLS Record Layer
//!
//! Explains the TLS record layer protocol, fragmentation, and MAC.

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "record_layer", about = "Lesson 5: TLS Record Layer")]
struct Args {
    /// Explain record layer concepts
    #[arg(long)]
    explain: bool,

    /// Show record format
    #[arg(long)]
    format: bool,
}

fn main() -> Result<()> {
    shared::logging::init_logging();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Lesson 5: TLS Record Layer Protocol                       ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    if args.format {
        show_record_format();
    } else {
        print_all_info();
    }

    Ok(())
}

fn show_record_format() {
    println!("\n=== TLS Record Format ===\n");

    println!("TLS Record Layer Header (5 bytes):");
    println!("┌──────────┬─────────────────┬────────────────┐");
    println!("│ Type(1B) │ Version(2B)     │ Length(2B)     │");
    println!("├──────────┼─────────────────┼────────────────┤");
    println!("│ 0x17     │ 0x0303 (TLS1.2) │ 0x0040 (64)    │");
    println!("└──────────┴─────────────────┴────────────────┘");

    println!("\nContent Types:");
    println!("  0x14 (20) = ChangeCipherSpec");
    println!("  0x15 (21) = Alert");
    println!("  0x16 (22) = Handshake");
    println!("  0x17 (23) = Application Data");
    println!("  0x18 (24) = Heartbeat (TLS 1.2)");

    println!("\nVersion Values:");
    println!("  0x0301 = TLS 1.0");
    println!("  0x0302 = TLS 1.1");
    println!("  0x0303 = TLS 1.2");
    println!("  0x0304 = TLS 1.3");

    println!("\n=== TLS 1.2 Record Structure (CBC suites: MAC-then-Encrypt) ===\n");
    println!("┌────────────────────────────────────────────────────┐");
    println!("│ Header (5 bytes, NOT encrypted/MACed)              │");
    println!("│   Content Type (1) │ Version (2) │ Length (2)      │");
    println!("├────────────────────────────────────────────────────┤");
    println!("│ Explicit IV (block-size bytes, TLS 1.1+)           │");
    println!("├────────────────────────────────────────────────────┤");
    println!("│ Encrypted region:                                  │");
    println!("│   Fragment (plaintext, max 2^14 bytes)             │");
    println!("│   MAC (20/32/48 B: HMAC-SHA1/SHA256/SHA384)        │");
    println!("│   Padding (each byte = padding_length value)       │");
    println!("│   padding_length (1 byte)                          │");
    println!("└────────────────────────────────────────────────────┘");
    println!("  (TLS 1.2 GCM instead: explicit_nonce(8) + ciphertext");
    println!("   + tag(16); no MAC field, no padding)");

    println!("\n=== TLS 1.3 Record Structure (AEAD) ===\n");
    println!("┌────────────────────────────────────────────────────┐");
    println!("│ Header (5 bytes)                                   │");
    println!("├────────────────────────────────────────────────────┤");
    println!("│ Opaque Type (always 0x17 = Application Data)       │");
    println!("│ Version (always 0x0303 = TLS 1.2 for compatibility)│");
    println!("│ Length (2 bytes)                                   │");
    println!("├────────────────────────────────────────────────────┤");
    println!("│ Ciphertext                                         │");
    println!("│   - Encrypted plaintext                            │");
    println!("│   - Authentication tag (16 bytes)                  │");
    println!("└────────────────────────────────────────────────────┘");
}

fn print_all_info() {
    show_record_format();

    println!("\n=== Fragmentation ===\n");

    println!("Maximum Fragment Size:");
    println!("  - TLS allows up to 2^14 bytes (16384) per fragment");
    println!("  - This limits memory requirements");
    println!("  - Allows interleaving of different content types");
    println!("  - Prevents DoS from huge records\n");

    println!("Fragmentation Process:");
    println!("  Application Data (e.g., 64KB HTTP response)");
    println!("        ↓");
    println!("  Split into 4 fragments of 16KB each");
    println!("        ↓");
    println!("  Each fragment gets its own record header");
    println!("        ↓");
    println!("  Each record encrypted independently");
    println!("        ↓");
    println!("  Receiver reassembles fragments\n");

    println!("=== MAC (Message Authentication Code) ===\n");

    println!("Purpose:");
    println!("  ✓ Ensure message integrity (not modified in transit)");
    println!("  ✓ Authenticate sender (only parties with key can compute)");
    println!("  ✓ Prevent replay attacks (includes sequence number)\n");

    println!("MAC Calculation (TLS 1.2):");
    println!("  MAC = HMAC(key, seq_num + type + version + length + data)\n");

    println!("  Where:");
    println!("    key = MAC write key");
    println!("    seq_num = 64-bit sequence number");
    println!("    type = content type");
    println!("    version = protocol version");
    println!("    length = fragment length");
    println!("    data = fragment data\n");

    println!("=== TLS 1.2 vs TLS 1.3 ===\n");

    println!("TLS 1.2 (MAC-then-Encrypt):");
    println!("  1. Compute MAC over plaintext");
    println!("  2. Append MAC to plaintext");
    println!("  3. Add padding");
    println!("  4. Encrypt (plaintext + MAC + padding)");
    println!("  Problems:");
    println!("    - Padding oracle attacks possible");
    println!("    - Must decrypt to verify MAC\n");

    println!("TLS 1.3 (AEAD: encryption and authentication in one primitive):");
    println!("  1. inner = content || real_content_type(1B) || padding");
    println!("  2. nonce = static_IV XOR seq (nothing sent on wire)");
    println!("  3. AAD = 5-byte record header (type=0x17, 0x0303, len)");
    println!("  4. ciphertext = AEAD-encrypt(inner) + 16-byte tag");
    println!("  Advantages:");
    println!("    ✓ No CBC padding oracle at all");
    println!("    ✓ Tag verified before any plaintext is used");
    println!("    ✓ Real content type hidden inside ciphertext\n");

    println!("=== Security Considerations ===\n");

    println!("Padding Oracle Attack (TLS 1.2 CBC mode):");
    println!("  Attacker observes how server responds to invalid padding");
    println!("  Can eventually decrypt data");
    println!("  Mitigation: Constant-time padding validation\n");

    println!("Record Size Limit:");
    println!("  Prevents memory exhaustion attacks");
    println!("  Limits amplification for DDoS\n");

    println!("AEAD Nonce Reuse:");
    println!("  Using same nonce with same key breaks security");
    println!("  TLS 1.3 uses sequence number as nonce base");
}
