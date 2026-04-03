//! Lesson 7: TLS 1.3 Key Derivation
//!
//! Explains HKDF and the TLS 1.3 key derivation tree.

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "hkdf_demo", about = "Lesson 7: TLS 1.3 Key Derivation")]
struct Args {
    /// Explain HKDF
    #[arg(long)]
    explain: bool,

    /// Show key derivation tree
    #[arg(long)]
    key_tree: bool,
}

fn main() -> Result<()> {
    shared::logging::init_logging();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Lesson 7: TLS 1.3 Key Derivation (HKDF)                   ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    if args.explain {
        explain_hkdf();
    } else if args.key_tree {
        show_key_tree();
    } else {
        print_all_info();
    }

    Ok(())
}

fn explain_hkdf() {
    println!("\n=== HKDF (RFC 5869) ===\n");

    println!("HKDF is a HMAC-based key derivation function that:");
    println!("  1. Extracts a fixed-length pseudo-random key from variable-length input");
    println!("  2. Expands it into multiple keys of any length\n");

    println!("HKDF-Extract(salt, IKM) -> PRK");
    println!("  PRK = HMAC-SHA256(salt, IKM)\n");

    println!("HKDF-Expand(PRK, info, L) -> OKM");
    println!("  T(0) = empty");
    println!("  T(1) = HMAC-SHA256(PRK, T(0) || info || 0x01)");
    println!("  T(2) = HMAC-SHA256(PRK, T(1) || info || 0x02)");
    println!("  ...");
    println!("  T(N) = HMAC-SHA256(PRK, T(N-1) || info || N)");
    println!("  OKM = T(1) || T(2) || ... || T(N) [first L bytes]\n");

    println!("Parameters:");
    println!("  salt: Non-secret random value (can be empty)");
    println!("  IKM: Input Key Material (high entropy)");
    println!("  PRK: Pseudo-Random Key (fixed length)");
    println!("  info: Context/application specific info");
    println!("  L: Desired output length\n");

    println!("TLS 1.3 uses HKDF with SHA-256 or SHA-384.");
}

fn show_key_tree() {
    println!("\n=== TLS 1.3 Key Derivation Tree ===\n");

    println!("Stage 1: Early Secrets (for 0-RTT)\n");

    println!("  derive_secret(Early Secret, \"c e traffic\", ClientHello)");
    println!("    → client_early_traffic_secret");
    println!("    → Used for 0-RTT application data encryption\n");

    println!("  derive_secret(Early Secret, \"e exp master\", ClientHello)");
    println!("    → early_exporter_master_secret");
    println!("    → Used for early exported keys\n");

    println!("Stage 2: Handshake Secrets\n");

    println!("  Handshake Secret = HKDF-Extract(Derived Secret, Shared Secret)");
    println!("  where Shared Secret is the (EC)DHE result\n");

    println!("  derive_secret(Handshake Secret, \"c hs traffic\", ClientHello...ServerHello)");
    println!("    → client_handshake_traffic_secret");
    println!("    → Used to encrypt Client Finished and post-handshake client data\n");

    println!("  derive_secret(Handshake Secret, \"s hs traffic\", ClientHello...ServerHello)");
    println!("    → server_handshake_traffic_secret");
    println!("    → Used to encrypt EncryptedExtensions, Certificate, Server Finished\n");

    println!("Stage 3: Master Secret\n");

    println!("  Master Secret = HKDF-Extract(Derived Secret, Handshake Secret)\n");

    println!("  derive_secret(Master Secret, \"c ap traffic\", transcript hash)");
    println!("    → client_application_traffic_secret_0");
    println!("    → Used for client application data encryption\n");

    println!("  derive_secret(Master Secret, \"s ap traffic\", transcript hash)");
    println!("    → server_application_traffic_secret_0");
    println!("    → Used for server application data encryption\n");

    println!("  derive_secret(Master Secret, \"exp master\", transcript hash)");
    println!("    → exporter_master_secret");
    println!("    → Used for exported keys (e.g., for other protocols)\n");

    println!("  derive_secret(Master Secret, \"res master\", ClientHello...ClientFinished)");
    println!("    → resumption_master_secret");
    println!("    → Used to derive PSK for session resumption\n");

    println!("=== Key Update ===\n");

    println!("TLS 1.3 supports Key Update to change traffic keys:");
    println!("  client_application_traffic_secret_N+1 =");
    println!("    HKDF-Expand-Label(client_application_traffic_secret_N, \"traffic upd\", \"\", Hash.length)\n");

    println!("Process:");
    println!("  1. Sender sends KeyUpdate message");
    println!("  2. Derives new traffic secret");
    println!("  3. Switches to new keys after sending 'finished' message");
    println!("  4. Receiver derives matching secret upon receiving KeyUpdate");
}

fn print_all_info() {
    explain_hkdf();
    println!();
    show_key_tree();

    println!("\n=== Traffic Key Derivation ===\n");

    println!("From traffic secrets, we derive:");
    println!("  - Key (for encryption)");
    println!("  - IV (for nonce)");

    println!("\nKey = HKDF-Expand-Label(secret, \"key\", \"\", key_length)");
    println!("IV  = HKDF-Expand-Label(secret, \"iv\", \"\", iv_length)\n");

    println!("For AES-256-GCM:");
    println!("  key_length = 32 bytes");
    println!("  iv_length = 12 bytes\n");

    println!("=== Security Properties ===\n");

    println!("1. Compartmentalization:");
    println!("   - Each stage has separate secrets");
    println!("   - Compromise of one doesn't affect others\n");

    println!("2. Forward Secrecy:");
    println!("   - Handshake Secret depends on ephemeral (EC)DHE");
    println!("   - Long-term keys only used for authentication\n");

    println!("3. Key Separation:");
    println!("   - Different keys for different purposes");
    println!("   - Read/write keys separated");
    println!("   - Handshake/application keys separated");
}
