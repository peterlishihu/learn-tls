//! Lesson 12: Fuzzing Example
//!
//! Demonstrates fuzzing concepts for TLS.

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "fuzzing_example", about = "Fuzzing Demo")]
struct Args {
    #[arg(long)]
    explain: bool,
}

fn main() -> Result<()> {
    shared::logging::init_logging();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Fuzzing Example                                           ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    if args.explain {
        explain_fuzzing();
    } else {
        println!("\nFuzzing is an automated testing technique that");
        println!("generates random or semi-random inputs to find bugs.\n");

        println!("For actual fuzzing, use:");
        println!("  cargo install cargo-fuzz");
        println!("  cargo fuzz init");
        println!("  cargo fuzz run target\n");

        println!("rustls fuzzing targets:");
        println!("  - client: Fuzz TLS 1.3 client");
        println!("  - server: Fuzz TLS 1.3 server");
        println!("  - deframer: Fuzz message deframing");
        println!("  - message: Fuzz message parsing");
        println!("  - persist: Fuzz session persistence");
    }

    Ok(())
}

fn explain_fuzzing() {
    println!("\n=== What is Fuzzing? ===\n");

    println!("Fuzzing is an automated software testing technique that");
    println!("involves providing invalid, unexpected, or random data");
    println!("as inputs to a computer program.\n");

    println!("Goals:");
    println!("  - Find crashes and security vulnerabilities");
    println!("  - Discover edge cases");
    println!("  - Improve code robustness\n");

    println!("=== Fuzzing TLS ===\n");

    println!("TLS implementations are complex and security-critical,");
    println!("making them excellent candidates for fuzzing.\n");

    println!("Target areas:");
    println!("  1. Message parsing");
    println!("     - Malformed TLS records");
    println!("     - Invalid extensions");
    println!("     - Truncated messages\n");

    println!("  2. Handshake state machine");
    println!("     - Unexpected message sequences");
    println!("     - Invalid state transitions\n");

    println!("  3. Cryptographic operations");
    println!("     - Invalid keys");
    println!("     - Edge case inputs\n");

    println!("=== Tools ===\n");

    println!("cargo-fuzz:");
    println!("  - libFuzzer-based");
    println!("  - Coverage-guided");
    println!("  - Rust-native\n");

    println!("AFL++:");
    println!("  - American Fuzzy Lop");
    println!("  - Very effective for TLS");
    println!("  - Supports persistent mode\n");

    println!("=== rustls Fuzzing ===\n");

    println!("rustls provides rustls-fuzzing-provider:");
    println!("  - Deterministic crypto for reproducibility");
    println!("  - Fast execution");
    println!("  - Good coverage\n");

    println!("Running fuzzer:");
    println!("  cd fuzz");
    println!("  cargo fuzz run client -- -max_total_time=60");
}
