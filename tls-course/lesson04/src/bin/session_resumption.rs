//! Lesson 4: Session Resumption Demo
//!
//! Demonstrates Session ID, Session Ticket, PSK, and 0-RTT mechanisms.

use std::time::Duration;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "session_resumption", about = "Lesson 4: Session Resumption")]
struct Args {
    /// Show session resumption comparison
    #[arg(long)]
    compare: bool,
}

fn main() -> Result<()> {
    shared::logging::init_logging();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Lesson 4: Session Resumption Mechanisms                   ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    if args.compare {
        compare_mechanisms();
    } else {
        print_all_info();
    }

    Ok(())
}

fn compare_mechanisms() {
    println!("\n=== Session Resumption Mechanisms Comparison ===\n");

    println!("┌─────────────────────┬─────────┬──────────────┬──────────┬──────────┐");
    println!("│ Mechanism           │ Version │ Server State │ Latency  │ Security │");
    println!("├─────────────────────┼─────────┼──────────────┼──────────┼──────────┤");
    println!("│ Full Handshake      │ 1.2/1.3 │ N/A          │ 1-2 RTT  │ High     │");
    println!("│ Session ID          │ 1.0-1.2 │ Stateful     │ 1 RTT    │ Medium   │");
    println!("│ Session Ticket      │ 1.0-1.2 │ Stateless    │ 1 RTT    │ Medium   │");
    println!("│ PSK (Ticket)        │ 1.3     │ Stateless    │ 1 RTT    │ High     │");
    println!("│ 0-RTT               │ 1.3     │ Stateless    │ 0 RTT    │ Medium*  │");
    println!("└─────────────────────┴─────────┴──────────────┴──────────┴──────────┘");
    println!("\n* 0-RTT requires anti-replay protection");

    println!("\n=== Latency Comparison ===\n");

    println!("TLS 1.2 Full Handshake:      2 RTT");
    println!("  ClientHello");
    println!("  ServerHello + Certificate + ServerKeyExchange");
    println!("  ClientKeyExchange + [CCS] + Finished");
    println!("  [CCS] + Finished");
    println!("  Application Data\n");

    println!("TLS 1.2 Abbreviated:         1 RTT");
    println!("  ClientHello + SessionTicket");
    println!("  ServerHello + [CCS] + Finished");
    println!("  [CCS] + Finished");
    println!("  Application Data\n");

    println!("TLS 1.3 Full Handshake:      1 RTT");
    println!("  ClientHello + KeyShare");
    println!("  ServerHello + {{EncryptedExtensions}} + {{Certificate}} + {{Finished}}");
    println!("  {{Finished}}");
    println!("  Application Data\n");

    println!("TLS 1.3 0-RTT:               0 RTT");
    println!("  ClientHello + PSK + KeyShare + {{early_data}}");
    println!("  ServerHello + {{Finished}} + {{application_data}}");
}

fn print_all_info() {
    println!("\n=== Session ID (TLS 1.0-1.2) ===\n");

    println!("Process:");
    println!("  1. First handshake completes");
    println!("  2. Server generates session ID");
    println!("  3. Server stores session state in memory");
    println!("  4. Client remembers session ID");
    println!("  5. Reconnect: Client sends Session ID in ClientHello");
    println!("  6. Server looks up state and resumes\n");

    println!("Advantages:");
    println!("  ✓ Simple implementation");
    println!("  ✓ Fast lookup\n");

    println!("Disadvantages:");
    println!("  ✗ Requires server-side state");
    println!("  ✗ Memory usage grows with connections");
    println!("  ✗ Load balancing issues\n");

    println!("=== Session Ticket (TLS 1.0-1.2) ===\n");

    println!("Process:");
    println!("  1. First handshake completes");
    println!("  2. Server encrypts session state into ticket");
    println!("  3. Server sends ticket to client");
    println!("  4. Client stores ticket");
    println!("  5. Reconnect: Client sends ticket in ClientHello");
    println!("  6. Server decrypts ticket to restore state\n");

    println!("Advantages:");
    println!("  ✓ Stateless server");
    println!("  ✓ Works with load balancing");
    println!("  ✓ Client controls ticket storage\n");

    println!("Disadvantages:");
    println!("  ✗ Ticket encryption key management");
    println!("  ✗ Ticket size overhead\n");

    println!("=== PSK and 0-RTT (TLS 1.3) ===\n");

    println!("PSK (Pre-Shared Key) Mode:");
    println!("  1. First connection: Full handshake");
    println!("  2. Server sends NewSessionTicket");
    println!("  3. Client stores PSK");
    println!("  4. Later: ClientHello + PSK + KeyShare");
    println!("  5. Server derives keys from PSK");
    println!("  6. 1-RTT handshake complete\n");

    println!("0-RTT Mode:");
    println!("  1. Same as PSK setup");
    println!("  2. Later: ClientHello + PSK + KeyShare + {{early_data}}");
    println!("  3. Client sends application data immediately!");
    println!("  4. ServerHello + {{Finished}} + {{response}}");
    println!("  5. No additional round trip!\n");

    println!("⚠️  0-RTT Security Considerations:");
    println!("   - Early data may be replayed by attacker");
    println!("   - Should not be used for state-changing operations");
    println!("   - Server must implement anti-replay protection");
}
