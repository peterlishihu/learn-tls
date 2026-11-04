//! Lesson 13 示例 2：TCP+TLS 1.3 vs QUIC —— 握手成本与多路复用实测
//!
//! 在本机回环上做 8 次串行请求，对比三种形态：
//!   A. 8 条独立 TCP+TLS 1.3 连接（每条都要完整握手）
//!   B. 8 条独立 QUIC 连接（传输+加密握手合一）
//!   C. 1 条 QUIC 连接 + 8 条流（一次握手，全部复用）
//!
//! 回环没有真实 RTT，A/B 的握手优势会被低估；但 C 的"一次握手"优势
//! 与网络无关，在任何环境下都成立——这正是 TUIC 复用一条连接的动机。
//!
//! 运行：cargo run --bin quic_vs_tls

use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use lesson13::{generate_self_signed, quinn_client_config, quinn_server_config, ALPN_QUIC_ECHO};

const N: usize = 8;

#[tokio::main]
async fn main() -> Result<()> {
    shared::logging::init_logging();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Lesson 13: TCP+TLS vs QUIC —— {} 次串行请求实测           ║", N);
    println!("╚════════════════════════════════════════════════════════════╝");

    let cert = generate_self_signed()?;
    let addr: std::net::SocketAddr = "127.0.0.1:9444".parse()?;

    // ══════════ A. TCP + TLS 1.3 × N ══════════
    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(lesson13::PinnedCertVerifier::new(
        cert.cert.clone(),
    )))
    .with_no_client_auth();
    let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

    let tls_server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(vec![cert.cert.clone()], cert.key.clone_key())?;
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_server_config));

    let tls_listener = tokio::net::TcpListener::bind(addr).await?;
    let tls_server = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = tls_listener.accept().await else { break };
            let acceptor = tls_acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let mut buf = [0u8; 64];
                    if let Ok(n) = tls.read(&mut buf).await {
                        let _ = tls.write_all(&buf[..n]).await;
                    }
                    let _ = tls.shutdown().await;
                }
            });
        }
    });

    let start = Instant::now();
    for i in 0..N {
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        let name = rustls::pki_types::ServerName::try_from("localhost".to_string())?;
        let mut tls = tls_connector.connect(name, tcp).await?;
        tls.write_all(format!("req-{i}").as_bytes()).await?;
        let mut buf = [0u8; 64];
        let _ = tls.read(&mut buf).await;
        // 每条连接都随作用域结束而关闭：N 次完整握手
    }
    let tls_time = start.elapsed();
    tls_server.abort();

    // ══════════ B/C. QUIC ══════════
    let endpoint = quinn::Endpoint::server(quinn_server_config(&cert, ALPN_QUIC_ECHO)?, addr)?;
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    client.set_default_client_config(quinn_client_config(&cert, ALPN_QUIC_ECHO, false)?);

    let quic_server = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let Ok(conn) = incoming.await else { continue };
            while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    if let Ok(Some(n)) = recv.read(&mut buf).await {
                        let _ = send.write_all(&buf[..n]).await;
                    }
                    let _ = send.finish();
                });
            }
        }
    });

    // B：N 条独立 QUIC 连接（每条 1-RTT 握手，但省掉 TCP 的那次往返）
    let start = Instant::now();
    for i in 0..N {
        let conn = client.connect(addr, "localhost")?.await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(format!("req-{i}").as_bytes()).await?;
        send.finish()?;
        let mut buf = [0u8; 64];
        let _ = recv.read(&mut buf).await;
        conn.close(0u32.into(), b"done");
    }
    let quic_n_time = start.elapsed();

    // C：1 条 QUIC 连接 + N 条流
    let start = Instant::now();
    let conn = client.connect(addr, "localhost")?.await?;
    for i in 0..N {
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(format!("req-{i}").as_bytes()).await?;
        send.finish()?;
        let mut buf = [0u8; 64];
        let _ = recv.read(&mut buf).await;
    }
    let quic_mux_time = start.elapsed();
    conn.close(0u32.into(), b"done");
    quic_server.abort();

    // ══════════ 结果 ══════════
    println!("\n┌──────────────────────────────┬──────────────┬──────────────────────────┐");
    println!("│ 形态                         │ 总耗时       │ 握手次数                 │");
    println!("├──────────────────────────────┼──────────────┼──────────────────────────┤");
    println!("│ A. TCP+TLS 1.3 × {0} 连接       │ {1:>10.2?} │ {0} 次 TCP + {0} 次 TLS   │", N, tls_time);
    println!("│ B. QUIC × {0} 连接             │ {1:>10.2?} │ {0} 次（传输+加密合一）   │", N, quic_n_time);
    println!("│ C. QUIC 1 连接 + {0} 流        │ {1:>10.2?} │ 1 次（流近乎零成本）     │", N, quic_mux_time);
    println!("└──────────────────────────────┴──────────────┴──────────────────────────┘");

    println!("\n解读：");
    println!("  · 回环无 RTT，A/B 差距被低估；真实网络里每次握手都要付 1×RTT");
    println!("  · TCP+TLS 首字节 2×RTT、QUIC 完整握手 1×RTT、QUIC 0-RTT 0×RTT");
    println!("  · C 的优势与 RTT 无关：一条连接打满所有请求，这正是 TUIC 的做法——");
    println!("    每条 TCP 中继=一条双向流，只有一次握手、一份拥塞控制状态");

    Ok(())
}
