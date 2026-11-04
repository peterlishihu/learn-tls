//! Lesson 13 示例 1：QUIC 基础 —— 用 quinn(rustls) 跑一个 echo 服务
//!
//! 演示要点：
//! 1. QUIC 的握手就是 TLS 1.3 握手（quinn 内部调 rustls），ALPN 是强制的
//! 2. 一条连接上并发多条双向流（STREAM 帧）—— 流之间互不阻塞
//! 3. 会话恢复 + 0-RTT：第二次连接直接带早期数据
//!
//! 运行：cargo run --bin quic_echo

use anyhow::Result;


use lesson13::{generate_self_signed, quinn_client_config, quinn_server_config, ALPN_QUIC_ECHO};

const SERVER_ADDR: &str = "127.0.0.1:9443";

#[tokio::main]
async fn main() -> Result<()> {
    shared::logging::init_logging();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Lesson 13: QUIC 基础 —— echo over QUIC (quinn + rustls)   ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    // ── 0. 自签证书（QUIC 一样要证书；TUIC 部署也常用自签+固定） ──
    let cert = generate_self_signed()?;

    // ── 1. 服务端 Endpoint：一个 UDP socket 就是整个"监听器" ──
    let server_addr: std::net::SocketAddr = SERVER_ADDR.parse()?;
    let endpoint = quinn::Endpoint::server(quinn_server_config(&cert, ALPN_QUIC_ECHO)?, server_addr)?;

    // ── 2. 客户端 Endpoint（独立 UDP socket；连接迁移靠 Connection ID 而非四元组） ──
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    client.set_default_client_config(quinn_client_config(&cert, ALPN_QUIC_ECHO, true)?);

    // ── 3. 服务端 echo 循环：必须先于客户端 connect 存在——
    //    quinn 的 Incoming 需要被 accept() 推进，握手才会完成 ──
    let server = {
        let endpoint = endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                println!("    [server] 新连接建立，开始 echo（每条流独立处理）");
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 256];
                        if let Ok(Some(n)) = recv.read(&mut buf).await {
                            let _ = send.write_all(&buf[..n]).await;
                        }
                        let _ = send.finish();
                    });
                }
            }
            Ok::<(), anyhow::Error>(())
        })
    };

    // ══════════ 第一段：完整握手（1-RTT）+ 多路复用 ══════════
    println!("\n[1] 首次连接（完整 TLS 1.3 握手，1-RTT）");
    let start = std::time::Instant::now();
    let conn = client.connect(server_addr, "localhost")?.await?;
    println!("    握手完成 {:?}（本机回环，真实网络≈1×RTT）", start.elapsed());

    // QUIC 握手数据：ALPN 协商结果、对端证书——与课时 1 的 rustls 查询同源。
    // quinn 通过 handshake_data() 暴露 rustls 的协商结果
    let alpn = conn
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|d| d.protocol);
    println!("    协商 ALPN: {}", alpn.map(|p| String::from_utf8_lossy(&p).to_string()).unwrap_or_default());
    println!("    对端证书: {} 字节（rustls 校验，quinn 携带）",
        conn.peer_identity()
            .and_then(|i| i.downcast::<Vec<rustls::pki_types::CertificateDer>>().ok())
            .map(|v| v.first().map(|c| c.len()).unwrap_or(0))
            .unwrap_or(0));

    println!("\n[2] 同一条连接并发 4 条双向流（多路复用，无队头阻塞）");
    let mut tasks = Vec::new();
    for i in 0..4u8 {
        let conn = conn.clone();
        tasks.push(tokio::spawn(async move {
            // open_bi 几乎零成本：流 ID 空间有 2^62 条，无需握手
            let (mut send, mut recv) = conn.open_bi().await?;
            send.write_all(format!("hello from stream {i}").as_bytes()).await?;
            send.finish()?; // 半关闭：FIN，相当于 TCP 的 shutdown(WR)
            let data = recv.read_to_end(64).await?;
            Ok::<Vec<u8>, anyhow::Error>(data)
        }));
    }
    // （服务端 echo 循环已在连接前启动，见上方 server 任务）

    for (i, t) in tasks.into_iter().enumerate() {
        match t.await {
            Ok(Ok(data)) => println!("    流 {} 收到回显: {:?}", i, String::from_utf8_lossy(&data)),
            Ok(Err(e)) => println!("    流 {} 失败: {}", i, e),
            Err(e) => println!("    流 {} 任务失败: {}", i, e),
        }
    }

    // ══════════ 第二段：会话恢复 + 0-RTT ══════════
    println!("\n[3] 断开后重连 —— rustls 会话票证生效，尝试 0-RTT 早期数据");
    conn.close(0u32.into(), b"bye");
    // 服务端 echo 循环仍在运行（server 任务持续 accept）

    // 给一点时间让首个连接的 NewSessionTicket 到达客户端会话缓存
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let connecting = client.connect(server_addr, "localhost")?;
    // into_0rtt：如果客户端持有带 early_data 许可的票证，可以立刻开始发送数据
    match connecting.into_0rtt() {
        Ok((conn2, zero_rtt_accepted)) => {
            println!("    0-RTT 可用：不等 ServerHello，立刻开流发数据");
            let start = std::time::Instant::now();
            let (mut send, mut recv) = conn2.open_bi().await?;
            send.write_all(b"0-rtt early data!").await?;
            send.finish()?;
            let buf = recv.read_to_end(64).await?;
            println!("    早期数据往返完成 {:?}: {:?}", start.elapsed(), String::from_utf8_lossy(&buf));

            // 服务器是否真的接受了 0-RTT（也可能拒绝并要求 1-RTT 重传）
            let accepted = zero_rtt_accepted.await;
            println!("    服务器{}了 0-RTT 早期数据", if accepted { "接受" } else { "拒绝" });
            conn2.close(0u32.into(), b"done");
        }
        Err(connecting) => {
            println!("    0-RTT 不可用（无可用票证），回退 1-RTT");
            let conn2 = connecting.await?;
            conn2.close(0u32.into(), b"done");
        }
    }
    server.abort();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    println!("\n┌─────────────────────┬───────────────┬──────────────────────────────┐");
    println!("│ 协议                │ 首字节延迟    │ 说明                         │");
    println!("├─────────────────────┼───────────────┼──────────────────────────────┤");
    println!("│ TCP + TLS 1.2       │ 3 RTT         │ TCP 1 + 握手 2               │");
    println!("│ TCP + TLS 1.3       │ 2 RTT         │ TCP 1 + 握手 1（课时 4）     │");
    println!("│ QUIC 完整握手       │ 1 RTT         │ 传输+加密握手合一            │");
    println!("│ QUIC 0-RTT 恢复     │ 0 RTT         │ early data 直接带请求        │");
    println!("└─────────────────────┴───────────────┴────────────────────────────┘");
    println!("\n提示：quinn 的 TLS 引擎就是 rustls——ClientHello/CryptoProvider/密钥派生");
    println!("      全部复用课时 1-12 的知识，只是记录层换成了 QUIC 包保护。");
    Ok(())
}
