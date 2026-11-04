//! Lesson 13 示例 3：mini-TUIC —— 按 TUIC v5 规范实现的玩具级代理
//!
//! 一个进程内跑起四个角色：
//!   1. 目标站：TCP echo（9101）+ UDP echo（9102）
//!   2. TUIC 服务端：QUIC Endpoint（ALPN=tuic-v5-mini）
//!   3. TUIC 客户端：同一条 QUIC 连接上完成全部操作
//!   4. 你：观察每一条 TUIC 命令的线上字节
//!
//! 覆盖 TUIC v5 的五个命令：
//!   Authenticate（TLS exporter 认证）→ Connect（TCP 中继）
//!   → Packet（DATAGRAM UDP 中继）→ Heartbeat（保活）
//!   → Dissociate（释放 UDP 会话）
//! 外加"无应答协议"的错误信令演示（Connect 失败 → 流 reset）。
//!
//! 运行：cargo run --bin tuic_demo

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{watch, Mutex};

use lesson13::tuic::{derive_auth_token, Address, Command};
use lesson13::{generate_self_signed, quinn_client_config, quinn_server_config, ALPN_TUIC};

/// 演示账号（TUIC 配置文件里的 uuid + password）
const UUID: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];
const PASSWORD: &[u8] = b"hunter2";

const TCP_TARGET: &str = "127.0.0.1:9101"; // 目标站 TCP echo
const UDP_TARGET: &str = "127.0.0.1:9102"; // 目标站 UDP echo
const TUIC_SERVER: &str = "127.0.0.1:9100"; // TUIC 监听

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

fn sockaddr_to_address(addr: SocketAddr) -> Address {
    match addr {
        SocketAddr::V4(a) => Address::Ipv4(*a.ip(), a.port()),
        SocketAddr::V6(a) => Address::Ipv6(*a.ip(), a.port()),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    shared::logging::init_logging();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Lesson 13: mini-TUIC —— TUIC v5 五命令全流程演示          ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    // ── [1] 目标站：最普通的 TCP echo + UDP echo ──
    println!("\n[1] 启动目标站（TUIC 对它们一无所知，只是中继对象）");
    tokio::spawn(tcp_echo_server(TCP_TARGET.parse()?));
    tokio::spawn(udp_echo_server(UDP_TARGET.parse()?));
    println!("    TCP echo: {TCP_TARGET} / UDP echo: {UDP_TARGET}");

    // ── [2] TUIC 服务端 ──
    let cert = generate_self_signed()?;
    let server_addr: SocketAddr = TUIC_SERVER.parse()?;
    let endpoint = quinn::Endpoint::server(quinn_server_config(&cert, ALPN_TUIC)?, server_addr)?;
    tokio::spawn(tuic_acceptor(endpoint.clone()));
    println!(
        "\n[2] TUIC 服务端监听 udp://{TUIC_SERVER}（ALPN={}）",
        String::from_utf8_lossy(ALPN_TUIC[0])
    );

    // ── [3] 客户端：QUIC 握手 + Authenticate ──
    println!("\n[3] 客户端：QUIC 握手（=TLS 1.3，由 rustls 完成）");
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    client.set_default_client_config(quinn_client_config(&cert, ALPN_TUIC, false)?);
    let conn = client.connect(server_addr, "localhost")?.await?;
    let alpn = conn
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|d| d.protocol)
        .map(|p| String::from_utf8_lossy(&p).to_string())
        .unwrap_or_default();
    println!("    连接建立：1-RTT，ALPN={alpn}，此后所有命令共用这一条连接");

    // TUIC v5 认证：token 不走明文，从 TLS 会话导出（RFC 5705 exporter）
    let token = derive_auth_token(&conn, &UUID, PASSWORD)?;
    let auth = Command::Authenticate { uuid: UUID, token };
    println!("\n[3.1] Authenticate（单向流）：");
    println!("      线上字节: {}", hex(&auth.encode()));
    println!("      token = TLS-exporter(label=UUID, context=password) = {}…", hex(&token[..8]));
    println!("      → 密码从不上线；token 绑定本连接，抓包重放无效");
    let mut send = conn.open_uni().await?;
    send.write_all(&auth.encode()).await?;
    send.finish()?;
    // 规范允许认证与其他命令并行；这里稍等服务器处理完
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // ── [4] TCP 中继：Connect（双向流） ──
    println!("\n[4] Connect（双向流）：TCP 中继");
    let (mut send, mut recv) = conn.open_bi().await?;
    let tcp_port = TCP_TARGET.parse::<SocketAddr>()?.port();
    let cmd = Command::Connect(Address::Ipv4("127.0.0.1".parse()?, tcp_port));
    let head = cmd.encode();
    println!("    命令头: {}  →  127.0.0.1:{tcp_port}", hex(&head));
    send.write_all(&head).await?; // 命令头
    send.write_all(b"PING over TUIC").await?; // 之后整条流就是 TCP 载荷，零额外封装
    let mut buf = vec![0u8; 128];
    let n = recv.read(&mut buf).await?.unwrap_or(0);
    println!("    收到回显: {:?}", String::from_utf8_lossy(&buf[..n]));
    println!("    → 服务器从不回复 Connect（无应答协议）；错误才用流关闭表达，见 [7]");

    // ── [5] UDP 中继：Packet（QUIC DATAGRAM 帧） ──
    println!("\n[5] Packet（QUIC DATAGRAM 帧）：UDP 中继");
    let payload = b"UDP-PING over TUIC".to_vec();
    let udp_port = UDP_TARGET.parse::<SocketAddr>()?.port();
    let pkt = Command::Packet {
        assoc_id: 1,
        pkt_id: 1,
        frag_total: 1,
        frag_id: 0,
        size: payload.len() as u16,
        addr: Address::Ipv4("127.0.0.1".parse()?, udp_port),
    };
    let mut frame = pkt.encode();
    frame.extend_from_slice(&payload);
    println!("    命令头: {} + {} 字节载荷（不可靠、无序，但不占流控窗口）", hex(&pkt.encode()), payload.len());
    conn.send_datagram(Bytes::from(frame))?;
    let resp = tokio::time::timeout(std::time::Duration::from_secs(3), conn.read_datagram())
        .await??;
    let (reply, used) = Command::decode(&resp)?;
    if let Command::Packet { assoc_id, addr, .. } = &reply {
        println!(
            "    收到 {}: 来自 {addr}，载荷 {:?}",
            reply.name(),
            String::from_utf8_lossy(&resp[used..])
        );
        println!("    → 服务器为 assoc_id={assoc_id} 分配独立 UDP socket（Full-cone 语义）：");
        println!("      任何远端发给该 socket 的包都会原路带回，游戏/NAT 穿透场景的关键");
    }

    // ── [6] Heartbeat：保活 ──
    println!("\n[6] Heartbeat（DATAGRAM）：空命令，只为让 QUIC 连接不因空闲超时");
    let hb = Command::Heartbeat;
    println!("    线上字节: {}（仅 2 字节！）", hex(&hb.encode()));
    conn.send_datagram(Bytes::from(hb.encode()))?;

    // ── [7] 错误信令：连一个没开的端口 ──
    println!("\n[7] 错误信令：Connect 到 127.0.0.1:1（无监听）");
    let (mut send, mut recv) = conn.open_bi().await?;
    let bad = Command::Connect(Address::Ipv4("127.0.0.1".parse()?, 1));
    send.write_all(&bad.encode()).await?;
    match recv.read(&mut buf).await {
        Err(e) => println!("    服务器 reset 了这条流: {e}（错误码 404 = 目标不可达）"),
        Ok(_) => println!("    （未观察到 reset）"),
    }
    println!("    → TUIC 规范没有定义应答，错误处理是实现自定义的——");
    println!("      这是\"0-RTT 优先\"设计的代价：省掉了应答通道，出错只能靠连接/流关闭暗示");

    // ── [8] Dissociate：结束 UDP 会话 ──
    println!("\n[8] Dissociate（单向流）：释放 assoc_id=1 的 UDP socket");
    let dis = Command::Dissociate { assoc_id: 1 };
    println!("    线上字节: {}", hex(&dis.encode()));
    let mut send = conn.open_uni().await?;
    send.write_all(&dis.encode()).await?;
    send.finish()?;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    conn.close(0u32.into(), b"demo done");
    println!("\n五种命令全部走完 —— 一条 QUIC 连接、一次握手、一份拥塞控制。");
    println!("回顾 TUIC 的三件武器：流（TCP 中继）+ 数据报（UDP 中继/心跳）+ exporter（认证）。");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    Ok(())
}

// ══════════════════ 目标站 ══════════════════

async fn tcp_echo_server(addr: SocketAddr) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    loop {
        let Ok((mut stream, _)) = listener.accept().await else { continue };
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok(n) = stream.read(&mut buf).await {
                let reply = format!("echo: {}", String::from_utf8_lossy(&buf[..n]));
                let _ = stream.write_all(reply.as_bytes()).await;
            }
        });
    }
}

async fn udp_echo_server(addr: SocketAddr) -> Result<()> {
    let sock = Arc::new(tokio::net::UdpSocket::bind(addr).await?);
    let mut buf = [0u8; 1500];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        let reply = format!("udp-echo: {}", String::from_utf8_lossy(&buf[..n])).into_bytes();
        let _ = sock.send_to(&reply, peer).await;
    }
}

// ══════════════════ TUIC 服务端 ══════════════════

/// 每条 TUIC 连接的 UDP 会话表：assoc_id → (服务器侧 socket, 回包任务)
type AssocTable = Arc<Mutex<HashMap<u16, (Arc<tokio::net::UdpSocket>, tokio::task::JoinHandle<()>)>>>;

async fn tuic_acceptor(endpoint: quinn::Endpoint) -> Result<()> {
    while let Some(incoming) = endpoint.accept().await {
        let conn = match incoming.await {
            Ok(c) => c,
            Err(_) => continue,
        };
        println!("    [tuic-server] 新 QUIC 连接（rustls 握手完成）");
        tokio::spawn(tuic_connection(conn));
    }
    Ok(())
}

async fn tuic_connection(conn: quinn::Connection) -> Result<()> {
    // 认证状态：规范允许认证与其他命令并行，先到的非认证命令"暂停"等待认证
    let (auth_tx, auth_rx) = watch::channel(false);
    let assocs: AssocTable = Arc::new(Mutex::new(HashMap::new()));

    // ── 单向流循环：Authenticate / Dissociate ──
    {
        let conn = conn.clone();
        let assocs = assocs.clone();
        tokio::spawn(async move {
            while let Ok(mut recv) = conn.accept_uni().await {
                let buf = match recv.read_to_end(1024).await {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                match Command::decode(&buf) {
                    Ok((cmd, _)) => match cmd {
                        Command::Authenticate { uuid, token } => {
                            println!("    [tuic-server] Authenticate：用本连接的 exporter 复算 token…");
                            // 服务器用同样的 (label=uuid, context=password) 导出并比对：
                            // token 绑定本 TLS 会话，换一条连接就不同
                            let expect = derive_auth_token(&conn, &uuid, PASSWORD).ok();
                            if expect == Some(token) {
                                println!("    [tuic-server] ✅ token 匹配，连接已认证");
                                let _ = auth_tx.send(true);
                            } else {
                                println!("    [tuic-server] ❌ token 不匹配，关闭连接");
                                conn.close(0u32.into(), b"auth failed");
                            }
                        }
                        Command::Dissociate { assoc_id } => {
                            println!("    [tuic-server] Dissociate：释放 assoc_id={assoc_id}");
                            if let Some((_, task)) = assocs.lock().await.remove(&assoc_id) {
                                task.abort(); // socket 随之 drop，远端不再能通过它进包
                            }
                        }
                        other => println!("    [tuic-server] 单向流收到意外命令 {}", other.name()),
                    },
                    Err(e) => println!("    [tuic-server] 命令解析失败: {e}"),
                }
            }
        });
    }

    // ── DATAGRAM 循环：Packet（UDP 中继）/ Heartbeat ──
    {
        let conn = conn.clone();
        let assocs = assocs.clone();
        let auth_rx = auth_rx.clone();
        tokio::spawn(async move {
            while let Ok(dg) = conn.read_datagram().await {
                let (cmd, used) = match Command::decode(&dg) {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                match cmd {
                    Command::Heartbeat => {
                        println!("    [tuic-server] Heartbeat（{} 字节）— 连接保活", dg.len());
                    }
                    Command::Packet { assoc_id, size, addr, .. } => {
                        if !*auth_rx.borrow() {
                            continue;
                        }
                        let addr = match addr {
                            Address::None => continue, // 非首片分片，教学演示不支持重组
                            a => a,
                        };
                        let payload = &dg[used..used + size as usize];
                        let sock = {
                            let mut table = assocs.lock().await;
                            match table.get(&assoc_id) {
                                Some((s, _)) => s.clone(),
                                None => {
                                    // Full-cone 核心：每个 assoc 分配独立、未连接的 UDP socket，
                                    // 之后任何远端发给它的包都会被回传给客户端
                                    let s = Arc::new(
                                        tokio::net::UdpSocket::bind("0.0.0.0:0").await.expect("bind"),
                                    );
                                    println!("    [tuic-server] 新 UDP 会话 assoc_id={assoc_id}（独立 socket）");
                                    let s2 = s.clone();
                                    let conn2 = conn.clone();
                                    let task = tokio::spawn(async move {
                                        let mut buf = [0u8; 1500];
                                        loop {
                                            let Ok((n, from)) = s2.recv_from(&mut buf).await else { break };
                                            let reply = Command::Packet {
                                                assoc_id,
                                                pkt_id: 0,
                                                frag_total: 1,
                                                frag_id: 0,
                                                size: n as u16,
                                                addr: sockaddr_to_address(from),
                                            };
                                            let mut frame = reply.encode();
                                            frame.extend_from_slice(&buf[..n]);
                                            if conn2.send_datagram(Bytes::from(frame)).is_err() {
                                                break;
                                            }
                                        }
                                    });
                                    table.insert(assoc_id, (s.clone(), task));
                                    s
                                }
                            }
                        };
                        let _ = sock.send_to(payload, addr.to_string()).await;
                    }
                    other => println!("    [tuic-server] DATAGRAM 收到意外命令 {}", other.name()),
                }
            }
        });
    }

    // ── 双向流循环：Connect（TCP 中继） ──
    let mut auth_rx = auth_rx.clone();
    while let Ok((send, recv)) = conn.accept_bi().await {
        // 规范：未认证时只收命令头并暂停（这里简化为等认证信号）
        while !*auth_rx.borrow() {
            if auth_rx.changed().await.is_err() {
                break;
            }
        }
        if !*auth_rx.borrow() {
            continue;
        }
        tokio::spawn(tcp_relay(send, recv));
    }
    Ok(())
}

/// 一条双向流 = 一条 TCP 中继：读 Connect 头，然后把流和 TCP 双向搬运。
///
/// 底层是 UDP（QUIC），因此避免了"TCP 套 TCP"的双重拥塞控制（meltdown）。
async fn tcp_relay(mut send: quinn::SendStream, mut recv: quinn::RecvStream) {
    // 1) 读命令头。注意：首读可能把首批 TCP 载荷也带进来，要分开处理
    let mut head = [0u8; 512];
    let mut filled = 0usize;
    while filled < 9 {
        // IPv4 Connect 头=9 字节；域名场景需按需再读（教学演示从简）
        match recv.read(&mut head[filled..]).await {
            Ok(Some(n)) => filled += n,
            _ => return,
        }
    }
    let (cmd, hdr_len) = match Command::decode(&head[..filled]) {
        Ok(x) => x,
        Err(_) => return,
    };
    let Command::Connect(addr) = cmd else {
        return;
    };
    let target = addr.to_string();
    println!("    [tuic-server] Connect → {target}");

    let tcp = match tokio::net::TcpStream::connect(&target).await {
        Ok(t) => t,
        Err(_) => {
            // 无应答协议：用流错误码表达失败（404 = 目标不可达）
            let _ = send.reset(quinn::VarInt::from_u32(404));
            return;
        }
    };
    let (mut tcp_r, mut tcp_w) = tcp.into_split();

    // 头部之后捎带的首批载荷直接转发
    if filled > hdr_len {
        if tcp_w.write_all(&head[hdr_len..filled]).await.is_err() {
            return;
        }
    }

    // 上行：QUIC 流 → 目标站
    let up = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(0)) | Ok(None) | Err(_) => break,
                Ok(Some(n)) => {
                    if tcp_w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // 下行：目标站 → QUIC 流
    let down = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match tcp_r.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = send.finish(); // FIN：目标站关闭，流也半关闭
                    break;
                }
                Ok(n) => {
                    if send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let _ = (up, down); // 两个方向各自跑到流/TCP 结束
}
