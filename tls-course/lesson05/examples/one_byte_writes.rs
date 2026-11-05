//! 实测：连续 100 次 1 字节 write，到底会发出多少条 TLS record？
//!
//! 原理：把 client→server 方向的线上字节镜像一份到 log，事后按
//! 「5 字节记录头（type 1B + version 2B + length 2B）+ length 字节载荷」
//! 逐条解析，数出真实发出的记录数。
//!
//! 运行：cargo run -p lesson05 --example one_byte_writes

use std::cell::RefCell;
use std::io::{IoSlice, Read, Write};
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::Result;
use rustls::pki_types::{PrivatePkcs8KeyDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig, ServerConnection};

use rustls::ClientConnection;

/// 镜像 socket：client 每次向网络写字节，都复制一份到 log。
struct Tap {
    inner: UnixStream,
    log: Rc<RefCell<Vec<u8>>>,
}

impl Write for Tap {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.log.borrow_mut().extend_from_slice(buf);
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl Read for Tap {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

/// 从线上字节流解析记录条数（假设流恰好由完整记录组成）。
fn count_records(wire: &[u8]) -> (usize, usize) {
    let mut count = 0usize;
    let mut pos = 0usize;
    while pos + 5 <= wire.len() {
        let len = u16::from_be_bytes([wire[pos + 3], wire[pos + 4]]) as usize;
        pos += 5 + len;
        count += 1;
    }
    (count, pos)
}

fn main() -> Result<()> {
    // ---- 证书与配置（CA 签发 localhost 证书，客户端信任该 CA）----
    let (ca_cert, ca_key) = shared::certgen::generate_ca(&Default::default())?;
    let (server_cert, server_key) =
        shared::certgen::generate_server_cert(&ca_cert, &ca_key, &Default::default())?;

    let mut roots = RootCertStore::empty();
    roots.add(ca_cert.der().clone())?;

    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![server_cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        )?;

    // ---- 建立内存双工通道，client 侧套 Tap ----
    let (client_end, server_end) = UnixStream::pair()?;
    let log = Rc::new(RefCell::new(Vec::new()));

    let mut client = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("localhost")?,
    )?;
    let mut tap = Tap {
        inner: client_end,
        log: log.clone(),
    };

    // ---- 服务器线程：完成握手，然后收满 300 字节明文就退出 ----
    const TOTAL_PLAINTEXT: usize = 100 + 100 + 100;
    let server_thread = std::thread::spawn(move || -> Result<usize> {
        let mut server = ServerConnection::new(Arc::new(server_config))?;
        let mut sock = server_end;

        while server.is_handshaking() {
            server.complete_io(&mut sock)?;
        }

        let mut received = 0usize;
        let mut buf = [0u8; 4096];
        while received < TOTAL_PLAINTEXT {
            if server.read_tls(&mut sock)? == 0 {
                anyhow::bail!("unexpected EOF after {received} bytes");
            }
            server.process_new_packets()?;
            loop {
                // 注意：rustls 的 Reader 在暂无明文时返回 Err(WouldBlock)，
                // 而不是像 TcpStream 那样阻塞或返回 Ok(0)。
                match server.reader().read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => received += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(received)
    });

    // ---- 客户端完成握手 ----
    while client.is_handshaking() {
        client.complete_io(&mut tap)?;
    }

    let protocol = format!("{:?}", client.protocol_version());

    // ---- 实验 A：100 次 × 1 字节 write ----
    let start = log.borrow().len();
    for _ in 0..100 {
        client.writer().write(&[b'x'])?;
        client.write_tls(&mut tap)?;
    }
    let (records_a, bytes_a) = count_records(&log.borrow()[start..]);

    // ---- 实验 B：1 次 × 100 字节 write ----
    let start = log.borrow().len();
    client.writer().write(&[b'x'; 100])?;
    client.write_tls(&mut tap)?;
    let (records_b, bytes_b) = count_records(&log.borrow()[start..]);

    // ---- 实验 C：1 次 vectored write（100 个 1 字节切片）----
    let start = log.borrow().len();
    let data = vec![b'x'; 100];
    let slices: Vec<IoSlice<'_>> = data.chunks(1).map(IoSlice::new).collect();
    client.writer().write_vectored(&slices)?;
    client.write_tls(&mut tap)?;
    let (records_c, bytes_c) = count_records(&log.borrow()[start..]);

    let received = server_thread
        .join()
        .map_err(|_| anyhow::anyhow!("server thread panicked"))??;

    // ---- 结果 ----
    println!("协商协议: {protocol}（每条记录 tag = 16 B）");
    println!();
    println!("实验                             记录数   线上字节   有效载荷   放大倍数");
    println!("-------------------------------  -------  ---------  ---------  --------");
    println!(
        "A: 100 次 write(1B)             {records_a:>7}  {bytes_a:>9}  {:>9}  {:>7.1}x",
        100,
        bytes_a as f64 / 100.0
    );
    println!(
        "B: 1 次 write(100B)             {records_b:>7}  {bytes_b:>9}  {:>9}  {:>7.1}x",
        100,
        bytes_b as f64 / 100.0
    );
    println!(
        "C: 1 次 write_vectored(100×1B)  {records_c:>7}  {bytes_c:>9}  {:>9}  {:>7.1}x",
        100,
        bytes_c as f64 / 100.0
    );
    println!();
    println!("服务器端共收到明文 {received} 字节");
    assert_eq!(received, TOTAL_PLAINTEXT, "服务器应收满 300 字节明文");
    Ok(())
}
