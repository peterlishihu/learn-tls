# rustls 源码笔记

配合课时 8-10（架构、Crypto Provider、异步 I/O）阅读。基于 rustls 0.23。

> 本仓库直接依赖 `rustls 0.23`（ring provider）。
> 值得记住的循环依赖知识：**quinn（课时 13 的 QUIC 实现）内部也是用 rustls 做 TLS 1.3 握手**，
> 学完 rustls 再看 QUIC，等于已经掌握它一半。

## 仓库布局

```
rustls/src/
├── lib.rs            # 模块导出、RootCertStore
├── client/           # 客户端：ClientConnection、danger(ServerCertVerifier)、handy traits
│   ├── client_conn.rs    # 状态机 + ClientConnection本体（~3000 行核心）
│   └── tls13.rs          # 客户端 TLS1.3 握手消息驱动
├── server/           # 服务器：ServerConnection、WebPkiClientVerifier、Acceptor、ReadEarlyData
├── conn.rs           # ConnectionCommon：读写公共路径、writer()/reader()、SideData
├── record_layer.rs   # 记录层序列化/反序列化
├── msgs/             # 消息定义与编解码（handshake.rs / enums.rs / codec.rs）
├── crypto/           # CryptoProvider 抽象 + ring/aws-lc-rs 两个内置实现
├── tls13/            # TLS 1.3 密钥调度、套件定义
├── tls12/            # TLS 1.2 PRF、套件定义
├── quic.rs           # QuicExt：rustls 给 QUIC 暴露的密钥/加密接口（课时13 的桥）
├── verify.rs         # 证书验证抽象（NoClientAuth 等）
├── webpki/           # 基于 rustls-webpki 的证书链验证、client/server verifier
└── vecbuf.rs         # 零拷贝 scatter/gather 缓冲
```

## 三层状态机

rustls 用**类型状态构建器 + 显式状态枚举**组合：

1. **配置期**：`ConfigBuilder<WantsVerifier/WantsServerCert/...>`
   每一步消费 self 返回下一阶段，编译期保证配置顺序：
   `builder_with_provider(...)` → `with_protocol_versions()` → `with_root_certificates()` → `with_no_client_auth()` → `ClientConfig`
2. **连接期**：`ClientConnection`/`ServerConnection` 内部 `State` 枚举
   （`AwaitServerHello` → `ExpectCertificate` … → `ConnectionState::Established`）
3. **公共层**：`ConnectionCommon`——`complete_io()` 循环 `read_tls → process_new_packets → write_tls`

## 一个包的生命周期（读路径）

```
socket.read()
  → conn.read_tls(&mut sock)        # 解析记录层头，收一个完整 record
  → conn.process_new_packets()      # 解密 + 喂给状态机，可能产出握手消息/触发密钥切换
  → conn.reader().read(&mut buf)    # 应用层数据出队（&ConnectionCommon::reader() 是 io::BufRead）
```

写路径：`conn.writer().write_all(b"...")` 只是把明文排入发送队列，
真正的加密与发送发生在下一次 `write_tls()`。

## CryptoProvider（课时 9）

```rust
pub struct CryptoProvider {
    pub cipher_suites: Vec<SupportedCipherSuite>,          // 套件=算法+实现
    pub kx_groups: Vec<&'static dyn SupportedKxGroup>,     // 首个元素=默认 key share
    pub signature_verification_algorithms: WebPkiSupportedAlgorithms,
    pub secure_random: &'static dyn SecureRandom,
    // ... 以及 provider 解析支持
}
```

- 进程级默认：`CryptoProvider::install_default()`（进程内只能装一次）
- 显式指定（课程采用，避免歧义）：
  `ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))`
- `SupportedCipherSuite` 是配置与实现的合体：
  `Tls13(&'static Tls13CipherSuite)` 携带 hkdf_provider / aead_alg / quic
  ——注意 `quic: Option<&'static dyn quic::Algorithm>` 字段，QUIC 能用哪些套件在这里决定。

## rustls ↔ QUIC 的接口（课时 13 预习）

`rustls::quic::QuicExt` 是 rustls 为 QUIC 暴露的门面：

- `read_hs()` / `write_hs()`：QUIC 把收到的 **CRYPTO 帧**内容喂进来，取出发往对端的握手字节——TLS 记录层被完全绕过，TLS 只负责"握手消息流 + 密钥调度"
- `write_level()`：当前 CRYPTO 帧应放在 Initial/Handshake/1-RTT 哪个加密级别
- `export_keying_material()`：RFC 5705 exporter，TUIC v5 用它派生认证 token
- 密钥切换：QUIC 在恰当时机调用 `Secrets` 相关接口拿走 packet protection 密钥

## 调试钩子

- `config.key_log = Arc::new(rustls::KeyLogFile::new())` → SSLKEYLOGFILE 环境变量自动导出密钥（Wireshark 可解密，课时 12）
- `RUST_LOG=trace`：rustls 内部有大量 tracing 事件
- `ConnectionCommon::peer_certificates()` / `alpn_protocol()` / `negotiated_cipher_suite()`：握手后查询协商结果
- 危险接口（自定义验证器）都在 `client::danger` / `server::danger` 模块——名字就是在提醒你

## 性能相关

- 发送方向 scatter/gather：`vecbuf::ChunkVecBuffer` 聚合小写入，配合 `write_vectored` 减少 syscall（课时 10）
- aws-lc-rs provider 在有 AES-NI/AVX 的机器上通常比 ring 快（本课程选 ring 是为了编译简单；切 provider 只需换 `default_provider()`）
- rustls 0.23 起 TLS1.2 套件裁剪为 4 个、1.3 套件 3 个——套件越少，状态机分支越少
