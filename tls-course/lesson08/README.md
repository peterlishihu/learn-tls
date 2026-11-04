# 课时8：rustls架构剖析

## 学习目标

1. 理解rustls的核心架构
2. 掌握ClientConfig和ServerConfig设计
3. 了解ConnectionCommon状态机
4. 理解rustls的模块化设计

## 核心概念

### rustls架构图

```
┌────────────────────────────────────────────────────────────┐
│                        Public API                          │
├────────────────────────────────────────────────────────────┤
│  ClientConfig          ServerConfig        RootCertStore   │
│  ClientConnection      ServerConnection    CertificateDer  │
│  Stream                Acceptor            ServerName      │
└────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────────────┐
│                     Connection State                         │
├────────────────────────────────────────────────────────────┤
│  ConnectionCommon                                            │
│  ├── CommonState (shared state)                            │
│  ├── DataState (read/write buffers)                        │
│  └── StateMachine (handshake state)                        │
└────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────────────┐
│                     Protocol Logic                           │
├────────────────────────────────────────────────────────────┤
│  tls12/                        tls13/                        │
│  ├── ClientHandshakeState      ├── ClientConnectionState     │
│  ├── ServerHandshakeState      ├── ServerConnectionState     │
│  └── CipherSuiteImpl           └── HandshakeDetails          │
└────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────────────┐
│                   Crypto Abstraction                         │
├────────────────────────────────────────────────────────────┤
│  crypto::CryptoProvider                                      │
│  ├── CipherSuite (AES-GCM, ChaCha20)                       │
│  ├── KeyExchange (X25519, P-256)                           │
│  ├── Signature (RSA, ECDSA, Ed25519)                       │
│  └── Hash (SHA-256, SHA-384)                               │
└────────────────────────────────────────────────────────────┘
```

### ClientConfig构建流程

```rust
let config = ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth()
    .build();
```

### 状态机设计

```
Client Handshake States:
  ExpectServerHello
    ↓
  ExpectEncryptedExtensions
    ↓
  ExpectCertificateOrCertReq
    ↓
  ExpectCertificateVerify
    ↓
  ExpectFinished
    ↓
  Traffic

Server Handshake States:
  ExpectClientHello
    ↓
  ExpectClientHelloOrHelloRetryRequest
    ↓
  ExpectFinished
    ↓
  Traffic
```

## 运行示例

```bash
# 架构探索
cargo run --bin architecture_explorer -- --explain

# 查看状态机
cargo run --bin architecture_explorer -- --state-machine
```

## 思考问题（附参考答案）

1. **为什么 rustls 使用状态机设计？**
   <details><summary>答案</summary>

   - TLS 握手本质是**强顺序协议**：每条消息都有严格的前序约束
     （不能在 ServerHello 前收 Certificate），状态机让约束显式化
   - rustls 的做法（本课示例可见）是 `State` 枚举 + 每状态一个 handler 函数，
     `process_new_packets` 按 `match state` 分发：
     - 非法消息序列 = 无法匹配的枚举变体 → 直接报错，而不是进入未定义行为
     - 状态切换 = 枚举值替换，旧状态（含其中的缓冲）被 move 走/释放，
       **不残留可被利用的旧状态**（很多 C 实现 TLS 的漏洞源头就是状态清理不彻底）
   - 配置期同样有类型状态构建器（ConfigBuilder<Wants...>），
     把"配置顺序错误"从运行时错误变成编译错误——同一思想在两个层面使用
   </details>

2. **ConnectionCommon 的作用是什么？**
   <details><summary>答案</summary>

   - 客户端/服务器 80% 的连接逻辑相同：记录层读写、加解密、
     `writer()/reader()` 应用数据接口、`complete_io` 循环
   - rustls 把这部分抽成 `ConnectionCommon<S>`：
     - `ClientConnection`/`ServerConnection` 通过 **Deref** 暴露它
       （课时 13 的 shared::util::Stream 泛型约束正是 `Deref<Target=ConnectionCommon>`）
     - 泛型参数 `S: SideData` 携带两端各自独有的数据
       （客户端的会话缓存句柄/服务器的 early data 状态），
       共享代码零开销、差异部分类型隔离
   - 这也解释了为什么 `StreamOwned<C, T>` 能同时包装两种连接
   </details>

3. **如何实现自定义 CryptoProvider？**
   <details><summary>答案</summary>

   - 路线图（课时 9 的完整演示）：
     1. 实现 crypto 模块的各 trait：`cipher::MessageEncrypter/Decrypter`（AEAD 调用）、
        `tls13::Hkdf` 或 `hmac::Hmac`（密钥派生）、`sign::SigningKey`、
        `kx::SupportedKxGroup`、`SecureRandom`
     2. 用静态集合包装：`SupportedCipherSuite::Tls13(&'static Tls13CipherSuite)`
        携带 hkdf_provider / aead_alg
     3. 组装 `CryptoProvider` 结构体（cipher_suites、kx_groups、
        signature_verification_algorithms、secure_random）
     4. `builder_with_provider(Arc::new(my_provider))` 显式启用
   - 最小可行版本：只注册一个套件 + 一个 kx 组（课时 9 的 custom_provider）
   </details>

4. **rustls 如何保证内存安全？**
   <details><summary>答案</summary>

   - **语言层**：所有权/借用检查消灭悬垂指针、越界、use-after-free
     这类 C 系 TLS 库的经典漏洞类别
   - **解析层**：所有线上输入经 `msgs/codec.rs` 的严格解码器，
     长度不足即错，不做隐式截断
   - **密钥材料**：zeroize 在 drop 时擦除内存；密钥类型不暴露原始字节
   - **测试层**：cargo-fuzz 持续 fuzz（课时 12）、与 openssl/boringssl 的
     interop 测试套件、正式发布前的大规模真实流量验证
   - **供应链**：算法实现放进 ring/aws-lc-rs（独立审计的密码库），
     rustls 本体不含手写密码学
   </details>
