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

## 思考问题

1. 为什么rustls使用状态机设计？
2. ConnectionCommon的作用是什么？
3. 如何实现自定义CryptoProvider？
4. rustls如何保证内存安全？
