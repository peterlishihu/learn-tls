# 课时9：Crypto Provider机制

## 学习目标

1. 理解CryptoProvider trait设计
2. 掌握如何实现自定义provider
3. 了解provider的注册机制
4. 实现简化版crypto provider

## 核心概念

### CryptoProvider Trait

```rust
pub struct CryptoProvider {
    pub cipher_suites: Vec<SupportedCipherSuite>,
    pub kx_groups: Vec<SupportedKxGroup>,
    pub signature_verification_algorithms: SignatureVerificationAlgorithms,
    pub secure_random: Arc<dyn SecureRandom>,
    pub key_provider: Arc<dyn KeyProvider>,
}
```

### Provider Components

```
Cipher Suite: Defines encryption + authentication
├── TLS 1.3: TLS_AES_256_GCM_SHA384
│   └── Aes256Gcm (AEAD encryption)
│   └── Sha384 (handshake hashing)
│   └── X25519 (key exchange)
│
└── TLS 1.2: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    └── Ecdhe (key exchange)
    └── Rsa (authentication)
    └── Aes128Gcm (encryption)
    └── Sha256 (hashing)

Key Exchange Group:
├── X25519 (recommended)
├── X448
├── P-256
├── P-384
└── P-521

Signature Algorithm:
├── ECDSA (P-256, P-384, P-521)
├── Ed25519
├── Ed448
└── RSA (PKCS1, PSS)
```

## 运行示例

```bash
# 自定义provider演示
cargo run --bin custom_provider -- --explain

# 列出当前provider的算法
cargo run --bin custom_provider -- --list
```

## 思考问题

1. 为什么需要pluggable crypto provider？
2. 如何实现硬件加速provider？
3. provider切换如何影响兼容性？
4. FIPS合规性如何实现？
