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

## 思考问题（附参考答案）

1. **为什么需要 pluggable crypto provider？**
   <details><summary>答案</summary>

   - **算法演进**：后量子 ML-KEM 从标准化到上线只用了两年——
     如果算法烧死在库里，每个新算法都要发新版本；provider 是算法的插件槽
   - **合规切换**：FIPS 场景要求 aws-lc-rs（有验证模块），
     嵌入式/交叉编译偏好 ring（构建简单）——同一个 rustls，两种后端
   - **硬件适配**：HSM、SGX、国产密码卡各自实现 trait 即可接入
   - **避免进程级歧义**：Rust 静态链接生态里两个 crate 各装默认 provider
     会冲突，显式 `builder_with_provider` 让依赖图里多实现共存（本课程全程显式指定）
   - 教学价值：拆开 provider 才真正理解 TLS 各算法之间的接口边界（课时 9 的实践）
   </details>

2. **如何实现硬件加速 provider？**
   <details><summary>答案</summary>

   - 分三种"硬"法：
     1. **SIMD 指令**（最常见的含义）：ring 内部已按 CPU 特性选择
        AES-NI/ARMv8 汇编路径，普通 provider 直接受益
     2. **独立加速卡**：实现 `MessageEncrypter` 把数据发给硬件引擎
        （或 `sign::SigningKey` 桥接 HSM 会话，私钥永不离开硬件）
     3. **CPU 内嵌**：如 SGX enclave 内跑完整 provider
   - 工程要点：CryptoProvider 是 `'static` 集合——在初始化时探测 CPU 特性并固化；
     对比基准用 criterion（课时 6 的 cipher_benchmark 就是模板）；
     注意加速器往返开销，小包场景"异步提交+批量取回"常常才是赢法
   </details>

3. **provider 切换如何影响兼容性？**
   <details><summary>答案</summary>

   - 套件/kx 组/签名算法列表变化 → **协商结果变化**：
     FIPS provider 去掉 ChaCha20 → 只支持 ChaCha20 的老移动端握手失败
   - 后量子组（X25519MLKEM768）对老服务器是未知组——
     服务器忽略扩展退回 X25519 没问题，但实现糟糕的中间盒/服务器可能直接失败
     （这正是要保留纯 X25519 组在列表里的原因）
   - 会话恢复跨 provider 通常兼容（PSK 派生只依赖哈希/AEAD 一致性），
     但栈升级后旧 ticket 可能因派生实现细节失效——客户端会静默回退全握手
   - 部署验证：SSLKEYLOGFILE + 抓包确认协商套件（课时 12 的流程）
   </details>

4. **FIPS 合规性如何实现？**
   <details><summary>答案</summary>

   - rustls 官方路径：**aws-lc-rs provider**（AWS 维护的 BoringSSL 分支，
    底层 aws-lc-fips-sys 是经过 NIST 认证的密码模块）
   - 合规不只是换 provider：
     1. 编译期启用 FIPS 模式的 aws-lc（算法参数、自检行为都进入认证边界）
     2. 随机数、密钥管理边界要同样落在认证模块内
        （自己用 /dev/urandom 补随机数会破坏边界）
     3. 禁用未认证的算法组合
   - rustls manual 有专章"FIPS"；文档明确警告：rustls 本体不在认证边界内，
     合规声明取决于整体系统的评估
   </details>
