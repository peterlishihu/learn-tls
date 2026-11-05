# 课时3：密钥交换机制

## 学习目标

1. 理解RSA vs ECDHE密钥交换的区别
2. 掌握前向保密(Forward Secrecy)概念
3. 对比TLS 1.2和1.3的密钥交换差异
4. 了解不同的椭圆曲线算法

## 核心概念

### 密钥交换方法对比

| 特性 | RSA | ECDHE (TLS 1.2) | ECDHE (TLS 1.3) |
|------|-----|-----------------|-----------------|
| 前向保密 | ❌ 否 | ✅ 是 | ✅ 是 |
| 握手RTT | 2 | 2 | 1 |
| 计算开销 | 高 (大数分解) | 中 (椭圆曲线) | 中 (椭圆曲线) |
| 密钥长度 | 2048+ bit | 256 bit | 256 bit |
| TLS 1.3支持 | ❌ | ❌ | ✅ |

### 前向保密 (Forward Secrecy)

```
场景：长期私钥被泄露

无FS (RSA):
    攻击者可以解密所有历史会话！
    因为会话密钥是用长期RSA私钥加密的

有FS (ECDHE):
    攻击者只能影响未来会话
    每次会话使用新的临时密钥对
    临时私钥在会话结束后销毁
```

### TLS 1.2 vs TLS 1.3 密钥交换

**TLS 1.2 (ECDHE):**
```
Client                                  Server
  |                                       |
  | -- ClientHello + KeyShare ----------> |  (包含客户端公钥)
  |                                       |
  | <------ ServerHello ----------------- |  (包含服务器公钥)
  | <------ Certificate ----------------- |
  | <------ ServerKeyExchange ----------- |  (包含签名)
  | <------ ServerHelloDone ------------- |
  |                                       |
  | -- ClientKeyExchange --------------> |  (客户端公钥)
  | -- [ChangeCipherSpec] -------------> |
  | -- Finished ------------------------> |
  |                                       |
  | <------ [ChangeCipherSpec] ---------- |
  | <------ Finished -------------------- |
  |                                       |
  | ===== 加密通信 ====================== |
```

**TLS 1.3 (1-RTT):**
```
Client                                  Server
  |                                       |
  | -- ClientHello + KeyShare ----------> |  (包含客户端公钥)
  | -- Key_share extensions               |
  |                                       |
  | <------ ServerHello ----------------- |  (包含服务器公钥)
  | <------ {EncryptedExtensions} ------- |  (加密消息)
  | <------ {Certificate} --------------- |
  | <------ {CertificateVerify} --------- |
  | <------ {Finished} ------------------ |
  |                                       |
  | -- {Finished} ----------------------> |
  |                                       |
  | ===== 加密通信 ====================== |
```

## 运行示例

```bash
# 运行密钥交换演示
cargo run --bin key_exchange_demo -- --help

# 对比TLS 1.2和1.3
cargo run --bin key_exchange_demo -- --compare

# 查看支持的密钥交换组
cargo run --bin key_exchange_demo -- --list-groups
```

## 思考问题（附参考答案）

1. **为什么 TLS 1.3 移除了 RSA 密钥交换？**
   <details><summary>答案</summary>

   - **无前向保密**：RSA 密钥交换中会话密钥用服务器证书公钥加密——
     攻击者录下历史流量，日后拿到服务器私钥即可全部解密（"先存后解"）
   - **实现复杂+易受攻击**：服务器要做 RSA 解密，历史上多次
     Bleichenbacher 填充预言攻击都是 RSA 密钥交换的锅（需要精心防御）
   - TLS 1.3 只保留 (EC)DHE 与 PSK 两种模式；注意**移除的是"RSA 密钥交换"而非
     RSA 证书**——RSA-PSS 签名的证书仍然广泛用于身份认证
   - 恢复模式还支持 PSK+DHE 混合（psk_dhe_ke），恢复的会话也有前向保密
   </details>

2. **ECDHE 的前向保密是如何实现的？**
   <details><summary>答案</summary>

   - 每条连接双方各生成**临时（ephemeral）密钥对**，私钥用完即弃
   - 会话密钥 = 自己的临时私钥 × 对端的临时公钥（ECDH 运算），
     中间人没有任一方的临时私钥，无法计算
   - 证书长期私钥**只用于签名**（证明"我确实是这个域名的服务器"），
     不参与任何密钥材料的计算——这就是"认证"与"密钥交换"的分离
   - 攻击者录下全部流量 + 日后攻破服务器拿到证书私钥，也只能验证签名，
     无法重构早已销毁的临时密钥（依赖 CDH 计算困难性假设）
   - 注意：ECDH 的输出**并不直接当加密密钥**——它是群元素（如 X25519
     的 u 坐标），比特分布有固定结构（最高位恒为 0），不是均匀随机串。
     必须先经 HKDF-Extract 均匀化、再按用途展开成握手/应用/IV 等多个
     密钥，派生时还掺入握手摘要做防篡改绑定——完整过程见课时 7 的密钥树
   </details>

3. **X25519 和 P-256 有什么区别？**
   <details><summary>答案</summary>

   | 维度 | X25519 | P-256 (secp256r1) |
   |------|--------|-------------------|
   | 来源 | djb 2006 年独立设计 | NIST 标准曲线 |
   | 实现安全 | Montgomery 阶梯天然**常数时间**，难写错 | 短 Weierstrass 曲线，实现易出 timing 侧信道 |
   | 性能 | 软实现快（无查表） | 有硬件/汇编优化时很快 |
   | 合规 | 非 FIPS | FIPS 必选 |
   | 争议 | 无 NSA 疑虑（常数结构） | 曲线参数来源曾被质疑（无后门证据） |

   - 实践：TLS 1.3 默认双发（X25519 优先），QUIC 的 hybrid 还在前面加了 ML-KEM；
     rustls 的 ring provider 首组就是 X25519（课时 9 的 kx_groups 列表可见）
   </details>

4. **量子计算对当前密钥交换有什么威胁？**
   <details><summary>答案</summary>

   - **Shor 算法**可多项式时间破解 ECDH/RSA/DSA——大容量容错量子计算机
     一旦出现，今天录下的流量全部可解（"先存后解"HNDL 已在进行）
   - 对称部分影响小得多：Grover 算法把 AES-256 的安全级减半到 128 位，仍然够用
   - 对策是**混合密钥交换**：X25519 + ML-KEM（Kyber，NIST 后量子标准）
     并联共享秘密，经典攻击破一个也破不了组合
   - TLS 部署上：Cloudflare/Google 已上线 X25519MLKEM768；
     rustls 0.23 有 `prefer-post-quantum` feature（默认在 aws-lc-rs provider 上开启）；
     证书签名的后量子迁移更慢（签名尺寸大，生态复杂）
   </details>
