# 课时11：安全扩展特性

## 学习目标

1. 理解SCT（证书透明度）
2. 掌握OCSP Stapling机制
3. 了解ECH（Encrypted Client Hello）
4. 配置并测试安全扩展

## 核心概念

### Certificate Transparency (CT)

```
Certificate Issuance Flow:

CA issues certificate
    ↓
CA submits to CT logs
    ↓
CT log returns Signed Certificate Timestamp (SCT)
    ↓
CA embeds SCT in certificate
    ↓
Browser validates SCT
    ↓
Certificate accepted
```

**目的**: 防止CA恶意/错误签发证书

### OCSP Stapling

```
Traditional OCSP:
  Client → OCSP Responder → Response → Certificate check
  (Adds latency, privacy concerns)

OCSP Stapling:
  Server periodically queries OCSP
  Server staples OCSP response to certificate
  Client validates stapled response
  (Faster, more private)
```

### Encrypted Client Hello (ECH)

```
Without ECH:
  ClientHello → Contains SNI (server name in plaintext!)
  → Attacker can see which site you're visiting

With ECH:
  ClientHello → Encrypted, contains dummy SNI
  → Real SNI in encrypted extension
  → Only server can decrypt
```

**ECH Flow:**
```
1. DNS returns HTTPS record with ECH config
2. Client encrypts ClientHello with ECH public key
3. Server decrypts with ECH private key
4. Proceed with normal TLS handshake
```

## 运行示例

```bash
# 安全扩展示例
cargo run --bin security_extensions -- --explain

# ECH客户端
cargo run --bin ech_client -- --help
```

## 思考问题（附参考答案）

1. **为什么需要证书透明度？**
   <details><summary>答案</summary>

   - CA 体系是**单点信任**：任何一家 CA 都能给任何域名签证书。
     DigiNotar 2011 年被入侵，攻击者拿到 google.com 的"合法"证书劫持了
     伊朗用户的 Gmail——数月后才被发现，因为没人知道"某 CA 给我的域名签了证书"
   - CT（RFC 6962）强制所有证书登记到**公开、仅追加**的 Merkle 树日志：
     - 域名所有者可以监控"我的域名新出现了什么证书"（crt.sh 一查便知）
     - 浏览器只信任携带 **SCT**（日志签名收据）的证书——
       流氓签发无处遁形，审计者可交叉验证日志一致性
   - 效果：误签发从"数年不发现"变成"数小时全网可见"
   </details>

2. **OCSP Stapling vs OCSP Must-Staple 的区别？**
   <details><summary>答案</summary>

   - **Stapling（钉扎）是服务器行为**：服务器定期取回自己证书的 OCSP 响应，
     在握手时"钉"给客户端（CertificateStatus 记录）——客户端不必再去问 CA，
     隐私与速度双赢。随时可开可关
   - **Must-Staple 是证书里的承诺**（TLS 特性扩展 id-ce 1.3.6.1.5.5.7.1.24）：
     证书声明"客户端必须要求有效的钉扎响应，否则拒绝此证书"
     ——把 stapling 从可选变成硬性，防服务器运维忘记
   - 实践困境：OCSP 响应有有效期， stapling 基础设施一抖动，
     Must-Staple 证书的站点就直接打不开——运维风险太高，
     Let's Encrypt 已宣布放弃 OCSP（转短周期证书 + CT），Must-Staple 基本被时代绕过
   </details>

3. **ECH 如何防止 SNI 泄露？**
   <details><summary>答案</summary>

   - 问题：SNI 在 ClientHello 里**明文**——路上任何中间盒/审查者
     直接读出你要访问的真实域名，即使后续全部加密
   - ECH（RFC 9460，前身 ESNI）的拆分方案：
     1. 真实的 ClientHello（内层，含真实 SNI）用**面向公众的 CDN 入口域名**（外层 SNI，
        如 cloudflare-ech.com）的公钥加密——公钥通过 DNS 的 HTTPS 记录类型分发
     2. 中间人只能看到"你连了某个 CDN 的公共入口"
     3. 入口服务器解密内层，把连接路由（或代理）到真实目标
   - 依赖链：DNS 查询本身要加密（DoH/DoT），否则审查者从 DNS 侧照样看到目标；
     ECHConfig 的分发完整性建议 DNSSEC
   - 本课 ech_client 连接 cloudflare-ech.com 即此流程；QUIC 场景 SNI 同样藏在
     Initial 的 CRYPTO 帧里，ECH 对 QUIC 一样适用
   </details>

4. **这些扩展对性能有什么影响？**
   <details><summary>答案</summary>

   - **SCT（CT 收据）**：几乎零开销——验证是几次数签名验证，
     且客户端可缓存日志公钥；证书体积增加几百字节
   - **OCSP Stapling**：**净优化**——握手多一条几百字节的 CertificateStatus，
     换掉客户端→CA 的一次在线查询（省 1 个 RTT + 可用性风险）
   - **ECH**：最贵的一个——多一次 DNS HTTPS 记录查询；双层 ClientHello 使
     Initial 变大；首次连接多一跳（外层握手→内层恢复）；
     恢复场景 PSK 需要绑定 ECH 配置，票据不能跨 ECH 密钥复用
   - 共同设计哲学：安全扩展尽量做成**零额外往返**（搭既有消息的便车），
     影响主要在证书体积与 CPU，而不是延迟
   </details>
