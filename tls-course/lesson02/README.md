# 课时2：证书与身份验证

## 学习目标

1. 理解X.509证书结构
2. 掌握证书链验证流程
3. 了解SNI（Server Name Indication）扩展
4. 学会自定义证书验证器

## 核心概念

### X.509证书结构

```
Certificate
├── tbsCertificate (待签名证书)
│   ├── version (版本号)
│   ├── serialNumber (序列号)
│   ├── signature (签名算法)
│   ├── issuer (颁发者)
│   ├── validity (有效期)
│   │   ├── notBefore
│   │   └── notAfter
│   ├── subject (主题)
│   ├── subjectPublicKeyInfo (公钥信息)
│   │   ├── algorithm
│   │   └── subjectPublicKey
│   └── extensions (扩展)
│       ├── subjectAltName (SAN) - 包含域名/IP
│       ├── keyUsage - 密钥用途
│       ├── extendedKeyUsage - 扩展密钥用途
│       └── basicConstraints - 是否为CA
├── signatureAlgorithm (签名算法)
└── signatureValue (签名值)
```

### 证书链验证流程

```
Root CA (自签名, 信任锚点)
    ↓ 签名
Intermediate CA
    ↓ 签名
Server Certificate
```

验证步骤：
1. 检查证书有效期
2. 验证签名链
3. 检查证书吊销状态 (CRL/OCSP)
4. 验证主机名 (SNI)

## 运行示例

### 1. 分析证书

```bash
# 分析本地证书
cargo run --bin cert_analyzer -- --cert ../certs/server/server-cert.pem

# 分析远程服务器证书
cargo run --bin cert_analyzer -- --host www.rust-lang.org --port 443

# 详细分析
cargo run --bin cert_analyzer -- --cert ../certs/ca/ca-cert.pem --detailed
```

### 2. 运行服务器（带客户端证书验证）

```bash
cargo run --bin server -- \
    --cert ../certs/server/server-cert.pem \
    --key ../certs/server/server-key.pem \
    --ca-cert ../certs/ca/ca-cert.pem \
    --require-client-cert
```

### 3. 运行客户端（带证书）

```bash
# 普通连接
cargo run --bin client -- --ca-cert ../certs/ca/ca-cert.pem

# 带客户端证书连接 (mTLS)
cargo run --bin client -- \
    --ca-cert ../certs/ca/ca-cert.pem \
    --client-cert ../certs/client/client-cert.pem \
    --client-key ../certs/client/client-key.pem
```

## 观察重点

1. **证书字段解析**: Subject, Issuer, Validity, Extensions
2. **SAN扩展**: 多个主机名的支持
3. **证书链**: 根证书→中间CA→服务器证书
4. **签名验证**: RSA/ECDSA签名算法
5. **自定义验证**: 如何实现特殊验证逻辑

## 思考问题（附参考答案）

1. **为什么需要证书链而不是直接用根证书签名服务器证书？**
   <details><summary>答案</summary>

   - **根 CA 安全**：根私钥离线保管（HSM、气隙机房），直接对外签发意味着
     私钥常年在线，泄露即全网信任崩塌
   - **风险隔离**：中间 CA 被入侵或误签发时，只需吊销该中间证书，
     根不受影响（DigiNotar 事件就是中间层事故）
   - **运营灵活**：根证书预装在操作系统/浏览器里，增删一次要数年；
     中间层可以按业务线、地域、用途随时开设，还能施加名字约束（Name Constraints）
   - 轮换成本：换中间证书只需重新签发叶子证书，换根要整个生态重装
   </details>

2. **SAN 扩展和 Common Name 有什么区别？**
   <details><summary>答案</summary>

   - 历史上浏览器用 CN 字段匹配域名，但它只能放一个名字、编码歧义大
     （大小写、通配符位置混乱）
   - SAN（Subject Alternative Name）是 RFC 6125 定义的标准位置，
     一张证书可同时声明多个 **DNS 名、IP 地址、Email、URI**
   - 现代验证器（包括 rustls/webpki）**只看 SAN，完全忽略 CN**；
     证书里保留 CN 纯粹是兼容旧工具的显示习惯
   - 实操：用 `openssl s_client ... -servername` + 本课 cert_analyzer 观察真实证书，
     会发现 Let's Encrypt 等签发的证书 CN 与 SAN[0] 相同——只是习惯
   </details>

3. **证书吊销是如何工作的？CRL vs OCSP 的区别？**
   <details><summary>答案</summary>

   - **CRL（证书吊销列表）**：CA 周期性签发"全部已吊销证书"的完整列表。
     大（几 MB）、更新慢（小时/天级）、下载方还要自己存
   - **OCSP**：在线查单张证书的状态。快且新鲜，但引入新问题——
     CA 能看到你访问了哪些网站（隐私），OCSP 服务可用性差会拖慢或阻断握手
   - **OCSP Stapling**：服务器代替客户端去取 OCSP 响应，**钉在握手里**带来，
     解决隐私与可用性（见课时 11）
   - 现代趋势：Let's Encrypt 已弃用 OCSP，转向**短周期证书（90 天→更短）+ CT 日志**，
     让"等它过期"比"查吊销"更便宜
   </details>

4. **自签名证书的风险是什么？**
   <details><summary>答案</summary>

   - 自签证书只能证明"我持有这对密钥"，**不能证明我是谁**——没有任何第三方担保
   - 最大风险在于使用方式：客户端若配置成"忽略验证"或"信任所有自签证书"，
     中间人可以随意替换证书，加密形同虚设（很多内网服务的 `verify=false` 惨案）
   - 安全用法：配合**证书固定（pinning）**——客户端写死服务器证书/公钥指纹，
     TUIC 的自签部署正是这个模式（课时 13 的 PinnedCertVerifier）
   - 内部 CA 要严肃做：根证书分发受控、中间层隔离、吊销流程，
     否则任何拿到内部根的攻击者都能签"任意内网域名"
   </details>

5. **mTLS（双向 TLS）的应用场景？**
   <details><summary>答案</summary>

   - **服务网格**：Istio/Linkerd 的 sidecar 之间双向认证，
     零信任内网"不信任网络位置，只信任工作负载身份"
   - **B2B/API**：支付网关、APNs 推送等要求客户端也出示证书
   - **IoT/设备认证**：设备出厂烧录客户端证书，私钥不出芯片，比密码/令牌强
   - 对比 API key：证书有完整生命周期（签发/轮换/吊销）、密钥从不在线传输、
     天然防重放；本课 server 的 `--require-client-cert` 演示了 WebPkiClientVerifier
     与自定义验证器（Acceptor 类"只收不验"仅用于教学）两条路
   </details>

## 代码要点

### 自定义证书验证器

```rust
impl ServerCertVerifier for CustomVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // 自定义验证逻辑
        // 1. 解析证书
        // 2. 验证签名
        // 3. 检查有效期
        // 4. 验证主机名
        // 5. 检查吊销状态
        Ok(ServerCertVerified::assertion())
    }
}
```

## 进一步学习

- [RFC 5280 - X.509证书和CRL](https://tools.ietf.org/html/rfc5280)
- [RFC 6066 - SNI扩展](https://tools.ietf.org/html/rfc6066)
- [证书透明度](https://certificate.transparency.dev/)
