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

## 思考问题

1. 为什么需要证书链而不是直接用根证书签名服务器证书？
2. SAN扩展和Common Name有什么区别？
3. 证书吊销是如何工作的？CRL vs OCSP的区别？
4. 自签名证书的风险是什么？
5. mTLS（双向TLS）的应用场景？

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
