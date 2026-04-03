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

## 思考问题

1. 为什么需要证书透明度？
2. OCSP Stapling vs OCSP Must-Staple的区别？
3. ECH如何防止SNI泄露？
4. 这些扩展对性能有什么影响？
