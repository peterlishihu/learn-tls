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

## 思考问题

1. 为什么TLS 1.3移除了RSA密钥交换？
2. ECDHE的前向保密是如何实现的？
3. X25519和P-256有什么区别？
4. 量子计算对当前密钥交换有什么威胁？
