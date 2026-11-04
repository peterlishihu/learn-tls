# TLS 速查表（TLS Cheatsheet）

配合课时 1-12 使用，快速回忆关键结构、流程与数字。

## 版本演进

| 版本 | 年份 | RFC | 状态 | 握手 RTT | 关键变化 |
|------|------|-----|------|----------|----------|
| SSL 3.0 | 1996 | — | ❌ 已废弃 (POODLE) | 2 | — |
| TLS 1.0 | 1999 | 2246 | ❌ 已废弃 | 2 | SSL3 的标准化 |
| TLS 1.1 | 2006 | 4346 | ❌ 已废弃 | 2 | 修复 CBC IV |
| TLS 1.2 | 2008 | 5246 | ⚠️ 遗留使用 | 2 | SHA-256、AEAD（GCM） |
| TLS 1.3 | 2018 | 8446 | ✅ 当前标准 | 1 | 0-RTT、去掉 RSA 密钥传输/压缩/重协商 |

## TLS 1.3 握手（1-RTT）

```
Client                                          Server
------                                          ------
ClientHello
  + key_share(X25519)          -------->
  + supported_groups
  + signature_algorithms
                                                ServerHello
                                                  + key_share
                                  <--------      {EncryptedExtensions}
                                                {Certificate}
                                                {CertificateVerify}
                                                {Finished}
  [此处客户端已可推导握手密钥]
{Finished}                     -------->
[Application Data]             <======>          [Application Data]
```

- `{}` = 已加密（用握手流量密钥）
- 0-RTT：携带 PSK 的 ClientHello 直接附带 `early_data`，无需等待 ServerHello

## TLS 1.3 密钥派生树（课时 7）

```
early_secret = HKDF-Extract(salt=0, IKM=PSK 或 0)
    │ handshake_secret = HKDF-Extract(salt=derived(early_secret), IKM=ECDHE)
    │     ├── c hs traffic = Expand-Label(hs_secret, "c hs traffic", hs_hash)
    │     └── s hs traffic = Expand-Label(hs_secret, "s hs traffic", hs_hash)
    │ master_secret = HKDF-Extract(salt=derived(hs_secret), IKM=0)
              ├── c ap traffic = Expand-Label(master, "c ap traffic", hs_hash)
              ├── s ap traffic = Expand-Label(master, "s ap traffic", hs_hash)
              ├── exp master   = Expand-Label(master, "exp master",    hs_hash)
              └── res master   = Expand-Label(master, "res master",    hs_hash)
```

每个 traffic secret 再派生 `key` / `iv`：
`key = Expand-Label(secret, "key", "", key_len)`，`iv = Expand-Label(secret, "iv", "", 12)`

## 记录层格式（TLS 1.2/1.3 相同的外层）

```
+------+------+-----------+
| type | ver  |   length  |   明文头 5 字节（TLS 1.3 中 type 固定填 23）
+------+------+-----------+
|      加密负载 (AEAD)     |   密文 + 16 字节 Poly1305/GCM tag
+-------------------------+
```

- TLS 1.3 的真实内容类型藏在密文**最后一个字节**（内容类型填充）
- Nonce = 静态 IV XOR 序列号（64-bit，隐式递增）

## 常用密码套件

| 套件 | TLS | 说明 |
|------|-----|------|
| TLS_AES_128_GCM_SHA256 | 1.3 | 必须实现 |
| TLS_AES_256_GCM_SHA384 | 1.3 | — |
| TLS_CHACHA20_POLY1305_SHA256 | 1.3 | 无 AES-NI 时首选 |
| ECDHE-RSA-AES128-GCM-SHA256 | 1.2 | 前向保密 + AEAD |

密钥交换组：X25519（首选）、P-256、P-384、X448（finney…）；签名：RSA-PSS、ECDSA、Ed25519。

## 会话恢复对比

| 机制 | 版本 | 服务器状态 | RTT | 备注 |
|------|------|-----------|-----|------|
| Session ID | ≤1.2 | 有状态 | 1 | 服务器内存查表 |
| Session Ticket | ≤1.2 | 无状态 | 1 | 加密票据存客户端 |
| PSK (resumption) | 1.3 | 无状态 | 1 | NewSessionTicket 派生 |
| 0-RTT early data | 1.3 | 无状态 | 0 | ⚠️ 有重放风险，只用于幂等请求 |

## 关键扩展（ClientHello）

| 扩展 | 作用 |
|------|------|
| server_name (SNI) | 明文携带目标域名（ECH 可加密它，课时 11） |
| supported_versions | 版本协商（TLS 1.3 不再依赖 version 字段） |
| key_share | 直接携带 (EC)DHE 公钥，省一个 RTT |
| pre_shared_key + psk_key_exchange_modes | 会话恢复 |
| early_data | 0-RTT 请求 |
| alpn | 应用层协议协商（HTTP/2、h3，QUIC 必需） |
| signature_algorithms | 签名算法白名单 |
| quic_transport_parameters | QUIC 传输参数（课时 13） |

## 常见攻击与防御

| 攻击 | 目标 | 防御 |
|------|------|------|
| POODLE / CBC 填充预言 | SSL3 / TLS1.0 CBC | 禁用旧版本；1.3 只保留 AEAD |
| Downgrade 中间人 | 版本回退 |Finished 消息覆盖握手摘要； server_hello.random 末字节标记降级 |
| 重放 0-RTT | 0-RTT early data | 单次票据 + 服务器反重放窗口 + 幂等设计 |
| SNI 泄露 | 隐私 | ECH（课时 11） |
| 撤销检查缺失 | 吊销证书 | OCSP Stapling / CRLite |
| 跨协议攻击 | ALPN 缺失 | ALPN 必填（QUIC 强制） |

## 排障命令

```bash
# 查看证书链与协议
openssl s_client -connect example.com:443 -servername example.com -showcerts

# 只看协商结果
openssl s_client -connect example.com:443 -brief </dev/null

# 强制 TLS 1.3 / 指定套件
openssl s_client -connect example.com:443 -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384

# 导出会话密钥给 Wireshark（curl/openssl 均支持）
SSLKEYLOGFILE=~/keys.log curl https://example.com
```
