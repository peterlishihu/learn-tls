# 课时1：TLS握手全景图

## 学习目标

1. 理解TLS握手的基本流程
2. 掌握ClientHello和ServerHello的结构
3. 了解密码套件协商过程
4. 学会使用日志观察握手过程

## 核心概念

### TLS握手流程 (简化)

```
客户端                                    服务器
   |                                         |
   | ----- ClientHello --------------------> |
   |    (支持的版本、密码套件、随机数)         |
   |                                         |
   | <---- ServerHello --------------------- |
   |    (选定的版本、密码套件、随机数)         |
   | <---- Certificate --------------------- |
   |    (服务器证书链)                        |
   | <---- ServerKeyExchange --------------- | (TLS 1.2)
   | <---- ServerHelloDone ----------------- | (TLS 1.2)
   |                                         |
   | ----- ClientKeyExchange --------------> | (TLS 1.2)
   | ----- [ChangeCipherSpec] -------------> |
   | ----- Finished -----------------------> |
   |                                         |
   | <---- [ChangeCipherSpec] -------------- |
   | <---- Finished ------------------------ |
   |                                         |
   | ===== 加密通信开始 ===================== |
```

### TLS 1.3 握手差异

- 1-RTT握手 (TLS 1.2需要2-RTT)
- 更多握手消息加密
- 移除ServerKeyExchange/ClientKeyExchange
- 使用KeyShare扩展

## 运行示例

### 1. 启动服务器

```bash
cargo run --bin server -- --cert certs/server/cert.pem --key certs/server/key.pem
```

### 2. 运行客户端

```bash
# 连接本地服务器
cargo run --bin client -- --host localhost --port 8443

# 连接真实服务器
cargo run --bin client -- --host www.rust-lang.org --port 443 --use-webpki

# 启用详细调试
RUST_LOG=debug cargo run --bin client -- --host localhost --port 8443
```

### 3. Wireshark抓包分析

```bash
# 设置SSLKEYLOGFILE
export SSLKEYLOGFILE=/tmp/tls-keys.log

# 运行客户端
cargo run --bin client

# 在Wireshark中: Edit -> Preferences -> Protocols -> TLS
# 设置 (Pre)-Master-Secret log filename 为 /tmp/tls-keys.log
```

## 观察重点

1. **ClientHello内容**: 支持的TLS版本、密码套件列表、扩展
2. **ServerHello响应**: 选定的协议版本和密码套件
3. **证书传输**: 证书链结构和验证
4. **密钥交换**: 密钥协商过程
5. **Finished消息**: 握手完整性验证

## 思考问题

1. 为什么TLS 1.3的握手更快？
2. ClientHello中的"supported_versions"扩展有什么作用？
3. 如果客户端和服务器没有共同支持的密码套件会怎样？
4. 随机数在握手中的作用是什么？

## 进一步学习

- [RFC 8446 Section 2](https://tools.ietf.org/html/rfc8446#section-2) - TLS 1.3协议概述
- [TLS 1.3 Illustrated](https://tls13.xargs.org/) - 可视化握手过程
