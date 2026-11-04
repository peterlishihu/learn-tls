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

## 思考问题（附参考答案）

1. **为什么 TLS 1.3 的握手更快？**
   <details><summary>答案</summary>

   - 握手轮次：TLS 1.2 需要 2-RTT，TLS 1.3 只要 1-RTT（PSK 恢复时 0-RTT）
   - 关键改动是 `key_share` 扩展：客户端在 ClientHello 里**直接带上 (EC)DHE 公钥**，
     服务器在 ServerHello 里就能完成密钥交换，省掉了 1.2 的
     ServerKeyExchange / ClientKeyExchange 一整个往返
   - ServerHello 之后的所有握手消息（证书、Finished 等）全部加密传输，
     既安全又减少了明文阶段的约束
   - 恢复场景配合 NewSessionTicket + PSK + early_data，首包即可携带应用数据
   - 注意区分"TLS 握手 1-RTT"与"TCP+TLS 共 2-RTT"——QUIC（课时 13）把两者合一
   </details>

2. **ClientHello 中的 "supported_versions" 扩展有什么作用？**
   <details><summary>答案</summary>

   - 版本协商从记录层的 `version` 字段**搬进了扩展**：中间盒看不懂扩展，也就无法
     依据记录层版本字段做拦截或降级——对抗协议僵化（ossification）
   - 客户端按优先序列出支持的版本，服务器在 ServerHello 的同名扩展中回选一个
   - 兼容性技巧：TLS 1.3 的记录层版本字段仍写 0x0303（TLS 1.2），
     真实版本只存在于扩展中
   - 降级保护：若中间人删改了版本列表，Finished 消息的握手摘要会校验失败；
     服务器降级时还会在 ServerHello.random 末字节做标记
   </details>

3. **如果客户端和服务器没有共同支持的密码套件会怎样？**
   <details><summary>答案</summary>

   - 服务器返回 `handshake_failure`（alert 40）警告并关闭连接，握手失败，
     协议**没有回退机制**——这正是安全设计：自动降级会招致降级攻击
   - TLS 1.3 中套件 = AEAD + 哈希（如 TLS_AES_128_GCM_SHA256），连哈希都没有交集
     时无法派生密钥，只能失败
   - 排查方法：`openssl s_client -cipher/-ciphersuites` 逐个尝试，
     或用 RUST_LOG=debug 观察 rustls 报错
   - 实践中更常见的原因：服务器太老只支持 TLS 1.0/1.1，而 rustls 早已移除支持
   </details>

4. **随机数在握手中的作用是什么？**
   <details><summary>答案</summary>

   - ClientHello.random / ServerHello.random（各 32 字节）有三个职责：
     1. **新鲜性**：保证每次握手的 transcript 都不同，防重放旧握手
     2. **密钥材料**：进入 HKDF 的 transcript hash（课时 7），会话密钥因此逐连接不同
     3. **降级信号**：服务器被迫降级时污染 ServerHello.random 末字节（见题 2）
   - PSK 恢复时，客户端随机数参与 binder 计算，服务器用它防 0-RTT 重放窗口判断
   - 反面教材：2008 年 Debian OpenSSL PRNG 种子熵不足，生成的密钥可被穷举——
     随机数质量是 TLS 安全的地基
   </details>

## 进一步学习

- [RFC 8446 Section 2](https://tools.ietf.org/html/rfc8446#section-2) - TLS 1.3协议概述
- [TLS 1.3 Illustrated](https://tls13.xargs.org/) - 可视化握手过程
