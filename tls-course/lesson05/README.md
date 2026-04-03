# 课时5：TLS记录层协议

## 学习目标

1. 理解TLS记录层格式
2. 掌握分片与重组机制
3. 了解MAC计算过程
4. 理解记录层安全性

## 核心概念

### TLS记录格式

```
+-----------+-------------+-------------+
| 类型(1B)  | 版本(2B)    | 长度(2B)    |
+-----------+-------------+-------------+
|                                       |
|            片段(0-2^14 bytes)         |
|                                       |
+---------------------------------------+
|            MAC (0/16/32 bytes)        |  (TLS 1.2)
+---------------------------------------+
```

**内容类型:**
- 20 = ChangeCipherSpec
- 21 = Alert
- 22 = Handshake
- 23 = Application Data
- 24 = Heartbeat (TLS 1.2)

### 分片机制

```
上层数据 (64KB)
    ↓
分成多个记录 (每个 ≤ 16KB)
    ↓
每个记录独立加密
    ↓
发送
```

### TLS 1.2 vs TLS 1.3 记录层

**TLS 1.2:**
- MAC-then-Encrypt (先计算MAC，再加密)
- 需要填充
- 容易受到padding oracle攻击

**TLS 1.3:**
- AEAD (Authenticated Encryption with Associated Data)
- Encrypt-and-MAC (同时加密和认证)
- 不需要填充

## 运行示例

```bash
# 记录层分析演示
cargo run --bin record_layer -- --explain

# 查看记录格式
cargo run --bin record_layer -- --format
```

## 思考问题

1. 为什么TLS记录有最大长度限制？
2. MAC的作用是什么？和数字签名有什么区别？
3. 什么是padding oracle攻击？
4. AEAD相比传统MAC+加密有什么优势？
