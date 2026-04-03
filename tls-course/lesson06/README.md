# 课时6：对称加密与AEAD

## 学习目标

1. 理解AES-GCM和ChaCha20-Poly1305算法
2. 掌握AEAD（认证加密）原理
3. 了解Nonce管理策略
4. 对比不同加密算法的性能

## 核心概念

### AEAD (Authenticated Encryption with Associated Data)

```
输入:
  - Key (对称密钥)
  - Nonce (一次性数字)
  - Plaintext (明文)
  - Associated Data (认证但不加密的数据)

输出:
  - Ciphertext (密文)
  - Authentication Tag (认证标签)
```

### AES-GCM

**Galois/Counter Mode:**
- CTR模式用于加密
- GHASH用于认证
- 硬件加速 (AES-NI)

```
加密流程:
1. Counter = Nonce || 初始值
2. 加密 Counter 得到密钥流
3. 明文 XOR 密钥流 = 密文
4. GHASH计算认证标签
5. 最终加密得到完整标签
```

### ChaCha20-Poly1305

**ChaCha20:** 流密码
**Poly1305:** 消息认证码

```
优点:
  ✓ 软件实现快 (无硬件也能高效运行)
  ✓ 抗时序攻击
  ✓ 设计简单，易于验证
  ✓ 不依赖AES-NI

缺点:
  ✗ 无硬件加速时比AES慢
```

### Nonce管理

**关键规则: Nonce必须唯一！**

```
TLS 1.3 Nonce构造:
  Base = 从Handshake派生
  XOR = 序列号
  Nonce = Base XOR 序列号

为什么这样可以:
  - 序列号单调递增
  - 确保每个记录Nonce唯一
  - 隐式nonce（不传输，节省带宽）
```

## 运行示例

```bash
# AEAD演示
cargo run --bin aead_demo -- --help

# 算法性能对比
cargo run --bin cipher_benchmark -- --size 1048576
```

## 思考问题

1. 为什么AES-GCM需要硬件加速才能高效？
2. ChaCha20-Poly1305的优势场景是什么？
3. 如果Nonce重复使用会怎样？
4. Associated Data的作用是什么？
