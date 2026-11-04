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

## 思考问题（附参考答案）

1. **为什么 AES-GCM 需要硬件加速才能高效？**
   <details><summary>答案</summary>

   - AES-GCM 的两部分都受益于专用指令：
     - AES 本体：AES-NI（x86）/ ARMv8 Crypto 扩展把每轮变换变成单周期指令
     - GHASH：GCM 的认证标签要在 GF(2^128) 上做乘法，
       软件实现每 16 字节块要多次大整数乘+规约；`PCLMULQDQ` 一条指令搞定
   - 纯软件（查表法 AES + 软件 GHASH）吞吐量差 **10 倍量级**，
     且查表实现还有 timing 侧信道风险
   - 判断方法：`lscpu | grep -o aes`；无硬件时的正确选择是 ChaCha20-Poly1305（见下一题）
   </details>

2. **ChaCha20-Poly1305 的优势场景是什么？**
   <details><summary>答案</summary>

   - **无 AES 硬件的平台**：老款 ARM/低端 Android/部分路由器与嵌入式设备，
     ARX 结构（加法-旋转-异或）纯软件实现快且常数时间
   - **实现安全性**：不需要 S 盒查表，没有 cache timing 泄露，
     软件写对的门槛比 AES 低
   - **性能可预测**：跨平台表现一致，不依赖 CPU 特性探测
   - 现代手机（ARMv8 之后）都有 AES 硬件，两者差距已缩小——
     但 TLS 1.3 把它列为必实现套件，作为"慢设备兜底"
   </details>

3. **如果 Nonce 重复使用会怎样？**
   <details><summary>答案</summary>

   - **ChaCha20/GCTR 流密码**：同一 nonce → 同一 keystream →
     两条密文异或即得明文差（crib-dragging 经典攻击）
   - **AES-GCM 更致命**：nonce 重用 + 两条消息可代数求解认证子密钥 H
     （GHASH 的线性结构）——攻击者从此能**伪造任意消息的合法 tag**，
     机密性和完整性同时完蛋
   - TLS 的防御（本课示例可见）：`nonce = 静态 IV (8B) XOR 显式序列号 (8B)`，
     序列号单调递增且密钥周期内唯一——**结构性保证不重**，不靠随机碰撞规避
   - QUIC 同理：包号唯一 + 每个密钥阶段独立 IV（课时 13）
   </details>

4. **Associated Data 的作用是什么？**
   <details><summary>答案</summary>

   - AEAD(key, nonce, plaintext, **aad**) = 加密明文 + 认证"明文 + AAD"整体——
     AAD 参与 tag 计算但**不加密**，接收方能验证其完整性
   - TLS 中 AAD = 记录头（类型/版本/长度）+ 序列号（TLS 1.3 隐式序列号）：
     - 防篡改记录头：攻击者改 type 字段把应用数据伪装成握手等
     - 防重排/重放：序列号进 AAD，乱序包解密直接失败
   - QUIC 中 AAD = 包头（含包号与长度），同样保证头部不可篡改
   - 没有 AAD 的"只加密"协议，头部字段是攻击面——这就是 AEAD 设计中
     "关联数据"一词的由来
   </details>
