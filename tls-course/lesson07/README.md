# 课时7：TLS 1.3密钥派生

## 学习目标

1. 理解HKDF算法
2. 掌握TLS 1.3密钥派生树
3. 了解Key Update机制
4. 理解流量密钥分离

## 核心概念

### HKDF (HMAC-based Extract-and-Expand Key Derivation Function)

```
HKDF-Extract(salt, IKM) -> PRK
HKDF-Expand(PRK, info, L) -> OKM
```

**Extract:** 从输入密钥材料提取伪随机密钥
**Expand:** 从PRK派生任意长度的输出密钥材料

### TLS 1.3密钥派生树

```
                0
                |
           Early Secret
           /    |    \
          /     |     \
    binder_key  |   client_early_traffic_secret
                |   early_exporter_master_secret
                |
           (EC)DHE Shared Secret
                |
           Handshake Secret
           /    |    \
          /     |     \
client_handshake_traffic_secret  server_handshake_traffic_secret
                |
           Master Secret
           /    |    \
          /     |     \
client_application_traffic_secret_N  server_application_traffic_secret_N
                                   |
                           resumption_master_secret
```

## 运行示例

```bash
# HKDF演示
cargo run --bin hkdf_demo -- --explain

# 密钥派生树
cargo run --bin hkdf_demo -- --key-tree
```

## 思考问题（附参考答案）

1. **为什么 TLS 1.3 使用 HKDF 而不是 TLS 1.2 的 PRF？**
   <details><summary>答案</summary>

   - TLS 1.2 的 PRF 是 P_hash：`PRF(secret, label, seed) = HMAC_sha256 展开`，
     单段结构直接混料——对分布不均匀的输入（ECDHE 共享秘密）
     和多用途派生没有理论分层
   - HKDF 是 **Extract-then-Expand** 两段：
     - Extract：把高熵但可能分布偏斜的输入均匀化成固定长度的 pseudorandom key
     - Expand：从 PRK 分层展开，`HKDF-Expand-Label(secret, "c ap traffic", hash)` 
       用结构化标签保证不同用途得到不同密钥
   - "分布偏斜的输入"具体指什么？就是课时 3 的 ECDH 输出——X25519 的
     共享秘密是群元素（u 坐标），最高位恒为 0、取值受曲线约束，
     不是均匀随机的 32 字节串，直接当对称密钥破坏可证明安全性；
     HKDF-Extract 专治这个。派生时掺入握手摘要（transcript hash），
     还让密钥绑定握手历史——中间人篡改任何消息，双方密钥即分叉
   - 这是全行业的标准姿势：WireGuard 把每轮 DH 输出都 Extract 进
     chaining key，Signal/Noise 同理——DH 输出只是原材料，KDF 层
     把它加工成合格且分用途的密钥
   - HKDF 有 NIST SP 800-56C 背书和成熟的安全性分析；
     TLS 1.3 的密钥调度树（本课的 key_tree）正是把 HKDF 当乐高：
     每层 Extract 的 salt 都是上一层的输出再 Expand("derived")——链式绑定握手进度
   </details>

2. **Early Secret 和 Master Secret 有什么区别？**
   <details><summary>答案</summary>

   - 它们是密钥调度树的**两个 Extract 节点**，时机与用途不同：

   | | early_secret | master_secret |
   |---|---|---|
   | Extract 输入 | PSK（无 PSK 则全 0） | 0（IKM 为常量） |
   | 时机 | ClientHello 之前就能算 | Finished 交换完成、握手终态 |
   | 派生 | binder_key（证明"我持有这个 PSK"）、client_early_traffic_secret（**0-RTT 密钥**） | 双向 application traffic secret、exporter、resumption master |

   - 命名指"派生时机"：early 在握手之初（安全属性只有 PSK），
     master 在握手完成（安全属性 = PSK + ECDHE + transcript 全量）
   - 0-RTT 数据用 early 派生的密钥加密，因此**没有前向保密**——
     这也是课时 4 讲"0-RTT 要小心"的密码学根源
   </details>

3. **Key Update 的作用是什么？**
   <details><summary>答案</summary>

   - 每个 AEAD 密钥有**使用量安全上限**：AES-GCM 单密钥加密超过约 2^32 条记录后，
     认证强度开始衰减（nonce/碰撞空间被消耗）
   - 长连接（数据库连接池、代理长隧道）可能几小时就逼近上限
   - TLS 1.3 的 KeyUpdate：任一方发 `update_requested / update_not_requested`，
     双方把 application secret 链式再派生一层
     （`application_secret_N+1 = Expand(app_secret_N, "traffic upd")`），
     **无需重新握手**就换钥，连接与流状态完全保留
   - QUIC 做得更激进：按包数自动密钥更新，应用层无感（课时 13）
   </details>

4. **流量密钥分离为什么重要？**
   <details><summary>答案</summary>

   - TLS 1.3 派生了 4+ 个方向/阶段独立的 secret：
     c hs traffic / s hs traffic / c ap traffic / s ap traffic
   - **方向分离防反射攻击**：双方密钥不同，攻击者无法把客户端发的消息
     原样反弹给服务器冒充客户端（若双向同钥，握手消息可反射）
   - **阶段分离限制泄露半径**：握手密钥泄露不影响应用数据，
     0-RTT 密钥与 1-RTT 密钥互不相干
   - **用途分离**（key separation 原则）：加密密钥、IV、exporter 密钥、
     重连 PSK 各自独立——一个用途被滥用不影响其他
   - 反例是 TLS 1.2 之前的双向共享 bulk key + "client/server MAC 密钥分开"，
     边界模糊且常量前缀拼接派生，1.3 的标签化派生干净得多
   </details>
