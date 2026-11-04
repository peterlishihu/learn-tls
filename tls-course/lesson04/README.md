# 课时4：会话恢复机制

## 学习目标

1. 理解Session ID vs Session Ticket的区别
2. 掌握PSK（Pre-Shared Key）机制
3. 了解0-RTT的原理和应用场景
4. 测量不同恢复机制的性能差异

## 核心概念

### 会话恢复机制对比

| 机制 | TLS版本 | 存储位置 | 服务器端状态 | 安全性 |
|------|---------|----------|--------------|--------|
| Session ID | 1.0-1.2 | 服务器内存 | 需要 | 中 |
| Session Ticket | 1.0-1.2 | 客户端 | 无状态 | 中 |
| PSK | 1.3 | 客户端 | 无状态 | 高 |
| 0-RTT | 1.3 | 客户端 | 无状态 | 需注意重放 |

### Session ID vs Session Ticket

**Session ID (Stateful):**
```
Server stores session state in memory
    ↓
Client sends Session ID in ClientHello
    ↓
Server looks up state and resumes
    ↓
Problem: Memory usage, load balancing
```

**Session Ticket (Stateless):**
```
Server encrypts session state into ticket
    ↓
Client stores ticket
    ↓
Client sends ticket in ClientHello
    ↓
Server decrypts ticket to restore state
    ↓
Advantage: No server-side state
```

### TLS 1.3 PSK和0-RTT

**PSK Mode (1-RTT):**
```
First connection: Full handshake
    ↓
Server sends NewSessionTicket
    ↓
Later connection:
    ClientHello + PSK (ticket) + KeyShare
    ↓
ServerHello + {Finished}
    ↓
{Finished}
    ↓
Encrypted communication
```

**0-RTT Mode:**
```
First connection: Full handshake
    ↓
Server sends NewSessionTicket (with early_data extension)
    ↓
Later connection:
    ClientHello + PSK + KeyShare + {early_data}
    ↓
ServerHello + {Finished} + {application_data}
    ↓
Client can send data immediately!
```

## 运行示例

```bash
# 会话恢复演示
cargo run --bin session_resumption -- --help

# 0-RTT客户端
cargo run --bin zerortt_client -- --help

# 0-RTT服务器
cargo run --bin zerortt_server -- --help
```

## 思考问题（附参考答案）

1. **为什么 TLS 1.3 移除了 Session ID？**
   <details><summary>答案</summary>

   - Session ID 是**有状态恢复**：服务器内存里存会话表，负载均衡下要么粘性路由、
     要么全集群同步状态——扩展性差
   - TLS 1.3 把恢复机制统一为 **PSK 模式**：服务器发 NewSessionTicket，
     客户端从 `resumption_master_secret` 派生 PSK，下次连接带上 ticket + binder
   - 本质上是把"Session Ticket（无状态）"升级为唯一路径，并修掉了 1.2 时代
     ticket 的安全缺陷（1.3 的 PSK 绑定握手摘要，且可与 DHE 组合保留前向保密）
   - 会话状态由客户端持有，服务器零内存——这正是"恢复"该有的形态
   </details>

2. **0-RTT 有什么安全隐患？如何缓解？**
   <details><summary>答案</summary>

   - 核心风险是**重放**：early data 只绑定 PSK（上一条连接的票据），
     不绑定当前连接——攻击者把录下的 0-RTT 包原样重发，服务器可能重复执行
     （重复下单、重复改密码）
   - 缓解手段分层：
     1. **应用层**：0-RTT 只放幂等请求（GET），有副作用的等 1-RTT
     2. **服务器**：单票据单用（一次性反重放缓存）+ 时间窗口限制；
        多机部署时共享反重放状态（或用 QUIC 的地址验证 token 辅助）
     3. **协议层**：PSK binder 保证新连接身份，但救不了 early data 本身
   - rustls 的立场：`ServerConfig.max_early_data_size` 默认 0——不显式打开就没有 0-RTT
     （课时 13 的 QUIC 演示里我们显式设为 u32::MAX 才启用了它）
   </details>

3. **Session Ticket 的生命周期如何管理？**
   <details><summary>答案</summary>

   - NewSessionTicket 携带 `ticket_lifetime`（最长 7 天）与 `ticket_age_add`，
     客户端按提示使用
   - **票证加密密钥（TEK）才是命门**：服务器用它加密会话状态注入 ticket。
     必须定期轮换（小时~天级），否则一台服务器被攻破 = 用旧票恢复的所有历史会话可解
   - 多机集群要么共享 TEK（风险集中），要么接受"票只在签发节点有效"（配合 LB 亲和）
   - TLS 1.3 客户端还应绑定恢复时的证书/ALPN 与原会话一致（rustls 自动校验），
     防止票据跨服务误用
   </details>

4. **在负载均衡环境中如何使用会话恢复？**
   <details><summary>答案</summary>

   - 首选**无状态恢复**（ticket/PSK）：任何后端节点都能解票，天然亲和 LB
   - 需要权衡的两点：
     - 共享 TEK = 所有节点等价（一台失守全线失守），要配合 KMS/定期轮换
     - 不共享 = LB 需要按客户端 IP/票 ID 做会话亲和，破坏完全均衡
   - 0-RTT 在 LB 后更麻烦：反重放窗口是集群状态（集中式存储或牺牲部分保证）
   - QUIC 的思路值得借鉴：地址验证 token（服务器签发、可含 LB 路由提示）
     让无状态 LB 也能安全接受新连接——TUIC 场景下 0-RTT 直连单服务器，
     问题简化为单机反重放
   </details>
