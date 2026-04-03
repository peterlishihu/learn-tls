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

## 思考问题

1. 为什么TLS 1.3移除了Session ID？
2. 0-RTT有什么安全隐患？如何缓解？
3. Session Ticket的生命周期如何管理？
4. 在负载均衡环境中如何使用会话恢复？
