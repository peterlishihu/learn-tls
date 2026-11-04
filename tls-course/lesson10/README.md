# 课时10：异步I/O与性能

## 学习目标

1. 理解Stream vs Acceptor API
2. 掌握mio集成原理
3. 了解异步TLS实现
4. 性能优化技巧

## 核心概念

### I/O Models

```
Blocking I/O:
  read() → wait for data → return data
  Simple but inefficient for many connections

Non-blocking I/O:
  read() → return immediately (EAGAIN if no data)
  Requires polling/notification mechanism

Async I/O (epoll/kqueue/IOCP):
  Register interest in file descriptors
  Wait for any ready events
  Process ready connections
```

### rustls with mio

```rust
// mio integration
let poll = Poll::new()?;
let mut events = Events::with_capacity(1024);

// Register socket for read/write events
poll.registry()
    .register(&mut socket, token, Interest::READABLE)?;

// Event loop
loop {
    poll.poll(&mut events, None)?;
    for event in events.iter() {
        match event.token() {
            SERVER => accept_connections(),
            CLIENT => handle_client(event),
        }
    }
}
```

### Async/Await with tokio-rustls

```rust
// tokio-rustls integration
let config = Arc::new(client_config);
let connector = TlsConnector::from(config);

let stream = TcpStream::connect(addr).await?;
let tls_stream = connector.connect(server_name, stream).await?;
```

## 运行示例

```bash
# MIO服务器
cargo run --bin mio_server -- --cert ../certs/server/cert.pem --key ../certs/server/key.pem

# Async客户端
cargo run --bin async_client -- --host localhost --port 8443

# Async服务器
cargo run --bin async_server -- --cert ../certs/server/cert.pem --key ../certs/server/key.pem
```

## 思考问题（附参考答案）

1. **什么时候使用 blocking vs async I/O？**
   <details><summary>答案</summary>

   | 维度 | Blocking（课时 1-9） | Async（课时 10 起） |
   |------|---------------------|---------------------|
   | 并发规模 | <几百连接 | 数千~数十万连接 |
   | 每连接成本 | 一个线程 ≈ 1-8MB 栈 | 一个任务 ≈ 几 KB |
   | 代码形态 | 顺序读写，直观易调试 | 状态机/await，需处理 Pending/取消 |
   | 组合能力 | 难（select/超时要靠线程） | 原生（tokio::select!、timeout） |
   | 生态 | std 即可 | tokio + tokio-rustls |

   - 选 blocking：CLI 工具、内部脚本、低并发服务、CPU 密集的流式处理
   - 选 async：代理/网关/长连接推送（成千上万 idle 连接——本课 proxy 场景）、
     需要精细超时控制、QUIC 生态（quinn 只有 async，课时 13）
   - 折中：少量 blocking 线程 + 池化，避免为小规模问题引入 async 复杂度
   </details>

2. **mio 的优势是什么？**
   <details><summary>答案</summary>

   - **统一抽象**：把 Linux epoll、macOS kqueue、Windows IOCP
     包装成一套 `Registry::register / Event` 就绪通知 API——跨平台网络代码写一次
   - **就绪模型而非完成模型**：告诉你"fd 可读了"，读写仍由你做——
     没有回调地狱，控制流始终在用户手里（对比 libuv 回调风格）
   - **零成本**：API 直接映射 syscall，没有隐藏线程或缓冲层
   - **教育价值**：tokio 的 reactor 底座就是 mio——本课用裸 mio 写 echo server，
     就是为了看懂 tokio::spawn 之下"事件循环 + Waker"的本质
   - 局限：只做网络事件，定时器/任务调度要自己搭（这就是 tokio 存在的理由）
   </details>

3. **如何处理 TLS 握手期间的异步 I/O？**
   <details><summary>答案</summary>

   - 难点：握手是**多轮 read/write 交替**，且中间任何一步都可能 EWOULDBLOCK
   - tokio-rustls 的 `TlsAcceptor::accept / TlsConnector::connect` 内部循环：
     1. `complete_io()`：驱动 rustls 直到再次阻塞
     2. 阻塞时返回 `Poll::Pending`，并通过 Waker 把 socket 注册回 reactor
     3. socket 就绪（Read/Writable 事件）→ 唤醒任务 → 继续 complete_io
   - 用户视角是一次 `.await`，Poll 状态机被库吃掉了
   - 两个生产要点：
     - 握手必须套 `tokio::time::timeout`——恶意/失联对端会在握手中途挂住任务，
       不设超时就是资源泄漏点（本课 proxy 示例的做法）
     - 握手期间收到的应用数据（TLS 1.3 允许客户端 Finished 后立即发数据）
       由库缓冲，握手完成后从同一条流读出，无需特殊处理
   - QUIC 同理但更复杂：握手在 UDP 上，CRYPTO 帧可能跨包重组
     （课时 13 的 Connecting future 内部处理）
   </details>

4. **性能优化的关键点？**
   <details><summary>答案</summary>

   - **减少 syscall**（大头）：批量写——rustls 用 `ChunkVecBuffer` 聚合小记录，
     配合 `write_vectored` 一次 send 走 scatter/gather；避免每记录一次 read
   - **关 Nagle**：`TCP_NODELAY`，小记录交互场景延迟敏感
     （Nagle + 延迟 ACK 的交互可能加 40ms）
   - **缓冲复用**：`BytesMut` 池化，避免每条记录堆分配；读缓冲对齐 4KB
   - **减少握手**：会话恢复/连接池（课时 4 的 1-RTT→0-RTT）；
     课时 13 实测——8 请求从 8 条 TLS 连接 8.8ms 降到 1 条 QUIC 连接 5.6ms，
     回环尚且如此，真实 RTT 下收益放大
   - **算法与后端**：有 AES-NI 选 AES-GCM，否则 ChaCha20（课时 6）；
     provider 选择影响吞吐（课时 9）
   - **别堵 runtime**：重 CPU 任务（大量加解密/证书解析）用 `spawn_blocking`
     或独立线程池，否则 woker 被占满，整个事件循环停摆
   - **度量先行**：criterion 微基准 + tokio-console/tracing 找热点，
     盲优化是反模式
   </details>
