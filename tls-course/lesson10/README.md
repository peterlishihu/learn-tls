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

## 思考问题

1. 什么时候使用blocking vs async I/O？
2. mio的优势是什么？
3. 如何处理TLS握手期间的异步I/O？
4. 性能优化的关键点？
