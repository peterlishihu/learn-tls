# TLS课程快速启动指南

## 环境准备

### 1. 系统依赖

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y openssl libssl-dev pkg-config

# macOS
brew install openssl

# 安装 Wireshark（用于抓包分析）
# Ubuntu
sudo apt-get install wireshark

# macOS
brew install --cask wireshark
```

### 2. Rust环境

```bash
# 安装 Rust (如果尚未安装)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 确保版本 >= 1.83
rustc --version
```

### 3. 生成测试证书

```bash
cd /home/peter/project/learn-tls/tls-course
./scripts/gen_certs.sh
```

这将生成:
- `certs/ca/ca-cert.pem` - CA根证书
- `certs/server/server-cert.pem` - 服务器证书
- `certs/client/client-cert.pem` - 客户端证书（用于mTLS）

## 课程运行示例

### 课时1: TLS握手探索

```bash
cd lesson01

# 启动服务器
cargo run --bin server -- --cert ../certs/server/server-cert.pem --key ../certs/server/server-key.pem

# 在另一个终端运行客户端
cargo run --bin client -- --ca-cert ../certs/ca/ca-cert.pem

# 启用详细日志
RUST_LOG=debug cargo run --bin client -- --ca-cert ../certs/ca/ca-cert.pem

# Wireshark解密
export SSLKEYLOGFILE=/tmp/tls-keys.log
cargo run --bin client -- --ca-cert ../certs/ca/ca-cert.pem
# 在Wireshark中配置解密
```

### 课时2: 证书分析

```bash
cd lesson02

# 分析证书
cargo run --bin cert_analyzer -- --cert ../certs/server/server-cert.pem --detailed

# 分析远程服务器
cargo run --bin cert_analyzer -- --host www.rust-lang.org --port 443

# 运行mTLS服务器
cargo run --bin server -- --cert ../certs/server/server-cert.pem --key ../certs/server/server-key.pem --ca-cert ../certs/ca/ca-cert.pem --require-client-cert

# 运行mTLS客户端
cargo run --bin client -- --ca-cert ../certs/ca/ca-cert.pem --client-cert ../certs/client/client-cert.pem --client-key ../certs/client/client-key.pem
```

### 课时3-7: 理论学习

```bash
# 课时3: 密钥交换
cd lesson03
cargo run --bin key_exchange_demo -- --explain
cargo run --bin key_exchange_demo -- --compare

# 课时4: 会话恢复
cd lesson04
cargo run --bin session_resumption -- --compare

# 课时5: 记录层
cd lesson05
cargo run --bin record_layer -- --explain

# 课时6: AEAD加密
cd lesson06
cargo run --bin aead_demo -- --explain
cargo run --bin cipher_benchmark -- --size 1048576

# 课时7: 密钥派生
cd lesson07
cargo run --bin hkdf_demo -- --explain
cargo run --bin hkdf_demo -- --key-tree
```

### 课时8: 架构分析

```bash
cd lesson08
cargo run --bin architecture_explorer -- --explain
cargo run --bin architecture_explorer -- --state-machine
```

### 课时9: Crypto Provider

```bash
cd lesson09
cargo run --bin custom_provider -- --explain
cargo run --bin custom_provider -- --list
```

### 课时10: 异步I/O

```bash
cd lesson10

# MIO服务器
cargo run --bin mio_server -- --cert ../certs/server/server-cert.pem --key ../certs/server/server-key.pem

# Async客户端（在另一个终端）
cargo run --bin async_client -- --ca-cert ../certs/ca/ca-cert.pem

# Async服务器
cargo run --bin async_server -- --cert ../certs/server/server-cert.pem --key ../certs/server/server-key.pem
```

### 课时11: 安全扩展

```bash
cd lesson11
cargo run --bin security_extensions -- --explain
cargo run --bin ech_client -- --host cloudflare-ech.com
```

### 课时12: 调试与贡献

```bash
cd lesson12
cargo run --bin debug_tools -- --explain
cargo run --bin fuzzing_example -- --explain
```

### 课时13: QUIC 与 TUIC

```bash
cd lesson13

# QUIC 基础：ALPN、多路复用、0-RTT 恢复
cargo run --bin quic_echo

# TCP+TLS vs QUIC 实测对比
cargo run --bin quic_vs_tls

# mini-TUIC：五个命令全流程（exporter 认证、TCP/UDP 中继、错误信令）
cargo run --bin tuic_demo

# 协议帧编解码单元测试
cargo test
```

QUIC 流量同样支持 Wireshark 解密（SSLKEYLOGFILE），配合 `quic` 显示过滤器观察
CRYPTO 帧里的 ClientHello 与 1-RTT 后的 STREAM/DATAGRAM 帧。

## 学习路径建议

### 第一周: 基础 (课时1-4)
- 每天完成1个课时
- 重点理解握手流程和证书机制
- 运行所有示例代码
- 用Wireshark抓包观察

### 第二周: 加密层 (课时5-7)
- 理解记录层和AEAD
- 掌握密钥派生流程
- 完成实践练习

### 第三周: 实现 (课时8-10)
- 阅读rustls源码
- 理解架构设计
- 实现自定义组件

### 第四周: 高级与实战 (课时11-13)
- 学习安全扩展
- 掌握调试技巧
- QUIC 与 TUIC：把 rustls 知识迁移到 QUIC，理解 0-RTT 代理协议

## 常见问题

### Q: 编译失败
```bash
# 更新依赖
cargo update

# 清理并重新构建
cargo clean
cargo build
```

### Q: 证书验证失败
```bash
# 检查证书有效期
openssl x509 -in certs/server/server-cert.pem -noout -dates

# 重新生成证书
./scripts/gen_certs.sh
```

### Q: 端口被占用
```bash
# 查找占用端口的进程
lsof -i :8443

# 或更换端口
cargo run --bin server -- -p 8444
```

### Q: 日志不显示
```bash
# 确保设置日志级别
RUST_LOG=debug cargo run ...
```

## 进阶学习

1. **阅读RFC**
   - RFC 8446 (TLS 1.3)
   - RFC 5246 (TLS 1.2)
   - RFC 5280 (X.509)

2. **实践项目**
   - 实现自定义crypto provider
   - 添加新的TLS扩展
   - 性能优化

3. **社区参与**
   - rustls GitHub issues
   - Discord频道
   - 提交PR

## 资源链接

- [rustls文档](https://docs.rs/rustls/)
- [TLS 1.3 Illustrated](https://tls13.xargs.org/)
- [Wireshark TLS](https://wiki.wireshark.org/TLS)
- [Certificate Transparency](https://certificate.transparency.dev/)

## 反馈

遇到问题或有建议？欢迎提交Issue!
