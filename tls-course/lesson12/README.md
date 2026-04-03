# 课时12：调试与贡献实战

## 学习目标

1. 掌握Wireshark TLS解密
2. 了解Fuzzing测试方法
3. 学会提交rustls PR
4. 参与开源社区

## 核心概念

### Wireshark TLS Decryption

```
Setup:
1. Set SSLKEYLOGFILE environment variable
2. Run TLS application
3. Capture traffic with tcpdump/Wireshark
4. Configure Wireshark with key log file
5. View decrypted traffic
```

### Fuzzing with rustls-fuzzing-provider

```
Fuzzing Types:
- Structure fuzzing: Mutate TLS messages
- Protocol fuzzing: Send unexpected sequences
- Crypto fuzzing: Test edge cases

Tools:
- cargo-fuzz (libFuzzer)
- AFL++
- rustls-bogo (BoringSSL test suite)
```

### Contributing to rustls

```
Steps:
1. Find issue or propose feature
2. Discuss in GitHub issue or Discord
3. Fork and create branch
4. Implement with tests
5. Run full test suite
6. Submit PR
7. Address review feedback
```

## 运行示例

```bash
# 调试工具演示
cargo run --bin debug_tools -- --explain

# Fuzzing示例
cargo run --bin fuzzing_example -- --help
```

## 调试技巧

### SSLKEYLOGFILE使用

```bash
# 1. 设置环境变量
export SSLKEYLOGFILE=/tmp/tls-keys.log

# 2. 运行TLS应用
cargo run --bin client

# 3. Wireshark配置
# Edit -> Preferences -> Protocols -> TLS
# Set "(Pre)-Master-Secret log filename" to /tmp/tls-keys.log
```

### 常见问题

1. 握手失败：检查证书、协议版本、密码套件
2. 证书验证失败：检查根证书、有效期、主机名
3. 性能问题：启用硬件加速、调整缓冲区大小

## 思考问题

1. 如何调试TLS握手失败？
2. Fuzzing发现了哪些类型的bug？
3. 如何准备一个好的PR？
4. 如何参与rustls社区？

## 进一步学习

- [rustls CONTRIBUTING.md](https://github.com/rustls/rustls/blob/main/CONTRIBUTING.md)
- [BoringSSL test suite](https://github.com/google/boringssl/tree/master/ssl/test)
- [Wireshark TLS decryption](https://wiki.wireshark.org/TLS)
