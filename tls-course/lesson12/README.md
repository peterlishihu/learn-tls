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

## 思考问题（附参考答案）

1. **如何调试 TLS 握手失败？**
   <details><summary>答案</summary>

   分层排查，从下往上：
   - **网络层**：`nc -vz host 443` 端口通不通；防火墙/中间盒是否劫持
   - **协议层**：`openssl s_client -connect host:443 -servername host -msg`
     看最后一个 alert：
     - `handshake_failure(40)` → 套件/版本不匹配（服务器太老？只支持 TLS1.0？）
     - `certificate_verify_failed` → 证书链不全/过期/主机名不匹配/系统时间错
     - `protocol_version(70)` → 版本协商失败
     - `unrecognized_name(112)` → SNI 不被服务器接受
   - **实现层**：`RUST_LOG=debug` 看 rustls 逐步日志（client::hs / server::hs）；
     `SSLKEYLOGFILE` + Wireshark 逐消息对照（本课 wireshark 脚本一键配置）
   - **常见坑**：服务器不送中间证书（老客户端有缓存能连，新客户端失败）；
     中间盒剥 ALPN；rustls 不支持 TLS 1.0/1.1 与 3DES 等老古董（by design）
   </details>

2. **Fuzzing 发现了哪些类型的 bug？**
   <details><summary>答案</summary>

   TLS 库 fuzz 的主要猎物（也是 rustls/cargo-fuzz targets 覆盖的）：
   - **解析器 panic**：截断的 key_share、超长扩展链、嵌套 ASN.1 长度撒谎、
     证书 DER 边界值——Rust 里 panic 即 DoS
   - **状态机非法序列**：Finished 之前的 ChangeCipherSpec、重复的 Hello、
     握手中途塞 application_data
   - **解码不变量破坏**：记录层声明的长度与实际不符、
     u16/u24 溢出回绕、空的向量字段
   - **ticket/PSK blob 解析**：服务器恢复路径的反序列化是常被忽略的输入面
   - 特点：绝大多数是 DoS/崩溃类，**内存破坏类（溢出、UAF）在 safe Rust 里
     结构性不存在**——这正是课时 8 "内存安全"的实证；
     密码学本身的漏洞（nonce 重用、时序）fuzz 基本测不出，要靠形式化分析
   </details>

3. **如何准备一个好的 PR？**
   <details><summary>答案</summary>

   - **先 issue 后代码**：描述问题/动机，维护者确认方向再动手
     （避免大而美的重构被拒）
   - **变更最小聚焦**：一个 PR 解决一件事；顺手重命名/格式化是评审毒药
   - **测试是主角**：
     - 修 bug → 先写会失败的回归测试，再修到绿
     - 新功能 → 单测 + 与 openssl/boringssl 的 interop 用例
     - 性能改动 → 附 criterion 基准数据（课时 6 的 benchmark 就是范例格式）
   - **同步文档**：CHANGELOG、rustdoc 注释、手册章节
   - **行政项**：签署 DCO/CLA、许可证声明（rustls 是 Apache-2.0/MIT 双许可）、CI 绿
   </details>

4. **如何参与 rustls 社区？**
   <details><summary>答案</summary>

   - **入门路径**：GitHub 上带 `good first issue` 标签的任务
     （多为文档、测试补充、错误信息改进）
   - **渠道**：rustls 的 GitHub Discussions / Discord 频道；
     安全漏洞**不要**发公开 issue——走 SECURITY.md 的私下披露流程
   - **高价值贡献**：
     - 真实流量兼容性报告（某银行/设备握手失败的抓包脱敏分析）
     - interop 测试矩阵的补充（老服务器、嵌入式栈）
     - fuzz target 的新输入面
   - **不算代码的贡献**：写教程/课程（就像本项目）、翻译文档、
     在 issue 里回答新手问题——开源项目的健康度一半靠这些
   </details>

## 进一步学习

- [rustls CONTRIBUTING.md](https://github.com/rustls/rustls/blob/main/CONTRIBUTING.md)
- [BoringSSL test suite](https://github.com/google/boringssl/tree/master/ssl/test)
- [Wireshark TLS decryption](https://wiki.wireshark.org/TLS)
