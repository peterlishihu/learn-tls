# TLS协议栈系统学习课程

基于 [rustls](https://github.com/rustls/rustls) 的渐进式TLS协议学习课程，从基础到高级，包含完整可运行的代码示例。

## 课程概览

| 阶段 | 课时 | 主题 | 难度 |
|------|------|------|------|
| **基础** | 1-4 | TLS握手、证书、密钥交换、会话恢复 | ⭐⭐ |
| **记录层** | 5-7 | 记录协议、加密机制、密钥派生 | ⭐⭐⭐ |
| **架构** | 8-10 | rustls架构、Crypto Provider、异步I/O | ⭐⭐⭐⭐ |
| **高级** | 11-12 | 安全扩展、调试与贡献 | ⭐⭐⭐⭐⭐ |

## 快速开始

```bash
# 克隆rustls参考项目
git clone https://github.com/rustls/rustls.git ../rustls

# 进入课程目录
cd tls-course

# 运行第一课示例
cd lesson01
cargo run --bin client --example handshake_explorer
cargo run --bin server --example simple_server
```

## 课程目录

### 第一阶段：TLS协议基础与握手流程

#### [课时1：TLS握手全景图](./lesson01/README.md)
- ClientHello/ServerHello结构详解
- 密码套件协商过程
- TLS版本选择机制
- 实践：带详细日志的echo client/server

#### [课时2：证书与身份验证](./lesson02/README.md)
- X.509证书结构解析
- 证书链验证流程
- SNI扩展详解
- 实践：自定义证书验证器

#### [课时3：密钥交换机制](./lesson03/README.md)
- RSA vs ECDHE对比
- Diffie-Hellman参数
- 前向保密(FS)原理
- 实践：对比TLS 1.2和1.3的密钥交换

#### [课时4：会话恢复机制](./lesson04/README.md)
- Session ID vs Session Ticket
- PSK(Pre-Shared Key)
- 0-RTT早期数据
- 实践：测量延迟差异

### 第二阶段：记录层与加密机制

#### [课时5：TLS记录层协议](./lesson05/README.md)
- 记录格式详解
- 分片与重组机制
- MAC计算过程
- 实践：手动构造TLS记录

#### [课时6：对称加密与AEAD](./lesson06/README.md)
- AES-GCM/ChaCha20-Poly1305
- Nonce管理策略
- 认证加密原理
- 实践：自定义crypto provider性能对比

#### [课时7：TLS 1.3密钥派生](./lesson07/README.md)
- HKDF算法详解
- 密钥更新(Key Update)
- 流量密钥分离
- 实践：追踪密钥派生树

### 第三阶段：rustls架构与实现

#### [课时8：rustls架构剖析](./lesson08/README.md)
- `ClientConfig`/`ServerConfig`设计
- 状态机实现分析
- `ConnectionCommon`核心逻辑
- 实践：绘制状态机图

#### [课时9：Crypto Provider机制](./lesson09/README.md)
- `CryptoProvider` trait详解
- 自定义provider实现
- 算法注册机制
- 实践：单cipher suite provider

#### [课时10：异步I/O与性能](./lesson10/README.md)
- `Stream` vs `Acceptor`
- mio集成原理
- 零拷贝优化
- 实践：高并发TLS代理

### 第四阶段：高级主题与实战

#### [课时11：安全扩展特性](./lesson11/README.md)
- SCT证书透明度
- OCSP Stapling
- Encrypted Client Hello (ECH)
- 实践：配置并测试ECH

#### [课时12：调试与贡献实战](./lesson12/README.md)
- Wireshark TLS解密
- Fuzzing测试
- rustls贡献流程
- 实践：提交PR

## 项目结构

```
tls-course/
├── README.md                 # 本文件
├── Cargo.toml               # 工作区配置
├── shared/                  # 共享工具库
│   ├── src/
│   │   ├── lib.rs          # 公共配置和日志
│   │   ├── certgen.rs      # 证书生成工具
│   │   └── logging.rs      # 详细日志记录
│   └── Cargo.toml
├── scripts/                 # 辅助脚本
│   ├── setup.sh            # 环境初始化
│   ├── gen_certs.sh        # 证书生成
│   └── wireshark_decrypt.sh # Wireshark解密配置
├── docs/                    # 补充文档
│   ├── tls_cheatsheet.md   # TLS速查表
│   └── rustls_notes.md     # rustls源码笔记
└── lesson{01..12}/        # 各课时代码
    ├── Cargo.toml
    ├── README.md           # 课时说明
    ├── src/
    │   ├── bin/
    │   │   ├── client.rs
    │   │   └── server.rs
    │   └── lib.rs
    ├── examples/           # 扩展示例
    └── wireshark/          # 抓包分析
```

## 前置要求

- **Rust**: 1.83+ (rustls要求)
- **系统依赖**: OpenSSL (用于证书生成), Wireshark (用于协议分析)
- **网络**: 可访问互联网(部分示例连接真实服务器)

## 推荐学习顺序

1. **按顺序完成**每个课时，不要跳过
2. **每课时目标**: 理解代码 + 成功运行 + 回答问题
3. **实践建议**: 每个示例至少修改运行3次，观察不同参数的影响
4. **抓包分析**: 配合Wireshark观察实际网络流量

## 调试工具

### SSLKEYLOGFILE解密

所有示例都支持`SSLKEYLOGFILE`环境变量，用于Wireshark解密TLS流量：

```bash
export SSLKEYLOGFILE=/tmp/tls-keys.log
cargo run --bin client
# 在Wireshark中配置: Edit -> Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename
```

### 详细日志

```bash
RUST_LOG=debug cargo run --bin client
```

## 参考资源

- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [RFC 5246 - TLS 1.2](https://tools.ietf.org/html/rfc5246)
- [rustls文档](https://docs.rs/rustls/)
- [rustls GitHub](https://github.com/rustls/rustls)
- [TLS Illustrated](https://tls12.xargs.org/) (可视化TLS 1.2)
- [TLS 1.3 Illustrated](https://tls13.xargs.org/) (可视化TLS 1.3)

## 贡献

欢迎提交Issue和PR！学习过程中发现的任何问题和改进建议都可以分享。

## 许可证

MIT License - 与rustls保持一致
