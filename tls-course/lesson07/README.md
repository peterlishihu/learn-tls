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

## 思考问题

1. 为什么TLS 1.3使用HKDF而不是TLS 1.2的PRF？
2. Early Secret和Master Secret有什么区别？
3. Key Update的作用是什么？
4. 流量密钥分离为什么重要？
