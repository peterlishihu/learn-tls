# 课时 13：QUIC 与 TUIC —— 从 TLS 1.3 到 0-RTT 代理

## 学习目标

1. 理解 QUIC 与 TLS 1.3 的关系：握手复用 rustls，记录层被替换为包保护
2. 掌握 QUIC 的核心机制：流（STREAM）、不可靠数据报（DATAGRAM）、连接 ID、0-RTT
3. **搞清楚 TUIC 解决了什么**：传统 TCP/UDP 代理的五大痛点
4. **搞清楚 TUIC 魔改了什么**：它如何"非常规"地使用 QUIC 的能力
5. 亲手实现一个 mini-TUIC：五个命令 + exporter 认证 + Full-cone UDP 中继

## 前置知识

- 课时 4（会话恢复 / 0-RTT）、课时 6（AEAD）、课时 7（HKDF 密钥派生）
- 课时 8-9（rustls 架构 / CryptoProvider）——因为 **quinn 的 TLS 引擎就是 rustls**

## 第一部分：QUIC —— 把 TLS 1.3 塞进 UDP

### 1.1 TCP+TLS 的天花板

| 痛点 | 原因 |
|------|------|
| 首字节延迟 | TCP 握手 1 RTT + TLS 1.3 握手 1 RTT = 2 RTT（两层协议各握各的） |
| 队头阻塞 | TCP 丢一个段，上面**所有**连接的数据都得等重传（HTTP/2 多路复用放大了这个问题） |
| 连接与四元组绑定 | 手机切 WiFi→蜂窝，NAT 重绑定，TCP 连接直接死掉 |
| 中间盒僵化 | TCP 头部三十年没人敢改，任何新特性都部署不下去 |
| 拥塞控制在内核 | 想换 BBR？等内核升级吧 |

QUIC（RFC 9000）把这些一次性解决：**传输层搬到 UDP 之上的用户空间**，
加密直接内嵌 TLS 1.3——不再是"TCP + TLS 两层夹心"，而是一个协议同时搞定传输与加密。

### 1.2 QUIC 与 TLS 1.3 的精确关系（本课程视角）

学完 rustls 再看 QUIC 会非常亲切，因为它**不是重新发明密码协议**：

```
┌───────────────────────────────────────────────────┐
│ 应用协议（HTTP/3、TUIC、本课演示）                │
├───────────────────────────────────────────────────┤
│ QUIC：流 / 数据报 / 拥塞控制 / 连接迁移           │
│   ┌─────────────────────────────────────────┐     │
│   │ TLS 1.3 握手（就是 rustls！）           │     │
│   │ · 握手消息装在 CRYPTO 帧里传输          │     │
│   │ · 密钥调度复用课时 7 的 HKDF 树         │     │
│   │ · 套件/CryptoProvider/ALPN 原样生效     │     │
│   └─────────────────────────────────────────┘     │
├───────────────────────────────────────────────────┤
│ UDP                                               │
└───────────────────────────────────────────────────┘
```

**复用的部分**（课时 1-9 的知识直接迁移）：
- ClientHello/ServerHello/Certificate/Finished 原样存在，只是装进 QUIC 的 **CRYPTO 帧**
- 密钥派生树（early/handshake/master secret）一模一样
- ALPN 强制必选（QUIC 规定拒绝没有 ALPN 的连接）
- rustls 的 `CryptoProvider`、`quic` 字段（课时 9 讲过！）决定哪些套件可用于 QUIC

**替换的部分**：

| TLS over TCP | QUIC |
|--------------|------|
| TLS 记录层（5 字节明文头 + AEAD） | QUIC 包保护：**包头也被加密**（首字节除外），包号单独加密（防关联分析） |
| Initial 包明文 | Initial 用"全网公开密钥"加密（RFC 9001 §5.2）——可解密但防篡改 |
| 密钥切换用 KeyUpdate | 每个包号独立密钥（密钥阶段递增） |
| TCP 传输参数不存在 | 传输参数放在 TLS 扩展 `quic_transport_parameters` 里（你在课时 1 的日志里见过它！） |

### 1.3 QUIC 的四个核心机制

**① 流（STREAM 帧）**：一条连接里最多 2^62 条独立的可靠字节流。
每条流有序，流与流之间**不互相阻塞**——一个流丢包，其他流的已到数据照常递交。
流几乎零成本：不需要握手，发数据时流就"诞生"了。

**② 不可靠数据报（DATAGRAM 帧，RFC 9221）**：QUIC 连接里直接塞 UDP 语义的消息。
不可靠、无序、不占流控窗口，但享受 QUIC 的加密与拥塞控制。
HTTP/3 都很少用它，TUIC 却把它当 UDP 中继的主力——这是"魔改"的第一处伏笔。

**③ 连接 ID**：每个 QUIC 包带连接 ID，寻址不再依赖四元组。
客户端换 IP/端口（WiFi→蜂窝），连接照常存活（PATH_CHALLENGE 验证新路径）。
TCP 做不到这一点。

**④ 0-RTT**：QUIC 直接继承 TLS 1.3 的 early data（课时 4 讲过 PSK/NewSessionTicket），
恢复连接时第一个包就能带应用数据。TUIC 的"0-RTT 代理"正是建立在这上面。

### 1.4 动手：三个演示

```bash
cd lesson13

# 演示 1：QUIC 基础——ALPN、多路复用、0-RTT 恢复
cargo run --bin quic_echo

# 演示 2：TCP+TLS vs QUIC 实测（8 次请求的三种形态）
cargo run --bin quic_vs_tls

# 演示 3：mini-TUIC——五个命令全流程（本课压轴）
cargo run --bin tuic_demo

# 协议帧编解码单元测试
cargo test
```

抓包观察（QUIC 同样支持 SSLKEYLOGFILE 解密）：

```bash
export SSLKEYLOGFILE=$PWD/tls-keys.log
cargo run --bin tuic_demo
# Wireshark: 过滤器 quic，Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename
# 能直接看到 CRYPTO 帧里的 ClientHello，以及 1-RTT 后 STREAM/DATAGRAM 帧的明文
```

## 第二部分：TUIC —— 拿 QUIC 当积木的代理协议

[TUIC](https://github.com/tuic-protocol/tuic)（Delicately-TUICed 0-RTT proxy protocol）
是构建在 QUIC 之上的代理协议，v5 是当前版本。
参考实现（[Itsusinn/tuic](https://github.com/Itsusinn/tuic)、sing-box、mihomo 等）中，
Rust 系用的 QUIC 库正是 quinn——**也就是本课时用的这套 quinn + rustls**。

一句话概括它的设计哲学（摘自官方 Motivation）：

> - Proxying TCP and UDP traffic in 0-RTT.
> - Achieving Full Cone NAT compatibility for UDP proxying.
> - Supporting both lossy and lossless (via streams) UDP proxying.
> - Leveraging the advantages of QUIC…

### 2.1 TUIC 解决了什么

传统代理（Shadowsocks/Trojan/V2Ray 系，跑在 TCP 或 TCP+TLS/WS 上）的痛点，
对照 TUIC 的解法：

| # | 痛点 | TUIC 的解法 |
|---|------|-------------|
| 1 | **TCP-over-TCP 崩溃（meltdown）**：代理流量本身走 TCP 隧道，两层 TCP 各自拥塞控制互相打架——内层因外层丢包而超时重传，放大到雪崩 | TCP 中继跑在 QUIC **流**上，底层是 UDP：全程只有目标站那一腿是真 TCP，拥塞控制只发生一次 |
| 2 | **握手开销**：每条代理连接都要 TCP 握手 + TLS 握手；翻墙场景 RTT 高达 200-300ms，2-RTT 就是半秒 | QUIC 传输+加密握手合一（1-RTT），配合 0-RTT 恢复首包即数据 |
| 3 | **连接数风暴**：浏览器随手开几十条连接，每条都要完整握手 | 多路复用：一条 QUIC 连接承载所有 TCP 中继（每条=一个双向流），见演示 2 的 C 组数据 |
| 4 | **UDP 转发残废**：SS 的 UDP 中继每个包都走完整封装且 NAT 行为受限；游戏/语音需要 Full-cone NAT | `Packet` 命令 + `ASSOC_ID` 会话表：服务器为每个会话开独立 UDP socket，**任意远端**的回包都原路带回（真 Full-cone）；且提供两种模式——DATAGRAM（native，低延迟）和流（quic，可靠不丢） |
| 5 | **证书成本**：要过 WebPKI 验证就得有域名 + CA 签发，还担心域名被封 | 自签证书 + 客户端固定（指纹/证书）即可；TLS 1.3 加密保证安全性不依赖 WebPKI |
| 6 | **弱网性能**：内核 CUBIC 在高丢包长 RTT 链路上表现差 | QUIC 拥塞控制在用户空间，可插拔（客户端服务端可配 BBR/CUBIC），无需动内核 |

一句话总结：**TUIC = 把"代理"这件事在 QUIC 上重新做一遍，让传输层问题回归传输层解决。**

### 2.2 TUIC 魔改了什么

"魔改"不是改 QUIC 协议本身（QUIC 一个字节都没改），而是**把 QUIC 的机制用在非常规的地方**。
对照"标准姿势"（HTTP/3 的用法）逐条看：

| # | 机制 | HTTP/3 的标准用法 | TUIC 的"魔改"用法 |
|---|------|------------------|-------------------|
| 1 | **ALPN** | `h3` | 自定义值标识协议与版本（如 `tuic`）；QUIC 强制 ALPN，正好当协议指纹 |
| 2 | **DATAGRAM 帧（RFC 9221）** | HTTP/3 几乎不用（MASAConnect 等场景才用） | ① UDP 中继的主力通道（native 模式）② Heartbeat 保活命令。把"不可靠数据报"用成了代理的 UDP 腿 |
| 3 | **TLS exporter（RFC 5705）** | 几乎无人使用 | **认证机制**：`token = exporter(label=UUID, context=密码)`。密码永不上线；token 绑定当前 TLS 会话，抓包重放到别的连接毫无意义。v4 时代认证还要一次 challenge 往返，v5 用 exporter 做到零往返认证 |
| 4 | **单向流** | QPACK 编码指令等辅助用途 | `Authenticate` / `Dissociate` / UDP 中继的 quic 模式——"发完就忘"的命令通道 |
| 5 | **双向流** | 请求-响应 | `Connect` 命令头写在流的最前面，**之后整条流就是裸 TCP 载荷**——协议头只有几个字节，没有任何额外封装 |
| 6 | **流错误码** | HTTP/3 状态码 | TUIC 规范不定义应答（无应答协议），实现自行约定错误语义：如 Connect 失败用流 reset（本课演示用错误码 404）向客户端暗示 |
| 7 | **自定义分片** | 无对应 | `Packet` 命令带 `PKT_ID / FRAG_TOTAL / FRAG_ID`：QUIC 数据报必须装进单个包（受路径 MTU 限制），TUIC 自己在应用层把大 UDP 包切片重组（QUIC 故意不提供数据报分片，TUIC 补上了） |
| 8 | **会话表（ASSOC_ID）** | 无对应 | 16 位会话号同步两端：客户端按 socket 分配，服务器为每个 ID 维护独立 UDP socket——这就是"0-RTT Full Cone UDP"的全部秘密 |

还有一处**实现层**的"魔改"值得知道：TUIC 大量使用 quinn 的底层接口
（`export_keying_material`、DATAGRAM、流 reset、自定义拥塞控制器），
这些在"拿 QUIC 当 HTTP/3 用"的库里都是冷门路径。

### 2.3 TUIC v5 命令一览（wire format）

```text
Command = VER(0x05) + TYPE(1) + OPT(变长)

0x00 Authenticate  UUID(16) + TOKEN(32)          ← 单向流 / DATAGRAM
                     TOKEN = TLS-exporter(label=UUID, context=password)
0x01 Connect       ADDR(变长)                    ← 双向流，之后是 TCP 载荷
0x02 Packet        ASSOC_ID(2)+PKT_ID(2)         ← DATAGRAM（native）或单向流（quic）
                   +FRAG_TOTAL(1)+FRAG_ID(1)
                   +SIZE(2)+ADDR(变长)，之后是 UDP 载荷
0x03 Dissociate    ASSOC_ID(2)                   ← 单向流
0x04 Heartbeat     （空）                        ← DATAGRAM

ADDR = TYPE(1) + ADDR(变长) + PORT(2)
  0xff=None（分片非首片） 0x00=域名 0x01=IPv4 0x02=IPv6
```

一次完整的 TUIC 会话（对照演示 3 的输出）：

```text
客户端                                            服务端
── QUIC 握手（rustls，1-RTT 或 0-RTT）─────────────────▶
── Authenticate(单向流) ────────────────────────────▶  exporter 复算 token ✅
── Connect(addr)+载荷(双向流) ─────────────────────▶  向目标站开 TCP，双向搬运
◀─────────────────────────────── 目标站数据（同一条流）
── Packet(assoc=1, DATAGRAM) ──────────────────────▶  为 assoc=1 分配 UDP socket
◀── Packet(assoc=1, DATAGRAM，来源地址) ────────────   任何远端→该 socket 的包都回传
── Heartbeat(DATAGRAM) ───────────────────────────▶  （维持连接不空闲超时）
── Dissociate(assoc=1, 单向流) ────────────────────▶  释放 UDP socket
```

注意"无应答"贯穿始终：**服务器从不回复任何命令**，认证失败/目标不可达等错误
只能通过关闭连接或 reset 流来暗示——用应答通道换 0-RTT，是 TUIC 最激进的取舍。

### 2.4 阅读真实实现

- 协议规范：[tuic-protocol/tuic SPEC.md](https://github.com/tuic-protocol/tuic/blob/master/SPEC.md)（本课 `src/tuic.rs` 逐字节对照实现）
- Rust 参考实现：[Itsusinn/tuic](https://github.com/Itsusinn/tuic)（quinn + rustls）
- 多协议实现：sing-box / mihomo（它们同时实现 TUIC v5 的 native 与 quic 两种 UDP 模式）

## 思考问题（附参考答案）

1. **TUIC 的 token 认证为什么抓包重放无效？如果攻击者拿到 UUID 但没有密码，能否伪造？**
   <details><summary>答案</summary>

   - token = `exporter(label=UUID, context=password)`，而 exporter 的底层是
     **本连接握手派生的 exporter_master_secret**（课时 7 密钥树的一支）——
     每条连接的握手 transcript 不同，导出值必然不同
   - 重放场景：攻击者录下连接 A 的 token，在连接 B 上原样发送——
     服务器用**连接 B 自己的** exporter 复算，值不匹配，认证失败。
     token 与连接绑定，不是跨连接的万能钥匙
   - 只知 UUID 不知密码：exporter 是 PRF（HKDF 展开），没有正确的 context 输入
     无法计算输出，求逆在计算上不可行——不能伪造
   - 唯一的攻击面是密码本身（弱密码可离线暴力尝试 exporter 组合），
     所以 TUIC 文档强调用强密码；这也是 v4→v5 的关键改进：
     v4 的 challenge 应答需要一次往返，v5 用 exporter 做到 0-RTT 认证
   </details>

2. **TCP-over-TCP 为什么会 meltdown？画出内层 TCP 重传定时器与外层拥塞窗口互相恶化的循环。**
   <details><summary>答案</summary>

   恶性循环的闭环：
   ```
   外层（隧道）丢包
     → 外层 cwnd 收缩，可用带宽下降
       → 内层 TCP 的数据/ACK 被外层排队延迟
         → 内层 RTO 到期，重传（流量翻倍！）并指数退避
           → 更多的外层流量 → 更多外层丢包
             → 外层 cwnd 进一步收缩 → 内层延迟更大 → 更多 RTO……
   ```
   - 两个独立拥塞控制器叠加在同一路径上：内层的重传放大外层负载，
     外层的收缩惩罚内层延迟——经典 meltdown
   - 缓解手段（TCP Mux 系协议）只是缓解：禁用内层拥塞、调大内层 RTO……
   - TUIC 的根治：TCP 中继跑在 QUIC **流**上（底层 UDP），
     全程只剩目标站那一腿是真 TCP，拥塞控制只发生一次；
     流之间互相独立（无跨流队头阻塞），一条流丢包不拖累其他流
   </details>

3. **QUIC 的 DATAGRAM 必须装进单个 QUIC 包（≈路径 MTU），TUIC 为什么不能指望 QUIC 帮它分片？这与"流"的可靠传输机制（课时 5 的分片重组）有何本质区别？**
   <details><summary>答案</summary>

   - RFC 9221 刻意不做数据报分片：数据报的卖点是**不可靠、低延迟**——
     一旦分片，"丢一片就整包重发"会变相引入可靠传输的复杂度与队头问题，
     还要占用重传缓冲，那和用流没有区别了
   - 所以 TUIC 在**应用层自己切片**：PKT_ID/FRAG_TOTAL/FRAG_ID 标记分片，
     两端自行重组；丢一个分片只损失这一个 UDP 包（对 UDP 语义可接受）
   - 与流机制的本质区别：
     - 流的分片（STREAM 帧）是**字节段**：有 ACK、按需重传、流控窗口、
       有序递交（课时 5 的记录重组在 QUIC 里对应流的 offset 重组）——可靠语义
     - TUIC 的分片是**包切片**：无 ACK 无重传，分片丢失即整个包放弃——
       保留 UDP "丢就丢了"的语义
   - 这也解释了 TUIC 的双模式：要可靠走流（quic 模式），要低延迟走 DATAGRAM
     （native 模式）——把选择权交给使用者
   </details>

4. **TUIC 无应答协议牺牲了什么？如果让你加一个 `ConnectResult` 应答命令，会破坏哪些 0-RTT 特性？**
   <details><summary>答案</summary>

   - 牺牲的东西：
     - **显式错误语义**：目标拒绝/DNS 失败/限流无法结构化表达，
       只能 reset 流（错误码自定义）或断连——客户端难以程序化区分处理
     - **状态确认**：客户端无法知道"服务器准备好没有"，只能超时探测
     - **能力协商**：协议演进缺少"服务器支持哪些特性"的协商通道
   - 加 ConnectResult 的代价：
     - Connect 要么等应答确认后才可靠发送数据——退化为 1-RTT 中继
       （0-RTT 的意义就是"命令+数据一次发出"）
     - 要么数据先发（赌服务器成功）——那应答只是事后通知，
       失败时已发数据要丢弃，流控状态更复杂
     - 应答命令本身还要防乱序/重复/与流数据交错——等于在 QUIC 之上
       再造一层小 TCP，违背"借 QUIC 之简"的初衷
   - TUIC 的取舍映射一个通用设计原则：**想要 0-RTT，就必须接受乐观执行 + 补偿**
   </details>

5. **把演示 3 的 UDP 中继从 DATAGRAM 模式改成单向流模式（quic mode），哪些行为会变化？（丢包语义、流控窗口、心跳必要性）**
   <details><summary>答案</summary>

   - **丢包语义**：DATAGRAM 丢就丢了（天然 UDP，适合语音/游戏）；
     流模式可靠有序——每个 Packet 作为流的字节段被确认重传，
     效果接近"UDP over TCP"，前一个包丢了后面的包要等（队头阻塞）
   - **流控窗口**：DATAGRAM 只受发送缓冲限制、不占流控；
     流模式每个 Packet 计入 STREAM 流控窗口与连接级窗口——
     慢消费者（对端处理不过来）会反压整个中继会话
   - **心跳必要性**：DATAGRAM 心跳不占窗口、开销 2 字节，顺手保持连接活跃；
     流模式下持续有数据流动时连接本来就不空闲，心跳价值下降，
     但空闲会话仍需靠 QUIC keep-alive（服务器配置的 keep_alive_interval）兜底
   - 帧开销：流模式可省去每包的地址重复（同一目标可约定只在首包带 ADDR），
     但 TUIC 规范仍保留完整字段——实现从简
   - 一句话：native 模式换"真 UDP 语义"，quic 模式换"弱网不丢包"——
     没有免费的午餐，这也是 SPEC 把两种模式都保留的原因
   </details>

6. **Wireshark 抓 QUIC 包：为什么 Initial 包"看起来是乱码"却又能被任何人解密？这与课时 5 的记录层加密有什么不同？**
   <details><summary>答案</summary>

   - RFC 9001 的设计：Initial 包用**全网公开派生的密钥**加密——
     `key = HKDF(salt="tls13 quic initial", IKM=目的连接ID DCID)`，
     DCID 就在包头里，任何人（包括 Wireshark、中间盒、攻击者）都能推导并解密
   - 那为什么还要加密？**完整性而非机密性**：
     AEAD 保证中间人**无法篡改**（改一个字节解密即失败）——
     防版本降级注入、防中间盒"优化" QUIC 包（TCP 前车之鉴），
     这是对抗协议僵化的核心手段
   - 与课时 5 记录层的对比：

     | | TLS over TCP 记录层 | QUIC 包保护 |
     |---|---|---|
     | 明文部分 | 完整 5 字节头 | 仅首字节标志 + DCID（早期） |
     | 加密对象 | 载荷 | 载荷 + **包头其余字段（含包号）** |
     | 包号 | 无对应（字节流无包） | 独立加密（防关联/重放分析） |
     | Initial/握手前 | ClientHello 明文 | 即使 Initial 也"加密"（公开密钥） |

   - 后续包（1-RTT）才用双方握手的真密钥——Wireshark 要解它们就必须导入
     SSLKEYLOGFILE（课时 12 的方法对 QUIC 同样有效）
   </details>

## 延伸阅读

- [RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)（看 §5.2 Initial 密钥、§5.4 包保护）
- [RFC 9221 — An Unreliable Datagram Extension to QUIC](https://www.rfc-editor.org/rfc/rfc9221)
- [TUIC Protocol 官方仓库与 SPEC](https://github.com/tuic-protocol/tuic)
- [quinn 文档](https://docs.rs/quinn)（注意 `Connection::export_keying_material`、`send_datagram` 这两个 TUIC 用的冷门 API）
- 拥塞控制进阶：[BBR 论文](https://research.google/pubs/pub45646/) 与 quinn 的 `congestion` 模块
