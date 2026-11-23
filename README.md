# WebRTC-Cloak (`webrtc-cloak-rs`)

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
[![Rust](https://img.shields.io/badge/Rust-Pure%20Rust%20%7C%20Zero%20C%20Deps-orange.svg)](#从源码构建与测试)
[![Interactive Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-0ea5e9.svg)](https://mumu-dada.github.io/webrtc-cloak/)
[![Release](https://img.shields.io/github/v/release/MUMU-DADA/webrtc-cloak?color=10b981)](https://github.com/MUMU-DADA/webrtc-cloak/releases)

一个**纯 Rust、零 C 依赖**的 WebRTC 单端口协议复用与 UDP 封装实验原型。本项目基于标准 RFC 规范（RFC 5389 / 8445 / 7675 / 6347 / 5764 / 7983 / 3711 / 7714 / 8285 / 3550），实现了一套完整的 `ICE STUN + 真双向证书 DTLS 1.2 + SRTP/SRTCP` 透明 UDP 传输层实验框架，用于研究现代网络协议识别（DPI）、UDP 状态化防火墙行为、前向安全混合密钥派生以及高性能无锁 `mio` 事件循环架构。

> **交互式协议原理演示**：可直接在线访问 **[GitHub Pages 交互演示页](https://mumu-dada.github.io/webrtc-cloak/)**，或克隆后离线打开 [`webrtc-cloak-demo.html`](./webrtc-cloak-demo.html)，即可交互查看全生命周期协议推演、字节级报文解剖、AEAD 内层填充分布模拟与 Hybrid PFS 密钥派生流程。

---

## 免责声明（Disclaimer）

> [!CAUTION]
> **本项目仅用于网络协议学习、学术研究、RFC 规范实现验证及授权环境下的网络传输实验。**
>
> 1. 本仓库中的源码、文档、演示页面及预编译产物均以学习与研究为唯一目的提供，**严禁用于任何违反您所在国家或地区法律法规、网络服务条款或未经授权的网络渗透、规避监管等行为**。
> 2. 使用者须自行评估并承担使用本项目所产生的一切法律与合规责任。项目作者与贡献者不对任何因使用或滥用本软件造成的直接、间接、附带或衍生损失承担任何责任。
> 3. 若您不同意上述条款，请立即停止下载、编译、分发或使用本项目。

---

## 目录结构

```text
.
├── LICENSE                                # MIT 开源许可证
├── README.md                              # 项目说明、协议架构与构建文档
├── .gitignore                             # 忽略构建产物、密钥文件与抓包日志
├── webrtc-cloak-demo.html                 # 交互式协议原理演示网页（离线单文件）
├── dist/                                  # 预编译 Release 产物（已剥离本机路径）
│   ├── webrtc-cloak-linux-x86_64          # Linux x86_64 静态 musl 二进制 (2.1 MB)
│   └── webrtc-cloak-macos-arm64           # macOS Apple Silicon 二进制 (1.5 MB)
└── webrtc-cloak-rs/                       # 纯 Rust 源码工程（零 unsafe / 零 OpenSSL）
    ├── Cargo.toml
    ├── Cargo.lock
    ├── .cargo/config.toml
    └── src/
        ├── main.rs                        # CLI / PSK 加载 / cpu / bench / sink / loadgen
        ├── protocol.rs                    # STUN / dimpl DTLS 1.2 / X.509 / SRTP / SRTCP
        ├── client.rs                      # 客户端 mio 非阻塞事件循环与失活重握状态机
        └── server.rs                      # 服务端 mio 事件循环 / 防重放 / Silent Drop / 乱序缓冲
```

---

## 协议架构与核心特性

### 1. 透明 UDP 封装拓扑

```mermaid
flowchart LR
    App["本地测试应用 / 上层 UDP<br/>(127.0.0.1:19543)"] -->|"原始 UDP 报文"| Cli["webrtc-cloak client<br/>(默认单线程 mio)"]
    Cli <-->|"单端口 RFC 7983 复用<br/>STUN + DTLS 1.2 + SRTP/SRTCP"| Net{{"公网 / 实验链路<br/>(NAT / 状态化中间件)"}}
    Net <-->|"UDP :19643"| Srv["webrtc-cloak server<br/>(默认单线程 mio)"]
    Srv -->|"解封装还原 UDP"| Backend["后端本地 UDP 服务<br/>(127.0.0.1:<BACKEND>)"]
```

### 2. RFC 7983 单端口四协议复用

两端在同一 UDP 五元组上按首字节精确分流，其余非预期首字节全部静默丢弃：

| 首字节范围 | 协议层 | 关键规范与实现要点 |
| :--- | :--- | :--- |
| `0..=3` | **ICE STUN** (RFC 5389 / 8445 / 7675) | 初始连通性检查（`4:4` Base64 `ufrag`、`USE-CANDIDATE`、HMAC-SHA1 `MESSAGE-INTEGRITY`、唯一尾部 8B `FINGERPRINT`、±30s 时间戳防重放），以及 `5s ± 20%` Consent Freshness 保活 |
| `20..=23` | **DTLS 1.2** (RFC 6347 / 5764) | 嵌入纯 Rust Sans-IO 库 **`dimpl 0.9.0`**，执行完整 6-Flight 双向 ECDSA P-256 证书 + `HelloVerifyRequest` Cookie + ECDHE 握手 |
| `128..=191` (`PT 64..95` 除外) | **SRTP** (RFC 3711 / 7714 / 8285) | 标准 **`0x90`**（`V=2, P=0, X=1, CC=0`）+ `0xBEDE` 单字节扩展头 + 90kHz 墙钟时间戳 + AEAD 密文内层长度与随机填充 |
| `128..=191` (`PT 64..95`) | **Compound SRTCP** (RFC 3550 / 7714) | 明文首包恒为 `PT=200 (SR)` 或 `PT=201 (RR)`，动态 `RC=0/1`，加密复合体包含 `SDES (202)` + `FB (205/206)` + 加密尾部 `BYE (203)` |

### 3. 核心工程设计亮点

- **双重混合前向安全（Hybrid PFS）**：最终会话主密钥由 `SHA-256("webrtc-cloak-v3-pfs-mix" || stun_key || dtls_keying_material)` 派生，将预置共享密钥（PSK）认证与每次会话独立的 ECDHE-P256 前向安全密钥材料深度绑定；SRTP 与 SRTCP 通过 `dir | 0x80` 实现 100% 不相交的 AEAD Nonce 域分离。
- **严谨的状态机边界防护**：
  - **纯 Silent Drop**：未通过 PSK 鉴权或新鲜度校验的探测包 0 字节静默丢弃；会话优雅退出时进入 `Closing(250ms)` 吸收在途尾包，避免触发 `ICMP Port Unreachable`。
  - **入口预校验与抗注入**：`validate_dtls_datagram` 拒绝 `Epoch=0` 明文 Alert 及 `<18B` 的伪造加密记录；`parse_stun` 严格执行 RFC 5389 §15.4 拒绝 `MESSAGE-INTEGRITY` 后的任何夹带属性；SRTP 与 SRTCP 均内置 **64-bit 滑动防重放窗口**。
  - **CGNAT 漂移与服务端重启自愈**：服务端拒绝无 `USE-CANDIDATE` 的孤儿保活误建会话；客户端按 RFC 7675 §5.1 独立追踪 `last_peer_rx`，失活超时后自动销毁旧句柄并在新端口重握恢复。
- **AEAD 密文内层随机填充**：线上传输首字节固定为 `0x90 (P=0)`，`[inner_len: u16 BE] || plaintext || [0..=31B random pad]` 全部位于 AEAD 密文内，大包（`>= 1340B`）自动收窄填充至 `0..=7B` 以适配 `1492B` PPPoE MTU 避免 IP 分片。
- **动态自签 X.509 证书缓存**：按 worker 缓存 `20–24h` 轮换的无扩展 `CN=WebRTC` 自签 ECDSA P-256 证书，支持秒级随机有效期与 High-S/Low-S 签名长度随机化；全平台 `ClientHello` 均完整宣告 3 个 ECDHE-ECDSA AEAD 套件。
- **默认单线程无锁 + 可选多核扩展**：默认 `--workers 1` 在主线程运行单个 `mio` 非阻塞事件循环（不启用 `SO_REUSEPORT`），即可并发承载数千 UDP 会话；在 Linux 多核服务器上可按需传入 `--workers <N|auto>` 开启多核横向扩展。

---

## 实验基准数据

> 以下数据均在自有实验环境测得（`AES-128-GCM` / `1260B` 载荷）：

| 测试平台 | 加解密微基准 | 端到端全隧道环回吞吐 | 真双向 DTLS 1.2 握手 | 内存占用 (RSS) |
| :--- | :---: | :---: | :---: | :---: |
| **Apple Silicon (ARM64)** | `9,360–9,820 Mbps` | — | — | — |
| **x86_64 云服务器（单核 `1W`）** | `3,228.6 Mbps` (`320.3 kpps`) | `1,124.2 Mbps` (`111.5 kpps`) | `3.01 ms` | `2.1–2.2 MB` |
| **x86_64 低功耗软路由（单核 `1W`）** | `2,139.8 Mbps` (`212.3 kpps`) | `900.0 Mbps` (`0.00%` 丢包，p50 RTT `50 µs`) | `6.85–9.02 ms` | `2.1–2.2 MB` |
| **x86_64 低功耗软路由（多核 `4W / 8S`）** | — | `1,448.7 Mbps` (`0.00%` 丢包，`143.7 kpps`) | `6.85–9.12 ms` | `2.5 MB` |

---

## 快速上手（实验部署示例）

### 1. 生成共享密钥文件（推荐 `--psk-file` 或环境变量 `WEBRTC_CLOAK_PSK`）

```bash
openssl rand -base64 32 > /tmp/webrtc-cloak.psk
chmod 600 /tmp/webrtc-cloak.psk
```

### 2. 启动服务端

```bash
# 默认单线程 (--workers 1)、--cipher auto（两端按硬件加速自动协商）
./dist/webrtc-cloak-linux-x86_64 server \
  --listen-host 0.0.0.0 \
  --listen-port 19643 \
  --backend-host 127.0.0.1 \
  --backend-port 19760 \
  --psk-file /tmp/webrtc-cloak.psk
```

### 3. 启动客户端

```bash
./dist/webrtc-cloak-linux-x86_64 client \
  --listen-host 127.0.0.1 \
  --listen-port 19543 \
  --server-host 203.0.113.10 \
  --server-port 19643 \
  --psk-file /tmp/webrtc-cloak.psk
```

也可以通过环境变量传入密钥：

```bash
WEBRTC_CLOAK_PSK="YOUR_TEST_PSK" ./dist/webrtc-cloak-macos-arm64 client \
  --listen-host 127.0.0.1 --listen-port 19543 \
  --server-host 203.0.113.10 --server-port 19643
```

### 4. 主要命令行参数

| 参数 | 默认值 | 说明 |
| :--- | :---: | :--- |
| `--psk-file <PATH>` / `WEBRTC_CLOAK_PSK` / `--psk <KEY>` | 必填其一 | 预置共享密钥（推荐文件或环境变量，避免 `ps` 泄露） |
| `--cipher <auto\|aes-gcm\|chacha20\|blake2b>` | `auto` | 加密套件；`auto` 经 DTLS 握手按两端 CPU 指令集自动协商 |
| `--workers <1\|N\|auto>` | `1` | 工作线程数；默认 `1` 为单线程模式，Linux 可选多核 `SO_REUSEPORT` |
| `--keepalive <SECS>` | `5` | RFC 7675 STUN 保活间隔（自动加 `±20%` 抖动，失活阈值 `5 × keepalive`） |
| `--idle-timeout <SECS>` | `120` | 空闲超时后发送加密 `SRTCP BYE` + DTLS `close_notify` 优雅退出 |
| `--max-sessions <N>` | `4096` | 单 worker 最大并发 UDP 会话数 |

### 5. 内置基准与环回诊断

```bash
# 查看本机硬件指令集与推荐加密套件
./dist/webrtc-cloak-macos-arm64 cpu

# 运行全部密码套件吞吐微基准（50000 包 × 1260B）
./dist/webrtc-cloak-macos-arm64 bench 50000 1260 all
```

---

## 从源码构建与测试

```bash
cd webrtc-cloak-rs

# 运行全套协议不变式与安全回归单元测试
cargo test

# 编译本机 Release 版本
cargo build --release

# 交叉编译 Linux x86_64 静态 musl 版本（零动态库依赖）
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

---

## 开源协议

本项目基于 **[MIT License](./LICENSE)** 开源发布。
