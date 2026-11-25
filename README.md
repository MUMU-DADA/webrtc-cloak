# WebRTC-Cloak (`webrtc-cloak-rs`)

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
[![Rust](https://img.shields.io/badge/Rust-Pure%20Rust%20%7C%20Zero%20C%20Deps-orange.svg)](#从源码构建与测试)
[![Interactive Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-0ea5e9.svg)](https://mumu-dada.github.io/webrtc-cloak/)
[![Release](https://img.shields.io/github/v/release/MUMU-DADA/webrtc-cloak?color=10b981)](https://github.com/MUMU-DADA/webrtc-cloak/releases)

一个**纯 Rust、零 C 依赖**的 WebRTC 单端口协议复用与 UDP 封装实验原型。本项目基于标准 RFC 规范（RFC 5389 / 8445 / 7675 / 9147 / 6347 / 5764 / 7983 / 3711 / 7714 / 8285 / 3550 / 7587），实现了一套完整的 `ICE STUN + 真双向加密证书 DTLS 1.3/1.2 + 双 SSRC SRTP/SRTCP` 透明 UDP 传输层实验框架，用于研究现代网络协议识别（DPI）、UDP 状态化防火墙行为、前向安全混合密钥派生以及高性能无锁 `mio` 事件循环架构。

> [!TIP]
> **在线交互式原理演示（无需下载）**：👉 **[https://mumu-dada.github.io/webrtc-cloak/](https://mumu-dada.github.io/webrtc-cloak/)**
>
> 支持在线交互体验 5 种对抗与自愈场景动态推演、字节级报文解剖（`ICE STUN / DTLS 1.3 & 1.2 / 双流 SRTP 0x90 / Compound SRTCP`）、双 SSRC + PPPoE MTU 1488 + AEAD 内层随机填充直方图模拟以及 Hybrid PFS 密钥派生流程（也可离线双击本地 [`webrtc-cloak-demo.html`](./webrtc-cloak-demo.html)）。
>
> **全平台预编译下载（16 架构）**：👉 **[GitHub Releases](https://github.com/MUMU-DADA/webrtc-cloak/releases/latest)**（含 Linux 11 架构静态 musl、macOS ARM64/x86_64、Windows x86_64/ARM64/i686 与 `SHA256SUMS.txt`）

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
├── .github/workflows/
│   ├── release.yml                        # Tag 触发 16 架构全自动交叉编译与 Release 发布
│   └── pages.yml                          # 自动部署交互原理演示页至 GitHub Pages
├── LICENSE                                # MIT 开源许可证
├── README.md                              # 项目说明、协议架构与构建文档
├── SPEC.md                                # V4.0 / v0.4.0 线格式、密码学与状态机协议规范
├── .gitignore                             # 忽略构建产物、密钥文件与抓包日志
├── webrtc-cloak-demo.html                 # 交互式协议原理演示网页（离线/Pages 双用）
└── webrtc-cloak-rs/                       # 纯 Rust 源码工程（零 unsafe / 零 OpenSSL）
    ├── Cargo.toml
    ├── Cargo.lock
    ├── .cargo/config.toml
    └── src/
        ├── main.rs                        # CLI 参数解析与子命令分发入口
        ├── constants.rs                   # 跨模块共享的协议契约、网络缓冲与双端耦合时序常量
        ├── bench_tools.rs                 # cpu / bench / sink / loadgen 压测与算力工具
        ├── protocol/                      # STUN / dimpl DTLS 1.3+1.2 / X.509 / 双 SSRC SRTP / SRTCP
        ├── client/                        # 客户端 mio 事件循环、黑洞 1-RTT 迁移、MBB 状态机与集成测试
        ├── server/                        # 服务端 mio 事件循环、防重放、跨 worker 注册表与 Silent Drop
        ├── selftest/                      # 线上直测 + 本地离线 12 项自测、劣化代理与报告渲染
        └── telemetry/                     # 外层链路健康只读遥测（原子 JSON 落盘 / HTTP / Prometheus）
```

---

## 协议架构与核心特性

### 1. 透明 UDP 封装拓扑

```mermaid
flowchart LR
    App["本地测试应用 / 上层 UDP<br/>(127.0.0.1:19543)"] -->|"原始 UDP 报文"| Cli["webrtc-cloak client<br/>(默认单线程 mio)"]
    Cli <-->|"单端口 RFC 7983 复用<br/>STUN + DTLS 1.3/1.2 + 双流 SRTP/SRTCP"| Net{{"公网 / 实验链路<br/>(NAT / 状态化中间件)"}}
    Net <-->|"UDP :19643"| Srv["webrtc-cloak server<br/>(默认单线程 mio)"]
    Srv -->|"解封装还原 UDP"| Backend["后端本地 UDP 服务<br/>(127.0.0.1:<BACKEND>)"]
```

### 2. RFC 7983 单端口四协议复用

两端在同一 UDP 五元组上按首字节精确分流，其余非预期首字节全部静默丢弃：

| 首字节范围 | 协议层 | 关键规范与实现要点 |
| :--- | :--- | :--- |
| `0..=3` | **ICE STUN** (RFC 5389 / 8445 / 7675) | 初始连通性检查（`4:4` Base64 `ufrag`、`USE-CANDIDATE`、零分配前置 HMAC-SHA1 `MESSAGE-INTEGRITY`、唯一尾部 8B `FINGERPRINT`、±30s 时间戳防重放），以及 `5s ± 20%` Consent Freshness 保活 |
| `20..=63` | **DTLS 1.3 / 1.2 Auto** (RFC 9147 / 6347 / 5764) | 嵌入纯 Rust Sans-IO 库 **`dimpl 0.9.0`**，默认 DTLS 1.3 优先（`0x2e` 全程加密双向 ECDSA P-256 证书 + 省 1 RTT + 多 MTU 预构建配置池打散 ClientHello 长度），同时无缝向下兼容 `v0.3.5` DTLS 1.2 滚动升级；支持 `--dtls-min-version 1.3` 锁定彻底防降级 |
| `128..=191` (`PT 64..95` 除外) | **双 SSRC SRTP** (RFC 3711 / 7714 / 8285 / 7587) | 标准 **`0x90`**（`V=2, P=0, X=1, CC=0`）+ 全局共享 `0xBEDE` TWCC 扩展头；DTLS 1.3 自动启用双 SSRC 分流：抖动阈值小包走 `PT=111` 48kHz Opus（每 20ms 严格限 1 包 `≤50 pps`），其余与大包走 `PT=96` 90kHz 视频（严格 `M=1` 帧尾因果律）+ AEAD 密文内层长度与随机填充 |
| `128..=191` (`PT 64..95`) | **Compound SRTCP** (RFC 3550 / 7714) | 明文首包恒为 `PT=200 (SR)` 或 `PT=201 (RR)`，动态 `RC=0/1` 且按实际音视频发包 SSRC 上报；加密复合体包含会话恒定 CNAME `SDES (202)`（严格 `0x00` 对齐）+ 平滑随机 `FB (205/206)` + 加密尾部 `BYE (203)`，0-based 序号 |

### 3. 核心工程设计亮点

- **双重混合前向安全（Fail-Closed Hybrid PFS）**：最终会话主密钥由 `SHA-256("webrtc-cloak-v3|pfs-bind|" || stun_key || "|dtls-km|" || dtls_keying_material)` 派生（缺失 `KeyingMaterial` 时严格 Fail-Closed 拒连）；Video SRTP（`dir`）、Audio SRTP（`dir | 0x40` + 高 16 位严格互异 `audio_ssrc`）与 SRTCP（`dir | 0x80`）三域 100% 数学正交隔离，并在序号逼近上限时主动重连永不回绕。
- **严谨的状态机边界防护**：
  - **纯 Silent Drop**：未通过 PSK 鉴权或新鲜度校验的探测包 0 字节静默丢弃；`parse_stun` 鉴权前零堆分配；会话退出进入 `Closing` 吸收在途尾包（客户端排空期仍 Make-Before-Break 解密投递合法下行 SRTP 且零公网回包），避免触发 `ICMP Port Unreachable`。
  - **入口预校验与抗注入**：`validate_dtls_datagram` 同时覆盖 DTLS 1.2 与 RFC 9147 DTLS 1.3（`C=0`、`≥18B`），拒绝 `Epoch=0` 明文 Alert 及 `Ready` 态明文 `ct=26`；服务端 `Ready` 态绝不被伪造 DTLS 垃圾包误续命 Consent；客户端在 `Ready` 态持续驱动 DTLS 1.3 Flight 5 重传定时器防单包丢包黑洞；`extract_dtls_server_hello_suite` 严格校检帧长与扩展边界并过滤 `TLS13_HRR_RANDOM`；SRTP 双流各自维护独立 **2048 包 RFC 6479 滑动防重放环**，SRTCP 内置 64-bit 滑动防重放窗口。
  - **V4.0 万用无感 UDP 承载与自愈（“换路不换门牌”）**：
    - **定时/定量无感轮换 + 密文过户**：主动 MBB 轮换走完整全新 DTLS 1.3（对外全新 `ufrag`/`SSRC`/`CNAME` 彻底防关联），在 AEAD 密文内通过 `0xFFFC` + HKDF 双密钥证明将服务端旧 `backend_sock` 原子过户给新会话（支持多核 `SO_REUSEPORT` 跨线程无锁迁移），哪怕内部是认死源端口的游戏/语音/OpenVPN 也 **0 端口变化、0 丢包**；同时保留 `2–10s` 随机延迟旧流 `BYE`、对数正态宽分布时长、随机字节预算（`600MB–2.2GB`）与夜间微流挂起。
    - **1-RTT 故障黑洞原地迁移**：确认上行黑洞后，客户端用 DTLS-PFS 派生的每会话 `ice-pwd-v4` 在新端口发 1 个标准 RFC 8445 `USE-CANDIDATE` 迁移包，服务端通过 `<1.5x` 防反射加密 `0xFFFD` 挑战验真后原地更新 `peer_addr` 并保留原 `backend_sock`（1-RTT 救活、0 DTLS 重握，并向下兼容旧版服务端自动回退）。
    - **空闲微流静音与优雅重连**：空闲/微流态自动关闭空载假 `PT=205/206` 反馈，双端 SRTCP 退避至 `20–40s`（服务端持续微流 `>60s` 后静默暂停），STUN 保活温和退避至 `10–14s` 且来包秒切回 `5s`；服务端 `SIGTERM` 退服后客户端抖动 `80–350ms` 快重连避免明文 `ICMP Port Unreachable`。
- **内置双模式 12 项自测与算力体检（`v0.3.5+`）**：`webrtc-cloak selftest` 支持**真实线上远程隧道直测**（`--server-host <IP> --server-port 19643 --psk-file <PATH>`，通过加密带内 `0xFFFE` SRTP 回显探针在不影响线上业务后端的前提下实测真实公网 NAT 映射、DTLS 1.3/1.2 握手、WAN 延迟/抖动/丢包、公网 Path MTU 边界、多端口 NAT 轮换与 7 类主动探测 Silent-Drop 验真，并兼容 `< v0.3.5` 服务端自动降级 `[SKIP]`）以及**离线本地故障注入沙箱**（`--local`），同时内置本机单核/全核加解密与 P-256 证书签发算力体检。
- **AEAD 密文内层随机填充**：线上传输首字节固定为 `0x90 (P=0)`，`[inner_len: u16 BE] || plaintext || [0..=31B random pad]` 全部位于 AEAD 密文内，大包（`>= 1340B`）自动收窄填充至 `0..=7B` 以适配 `1492B` PPPoE MTU 避免 IP 分片。
- **动态自签 X.509 证书缓存**：按 worker 缓存 `20–24h` 轮换的无扩展 `CN=WebRTC` 自签 ECDSA P-256 证书（DTLS 1.3 模式下证书在公网 100% 加密不可见）；客户端全平台完整宣告 6 个 DTLS 1.3/1.2 AEAD 套件，并通过多 MTU 预构建配置池打散 ClientHello 长度。
- **默认单线程无锁 + 可选多核扩展**：默认 `--workers 1` 在主线程运行单个 `mio` 非阻塞事件循环（不启用 `SO_REUSEPORT`），即可并发承载数千 UDP 会话；在 Linux 多核服务器上可按需传入 `--workers <N|auto>` 开启多核横向扩展。

---

## 实验基准数据

> 以下数据均在自有实验环境测得（`AES-128-GCM` / `1260B` 载荷）：

| 测试平台 | 加解密微基准 | 端到端全隧道环回吞吐 | 真双向 DTLS 1.2 握手 | 内存占用 (RSS) |
| :--- | :---: | :---: | :---: | :---: |
| **Apple Silicon (ARM64, 12C)** | `10,129 Mbps` (1C) / `81.06 Gbps` (12C) | `1,557–2,109 Mbps` (`162–188 kpps`, `1200–1350B`) | `11.8 ms` (`selftest`) | — |
| **x86_64 云服务器（单核 `1W`）** | `3,228.6 Mbps` (`320.3 kpps`) | `1,124.2 Mbps` (`111.5 kpps`) | `3.01 ms` | `2.1–2.2 MB` |
| **x86_64 低功耗软路由（单核 `1W`）** | `2,139.8 Mbps` (`212.3 kpps`) | `900.0 Mbps` (`0.00%` 丢包，p50 RTT `50 µs`) | `6.85–9.02 ms` | `2.1–2.2 MB` |
| **x86_64 低功耗软路由（多核 `4W / 8S`）** | — | `1,448.7 Mbps` (`0.00%` 丢包，`143.7 kpps`) | `6.85–9.12 ms` | `2.5 MB` |

---

## 快速上手（实验部署示例）

> 请直接从 **[GitHub Releases](https://github.com/MUMU-DADA/webrtc-cloak/releases/latest)** 下载对应平台/架构的预编译压缩包并解压得到 `webrtc-cloak`（或 `webrtc-cloak.exe`）。

### 1. 生成共享密钥文件（推荐 `--psk-file` 或环境变量 `WEBRTC_CLOAK_PSK`）

```bash
openssl rand -base64 32 > /tmp/webrtc-cloak.psk
chmod 600 /tmp/webrtc-cloak.psk
```

### 2. 启动服务端

```bash
# 默认单线程 (--workers 1)、--cipher auto（两端按硬件加速自动协商）、默认 --mtu 1488
./webrtc-cloak server \
  --listen-host 0.0.0.0 \
  --listen-port 19643 \
  --backend-host 127.0.0.1 \
  --backend-port 19760 \
  --psk-file /tmp/webrtc-cloak.psk
```

### 3. 启动客户端

```bash
./webrtc-cloak client \
  --listen-host 127.0.0.1 \
  --listen-port 19543 \
  --server-host 203.0.113.10 \
  --server-port 19643 \
  --psk-file /tmp/webrtc-cloak.psk
```

也可以通过环境变量传入密钥：

```bash
WEBRTC_CLOAK_PSK="YOUR_TEST_PSK" ./webrtc-cloak client \
  --listen-host 127.0.0.1 --listen-port 19543 \
  --server-host 203.0.113.10 --server-port 19643
```

### 4. 主要命令行参数

| 参数 | 默认值 | 说明 |
| :--- | :---: | :--- |
| `--psk-file <PATH>` / `WEBRTC_CLOAK_PSK` / `--psk <KEY>` | 必填其一 | 预置共享密钥（推荐文件或环境变量，避免 `ps` 泄露） |
| `--cipher <auto\|aes-gcm\|chacha20\|blake2b>` | `auto` | 加密套件；`auto` 经 DTLS 握手按两端 CPU 指令集自动协商 |
| `--dtls-min-version <auto\|1.2\|1.3>` | `auto` | DTLS 最低版本；`auto`/`1.2` 优先 DTLS 1.3 并无缝兼容旧版 1.2 滚动升级，双端升完后可设为 `1.3` 彻底锁定防降级 |
| `--rotate-interval <SECS>` | `0`（关闭） | 客户端可选定时 Make-Before-Break 无感五元组滚动轮换中位间隔（对数正态 `[0.35x, 2.80x]` 宽分布，后台微流 `<64KB/5m` 自动挂起，切流后旧口延迟 `2–10s` 发 `BYE` 排空慢回包，刷新 PFS 密钥；适合 Hysteria 2 / WireGuard 等支持源端口迁移的上层协议） |
| `--rotate-bytes <MB>` | 随 `--rotate-interval` 自动启用 `1200`（`0` 关闭） | 客户端可选单流字节预算 MBB 轮换基线（每会话按对数正态在 `[0.50x, 1.85x]` 随机抽取，如 `600MB–2.2GB`，带 60s 防震荡冷却锁） |
| `--workers <1\|N\|auto>` | `1` | 工作线程数；默认 `1` 为单线程模式，Linux 可选多核 `SO_REUSEPORT` |
| `--keepalive <SECS>` | `5` | RFC 7675 STUN Consent 保活间隔（自动加 `±20%` 抖动；无应答时按 RFC 5389 §7.2.1 同 `txid` 重传 2 次，约 `4.7s` 确认黑洞并自动换口） |
| `--idle-timeout <SECS>` | `120` | 空闲超时后发送加密 `SRTCP BYE` + DTLS `close_notify` 优雅退出 |
| `--max-sessions <N>` | `4096` | 单 worker 最大并发 UDP 会话数 |
| `--mtu <BYTES>` | `1488` | 外层 IPv4 WAN MTU 上限（默认 `1488 < 1492` PPPoE，自动引导内层 QUIC/Hysteria 2 收敛至零分片；`0` 表示不限制） |
| `--status-file <PATH>` | 关闭 | 可选外层健康状态原子 JSON 快照文件（经临时文件 `rename` 原子落盘，支持 `/tmp` 内存盘零闪存磨损，供外部脚本/内层协议自适应读取） |
| `--status-http <IP:PORT>` | 关闭 | 可选本地只读 HTTP 遥测端点（推荐 `127.0.0.1:PORT`；提供 `/status` / `/health` JSON、`/healthz` 探活与 `/metrics` Prometheus 指标） |
| `--status-interval <SECS>` | `5` | 外层健康遥测快照刷新周期（`1..=60s`；发生黑洞/迁移/轮换等关键事件时额外即时刷新） |

### 5. 内置自测套件与基准诊断

`webrtc-cloak selftest` 提供**真实线上隧道直测**、**双端临时隧道压测**与**本地离线故障注入沙箱**三种诊断方式：

#### 方式 A：直测已运行的线上隧道（推荐，零停服、不干扰现有业务）

```bash
# 直连已部署好的线上 webrtc-cloak server，实测真实公网链路 + 线上防探测 + 本机 CPU 算力（约 3–6 秒）
./webrtc-cloak selftest \
  --server-host 203.0.113.10 \
  --server-port 19643 \
  --psk-file /tmp/webrtc-cloak.psk

# 自定义探测次数 / 跳过主动攻击探针 / 指定套件或输出 JSON
./webrtc-cloak selftest --server-host 203.0.113.10 --server-port 19643 --psk-file /tmp/webrtc-cloak.psk --count 30
./webrtc-cloak selftest --server-host 203.0.113.10 --server-port 19643 --psk-file /tmp/webrtc-cloak.psk --no-probe --json
```

> [!NOTE]
> - 线上模式会从临时本地端口建立独立测试会话并在结束时发送 `SRTCP BYE + DTLS close_notify` 优雅拆除，**绝不干扰线上正在运行的 Hysteria 2 / QUIC 业务会话**。
> - 当远端服务端为 **`v0.3.5+`** 时，服务端支持加密带内 `0xFFFE` SRTP 诊断回显（严格处于 Ready + Hybrid PFS AEAD 密文内部，线上报文与正常 Chrome `0x90` SRTP 100% 一致，且**永不转发给后端服务**），可直接实测真实公网 SRTP 丢包/乱序与端到端 Path MTU；当远端仍为旧版 `v0.3.4` 时，这两项自动标记 `[SKIP]`，其余 10 项仍完整执行。

| 编号 | 线上直测场景 | 实测内容与运维价值 |
| :---: | :--- | :--- |
| `#01` | **WAN ICE STUN & NAT Mapping** | 实测真实公网 STUN RTT 与运营商分配的外网 `IP:Port`（`XOR-MAPPED-ADDRESS`） |
| `#02` | **WAN DTLS Mutual-Cert HS** | 真实公网 DTLS 1.3/1.2 自动协商双向证书握手耗时、实际协议版本、双 SSRC 状态与加密套件 |
| `#03` | **WAN Consent RTT/Jitter/Loss** | 连续 `N` 次 RFC 7675 STUN 保活探测，统计真实公网 P50/P95 RTT、抖动与丢包率 |
| `#04` | **WAN STUN Retransmit Cache** | 验证线上服务端 `SeenTxidCache` 同 `txid` 幂等缓存重传正常 |
| `#05` | **WAN Server SRTCP Heartbeat** | 校验服务端穿透公网 NAT 下发的 AEAD `Compound SRTCP` 心跳 |
| `#06` | **WAN SRTP Data-Plane Echo** | 发送 `30 × 1200B` 加密带内 SRTP 探针，测真实公网数据面 RTT、丢包、乱序与封装开销（需服务端 `v0.3.5+`） |
| `#07` | **WAN Path MTU Anti-Frag Probe** | 梯度探测 `1000..1422B` 公网实通极限与 `1452B` 本地防分片拦截，定位真实 PPPoE / CGNAT MTU（需服务端 `v0.3.5+`） |
| `#08` | **WAN 5-Tuple Rotate & NAT** | 开启第二端口完成新握手，验证黑洞换口可用性并识别运营商 NAT 端口映射行为 |
| `#09` | **WAN Active Probe Silent-Drop** | 并行发送 7 类恶意探针直击线上端口，验真公网严格 **0 字节静默丢弃** 且正常会话不受干扰 |
| `#10` | **Graceful Teardown (BYE/Close)** | 发送加密 `SRTCP BYE + DTLS close_notify` 清理测试会话，零僵尸残留 |
| `#11` | **CPU Single-Core Crypto Bench** | 本机单核全三套密码（`AES-128-GCM` / `ChaCha20-Poly1305` / `BLAKE2b-128`）加解密往返吞吐 |
| `#12` | **CPU Multi-Core & P-256 Certs** | 本机全核并发加密算力天花板（Gbps）+ DTLS 临时 ECDSA P-256 证书签发速率（`certs/s`） |

#### 方式 B：双端临时启动独立测试隧道（公网极限带宽压测）

如需对公网链路做大流量满载吞吐压测，可在远端临时起一对独立端口的 `sink` + `server`，测完即停，完全隔离线上业务：

```bash
# 1) 远端 VPS 临时启动接收端与独立测试服务端
./webrtc-cloak sink 127.0.0.1:19799
./webrtc-cloak server --listen-host 0.0.0.0 --listen-port 19699 --backend-host 127.0.0.1 --backend-port 19799 --psk-file /tmp/webrtc-cloak.psk

# 2) 本地启动临时客户端并压测（50000 包 × 1200B，限速 100 Mbps，4 并发流）
./webrtc-cloak client --listen-host 127.0.0.1 --listen-port 19599 --server-host 203.0.113.10 --server-port 19699 --psk-file /tmp/webrtc-cloak.psk
./webrtc-cloak loadgen 127.0.0.1:19599 50000 1200 100 100 4
```

#### 方式 C：本地离线故障注入沙箱与微基准（开发 / CI 验证）

```bash
# 本地 12 项弱网故障注入沙箱（模拟单向上行黑洞、服务端重启、35% 乱序 + 30% 重放、8% 双向丢包等不可在线上直接触发的故障）
./webrtc-cloak selftest --local
./webrtc-cloak selftest --local --no-color
./webrtc-cloak selftest --local --json

# 查看本机硬件指令集与推荐加密套件 / 运行纯加解密微基准
./webrtc-cloak cpu
./webrtc-cloak bench 50000 1260 all
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
