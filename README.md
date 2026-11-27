# WebRTC-Cloak (`webrtc-cloak-rs`)

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
[![Rust](https://img.shields.io/badge/Rust-Pure%20Rust%20%7C%20Zero%20C%20Deps-orange.svg)](#从源码构建与目录结构)
[![Protocol Spec](https://img.shields.io/badge/Protocol%20Spec-V4.0%20%7C%20v0.6.0-6366f1.svg)](./SPEC.md)
[![Interactive Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-0ea5e9.svg)](https://mumu-dada.github.io/webrtc-cloak/)
[![Release](https://img.shields.io/github/v/release/MUMU-DADA/webrtc-cloak?color=10b981)](https://github.com/MUMU-DADA/webrtc-cloak/releases)

> 快捷导航：[协议架构与五大模式](#协议架构与核心特性) · [全架构 SIMD 加速](#全架构指令集simd加速矩阵) · [实测数据与图表](#实测数据与效果对比) · [快速上手](#快速上手) · [自测诊断](#内置自测套件与基准诊断) · [源码构建](#从源码构建与目录结构) · [协议规范 (`SPEC.md`)](./SPEC.md)

一个**纯 Rust、零 C 依赖**的 WebRTC 单端口协议复用与透明 UDP 封装实验原型。基于标准 RFC 规范（RFC 5389 / 8445 / 7675 / 9147 / 6347 / 5764 / 7983 / 3711 / 7714 / 8285 / 3550 / 7587），完整实现 `ICE STUN + 真双向加密证书 DTLS 1.3/1.2 + 音视频双 SSRC SRTP/SRTCP` 传输层框架，覆盖**正向封装 (`client`/`server`)、单进程零回环原生中继 (`relay`)、零入站端口原生反向隧道 (`reverse`) 与带外优车道旁路直通 (`bypass`)** 全套模式，用于研究现代协议识别（DPI）、UDP 状态化防火墙/CGNAT 黑洞自愈、ECMP 多路径优选、前向安全混合密钥派生以及高性能无锁 `mio` 事件循环架构。

> [!TIP]
> - **在线交互式原理演示**：👉 **[https://mumu-dada.github.io/webrtc-cloak/](https://mumu-dada.github.io/webrtc-cloak/)**（6 种对抗与自愈推演、字节级报文解剖、双 SSRC / PPPoE MTU 1488 模拟，亦可离线打开 [`webrtc-cloak-demo.html`](./webrtc-cloak-demo.html)）
> - **协议规范文档（线格式 / 密钥派生 / 状态机 / 全部模式与 SIMD）**：👉 **[`SPEC.md`](./SPEC.md)**（`V4.0 / v0.6.0`）
> - **全平台预编译下载（16 架构）**：👉 **[GitHub Releases](https://github.com/MUMU-DADA/webrtc-cloak/releases/latest)**（Linux 11 架构静态 musl、macOS ARM64/x86_64、Windows x86_64/ARM64/i686 与 `SHA256SUMS.txt`）

---

## 免责声明

> [!CAUTION]
> **本项目仅用于网络协议学习、学术研究、RFC 规范实现验证及授权环境下的网络传输实验。**
>
> 1. 本仓库中的源码、文档、演示页面及预编译产物均以学习与研究为唯一目的提供，**严禁用于任何违反您所在国家或地区法律法规、网络服务条款或未经授权的网络渗透、规避监管等行为**。
> 2. 使用者须自行评估并承担使用本项目所产生的一切法律与合规责任。项目作者与贡献者不对任何因使用或滥用本软件造成的直接、间接、附带或衍生损失承担任何责任。
> 3. 若您不同意上述条款，请立即停止下载、编译、分发或使用本项目。

---

## 协议架构与核心特性

### 运行模式全景

`webrtc-cloak` 单一静态二进制内置四类传输模式与内置诊断工具，按实际链路拓扑自由组合：

| 模式 | 子命令 | 适用场景与核心特性 |
| :--- | :--- | :--- |
| **正向加密隧道** | `client` ↔ `server` | 标准点对点透明 UDP 封装（STUN + DTLS 1.3/1.2 + 双 SSRC SRTP/SRTCP），支持 MBB `0xFFFC` 0 丢包轮换、1-RTT `0xFFFD` 黑洞迁移与 `--lane-hunt` 优车道 |
| **原生零回环中继** | `relay` (`--upstream-mode bypass\|cloak`) | **单进程单线程 `mio::Poll`** 融合入站 `ServerWorker` 与出站 `Bypass`/`Client`，彻底消除本地回环 socket 与双进程切换；支持 `bypass`（裸 UDP + 带外 STUN ECMP 优选）与 `cloak`（双段加密双 PSK）双形态 |
| **原生反向隧道** | `reverse --entry` ↔ `reverse --agent` | 类反向 WireGuard：**内网/NAT 侧零公网入站端口**，Agent 主动外拨 Entry 建立 24×7 常驻加密隧道；单隧道内借密文 `0xFFFB` 帧按 `flow_id: u32` 复用任意多条 L4 UDP 业务流，Agent 侧按流固定本地源端口，继承 MBB / 1-RTT / `--lane-hunt` |
| **旁路优车道直通** | `bypass` / `bypass --responder` | 共享五元组带外认证 ICE STUN 抽卡/劣化切路/黑洞逃生 + 数据面 0 封装原始 UDP 透传（兼容内核 `UDP_SEGMENT` / GSO、零二次加密） |
| **自测与基准工具** | `selftest` / `cpu` / `bench` / `sink` / `loadgen` | 线上零干扰 12 项实网体检、本地离线故障注入沙箱、全密码后端/SIMD 诊断与吞吐压测 |

### 典型拓扑示意

```mermaid
flowchart LR
    subgraph FWD["1. 正向加密隧道 (client ↔ server)"]
        App1["本地 UDP 应用"] --> Cli["client"]
        Cli <-->|"RFC 7983 单端口 WebRTC"| Srv["server"]
        Srv --> Back1["后端 UDP 服务"]
    end

    subgraph RLY["2. 原生单进程零回环中继 (relay)"]
        Cli2["接入端 client"] <-->|"WebRTC Leg 1"| Relay["relay (单线程 mio, 零回环)"]
        Relay <-->|"bypass 直通 / cloak 加密 Leg 2"| Exit["上游出口 / server"]
    end

    subgraph REV["3. 原生反向隧道 (reverse: NAT 侧零入站端口)"]
        Peer["公网调用方 / WG Peer"] <-->|"--expose-port"| Entry["reverse --entry (公网)"]
        Agent["reverse --agent (NAT 内网)"] ==>|"主动外拨常驻 WebRTC 隧道 (0xFFFB 多流复用)"| Entry
        Agent <-->|"按 flow_id 固定源端口"| LocalSvc["内网本地 UDP 服务"]
    end
```

### RFC 7983 单端口四协议复用

两端在同一 UDP 五元组上严格按首字节分流，所有未通过鉴权或首字节异常的流量一律 **0 字节静默丢弃（Silent Drop）**：

| 首字节范围 | 协议层 | 核心能力 |
| :--- | :--- | :--- |
| `0..=3` | **ICE STUN** (RFC 5389 / 8445 / 7675) | 初始连通性检查、HMAC-SHA1 鉴权前零堆分配、±30s 防重放与 `5s ± 20%` Consent 保活 |
| `20..=63` | **DTLS 1.3 / 1.2 Auto** (RFC 9147 / 6347) | 嵌入式纯 Rust Sans-IO **`dimpl 0.9.0`**，默认 DTLS 1.3 优先（双向 ECDSA P-256 证书 100% 加密、省 1 RTT），兼容 1.2 滚动升级，支持 `--dtls-min-version 1.3` 锁定 |
| `128..=191` (`PT 64..95` 除外) | **双 SSRC SRTP** (RFC 3711 / 7714 / 8285) | 标准 `0x90` + 全局 `0xBEDE` TWCC 扩展；DTLS 1.3 自动启用 `PT=111` Opus（`≤50 pps`）+ `PT=96` Video 双流分流，密文内承载普通数据及 `0xFFFE`/`0xFFFD`/`0xFFFC`/`0xFFFB`/`0xFFFA` 控制与复用帧 |
| `128..=191` (`PT 64..95`) | **Compound SRTCP** (RFC 3550 / 7714) | 明文 `SR/RR` 头 + 加密复合 `SDES / FB / BYE`，支持严格零媒体语义与微流退避静音 |

### 核心工程亮点

- **Fail-Closed 混合前向安全（Hybrid PFS）**：由 `STUN 会话种子 + DTLS 出口密钥材料` 联合派生主密钥，Video / Audio / SRTCP 三域采用数学正交 Nonce 与独立滑动防重放窗口，序号逼近上限主动重连永不回绕。
- **V4.0 无感承载与弱网自愈（“换路不换门牌”）**：
  - **定时/定量无感轮换（MBB）**：按对数正态宽分布时长或字节预算发起全新 DTLS 1.3 握手（全新 `ufrag`/`SSRC`/`CNAME` 防关联），通过 AEAD 密文内 `0xFFFC` 原子过户服务端 `backend_sock`（支持跨 worker 无锁迁移、中继直连与反向隧道过户），有状态 UDP 后端 **0 端口变化、0 丢包**。
  - **单向上行黑洞 1-RTT 迁移**：经 RFC 7675 同 `txid` 重传确认黑洞后，客户端用每会话 HKDF 派生密钥在新端口 1-RTT 原地迁移（防反射挑战验真、0 DTLS 重握、保留后端源端口，旧口静默排空避免 ICMP 弹包）。
  - **优雅重启与微流静音**：服务端 `SIGTERM` 广播加密 `SRTCP BYE + close_notify`，客户端 `80–350ms` 抖动快切；空闲/微流态自动退避控制面报文，来包秒恢复。
- **原生单进程中继 (`relay`) 与反向隧道 (`reverse`)（`v0.6.0`）**：
  - `relay` 在单线程 `mio::Poll` 中直连入站与出站热路径，零本地回环、零额外拆包/锁开销，兼容独立上下游 PSK、独立加密套件与双段 MBB/1-RTT 自愈。
  - `reverse` 通过密文内 `0xFFFB`（`flow_id: u32` 多路复用）与 `0xFFFA`（`HELLO`/`HELLO_ACK`/`FLOW_CLOSE`）实现 NAT 后零入站端口服务暴露；常驻隧道免受数据静默断线（保留 45s 同意保活），Entry 在 Agent 上线或重连前自动缓存首包（64 包 / 3s TTL），实现 0-RTT 首包转发。
- **双栈 IPv6 与 ECMP 多维自适应优车道引擎（`v0.4.4`–`v0.5.0`）**：
  - 全链路原生支持 IPv4 / IPv6 双栈（`--listen-host` / `--server-host` / `--upstream-host` / `--expose-host` / `selftest`，遵循 RFC 5389 §15.2 IPv6 `XOR-MAPPED-ADDRESS` 与 48B IPv6+UDP 外层 MTU/DTLS 精确核算）。
  - `--lane-hunt` 通用多维自适应优车道引擎（**0 线格式改动，100% 兼容既有服务端**）：默认 `--lane-target-rtt 0` 纯自适应模式，冷启动自动跨轮（`≥ 2` 轮）寻找全局最低 RTT 建立跨地域基线；运行期融合**相对延迟倍率 + 双 SSRC SRTP 已稳定序号窗口真实数据面下行丢包（剥离 24 包乱序尾窗）+ STUN 同意丢包 + 抖动**输出 `0–100` 综合评分，配备 Canary 试用确认期、假优高丢包/限速信道 0ms MBB 原子过户逃逸（`0xFFFC`）、亚健康静默寻优、最优基线持续强化与温和松弛，并在定时轮换与 1-RTT 黑洞迁移阶段同样多候选竞速。
- **可选 Linux UDP 批量 I/O 与突发缓冲扩容（`v0.4.6`–`v0.4.7`）**：
  - 支持 `--udp-batch <0|2..64>`（默认 `0` 零额外内存分配；Linux 下设为如 `32` 时，全热路径启用零拷贝 `recvmmsg` / `sendmmsg` 批量收发，大幅降低系统调用与 KVM VM-exit/KPTI 开销；非 Linux 平台安全回退单包路径）。
  - 会话级后端 `backend_sock` 核缓冲上限 `4 MiB`、客户端上行 `up_sock` 上限 `8 MiB`，有效消除虚拟化调度抖动与多跳中继突发丢包（`RcvbufErrors`）。
- **PPPoE MTU 1488 防分片与零指纹响应**：默认 `--mtu 1488`（`< 1492B` PPPoE）自动按 IPv4/IPv6 报头开销引导内层 QUIC/Hysteria 2 收敛至零分片；主动探测与孤儿保活严格 0 字节静默丢弃。
- **解耦外层健康遥测（`v0.4.1+`）**：严格旁路于 SRTP 热路径，采用零外部依赖手写 RFC 8259 JSON 原子落盘（`--status-file`）与单线程事件驱动 `mio::Poll` 本地只读 HTTP / Prometheus 端点（`--status-http`，64 KiB 栈、空闲 0 唤醒，覆盖 `client` / `server` / `relay` / `reverse-entry` / `reverse-agent` / `bypass` 全角色）。
- **轻量极致性能**：默认 `--workers 1` 单线程无锁 `mio` 事件循环即可承载千级并发会话（静态 musl 二进制 `x86_64` 约 `2.0 MiB`、`aarch64` `1.6 MiB`、`macos-arm64` `1.5 MiB`；Unix 采用无锁 `sigaction` 自管道优雅退出，纯隧道常驻 **1 线程**、开启 HTTP 遥测 **2 线程**，macOS 实测 RSS `2.7–3.4 MiB`），Linux 多核按需支持 `--workers <N|auto>`。

> 📘 完整线格式字节布局、密钥派生公式、正交 Nonce 定义、中继/反向/旁路状态机与安全边界，请参阅 **[`SPEC.md`](./SPEC.md)**。

---

## 全架构指令集（SIMD）加速矩阵

`webrtc-cloak` 针对全部 16 个发布架构的密码学热路径做了逐 crate 审计与补丁加固（`v0.5.1`–`v0.6.0`）：
- **非 AVX x86/x86_64 硬件两级 `PCLMULQDQ`（[`patches/polyval`](./webrtc-cloak-rs/patches/polyval)）**：上游 `polyval` 仅在同时具备 `AVX + PCLMULQDQ` 时启用硬件 GHASH；补丁新增 Legacy SSE2 + `PCLMULQDQ` 二级运行时分发，使仅具 `AES-NI + PCLMULQDQ` 而无 `AVX` 的低功耗 x86 嵌入式/软路由 CPU 同样执行完整 4 块聚合硬件 GHASH。
- **全 64 位架构常时间 `radix-2^44` Poly1305（[`patches/poly1305`](./webrtc-cloak-rs/patches/poly1305)）**：上游 `poly1305` 除 `x86-avx2` 外全退化为 32 位 5-limb 实现（25 次乘法/块）；补丁在全部 64 位目标升级为常时间 `u64/u128` 3-limb `radix-2^44`（仅 9 次乘法/块），覆盖全部 `aarch64`（含无 AES 扩展而自动选 ChaCha20 的 ARMv8 路由器、树莓派与 Apple Silicon）、非 AVX2 `x86_64`、`riscv64`、`loongarch64`、`powerpc64le`。Apple Silicon 实测 `ChaCha20-Poly1305` 端到端 SRTP 加解密提升 **`+23.5%`（`3,261 → 4,027 Mbps`）**。
- **x86/x86_64 运行时 `AVX-512F+VL` ChaCha20（[`.cargo/config.toml`](./webrtc-cloak-rs/.cargo/config.toml)）**：启用 `chacha20_avx512` 运行时 CPUID 分发（16 块并行，无 AVX-512 自动回落 AVX2 → SSE2 → soft）。
- **真实后端探针与精准自动选型（`webrtc-cloak cpu`）**：补齐 `i686` 硬件检测，并由底层 crate 实际生效状态 `aes::hardware_accelerated() && polyval::hardware_accelerated()` 决定 `auto` 套件选择（杜绝仅看裸 CPUID 误选软件 AES-GCM 的问题，如 `windows-arm64` 自动安全回落至 NEON ChaCha20-Poly1305）；运行 `./webrtc-cloak cpu` 可直接核验当前机器每个密码学后端实际运行的指令集实现。

<details>
<summary>⚡ 展开查看 16 发布架构全密码学后端 SIMD 覆盖矩阵</summary>

| 目标平台 / CPU 类型 | `aes` (AES-128) | `polyval` (GHASH/GCM) | `chacha20` | `poly1305` | `sha1` / `sha2` | `--cipher auto` 选型 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **x86_64（现代 AVX2 / AVX-512）** | VAES-512 / VAES-256 / AES-NI | AVX+PCLMULQDQ | **AVX-512F+VL** / AVX2 / SSE2 | AVX2 | SHA-NI / AVX2 | `aes-128-gcm` |
| **x86_64（无 AVX 低功耗软路由/Atom）** | **AES-NI**（无 AVX 门控） | **SSE2+PCLMULQDQ**（补丁） | SSE2 | **radix44-u128**（补丁） | **SHA-NI**（无 AVX 门控） | `aes-128-gcm` |
| **i686（32 位 x86）** | **AES-NI** | **AVX / SSE2+PCLMULQDQ** | AVX-512 / AVX2 / SSE2 | AVX2 / radix26-u32 | SHA-NI / SSE4.1 | 有硬件走 AES-GCM，否则 ChaCha20 |
| **aarch64 Linux / macOS（含加密扩展）** | ARMv8 AES | ARMv8 PMULL (4-blk) | ARMv8 NEON | **radix44-u128**（补丁） | ARMv8 SHA2/SHA3 | `aes-128-gcm` |
| **aarch64 Linux（无 AES 扩展路由/板卡）** | soft | soft | ARMv8 NEON | **radix44-u128**（补丁） | soft | `chacha20-poly1305` |
| **aarch64 Windows** *(上游 `cpufeatures` 限制)* | soft | soft | ARMv8 NEON | **radix44-u128**（补丁） | soft | **安全回落 `chacha20-poly1305`** |
| **riscv64 / loongarch64 / powerpc64le** | soft | soft | soft | **radix44-u128**（补丁） | loongarch64 asm / soft | `chacha20-poly1305` |
| **armv7hf / armv7 / armhf / arm / armv5te** *(上游限制)* | soft | soft | soft | radix26-u32 | soft | `chacha20-poly1305` |

</details>

---

## 实测数据与效果对比

> 以下 5 组图表按 **「隐蔽抗探测 → 无感换口 → 弱网/黑洞自愈 → 带宽损耗 → 硬件算力」** 递进呈现，数据均来自实测采样。

### 1. 协议隐蔽性、双 SSRC 包长分布与抗探测验真

![协议隐蔽性与双 SSRC 包长分布实测](./docs/stealth-fingerprint-profile.svg)

### 2. V4.0「换路不换门牌」MBB 无感五元组轮换实测

![V4.0 MBB 无感轮换时序实测](./docs/mbb-zero-loss-rotation.svg)

### 3. 恶劣垃圾网络对抗与黑洞自愈曲线

![恶劣垃圾网络对抗与黑洞自愈实测曲线](./docs/trash-network-resilience.svg)

### 4. 带宽损耗与外层流量放大曲线

![带宽损耗与外层流量放大实测曲线](./docs/bandwidth-overhead.svg)

- **封装开销极低且恒定**：在 PPPoE `1492B` 环境下，`--mtu 1488` 自动引导内层 QUIC 收敛至 `1485B/包`（`0` IPv4 分片）；跨 `100M / 300M` 单流与 4 并发场景，纯 L3 额外字节开销稳定在 **`+2.80% ~ +2.86%`**，端到端有效吞吐损失约 `1.7% ~ 5.8%`。
- **自适应大包填充**：内层 `>= 1340B` 大包自动收窄随机填充（`0–7B`），单核回环实测净膨胀从 `1200B (+4.46%)` 降至 `1400B (+2.96%)`。

### 5. 多平台加解密算力、原生中继与反向隧道压测

![WebRTC-Cloak 性能基准跑分](./docs/benchmark-performance.svg)

#### 点对点基础算力与环回吞吐

| 测试平台 | 单核加解密微基准 (`AES-128-GCM` / `ChaCha20`) | 端到端全隧道环回吞吐 | 真双向 DTLS 1.3 / 1.2 握手 | 运行内存 (RSS) |
| :--- | :---: | :---: | :---: | :---: |
| **Apple Silicon (ARM64, 12C)** | `18,101–18,720 Mbps` / **`4,027 Mbps`** | `1,581–2,240 Mbps` (`165–222 kpps`) | `1.5–11.8 ms` | `2.7–3.4 MiB` (`1–2` 线程) |
| **x86_64 云服务器（单核 `1W`）** | `3,228.6 Mbps` (`320.3 kpps`) | `1,124.2 Mbps` (`111.5 kpps`) | `3.01 ms` | `2.1–2.8 MB` |
| **x86_64 低功耗软路由（单核 `1W`）** | `2,139.8 Mbps` (`212.3 kpps`) | `900.0 Mbps` (`0.00%` 丢包，p50 `50 µs`) | `6.85–9.02 ms` | `2.1–2.8 MB` |
| **x86_64 低功耗软路由（多核 `4W / 8S`）** | — | `1,448.7 Mbps` (`0.00%` 丢包，`143.7 kpps`) | `6.85–9.12 ms` | `2.5–2.8 MB` |

#### 原生单进程中继 (`relay`) vs 传统双进程回环 A/B 对比（Apple Silicon Release，1260B）

| 对比场景 | 吞吐变化 (`goodput`) | 中继侧总 CPU | 上下文切换 (`csw`) | 峰值内存 (`RSS`) |
| :--- | :---: | :---: | :---: | :---: |
| **`relay --upstream-mode bypass`（400 Mbps 稳态）** | `400.0 Mbps` (`0.00%` 丢包) | **`-29.1%`** | **`-68.4%`** | **`-42.1%`** |
| **`relay --upstream-mode bypass`（无节流峰值）** | **`2,251 Mbps (+16.8%)`** | **`-52.4%`** | — | — |
| **`relay --upstream-mode cloak`（400 Mbps 稳态）** | `400.0 Mbps` (`0.00%` 丢包) | **`-39.3%`** | **`-78.7%`** | **`-43.8%`** |
| **`relay --upstream-mode cloak`（无节流峰值）** | **`1,885 Mbps (+20.3%)`** | **`-58.7%`** | — | — |

#### 原生反向隧道 (`reverse`) 实测表现（Apple Silicon Release，1260B）

| 场景 | 首包延迟 (`hs`) | 丢包率 | 有效吞吐 (`goodput`) | 双端总 CPU | 双端合计 RSS |
| :--- | :---: | :---: | :---: | :---: | :---: |
| 正向基线 400 Mbps 稳态（100k） | `3.87 ms` | `0.00%` | `400.0 Mbps` | `1435.9 ms` | `6.72 MiB` |
| **反向隧道 400 Mbps 稳态（1 流）** | **`0.47 ms`** (0-RTT) | **`0.00%`** | **`400.0 Mbps`** | **`1437.9 ms`** | `6.77 MiB` |
| **反向隧道 400 Mbps（4 并发流复用 1 隧道）** | — | **`0.00%`** | **`400.4 Mbps`** | **`1363.3 ms`** | `6.77 MiB` |
| **反向隧道无节流峰值（AES-128-GCM）** | **`0.54 ms`** | — | **`1,833.9 Mbps`** (`181.9 kpps`) | `633.7 ms` | `6.77 MiB` |
| **反向隧道无节流峰值（ChaCha20-Poly1305）** | **`0.33 ms`** | — | **`1,442.9 Mbps`** (`143.1 kpps`) | `660.6 ms` | `6.75 MiB` |

> 微基准测试 `1200–1260B` 载荷单次 `wrap + unwrap` 往返吞吐；依赖统一至 RustCrypto `0.11`/`0.14` 代际并启用 `fat LTO` + 混合 `-O3/-Os` 优化以及 64 位 `radix-2^44` Poly1305 补丁后，Apple Silicon 同机实测 `AES-128-GCM` `18,101–18,720 Mbps`（12 核 `127.4 Gbps`）、`ChaCha20-Poly1305` `4,027.4 Mbps`、`BLAKE2b-128` `1,293.9 Mbps`，纯 Rust ECDSA P-256 临时证书签发速率 `13,005 certs/s`（上方历史基准 SVG 图表基于早期 `v0.4.2` 采样）。

### 综合对抗与工程边界总览

| 对抗 / 故障场景 | 裸 UDP / 早期版本 | **WebRTC-Cloak V4.0 (`v0.6.0`)** |
| :--- | :--- | :--- |
| **严苛 NAT 5 包截断 & 主动探测** | 裸 UDP/QUIC 第 6 包起截断 | ICE STUN 握手后 `100%` 放行；双 SSRC 将 7 类固定包长展宽为 `168` 种长度；主动探测 `0 B` 静默丢弃 |
| **定时 / 定量五元组轮换 (MBB)** | 固定五元组易关联；硬重连断流 | **4 次全新 DTLS 1.3 换口 + `0xFFFC` 密文过户**：`33,280 / 33,280` 实收（`0.00%` 丢包、`0 ms` 卡顿、后端 `0` 换口） |
| **0%–10% 丢包 / 乱序弱网 (P1–P5)** | BBR 随丢包迅速降窗 | `Cloak + BBR` 紧贴直连曲线（TTFB P50 差 `< 2 ms`）；内层切温和 Brutal 在 `1%–15%` 丢包下仍稳跑 `20–55 Mbps` |
| **P8 单向上行黑洞 (`t=3.5s` 断上行)** | 裸 HY2 永久死锁在 `0 Mbps` | `t=8.7s`（约 `5.2s`）自动换口满血恢复至 `18.9 Mbps`，内层零断流、后端源端口零变更 |
| **跨洋 DTLS 握手 & 滚动重启** | DTLS 1.2 `853 ms`（明文证书）；重启冷超时 `15–45s` | **DTLS 1.3 `667 ms`**（省 1 RTT、证书 100% 加密）；`SIGTERM` 广播 `SRTCP BYE` **`0.23 s`** 优雅快切 |
| **NAT 后无公网 IP / 多跳中继场景** | 需双进程本地回环或额外部署反向隧道软件 | 单二进制原生提供零回环 `relay`（CPU `-29% ~ -59%`）与零入站端口 `reverse`（0-RTT 首包、多流固定源端口复用） |

> [!NOTE]
> **工程定位与适用边界**：本项目是面向 Hysteria 2 / QUIC / WireGuard 等上层协议的透明 UDP 传输外壳，非通用 TCP/TUN VPN；内层业务机密性仍由上层协议独立保障。持续突发连丢 `>= 15%`（P6–P7）会显著拉长双层冷启动握手，且无法绕过彻底禁止 100% UDP 出口的网络策略。

---

## 快速上手

> 实验部署示例：从 **[GitHub Releases](https://github.com/MUMU-DADA/webrtc-cloak/releases/latest)** 下载对应平台/架构的预编译压缩包，解压得到 `webrtc-cloak`（或 `webrtc-cloak.exe`）。

### 1. 生成共享密钥文件

```bash
openssl rand -base64 32 > /tmp/webrtc-cloak.psk
chmod 600 /tmp/webrtc-cloak.psk
```

### 2. 按需选择部署模式

#### 模式 A：正向加密封装（`server` + `client`）

```bash
# 服务端：默认单线程 (--workers 1)、--cipher auto、--mtu 1488
./webrtc-cloak server \
  --listen-host 0.0.0.0 --listen-port 19643 \
  --backend-host 127.0.0.1 --backend-port 19760 \
  --psk-file /tmp/webrtc-cloak.psk

# 客户端（也支持环境变量 WEBRTC_CLOAK_PSK="..." 传入密钥；可选 --lane-hunt）
./webrtc-cloak client \
  --listen-host 127.0.0.1 --listen-port 19543 \
  --server-host 203.0.113.10 --server-port 19643 \
  --psk-file /tmp/webrtc-cloak.psk --lane-hunt
```

#### 模式 B：原生单进程零回环中继（`relay`）

```bash
# B1. 入站 WebRTC 终止 + 出站 bypass 原始 UDP 优车道直通（省二次加解密与本地回环）
./webrtc-cloak relay \
  --listen-host 0.0.0.0 --listen-port 19643 \
  --upstream-mode bypass \
  --upstream-host 198.51.100.20 --upstream-port 19643 \
  --psk-file /tmp/leg1.psk --upstream-psk-file /tmp/leg2.psk \
  --udp-batch 32

# B2. 入站 WebRTC + 出站 WebRTC 双段独立加密中继（零本地回环）
./webrtc-cloak relay \
  --listen-host 0.0.0.0 --listen-port 19643 \
  --upstream-mode cloak \
  --upstream-host 198.51.100.20 --upstream-port 19643 \
  --psk-file /tmp/leg1.psk --upstream-psk-file /tmp/leg2.psk \
  --lane-hunt --udp-batch 32
```

#### 模式 C：原生反向隧道（`reverse --entry` + `reverse --agent`，NAT 侧零入站端口）

```bash
# 公网入口端（Entry）：监听 WebRTC 隧道端口 19643，并将内网 UDP 服务暴露在 51820
./webrtc-cloak reverse --entry \
  --listen-host 0.0.0.0 --listen-port 19643 \
  --expose-host 0.0.0.0 --expose-port 51820 \
  --psk-file /tmp/webrtc-cloak.psk --dtls-min-version 1.3

# 内网/NAT 出口端（Agent）：零公网入站端口，主动外拨 Entry 并转发到本地 127.0.0.1:51820
./webrtc-cloak reverse --agent \
  --server-host 203.0.113.10 --server-port 19643 \
  --backend-host 127.0.0.1 --backend-port 51820 \
  --psk-file /tmp/webrtc-cloak.psk --dtls-min-version 1.3 --lane-hunt
```

#### 模式 D：一级旁路优车道直通（`bypass` + `bypass --responder`）

```bash
# 远端超轻量 STUN 应答器（与业务 UDP 服务同机或同五元组）
./webrtc-cloak bypass --responder \
  --listen-host 0.0.0.0 --listen-port 19643 \
  --psk-file /tmp/webrtc-cloak.psk

# 入口侧旁路转发器（带外认证 STUN ECMP 抽卡/劣化切路/黑洞自愈 + 数据面零封装原始 UDP 直通）
./webrtc-cloak bypass \
  --listen-host 127.0.0.1 --listen-port 19543 \
  --server-host 203.0.113.10 --server-port 19643 \
  --psk-file /tmp/webrtc-cloak.psk
```

### 3. 主要命令行参数

| 参数 | 默认值 | 说明 |
| :--- | :---: | :--- |
| `--psk-file <PATH>` / `WEBRTC_CLOAK_PSK` / `--psk <KEY>` | 必填其一 | 预置共享密钥（推荐文件或环境变量，避免进程列表泄露） |
| `--cipher <auto\|aes-gcm\|chacha20\|blake2b>` | `auto` | 加密套件；`auto` 依据两端真实硬件加速能力经 DTLS 握手自动协商 |
| `--dtls-min-version <auto\|1.2\|1.3>` | `auto` | DTLS 最低版本；默认优先 1.3 兼容 1.2 滚动升级，双端升完可设为 `1.3` 防降级 |
| `--upstream-mode <bypass\|cloak>` *(仅 `relay`)* | `bypass` | 中继出站形态：`bypass`（带外 STUN 优车道 + 原始 UDP 直通）或 `cloak`（完整二段 WebRTC 加密） |
| `--upstream-host` / `--upstream-port` *(仅 `relay`)* | 必填 | 中继上游目标地址（支持 IPv4 / IPv6）与端口 |
| `--upstream-psk[-file]` / `WEBRTC_CLOAK_UPSTREAM_PSK` *(仅 `relay`)* | 同入站 PSK | 可选独立上游 PSK；另支持 `--upstream-cipher`、`--upstream-dtls-min-version` |
| `--entry` / `--agent` *(仅 `reverse`)* | 二选一必填 | 反向隧道角色：公网入口端 (`--entry` + `--expose-host`/`--expose-port`) 或 NAT 内网出口端 (`--agent` + `--server-host`/`--backend-port`) |
| `--lane-hunt` / `--no-lane-hunt` | `bypass` 默认开，其余默认关 | 非阻塞 ECMP 多维自适应优车道引擎（冷启动多轮校准 + 数据面丢包/RTT/抖动综合评分与 Canary 确认 + 后台 0ms MBB 寻优逃逸 + 轮换/黑洞迁移竞速） |
| `--lane-probes <2..=8>` / `--lane-rounds <1..=6>` | `4` / `3` | 单轮并发 STUN 候选探测口数量与最大多轮探测次数 |
| `--lane-target-rtt <MS>` / `--lane-cooldown <5..=3600>` | `0`（纯自适应）/ `60s` | 可选显式 RTT 上限（`0` 自动按冷启动最低延迟建基线并动态强化/松弛）与劣化寻优冷却秒数 |
| `--rotate-interval <SECS>` / `--rotate-bytes <MB>` | `0` / 随轮换启 `1200` | 定时（对数正态 `[0.35x, 2.80x]`）与单流字节预算（`[0.50x, 1.85x]`）MBB 无感五元组轮换 |
| `--udp-batch <0\|2..64>` | `0`（关闭） | Linux 可选 `recvmmsg/sendmmsg` 批量 UDP 收发批大小（如 `32`）；非 Linux 自动回退单包 I/O |
| `--workers <1\|N\|auto>` | `1` | 工作线程数；默认 `1` 单线程，Linux 可选多核 `SO_REUSEPORT`（`reverse` 自动锁定为 `1` 以保证流固定源端口） |
| `--keepalive <SECS>` | `5` | RFC 7675 STUN Consent 保活间隔（`±20%` 抖动；连续 3 次无应答自动触发 1-RTT 黑洞迁移） |
| `--idle-timeout <SECS>` | `120` | 空闲超时后优雅拆除会话（`reverse` 常驻隧道免疫数据静默超时，流表按此值回收并发送 `REV_OP_FLOW_CLOSE`） |
| `--max-sessions <N>` | `4096` | 单 worker 最大并发 UDP 会话数（`reverse` 中对应最大并发复用流数） |
| `--mtu <BYTES>` | `1488` | 外层 IPv4/IPv6 WAN MTU 上限（适配 `1492B` PPPoE 零分片；`0` 表示不限制） |
| `--status-file <PATH>` / `--status-http <IP:PORT>` | 关闭 | 外层健康快照原子 JSON 落盘路径与本地只读 HTTP / Prometheus 端点（`/status` `/health` `/healthz` `/metrics`） |
| `--status-interval <SECS>` | `5` | 遥测快照刷新周期（`1..=60s`；黑洞/迁移/轮换事件即时刷新） |

---

## 内置自测套件与基准诊断

`webrtc-cloak` 内置三种诊断工具，覆盖**线上零干扰体检**、**公网满载压测**与**本地离线故障注入**：

```bash
# 方式 A：直测已运行的线上隧道（独立临时会话 + 带内 0xFFFE 探针，零干扰线上业务，约 3–6 秒）
./webrtc-cloak selftest --server-host 203.0.113.10 --server-port 19643 --psk-file /tmp/webrtc-cloak.psk
./webrtc-cloak selftest --server-host 203.0.113.10 --server-port 19643 --psk-file /tmp/webrtc-cloak.psk --count 30 --no-probe --json

# 方式 B：双端临时独立端口极限带宽压测（服务端先起 sink + server，客户端连入后运行 loadgen）
./webrtc-cloak sink 127.0.0.1:19799
./webrtc-cloak loadgen 127.0.0.1:19599 50000 1200 100 100 4

# 方式 C：本地离线 12 项故障注入沙箱 + 真实密码后端 SIMD 诊断与三套件基准
./webrtc-cloak selftest --local
./webrtc-cloak cpu
./webrtc-cloak bench 50000 1260 all
```

<details>
<summary>📋 展开查看 12 项线上直测场景明细 (#01–#12)</summary>

| 编号 | 线上直测场景 | 实测内容与运维价值 |
| :---: | :--- | :--- |
| `#01` | **WAN ICE STUN & NAT Mapping** | 实测真实公网 STUN RTT 与外网 `IP:Port`（`XOR-MAPPED-ADDRESS`） |
| `#02` | **WAN DTLS Mutual-Cert HS** | 真实公网 DTLS 1.3/1.2 自动协商握手耗时、协议版本、双 SSRC 状态与加密套件 |
| `#03` | **WAN Consent RTT/Jitter/Loss** | 连续 `N` 次 RFC 7675 STUN 保活探测，统计 P50/P95 RTT、抖动与丢包率 |
| `#04` | **WAN STUN Retransmit Cache** | 验证线上服务端 `SeenTxidCache` 同 `txid` 幂等重传缓存 |
| `#05` | **WAN Server SRTCP Heartbeat** | 校验服务端穿透公网 NAT 下发的 AEAD `Compound SRTCP` 心跳 |
| `#06` | **WAN SRTP Data-Plane Echo** | 发送 `30 × 1200B` 加密带内 `0xFFFE` 探针，测数据面 RTT、丢包、乱序与封装开销（服务端 `v0.3.5+`，永不转发给后端） |
| `#07` | **WAN Path MTU Anti-Frag Probe** | 梯度探测 `1000..1422B` 公网实通极限与 `1452B` 本地防分片拦截（服务端 `v0.3.5+`） |
| `#08` | **WAN 5-Tuple Rotate & NAT** | 开启第二端口完成新握手，验证换口可用性并识别 NAT 端口映射行为 |
| `#09` | **WAN Active Probe Silent-Drop** | 并行发送 7 类恶意探针直击线上端口，验真 **0 字节静默丢弃** 且正常会话不受影响 |
| `#10` | **Graceful Teardown (BYE/Close)** | 发送加密 `SRTCP BYE + DTLS close_notify` 优雅拆除测试会话，零僵尸残留 |
| `#11` | **CPU Single-Core Crypto Bench** | 本机单核全三套密码（`AES-128-GCM` / `ChaCha20-Poly1305` / `BLAKE2b-128`）加解密吞吐 |
| `#12` | **CPU Multi-Core & P-256 Certs** | 本机全核并发加密算力天花板（Gbps）+ 临时 ECDSA P-256 证书签发速率（`certs/s`） |

</details>

---

## 从源码构建与目录结构

```bash
cd webrtc-cloak-rs
cargo test --all-targets                                          # 39 项协议不变式、中继、反向隧道与安全回归测试
cargo build --release                                             # 编译本机 Release 版本
rustup target add x86_64-unknown-linux-musl                       # 可选：交叉编译 Linux 静态 musl
cargo build --release --target x86_64-unknown-linux-musl
```

> 注：macOS 默认 `ulimit -n` 为 `256`，并发运行 39 项网络集成测试前建议先执行 `ulimit -n 4096`。

```text
.
├── .github/workflows/                     # CI 门禁 + 16 架构 Release 自动发布 + GitHub Pages 部署
├── docs/
│   ├── stealth-fingerprint-profile.svg    # 1. 双 SSRC 包长分布与抗探测特征图
│   ├── mbb-zero-loss-rotation.svg         # 2. V4.0 MBB 无感轮换时序折线图
│   ├── trash-network-resilience.svg       # 3. 恶劣弱网对抗与黑洞自愈折线图
│   ├── bandwidth-overhead.svg             # 4. 带宽损耗与外层流量放大折线图
│   └── benchmark-performance.svg          # 5. 多平台加解密算力与全隧道环回跑分图
├── README.md                              # 项目说明、全模式指南、SIMD 矩阵与实测对比
├── SPEC.md                                # V4.0 / v0.6.0 线格式、密码学、全模式与状态机协议规范
├── webrtc-cloak-demo.html                 # 交互式协议原理演示页（离线 / GitHub Pages）
├── LICENSE                                # MIT 开源许可证
└── webrtc-cloak-rs/                       # 纯 Rust 源码工程（零 C 外部库依赖 / 零 OpenSSL）
    ├── .cargo/config.toml                 # 跨架构静态 musl / AVX-512 ChaCha20 运行时开关
    ├── Cargo.toml
    ├── patches/
    │   ├── polyval/                       # x86 两级 PCLMULQDQ (AVX + Legacy SSE2) 与真实后端探针补丁
    │   └── poly1305/                      # 全 64 位架构常时间 radix-2^44 (u64/u128) Poly1305 补丁
    └── src/
        ├── main.rs                        # CLI 参数解析 (pico-args) 与全子命令分发
        ├── constants.rs                   # 跨模块共享的协议契约、帧魔数、缓冲与双端耦合时序常量
        ├── bench_tools.rs                 # cpu (真实 SIMD 后端) / bench / sink / loadgen 诊断工具
        ├── protocol/                      # STUN / dimpl DTLS 1.3+1.2 / X.509 / 双 SSRC SRTP / SRTCP
        ├── client/                        # 客户端 mio 循环、1-RTT 黑洞迁移、MBB 状态机、ECMP 优车道与测试
        ├── server/                        # 服务端 mio 循环、防重放、跨 worker 注册表与 Silent Drop
        ├── relay/                         # 原生单进程零回环中继模式 (bypass / cloak 双出站) 与测试
        ├── reverse/                       # 原生反向隧道模式 (entry / agent, 0xFFFB/0xFFFA 多流复用) 与测试
        ├── bypass/                        # 一级旁路直通模式（带外 STUN ECMP 抽卡 + 原始 UDP 零损耗透传）
        ├── udp_batch.rs                   # 可选 Linux recvmmsg/sendmmsg 批量收发引擎 (--udp-batch)
        ├── selftest/                      # 线上直测 + 本地离线 12 项自测、劣化代理与报告渲染
        └── telemetry/                     # 外层链路健康只读遥测（原子 JSON / HTTP / Prometheus）
```

---

## 开源协议

本项目基于 **[MIT License](./LICENSE)** 开源发布。
