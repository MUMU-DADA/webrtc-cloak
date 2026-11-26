//! 跨模块共享的协议契约、网络缓冲规格与双端耦合时序常量。

use mio::Token;
use std::time::Duration;

// ============================================================================
// 1. 网络 MTU、UDP 边界、套接字缓冲与事件循环规格
// ============================================================================

/// IPv4 (20B) + UDP (8B) 固定外层包头总长度（字节）。
pub const IPV4_UDP_HDR_LEN: usize = 28;
/// 默认外层 IPv4 WAN MTU 上限（< 1492B PPPoE，避免公网分片并引导内层 QUIC DPLPMTUD 收敛）。
pub const DEFAULT_WAN_MTU: usize = 1488;
/// 启用 WAN MTU 限制时外层 UDP 负载的最小安全下限（RFC 791 IPv4 最小重组 MTU）。
pub const MIN_WIRE_UDP_MTU: usize = 576;
/// 允许封装的内层 UDP 报文硬上限（字节），确保加头、填充和认证标签后不溢出写缓冲。
pub const MAX_INNER_UDP_LEN: usize = 65_400;
/// 通用 UDP 接收缓冲区大小（字节，用于 `--mtu 0` 大包或压测）。
pub const UDP_RECV_BUF_LEN: usize = 65_536;
/// 按外层 WAN MTU 计算单 worker UDP 收包缓冲长度（`wan_mtu > 0` 时无需预留 64 KiB，省 ~124 KiB/worker）。
pub const fn worker_udp_recv_buf_len(wan_mtu: usize) -> usize {
    if wan_mtu == 0 {
        UDP_RECV_BUF_LEN
    } else {
        let base = if wan_mtu > PROBE_IO_BUF_LEN {
            wan_mtu
        } else {
            PROBE_IO_BUF_LEN
        };
        let len = base + 256;
        if len > UDP_RECV_BUF_LEN {
            UDP_RECV_BUF_LEN
        } else {
            len
        }
    }
}
/// 按外层 WAN MTU 计算单 worker UDP 封装写缓冲长度。
pub const fn worker_udp_write_buf_len(wan_mtu: usize) -> usize {
    worker_udp_recv_buf_len(wan_mtu) + 128
}
/// DTLS 记录收发临时缓冲区初始大小（字节）。
pub const DTLS_IO_BUF_LEN: usize = 4096;
/// 探测报文与早期 SRTP 缓冲的单包缓冲区上限（字节）。
pub const PROBE_IO_BUF_LEN: usize = 2048;
/// 带内控制帧封装缓冲区大小（字节）。
pub const CTRL_FRAME_BUF_LEN: usize = 256;
/// 主监听套接字及压测套接字收发内核缓冲大小（8 MiB）。
pub const SOCK_BUF_8MIB: usize = 8 * 1024 * 1024;
/// `mio::Events` 单次 poll 事件数组容量。
pub const MIO_EVENTS_CAP: usize = 256;
/// `mio::Poll` 中主监听套接字的保留事件令牌。
pub const LISTEN_TOKEN: Token = Token(0);
/// `mio::Poll` 中用于 Unix 信号自管道无锁优雅退出唤醒的保留令牌。
#[cfg(unix)]
pub const SHUTDOWN_PIPE_TOKEN: Token = Token(usize::MAX - 1);
/// `mio::Poll` 中用于跨线程命令和优雅退出唤醒的保留令牌。
pub const WAKE_TOKEN: Token = Token(usize::MAX);

// ============================================================================
// 2. 跨模块协议线格式契约（STUN / DTLS / SRTP / V4 带内控制帧）
// ============================================================================

/// STUN 固定报文头长度（字节）。
pub const STUN_HDR_LEN: usize = 20;
/// STUN Binding Request 消息类型。
pub const STUN_BINDING_REQUEST: u16 = 0x0001;
/// STUN Binding Success Response 消息类型。
pub const STUN_BINDING_SUCCESS: u16 = 0x0101;
/// STUN `USERNAME` 属性允许的最大字节长度。
pub const STUN_MAX_USERNAME_LEN: usize = 64;

/// DTLS 1.2 / 明文记录固定报文头长度（字节）。
pub const DTLS_PLAINTEXT_HDR_LEN: usize = 13;
/// DTLS 记录类型：Handshake (22)。
pub const DTLS_CT_HANDSHAKE: u8 = 22;
/// DTLS 握手消息类型：ClientHello (0x01)。
pub const DTLS_HS_CLIENT_HELLO: u8 = 0x01;
/// DTLS 协议主版本号高字节（0xFE）。
pub const DTLS_VER_MAJOR: u8 = 0xFE;
/// DTLS 1.2 协议次版本号低字节（0xFD）。
pub const DTLS_VER_MINOR_12: u8 = 0xFD;
/// 用于区分 `dimpl` 十年空闲定时器与活跃 Flight 5 重传定时器的阈值（秒）。
pub const DTLS_IDLE_TIMEOUT_THRESHOLD_SECS: u64 = 60;
/// 会话进入 Ready 后允许接收重传握手尾包的宽限期（秒），超时后仅允许加密 Alert/ACK。
pub const DTLS_READY_ALERT_ONLY_GRACE_SECS: u64 = 5;
/// DTLS 握手期遭遇畸形/污染包时允许快速重置状态机的最大次数。
pub const MAX_DTLS_RESETS: u8 = 3;

/// RFC 3550 固定 RTP 头部长度（字节）。
pub const RTP_FIXED_HDR_LEN: usize = 12;
/// RFC 8285 单字节扩展头总长度（4B `0xBEDE` 扩展前缀 + 4B transport-wide-cc 数据）。
pub const RTP_EXT_LEN: usize = 8;
/// 本协议完整明文 RTP 头部长度（12B 固定头 + 8B 扩展头 = 20B）。
pub const RTP_FULL_HDR_LEN: usize = RTP_FIXED_HDR_LEN + RTP_EXT_LEN;
/// 标准 Chrome RTP 首字节：`V=2, P=0, X=1, CC=0`（0x90）。
pub const RTP_V2_EXT_BYTE: u8 = 0x90;
/// 视频流动态 Payload Type（对齐 Chrome VP8/VP9/H264 常见 PT=96）。
pub const RTP_VIDEO_PT: u8 = 96;
/// 音频流动态 Payload Type（对齐 Chrome 48 kHz Opus PT=111）。
pub const RTP_AUDIO_PT: u8 = 111;
/// SRTP / SRTCP 统一 AEAD/MAC 认证标签长度（字节）。
pub const SRTP_TAG_LEN: usize = 16;
/// 普通数据帧加密区前缀长度（2B 内层长度字段）。
pub const SRTP_DATA_PREFIX_LEN: usize = 2;
/// 普通数据帧最小线长开销（20B RTP 头 + 2B 内层长度 + 16B AEAD 标签 = 38B）。
pub const SRTP_DATA_MIN_WIRE_LEN: usize = RTP_FULL_HDR_LEN + SRTP_DATA_PREFIX_LEN + SRTP_TAG_LEN;
/// 带内加密自测回显帧保留魔数（严格大于 `MAX_INNER_UDP_LEN`，零冲突）。
pub const SRTP_PROBE_MAGIC_LEN: u16 = 0xFFFE;
/// V4 带内加密 1-RTT ICE 路径迁移挑战/应答/确认帧魔数。
pub const SRTP_PATH_CHALLENGE_MAGIC: u16 = 0xFFFD;
/// V4 带内加密 MBB 后端套接字原子交接请求/确认帧魔数。
pub const SRTP_HANDOVER_MAGIC: u16 = 0xFFFC;
/// 路径挑战控制帧操作码：服务端发往候选地址的挑战请求。
pub const PATH_CHALLENGE_OP_REQ: u8 = 0x01;
/// 路径挑战控制帧操作码：客户端回传的挑战响应。
pub const PATH_CHALLENGE_OP_RESP: u8 = 0x02;
/// 路径挑战控制帧操作码：服务端切换成功后的确认包。
pub const PATH_CHALLENGE_OP_CONFIRM: u8 = 0x03;
/// 路径挑战请求/响应固定负载长度（1B 操作码 + 8B Nonce + 8B 路径纪元）。
pub const PATH_CHALLENGE_PAYLOAD_LEN: usize = 17;
/// 路径挑战确认固定负载长度（1B 操作码 + 8B Nonce）。
pub const PATH_CONFIRM_PAYLOAD_LEN: usize = 9;
/// MBB 交接控制帧操作码：新会话发出的后端套接字接管请求。
pub const HANDOVER_OP_REQ: u8 = 0x01;
/// MBB 交接控制帧操作码：服务端返回的交接确认。
pub const HANDOVER_OP_ACK: u8 = 0x02;
/// MBB 交接加密证明长度（HKDF-SHA256 输出 32 字节）。
pub const HANDOVER_PROOF_LEN: usize = 32;
/// MBB 交接请求最小负载长度（1B 操作码 + 1B ufrag 长度 + 32B 证明）。
pub const HANDOVER_MIN_REQ_LEN: usize = 2 + HANDOVER_PROOF_LEN;

// ============================================================================
// 3. 双端强耦合时序、细流退避与共享默认值
// ============================================================================

/// 会话无有效数据活动后的默认空闲超时时间（秒）。
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 120;
/// 触发字节预算 MBB 轮换前的最小会话存活冷却期（秒），防止握手风暴。
pub const DEFAULT_ROTATE_COOLDOWN_SECS: u64 = 60;
/// `--status-interval` 未设置（0）时的默认遥测刷新间隔（秒）。
pub const TELEMETRY_DEFAULT_INTERVAL_SECS: u64 = 5;

/// 常规关闭前保留接收窗口的短暂引流时长（毫秒），避免尾包触发 ICMP Port Unreachable。
pub const CLOSING_DRAIN_MS: u64 = 250;
/// 客户端主动发送 SRTCP BYE 后的只收引流时长（毫秒，须严格大于服务端 `CLOSING_DRAIN_MS` + 跨洋 RTT）。
pub const POST_BYE_CLOSING_DRAIN_MS: u64 = 1000;
/// RFC 7675 §5.1 服务端同意超时时长：连续无认证包超过 45 秒即静默释放会话并停止发包。
pub const PEER_CONSENT_TIMEOUT: Duration = Duration::from_secs(45);
/// 黑洞触发迁移或轮换后旧端口的静默只收引流时长（秒，须严格大于服务端 `PEER_CONSENT_TIMEOUT` 45s）。
pub const BLACKHOLE_DRAIN_SECS: u64 = 50;

/// 细流（trickle）速率判定滑动窗口时长（15 秒，客户端与服务端对齐）。
pub const TRICKLE_WINDOW_15S_SECS: u64 = 15;
/// 15 秒滑动窗口内低于该字节数（4 KiB，约 270 B/s）即进入安静细流控制面退避模式。
pub const TRICKLE_RATE_15S_BYTES: u64 = 4 * 1024;
/// 判定当前处于活跃媒体流（采用高频 SRTCP 节奏）的最近收发时间窗（秒）。
pub const SRTCP_ACTIVE_MEDIA_WINDOW_SECS: u64 = 3;
/// 非细流短暂停顿期 SRTCP 最小发送间隔（毫秒）。
pub const SRTCP_IDLE_MIN_MS: u64 = 3500;
/// 非细流短暂停顿期 SRTCP 最大发送间隔（毫秒）。
pub const SRTCP_IDLE_MAX_MS: u64 = 6500;
/// 细流退避期 SRTCP 最小发送间隔（毫秒）。
pub const SRTCP_TRICKLE_MIN_MS: u64 = 20_000;
/// 细流退避期 SRTCP 最大发送间隔（毫秒）。
pub const SRTCP_TRICKLE_MAX_MS: u64 = 40_000;

/// 工作线程无活跃会话时的 `mio::Poll` 最大阻塞等待时间（秒）。
pub const WORKER_IDLE_POLL_SECS: u64 = 5;
/// 工作线程存在活跃会话时的 `mio::Poll` 基准最大等待时间（秒）。
pub const WORKER_ACTIVE_POLL_SECS: u64 = 1;
/// 静默测试模式检测 `stop` 退出标志的最大 poll 等待上限（毫秒）。
pub const WORKER_QUIET_STOP_POLL_MS: u64 = 20;
/// 高频握手/重传定时器计算的最小 poll 步进下限（毫秒）。
pub const WORKER_MIN_FAST_WAIT_MS: u64 = 5;
/// 常规保活/SRTCP/关闭定时器计算的最小 poll 步进下限（毫秒）。
pub const WORKER_MIN_NORMAL_WAIT_MS: u64 = 10;
