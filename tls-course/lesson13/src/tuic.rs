//! TUIC v5 协议帧编解码（教学实现）
//!
//! 严格按照官方规范实现：<https://github.com/tuic-protocol/tuic/blob/master/SPEC.md>
//!
//! ```text
//! Command = VER(1) + TYPE(1) + OPT(变长)
//!
//! Authenticate (0x00): UUID(16) + TOKEN(32)
//!     TOKEN = TLS Keying Material Exporter(label=UUID, context=原始密码)
//! Connect     (0x01): ADDR(变长)     —— 之后整条双向流就是 TCP 载荷
//! Packet      (0x02): ASSOC_ID(2) + PKT_ID(2) + FRAG_TOTAL(1) + FRAG_ID(1) + SIZE(2) + ADDR —— 之后是 UDP 载荷
//! Dissociate  (0x03): ASSOC_ID(2)
//! Heartbeat   (0x04): (空)
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;

/// TUIC 协议版本（v5）
pub const VERSION: u8 = 0x05;

/// 命令类型
pub mod command_type {
    /// 认证（单向流）
    pub const AUTHENTICATE: u8 = 0x00;
    /// 建立 TCP 中继（双向流）
    pub const CONNECT: u8 = 0x01;
    /// UDP 包中继（DATAGRAM 或单向流）
    pub const PACKET: u8 = 0x02;
    /// 结束一个 UDP 中继会话（单向流）
    pub const DISSOCIATE: u8 = 0x03;
    /// 保活（DATAGRAM）
    pub const HEARTBEAT: u8 = 0x04;
}

/// 解码错误
#[derive(Debug, Error, PartialEq)]
pub enum DecodeError {
    #[error("buffer too short: need {need} bytes, have {have}")]
    TooShort { need: usize, have: usize },
    #[error("unknown TUIC version: 0x{0:02x}")]
    UnknownVersion(u8),
    #[error("unknown command type: 0x{0:02x}")]
    UnknownCommand(u8),
    #[error("unknown address type: 0x{0:02x}")]
    UnknownAddress(u8),
}

/// TUIC 地址类型：0xff=None / 0x00=域名 / 0x01=IPv4 / 0x02=IPv6
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// 0xff：用于 Packet 命令中非首片的分片（无地址、无端口）
    None,
    /// 0x00：长度前缀域名 + 端口
    Domain(String, u16),
    /// 0x01：4 字节 IPv4 + 端口
    Ipv4(Ipv4Addr, u16),
    /// 0x02：16 字节 IPv6 + 端口
    Ipv6(Ipv6Addr, u16),
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::None => write!(f, "(none)"),
            Address::Domain(d, p) => write!(f, "{}:{}", d, p),
            Address::Ipv4(ip, p) => write!(f, "{}:{}", ip, p),
            Address::Ipv6(ip, p) => write!(f, "[{}]:{}", ip, p),
        }
    }
}

impl Address {
    /// 编码到 out
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Address::None => out.push(0xff),
            Address::Domain(domain, port) => {
                out.push(0x00);
                out.push(domain.len() as u8);
                out.extend_from_slice(domain.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Address::Ipv4(ip, port) => {
                out.push(0x01);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Address::Ipv6(ip, port) => {
                out.push(0x02);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    /// 从 buf 开头解码，返回 (地址, 消耗字节数)
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let need = |n: usize| -> Result<(), DecodeError> {
            if buf.len() < n {
                Err(DecodeError::TooShort { need: n, have: buf.len() })
            } else {
                Ok(())
            }
        };

        need(1)?;
        match buf[0] {
            0xff => Ok((Address::None, 1)),
            0x00 => {
                need(2)?;
                let dlen = buf[1] as usize;
                let total = 2 + dlen + 2;
                need(total)?;
                let domain =
                    std::str::from_utf8(&buf[2..2 + dlen]).map_err(|_| DecodeError::UnknownAddress(0x00))?;
                let port = u16::from_be_bytes([buf[2 + dlen], buf[3 + dlen]]);
                Ok((Address::Domain(domain.to_string(), port), total))
            }
            0x01 => {
                need(7)?;
                let mut o = [0u8; 4];
                o.copy_from_slice(&buf[1..5]);
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                Ok((Address::Ipv4(Ipv4Addr::from(o), port), 7))
            }
            0x02 => {
                need(19)?;
                let mut o = [0u8; 16];
                o.copy_from_slice(&buf[1..17]);
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                Ok((Address::Ipv6(Ipv6Addr::from(o), port), 19))
            }
            other => Err(DecodeError::UnknownAddress(other)),
        }
    }
}

/// TUIC v5 命令（仅头部；Connect 之后流内剩余部分、Packet 之后 SIZE 字节是载荷）
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    /// 认证：UUID + 32 字节 token（token 由 TLS exporter 派生）
    Authenticate { uuid: [u8; 16], token: [u8; 32] },
    /// TCP 中继：目标地址（命令之后整条流都是 TCP 载荷）
    Connect(Address),
    /// UDP 中继：会话/分片信息 + 目标（或来源）地址
    Packet {
        assoc_id: u16,
        pkt_id: u16,
        frag_total: u8,
        frag_id: u8,
        size: u16,
        addr: Address,
    },
    /// 结束 UDP 中继会话
    Dissociate { assoc_id: u16 },
    /// 保活
    Heartbeat,
}

impl Command {
    pub fn type_byte(&self) -> u8 {
        match self {
            Command::Authenticate { .. } => command_type::AUTHENTICATE,
            Command::Connect(_) => command_type::CONNECT,
            Command::Packet { .. } => command_type::PACKET,
            Command::Dissociate { .. } => command_type::DISSOCIATE,
            Command::Heartbeat => command_type::HEARTBEAT,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Command::Authenticate { .. } => "Authenticate",
            Command::Connect(_) => "Connect",
            Command::Packet { .. } => "Packet",
            Command::Dissociate { .. } => "Dissociate",
            Command::Heartbeat => "Heartbeat",
        }
    }

    /// 编码命令头
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![VERSION, self.type_byte()];
        match self {
            Command::Authenticate { uuid, token } => {
                out.extend_from_slice(uuid);
                out.extend_from_slice(token);
            }
            Command::Connect(addr) => addr.encode(&mut out),
            Command::Packet { assoc_id, pkt_id, frag_total, frag_id, size, addr } => {
                out.extend_from_slice(&assoc_id.to_be_bytes());
                out.extend_from_slice(&pkt_id.to_be_bytes());
                out.push(*frag_total);
                out.push(*frag_id);
                out.extend_from_slice(&size.to_be_bytes());
                addr.encode(&mut out);
            }
            Command::Dissociate { assoc_id } => {
                out.extend_from_slice(&assoc_id.to_be_bytes());
            }
            Command::Heartbeat => {}
        }
        out
    }

    /// 从 buf 开头解码命令头，返回 (命令, 消耗字节数)。
    ///
    /// 注意：对 `Connect`，buf 里头部之后可能还有载荷；
    /// 对 `Packet`，头部之后还有 `size` 字节载荷。
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let need = |n: usize| -> Result<(), DecodeError> {
            if buf.len() < n {
                Err(DecodeError::TooShort { need: n, have: buf.len() })
            } else {
                Ok(())
            }
        };

        need(2)?;
        if buf[0] != VERSION {
            return Err(DecodeError::UnknownVersion(buf[0]));
        }
        match buf[1] {
            command_type::AUTHENTICATE => {
                need(2 + 16 + 32)?;
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&buf[2..18]);
                let mut token = [0u8; 32];
                token.copy_from_slice(&buf[18..50]);
                Ok((Command::Authenticate { uuid, token }, 50))
            }
            command_type::CONNECT => {
                let (addr, n) = Address::decode(&buf[2..])?;
                Ok((Command::Connect(addr), 2 + n))
            }
            command_type::PACKET => {
                need(2 + 8)?;
                let assoc_id = u16::from_be_bytes([buf[2], buf[3]]);
                let pkt_id = u16::from_be_bytes([buf[4], buf[5]]);
                let frag_total = buf[6];
                let frag_id = buf[7];
                let size = u16::from_be_bytes([buf[8], buf[9]]);
                let (addr, n) = Address::decode(&buf[10..])?;
                Ok((
                    Command::Packet { assoc_id, pkt_id, frag_total, frag_id, size, addr },
                    10 + n,
                ))
            }
            command_type::DISSOCIATE => {
                need(4)?;
                let assoc_id = u16::from_be_bytes([buf[2], buf[3]]);
                Ok((Command::Dissociate { assoc_id }, 4))
            }
            command_type::HEARTBEAT => Ok((Command::Heartbeat, 2)),
            other => Err(DecodeError::UnknownCommand(other)),
        }
    }
}

/// 从 QUIC 连接的 TLS 会话导出 TUIC 认证 token。
///
/// 这是 TUIC v5 最精妙的一笔：
/// `token = HKDF-Expand-Label(TLS exporter secret, label=UUID, context=原始密码)`
/// —— 密码本身从不上网络，token 又绑定当前 TLS 会话，
/// 抓包重放到另一条连接上毫无意义（exporter 输出逐连接不同）。
pub fn derive_auth_token(
    conn: &quinn::Connection,
    uuid: &[u8; 16],
    password: &[u8],
) -> anyhow::Result<[u8; 32]> {
    let mut token = [0u8; 32];
    conn.export_keying_material(&mut token, uuid, password)
        .map_err(|e| anyhow::anyhow!("export_keying_material 失败: {e:?}"))?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_commands() {
        let cases = vec![
            Command::Heartbeat,
            Command::Dissociate { assoc_id: 0x1234 },
            Command::Connect(Address::Domain("example.com".into(), 443)),
            Command::Connect(Address::Ipv4(Ipv4Addr::LOCALHOST, 8080)),
            Command::Connect(Address::None),
            Command::Packet {
                assoc_id: 1,
                pkt_id: 7,
                frag_total: 3,
                frag_id: 1,
                size: 1200,
                addr: Address::None,
            },
        ];
        for cmd in cases {
            let bytes = cmd.encode();
            let (decoded, used) = Command::decode(&bytes).unwrap();
            assert_eq!(used, bytes.len(), "consumed length mismatch for {cmd:?}");
            assert_eq!(decoded, cmd);
        }
    }

    #[test]
    fn authenticate_wire_format() {
        let cmd = Command::Authenticate { uuid: [1; 16], token: [2; 32] };
        let bytes = cmd.encode();
        assert_eq!(bytes.len(), 2 + 16 + 32);
        assert_eq!(bytes[0], VERSION);
        assert_eq!(bytes[1], command_type::AUTHENTICATE);
        let (decoded, used) = Command::decode(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(decoded, cmd);
    }

    #[test]
    fn connect_with_trailing_payload() {
        // Connect 头 + 后续 TCP 载荷混在一个 buffer（流的真实形态）
        let mut buf = Command::Connect(Address::Ipv4(Ipv4Addr::LOCALHOST, 9000)).encode();
        buf.extend_from_slice(b"GET / HTTP/1.1\r\n");
        let (cmd, used) = Command::decode(&buf).unwrap();
        assert_eq!(cmd, Command::Connect(Address::Ipv4(Ipv4Addr::LOCALHOST, 9000)));
        assert_eq!(used, 9); // VER + TYPE + (1 + 4 + 2)
        assert_eq!(&buf[used..], b"GET / HTTP/1.1\r\n");
    }

    #[test]
    fn ipv6_address_roundtrip() {
        let addr = Address::Ipv6(Ipv6Addr::LOCALHOST, 53);
        let mut buf = Vec::new();
        addr.encode(&mut buf);
        assert_eq!(buf.len(), 1 + 16 + 2);
        let (decoded, used) = Address::decode(&buf).unwrap();
        assert_eq!(used, buf.len());
        assert_eq!(decoded, addr);
    }

    #[test]
    fn reject_bad_version() {
        let bytes = [0x04, command_type::HEARTBEAT];
        assert_eq!(
            Command::decode(&bytes),
            Err(DecodeError::UnknownVersion(0x04))
        );
    }
}
