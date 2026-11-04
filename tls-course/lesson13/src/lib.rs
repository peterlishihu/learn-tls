//! Lesson 13: QUIC 与 TUIC —— 共享库
//!
//! 包含两部分：
//! 1. [`tuic`] 模块：按 TUIC v5 官方规范（tuic-protocol/tuic 的 SPEC.md）实现的
//!    协议帧编解码——这是"魔改"的最直接体现：TUIC 把整个代理协议压进了
//!    QUIC 的流（STREAM 帧）与不可靠数据报（DATAGRAM 帧）里。
//! 2. QUIC/TLS 配置助手：自签证书 + 证书固定（certificate pinning）+
//!    quinn Endpoint 构建。注意 quinn 的 TLS 引擎正是 rustls——
//!    课时 1-12 所学的握手、密钥派生、CryptoProvider 在 QUIC 里原样生效。

pub mod tuic;

use std::sync::Arc;

use anyhow::Result;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, PrivateKeyDer, ServerName, UnixTime};

/// 演示用 ALPN——QUIC 强制要求 ALPN，TUIC 真实实现使用 "tuic" 一类的自定义值
pub const ALPN_QUIC_ECHO: &[&[u8]] = &[b"demo-quic"];
/// mini-TUIC 演示用的 ALPN
pub const ALPN_TUIC: &[&[u8]] = &[b"tuic-v5-mini"];

/// 一对自签证书 + 私钥（演示用；TUIC 真实部署同样允许自签证书 + 客户端固定指纹）
pub struct SelfSignedCert {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

/// 生成自签证书（CN=localhost）
pub fn generate_self_signed() -> Result<SelfSignedCert> {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    Ok(SelfSignedCert {
        cert: ck.cert.der().clone(),
        key: PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()).into(),
    })
}

/// 证书固定验证器：只在端实体证书 DER 与预期完全一致时通过。
///
/// 这模拟了 TUIC 常见的部署形态——自签证书 + 客户端写死证书（或指纹），
/// 从而不需要域名和 CA 体系。生产环境请用 WebPKI 验证。
#[derive(Debug)]
pub struct PinnedCertVerifier {
    expected: CertificateDer<'static>,
}

impl PinnedCertVerifier {
    pub fn new(expected: CertificateDer<'static>) -> Self {
        Self { expected }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity == &self.expected {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// 构建 quinn 服务端配置（TLS 1.3-only + 指定 ALPN + 允许 0-RTT 早期数据）
pub fn quinn_server_config(
    cert: &SelfSignedCert,
    alpn: &'static [&'static [u8]],
) -> Result<quinn::ServerConfig> {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])? // QUIC 强制 TLS 1.3
    .with_no_client_auth()
    .with_single_cert(vec![cert.cert.clone()], cert.key.clone_key())?;
    tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    // 允许客户端 0-RTT：NewSessionTicket 里携带 early_data 指示。
    // quinn 约束：QUIC 会话的 max_early_data 只能取 0 或 u32::MAX
    tls.max_early_data_size = u32::MAX;

    let mut config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
    ));
    // 会话保活：TUIC 用 Heartbeat 命令维持连接，这里用 QUIC 自带的 keep-alive 做对照
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// 构建 quinn 客户端配置（证书固定 + 指定 ALPN + 开启 0-RTT 早期数据）
pub fn quinn_client_config(
    cert: &SelfSignedCert,
    alpn: &'static [&'static [u8]],
    enable_0rtt: bool,
) -> Result<quinn::ClientConfig> {
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(PinnedCertVerifier::new(
        cert.cert.clone(),
    )))
    .with_no_client_auth();
    tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    // 0-RTT：rustls 默认不主动发送早期数据，需要显式打开
    tls.enable_early_data = enable_0rtt;
    // 会话恢复：默认即内存票证缓存（quinn 文档：默认 256 个 server name）

    Ok(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    )))
}
