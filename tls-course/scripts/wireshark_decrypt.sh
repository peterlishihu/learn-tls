#!/usr/bin/env bash
# 配置 Wireshark 的 TLS/QUIC 解密：把 SSLKEYLOGFILE 配置进 Wireshark
# 用法: ./scripts/wireshark_decrypt.sh [keylog 文件路径]

set -euo pipefail

KEYLOG="${1:-$HOME/.tls-keys.log}"

if [ ! -f "$KEYLOG" ]; then
    echo "提示: $KEYLOG 尚不存在，先跑一次示例生成它："
    echo "  SSLKEYLOGFILE=$KEYLOG cargo run --bin client"
    touch "$KEYLOG"
fi

# Linux (GTK Wireshark 4.x): 直接写入配置文件
if [ -f "${HOME}/.config/wireshark/preferences" ] || [ -d "${HOME}/.config/wireshark" ]; then
    WS_DIR="${HOME}/.config/wireshark"
elif [ -d "${HOME}/.wireshark" ]; then
    WS_DIR="${HOME}/.wireshark"
else
    echo "未找到 Wireshark 配置目录，请手动配置："
    echo "  Edit -> Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename"
    echo "  填入: $KEYLOG"
    echo "  （QUIC 解密同样使用该文件，Wireshark 会自动把 TLS 1.3 密钥用于 QUIC）"
    exit 0
fi

sed -i '/^tls.keylog_file:/d' "$WS_DIR/preferences" 2>/dev/null || true
echo "tls.keylog_file: $KEYLOG" >> "$WS_DIR/preferences"
echo "✅ 已写入 $WS_DIR/preferences"
echo "   TLS 与 QUIC 流量现在可在 Wireshark 中解密查看"
