#!/usr/bin/env bash
# 环境初始化：安装系统依赖、检查 Rust 版本、生成测试证书
# 用法: ./scripts/setup.sh

set -euo pipefail

cd "$(dirname "$0")/.."

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[setup]${NC} $1"; }
warn()  { echo -e "${YELLOW}[setup]${NC} $1"; }

# 1. 系统依赖
if command -v apt-get >/dev/null 2>&1; then
    info "检测到 Debian/Ubuntu，安装 openssl 与 wireshark(可选)..."
    sudo apt-get update -qq
    sudo apt-get install -y openssl libssl-dev pkg-config
elif command -v brew >/dev/null 2>&1; then
    info "检测到 macOS，安装 openssl..."
    brew install openssl
else
    warn "未识别的包管理器，请手动安装 openssl 与 wireshark"
fi

# 2. Rust 工具链
if ! command -v cargo >/dev/null 2>&1; then
    info "安装 Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

RUSTC_VERSION=$(rustc --version | awk '{print $2}')
info "Rust 版本: ${RUSTC_VERSION} (课程要求 >= 1.83)"

# 3. 生成测试证书
if [ -f certs/ca/ca-cert.pem ]; then
    info "证书已存在，跳过生成（删除 certs/ 目录可强制重新生成）"
else
    info "生成测试证书..."
    ./scripts/gen_certs.sh
fi

# 4. 预编译整个课程
info "编译 workspace（首次需要几分钟）..."
cargo build --workspace

cat <<'EOF'

✅ 环境就绪！

快速开始：
  cd lesson01
  cargo run --bin server -- --cert ../certs/server/cert.pem --key ../certs/server/key.pem
  cargo run --bin client -- --ca-cert ../certs/ca/ca-cert.pem

Wireshark 解密：
  export SSLKEYLOGFILE=$PWD/tls-keys.log
  # Wireshark -> Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename
EOF
