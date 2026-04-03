#!/bin/bash
# Generate test certificates for TLS course

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/../certs"

echo "Generating test certificates for TLS course..."
echo "Output directory: ${CERTS_DIR}"

# Create directory structure
mkdir -p "${CERTS_DIR}/ca"
mkdir -p "${CERTS_DIR}/server"
mkdir -p "${CERTS_DIR}/client"
mkdir -p "${CERTS_DIR}/expired"

# Generate CA certificate (valid for 10 years)
echo ""
echo "[1] Generating CA certificate..."
openssl req -x509 -newkey rsa:4096 -keyout "${CERTS_DIR}/ca/ca-key.pem" \
    -out "${CERTS_DIR}/ca/ca-cert.pem" -days 3650 -nodes \
    -subj "/CN=TLS Course Test CA/O=TLS Course/C=CN" \
    -addext "basicConstraints=critical,CA:TRUE"

echo "    ✓ CA certificate generated"
echo "    CA Cert: ${CERTS_DIR}/ca/ca-cert.pem"
echo "    CA Key: ${CERTS_DIR}/ca/ca-key.pem"

# Generate server certificate (valid for 1 year)
echo ""
echo "[2] Generating server certificate..."

# Create server private key
openssl genrsa -out "${CERTS_DIR}/server/server-key.pem" 2048 2>/dev/null

# Create certificate signing request
openssl req -new -key "${CERTS_DIR}/server/server-key.pem" \
    -out "${CERTS_DIR}/server/server.csr" -nodes \
    -subj "/CN=localhost/O=TLS Course/C=CN" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"

# Sign with CA
openssl x509 -req -in "${CERTS_DIR}/server/server.csr" \
    -CA "${CERTS_DIR}/ca/ca-cert.pem" \
    -CAkey "${CERTS_DIR}/ca/ca-key.pem" \
    -CAcreateserial -out "${CERTS_DIR}/server/server-cert.pem" \
    -days 365 -sha256 \
    -extfile <(cat <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1
EOF
)

# Create fullchain
cat "${CERTS_DIR}/server/server-cert.pem" \
    "${CERTS_DIR}/ca/ca-cert.pem" > "${CERTS_DIR}/server/fullchain.pem"

echo "    ✓ Server certificate generated"
echo "    Server Cert: ${CERTS_DIR}/server/server-cert.pem"
echo "    Server Key: ${CERTS_DIR}/server/server-key.pem"
echo "    Fullchain: ${CERTS_DIR}/server/fullchain.pem"

# Generate client certificate (valid for 1 year)
echo ""
echo "[3] Generating client certificate..."

# Create client private key
openssl genrsa -out "${CERTS_DIR}/client/client-key.pem" 2048 2>/dev/null

# Create certificate signing request
openssl req -new -key "${CERTS_DIR}/client/client-key.pem" \
    -out "${CERTS_DIR}/client/client.csr" -nodes \
    -subj "/CN=tls-course-client/O=TLS Course/C=CN"

# Sign with CA
openssl x509 -req -in "${CERTS_DIR}/client/client.csr" \
    -CA "${CERTS_DIR}/ca/ca-cert.pem" \
    -CAkey "${CERTS_DIR}/ca/ca-key.pem" \
    -CAcreateserial -out "${CERTS_DIR}/client/client-cert.pem" \
    -days 365 -sha256 \
    -extfile <(cat <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF
)

echo "    ✓ Client certificate generated"
echo "    Client Cert: ${CERTS_DIR}/client/client-cert.pem"
echo "    Client Key: ${CERTS_DIR}/client/client-key.pem"

# Generate expired certificate (already expired)
echo ""
echo "[4] Generating expired certificate (for testing)..."

# Create expired private key
openssl genrsa -out "${CERTS_DIR}/expired/expired-key.pem" 2048 2>/dev/null

# Create certificate signing request
openssl req -new -key "${CERTS_DIR}/expired/expired-key.pem" \
    -out "${CERTS_DIR}/expired/expired.csr" -nodes \
    -subj "/CN=expired.example.com/O=TLS Course/C=CN"

# Sign with CA (already expired)
openssl x509 -req -in "${CERTS_DIR}/expired/expired.csr" \
    -CA "${CERTS_DIR}/ca/ca-cert.pem" \
    -CAkey "${CERTS_DIR}/ca/ca-key.pem" \
    -CAcreateserial -out "${CERTS_DIR}/expired/expired-cert.pem" \
    -days 365 -sha256 -startdate 200101000000Z -enddate 200101000001Z

echo "    ✓ Expired certificate generated"
echo "    Expired Cert: ${CERTS_DIR}/expired/expired-cert.pem"

# Clean up CSR files
rm -f "${CERTS_DIR}/server/server.csr"
rm -f "${CERTS_DIR}/client/client.csr"
rm -f "${CERTS_DIR}/expired/expired.csr"

# Display certificate info
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║ Certificate Summary                                        ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║ CA Certificate:                                            ║"
openssl x509 -in "${CERTS_DIR}/ca/ca-cert.pem" -noout -subject -dates | sed 's/^/║   /'
echo "╠════════════════════════════════════════════════════════════╣"
echo "║ Server Certificate:                                        ║"
openssl x509 -in "${CERTS_DIR}/server/server-cert.pem" -noout -subject -dates | sed 's/^/║   /'
echo "╠════════════════════════════════════════════════════════════╣"
echo "║ Client Certificate:                                        ║"
openssl x509 -in "${CERTS_DIR}/client/client-cert.pem" -noout -subject -dates | sed 's/^/║   /'
echo "╚════════════════════════════════════════════════════════════╝"

echo ""
echo "✓ All certificates generated successfully!"
echo ""
echo "You can now run the examples:"
echo "  cd lesson01"
echo "  cargo run --bin server -- --cert ../certs/server/server-cert.pem --key ../certs/server/server-key.pem"
echo "  cargo run --bin client -- --ca-cert ../certs/ca/ca-cert.pem"
