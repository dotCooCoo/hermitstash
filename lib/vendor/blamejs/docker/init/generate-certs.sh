#!/bin/sh
# One-shot cert generator. Runs in a tiny alpine + openssl container at
# stack startup, populates /certs with a self-signed Ed25519 CA plus
# per-service leaf certs. Idempotent — re-runs short-circuit if /certs/ca.crt
# already exists.
#
# Why Ed25519: it's the closest to the framework's PQC-first posture
# that the external services in this stack actually accept. ML-DSA / SLH-DSA
# certs are not yet supported by any of these servers. When server-side
# PQC certs land we'll regenerate. The CA's signature alg is NOT what
# determines TLS handshake KEM — that's negotiated from the cipher/groups
# on each connection. Where the server supports it we still negotiate
# X25519MLKEM768 hybrid (Caddy, recent OpenSSL builds).

set -eu

CERT_DIR="${CERT_DIR:-/certs}"
DAYS="${DAYS:-3650}"

if [ -f "$CERT_DIR/ca.crt" ] && [ -f "$CERT_DIR/.complete" ]; then
  echo "[pki-init] /certs/ca.crt already present — skipping regen"
  exit 0
fi

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# Preserve an existing CA across .complete-only resets so that
# already-issued leaves keep chaining. Only generate a new CA when none
# is present.
if [ -f "$CERT_DIR/ca.crt" ] && [ -f "$CERT_DIR/ca.key" ]; then
  echo "[pki-init] reusing existing CA (ca.crt + ca.key present)"
else
  echo "[pki-init] generating Ed25519 CA..."
  openssl genpkey -algorithm ED25519 -out ca.key
  openssl req -x509 -new -key ca.key -out ca.crt -days "$DAYS" \
    -subj "/CN=blamejs-test-ca/O=blamejs-test/C=US"
fi

# Service list — each gets a leaf cert covering the docker-network
# hostname, the host-bind 127.0.0.1 / [::1], and localhost.
SERVICES="redis postgres mysql mongo minio rabbitmq nats syslog mailpit haproxy caddy nginx mitmproxy squid coredns azurite gcs otel localstack"

for SVC in $SERVICES; do
  if [ -f "$CERT_DIR/$SVC.crt" ]; then
    echo "[pki-init] $SVC.crt exists — skipping"
    continue
  fi
  echo "[pki-init] issuing leaf cert for $SVC..."

  # syslog-ng's TLS module in this image doesn't accept Ed25519 server
  # certs cleanly (handshake aborts before ClientHello completes); fall
  # back to ECDSA P-256 just for that fixture. All other services serve
  # Ed25519 leaves and the framework's TLS client verifies them OK.
  if [ "$SVC" = "syslog" ]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$SVC.key"
  else
    openssl genpkey -algorithm ED25519 -out "$SVC.key"
  fi

  cat > "/tmp/$SVC.cnf" <<EOF
[req]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no

[req_dn]
CN = $SVC

[v3_req]
basicConstraints     = CA:FALSE
keyUsage             = critical, digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage     = serverAuth, clientAuth
subjectAltName       = @alt

[alt]
DNS.1 = $SVC
DNS.2 = blamejs-test-$SVC
DNS.3 = localhost
IP.1  = 127.0.0.1
IP.2  = ::1
EOF

  openssl req -new -key "$SVC.key" -out "$SVC.csr" -config "/tmp/$SVC.cnf"
  openssl x509 -req -in "$SVC.csr" -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out "$SVC.crt" -days "$DAYS" \
    -extensions v3_req -extfile "/tmp/$SVC.cnf"
  rm -f "$SVC.csr" "/tmp/$SVC.cnf"

  cat "$SVC.crt" "$SVC.key" > "$SVC.combined.pem"

  openssl pkcs12 -export -in "$SVC.crt" -inkey "$SVC.key" \
    -CAfile ca.crt -name "$SVC" -out "$SVC.p12" \
    -passout pass:blamejs_test
done

# MinIO expects public.crt + private.key + CAs/ca.crt under a single
# certs dir. Lay that out so its --certs-dir flag has what it needs.
mkdir -p "$CERT_DIR/minio/CAs"
cp "$CERT_DIR/minio.crt" "$CERT_DIR/minio/public.crt"
cp "$CERT_DIR/minio.key" "$CERT_DIR/minio/private.key"
cp "$CERT_DIR/ca.crt"    "$CERT_DIR/minio/CAs/ca.crt"
chmod 644 "$CERT_DIR/minio/public.crt" "$CERT_DIR/minio/private.key" "$CERT_DIR/minio/CAs/ca.crt"

if [ ! -f "$CERT_DIR/dhparams.pem" ]; then
  echo "[pki-init] generating 2048-bit DH params (one-time, ~10s)..."
  openssl dhparam -out dhparams.pem 2048
fi

# World-readable so non-root services can bind their TLS listeners.
# These are TEST CERTS only — the keys are in a docker volume on the
# operator's machine and never leave it.
chmod 644 "$CERT_DIR"/*.key "$CERT_DIR"/*.combined.pem 2>/dev/null || true

touch "$CERT_DIR/.complete"
# find -maxdepth/-mindepth 1 lists immediate children (files + dirs)
# safely; ls + wc -l is fragile on filenames with newlines.
echo "[pki-init] done — $(find "$CERT_DIR" -maxdepth 1 -mindepth 1 | wc -l) files in $CERT_DIR"
