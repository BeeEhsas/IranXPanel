#!/usr/bin/env bash
# IranXPanel WEB-proxy entrypoint: generate the tproxy-server config from env vars,
# detect NAT for the MTProxy middle-end, start MTProxy on loopback, put the L7 edge
# (tproxy-edge: Host canonicalization + one-address X-Forwarded-For) on $PORT, then
# hand PID 1 to the official relay. See Dockerfile for the env contract and edge.go
# for why a plain socat pipe is not enough on Railway/Render.
#
# Why an edge at all: upstream tproxy-server VALIDATES that its "listen" address is a
# numeric LOOPBACK address (internal/config/config.go — "must use a numeric loopback
# address"). The reference layout is "edge -> 127.0.0.1:8080 tproxy-server", where Caddy
# is the only thing on an external interface. Render/Railway terminate TLS at their
# platform edge and forward plain HTTP/WebSocket to $PORT, so the edge plays Caddy's
# role inside the container: 0.0.0.0:$PORT -> 127.0.0.1:$RELAY_PORT. Pointing the
# config's "listen" at 0.0.0.0 instead makes the relay exit on startup and the deploy
# die at the healthcheck stage ("Service offline"). It is an L7 hop (tproxy-edge), not
# a raw socat pipe, because the relay also demands the original Host and exactly one
# X-Forwarded-For address — see edge.go.
set -euo pipefail

die() { echo "entrypoint: $*" >&2; exit 1; }

SECRET="${TGP_SECRET:-}"
HOST_PUB="${TGP_PUBLIC_HOSTNAME:-}"
CARRIER="${TGP_CARRIER:-websocket}"
PORT="${PORT:-8080}"
# The relay's own loopback listener. 8081 is taken by admin_listen, 2398 by MTProxy.
# Exported: tproxy-edge reads TGP_RELAY_PORT itself.
export TGP_RELAY_PORT="${TGP_RELAY_PORT:-8082}"
RELAY_PORT="$TGP_RELAY_PORT"
PAUSED="${TGP_PAUSED:-}"

[[ "$PORT" != "$RELAY_PORT" ]] || die "PORT and TGP_RELAY_PORT must differ"

[[ "$SECRET" =~ ^[0-9a-f]{32}$ ]] || die "TGP_SECRET must be 32 lowercase hex chars"
# The client derives the bridge capability from the hostname it stores, so this value
# must be exactly the bare public host — lowercase, no scheme, no port, no path.
[[ "$HOST_PUB" =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] || die "TGP_PUBLIC_HOSTNAME must be a bare lowercase host"
case "$CARRIER" in
  https|https-lanes|websocket|websocket-lanes) ;;
  *) die "TGP_CARRIER must be https, https-lanes, websocket or websocket-lanes" ;;
esac

RUN=/run/tproxy
mkdir -p "$RUN"

# ── pause: park the container without a listener; the public hostname stays the same,
#    so resuming later keeps every issued t.me/webproxy link valid. ──
if [[ "$PAUSED" == "1" ]]; then
  echo "entrypoint: TGP_PAUSED=1 — idling without a listener (paused by panel)"
  exec sleep infinity
fi

# ── relay token key: exactly 32 random bytes (see deploy/ensure-token-key.sh upstream).
#    Lives in tmpfs — fresh per container lifetime, clients re-bootstrap on restart.
if [[ ! -s "$RUN/token.key" ]]; then
  head -c 32 /dev/urandom > "$RUN/token.key"
  chmod 0400 "$RUN/token.key"
fi

# ── MTProxy runtime files: refresh from Telegram, fall back to the bundled copies. ──
fetch() { # fetch <url> <dest> <min-bytes>
  curl -fsSL --proto '=https' --tlsv1.2 --max-time 20 "$1" -o "$2" 2>/dev/null || return 1
  [[ "$(wc -c < "$2")" -ge "$3" ]] || return 1
  return 0
}
cp /opt/mtproxy/proxy-secret      "$RUN/proxy-secret"
cp /opt/mtproxy/proxy-multi.conf  "$RUN/proxy-multi.conf"
if fetch https://core.telegram.org/getProxySecret  "$RUN/proxy-secret.new" 128; then
  mv "$RUN/proxy-secret.new" "$RUN/proxy-secret"
else
  rm -f "$RUN/proxy-secret.new" 2>/dev/null || true
fi
if fetch https://core.telegram.org/getProxyConfig "$RUN/proxy-multi.new" 100 \
   && grep -q '^default ' "$RUN/proxy-multi.new" \
   && grep -q '^proxy_for ' "$RUN/proxy-multi.new"; then
  mv "$RUN/proxy-multi.new" "$RUN/proxy-multi.conf"
else
  rm -f "$RUN/proxy-multi.new" 2>/dev/null || true
fi

# ── NAT detection: on Render/Railway the container sits behind 1:1 NAT, so MTProxy
#    hashes the wrong address into its middle-end keys and silently serves nobody
#    unless --nat-info <local>:<public> is passed (the official unit does the same). ──
IFACE_IP="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1 || true)"
PUB_IP=""
for src in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
  PUB_IP="$(curl -fsS4 --max-time 8 "$src" 2>/dev/null | tr -d '[:space:]' || true)"
  [[ "$PUB_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && break
  PUB_IP=""
done
NAT_ARGS=()
if [[ -n "$IFACE_IP" && -n "$PUB_IP" && "$IFACE_IP" != "$PUB_IP" ]]; then
  echo "entrypoint: NAT detected ($IFACE_IP -> $PUB_IP), passing --nat-info"
  NAT_ARGS=(--nat-info "$IFACE_IP:$PUB_IP")
elif [[ -z "$PUB_IP" ]]; then
  echo "entrypoint: could not detect the public egress IP; continuing without --nat-info"
fi

# ── start the MTProxy backend on loopback 2398 ──
echo "entrypoint: starting MTProxy on 127.0.0.1:2398 (carrier: $CARRIER, relay: 127.0.0.1:$RELAY_PORT, edge: 0.0.0.0:$PORT)"
/opt/mtproxy/mtproto-proxy \
  -u mtproxy -p 8888 -H 2398 \
  -S "$SECRET" \
  "${NAT_ARGS[@]+"${NAT_ARGS[@]}"}" \
  --aes-pwd "$RUN/proxy-secret" "$RUN/proxy-multi.conf" \
  -M "${MTPROXY_WORKERS:-1}" -C "${MTPROXY_MAX_CONNECTIONS:-4096}" &

UP=0
for _ in $(seq 1 40); do
  if (exec 3<>/dev/tcp/127.0.0.1/2398) 2>/dev/null; then
    exec 3>&- 3<&- || true
    UP=1
    break
  fi
  sleep 0.5
done
[[ "$UP" == "1" ]] || die "MTProxy did not open 127.0.0.1:2398"

# ── generate the relay config (minimal — upstream defaults fill the rest) ──
cat > "$RUN/config.json" <<EOF
{
  "public_hostname": "$HOST_PUB",
  "base_path": "",
  "listen": "127.0.0.1:$RELAY_PORT",
  "admin_listen": "127.0.0.1:8081",
  "public_dir": "/srv/tproxy-site",
  "static_routes": "exact",
  "token_key_file": "$RUN/token.key",
  "profiles_file": "$RUN/profiles.json"
}
EOF
cat > "$RUN/profiles.json" <<EOF
{
  "profiles": [
    {
      "name": "default",
      "secret": "$SECRET",
      "backend": "127.0.0.1:2398",
      "carrier_mode": "$CARRIER"
    }
  ]
}
EOF
chmod 0600 "$RUN/config.json" "$RUN/profiles.json"

# ── the public edge: tproxy-edge owns 0.0.0.0:$PORT. Unlike the socat pipe it
#    replaces, it is an L7 hop: it rewrites Host to the canonical public hostname
#    (PaaS edges do not deliver it — the relay 404s every authenticated request
#    otherwise) and collapses X-Forwarded-For to exactly one address (the relay
#    rejects a list; Railway appends client-supplied entries). WebSocket upgrades
#    and streaming bodies pass through untouched. ──
echo "entrypoint: starting L7 edge 0.0.0.0:$PORT -> 127.0.0.1:$RELAY_PORT (host rewrite -> $HOST_PUB)"
/usr/local/bin/tproxy-edge &
EDGE_PID=$!
sleep 0.3
kill -0 "$EDGE_PID" 2>/dev/null || die "tproxy-edge could not bind 0.0.0.0:$PORT"
echo "entrypoint: edge forwarder 0.0.0.0:$PORT -> 127.0.0.1:$RELAY_PORT (tproxy-edge pid $EDGE_PID)"

echo "entrypoint: handing over to tproxy-server (public_hostname=$HOST_PUB)"
exec /usr/local/bin/tproxy-server -config "$RUN/config.json"
