#!/usr/bin/env bash
# WEB-proxy entrypoint: generate the tproxy-server config from env vars,
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

# ── cover site: every container start writes a different small static site into
#    /srv/tproxy-site, so an unauthenticated visitor (or an active prober) sees an
#    ordinary page instead of the relay. Same idea as the panel's own cover layer,
#    done in plain shell because the runtime image has no interpreter.
if [[ "${TGP_COVER:-1}" != "0" ]]; then
  COVER_A=(Lumen North Cedar Atlas Kite Verde Solace Harbor Ember Quill Aster Nimbus Onyx Willow Copper)
  COVER_B=(Atelier Studio Works Collective Labs Design Supply Press Roasters Gallery Craft House)
  COVER_CITY=(Lisbon Porto Tbilisi Istanbul Athens Tallinn Ljubljana Brno Bergen Taipei Melbourne)
  COVER_TAG=("Small things, made carefully" "Slow work for everyday use" "A workshop, not a factory" \
             "Objects with a long life" "Quiet design, honest materials" "Made to order, shipped weekly")
  pick() { local -n _arr=$1; echo "${_arr[$((RANDOM % ${#_arr[@]}))]}"; }
  BRAND="$(pick COVER_A) $(pick COVER_B)"
  CITY="$(pick COVER_CITY)"
  TAG="$(pick COVER_TAG)"
  HUE=$((RANDOM % 360))
  HUE2=$(((HUE + 120 + RANDOM % 100) % 360))
  ACC="hsl(${HUE} 58% 42%)"
  ACC2="hsl(${HUE2} 62% 46%)"
  INITIAL="${BRAND:0:1}"
  YEAR=$((2014 + RANDOM % 12))
  mkdir -p /srv/tproxy-site
  cat > /srv/tproxy-site/index.html <<HTML
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${BRAND}</title><link rel="icon" href="favicon.svg" type="image/svg+xml">
<style>
:root{--bg:#fbfaf8;--fg:#1b1b1f;--dim:#6b6b74;--line:#e6e3dd;--card:#fff;--acc:${ACC};--acc2:${ACC2}}
@media (prefers-color-scheme:dark){:root{--bg:#121316;--fg:#ececed;--dim:#9a9aa4;--line:#26262b;--card:#181a1e;--acc:${ACC};--acc2:${ACC2}}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:0 22px}
header{border-bottom:1px solid var(--line);background:var(--card)}
header .wrap{display:flex;align-items:center;gap:12px;height:60px}
.brand{display:flex;align-items:center;gap:10px;font-weight:650;margin-right:auto}
.mark{width:28px;height:28px;border-radius:8px;background:var(--acc);color:#fff;display:grid;place-items:center;font-size:13px;font-weight:700}
h1{font-size:clamp(30px,5vw,44px);line-height:1.12;letter-spacing:-.02em;margin:0 0 14px}
h2{font-size:21px;margin:46px 0 12px}
p{color:var(--dim);margin:0 0 14px}
.hero{padding:72px 0 20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px}
.card h3{margin:0 0 6px;font-size:16px}.card p{margin:0;font-size:14.5px}
footer{border-top:1px solid var(--line);margin-top:60px;padding:22px 0;color:var(--dim);font-size:13.5px}
.kicker{color:var(--acc2);font-size:13px;letter-spacing:.09em;text-transform:uppercase;font-weight:600}
</style></head><body>
<header><div class="wrap"><div class="brand"><div class="mark">${INITIAL}</div>${BRAND}</div></div></header>
<main class="wrap">
<section class="hero"><div class="kicker">${CITY}</div><h1>${TAG}</h1>
<p>We are a small studio in ${CITY}. Everything is made to order and dispatched every week —
write to us and we will send a written proposal with fixed prices.</p></section>
<h2>What we do</h2>
<div class="grid">
<div class="card"><h3>Brand identity</h3><p>Naming, marks and a type system that survives the real world.</p></div>
<div class="card"><h3>Design</h3><p>Small, fast pages and printed pieces, made locally.</p></div>
<div class="card"><h3>Repairs</h3><p>Fixing what you already own before replacing it.</p></div>
</div>
</main>
<footer><div class="wrap">${BRAND} — ${CITY} · ${YEAR}</div></footer>
</body></html>
HTML
  cat > /srv/tproxy-site/favicon.svg <<SVG
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="16" fill="${ACC}"/>
<text x="32" y="43" font-family="system-ui,sans-serif" font-size="30" font-weight="700" fill="#fff" text-anchor="middle">${INITIAL}</text></svg>
SVG
  printf 'User-agent: *\nAllow: /\n' > /srv/tproxy-site/robots.txt
  echo "entrypoint: cover site written (${BRAND})"
fi

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
