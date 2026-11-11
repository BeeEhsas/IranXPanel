# IranXPanel — Telegram WEB-proxy endpoint (one container, Render/Railway ready).
#
# What runs inside:
#   * the official telegramdesktop/tproxy-server relay (the WEB-proxy half Telegram
#     Desktop 7.1+ talks to: HTTPS / WebSocket carriers, bridge page, capability checks);
#   * the stock official MTProxy as the loopback backend on 127.0.0.1:2398, built from
#     the exact commit + checksum the official tproxy-server installer pins;
#   * a small neutral static site at /srv/tproxy-site that unauthenticated visitors see
#     (the active-probing cover required by the WEB-proxy design).
#
# Listening layout: upstream tproxy-server REQUIRES a loopback "listen" (it validates
# the config and refuses 0.0.0.0 with "must use a numeric loopback address"). The
# official reference layout puts Caddy on the external interface; here the platform
# (Render / Railway) already terminates TLS and forwards plain HTTP/WebSocket to $PORT,
# so a socat edge takes Caddy's L4 role inside the container:
#
#     platform edge :443 -> container 0.0.0.0:$PORT (socat)
#                         -> 127.0.0.1:$RELAY_PORT tproxy-server
#                         -> 127.0.0.1:2398 mtproto-proxy
#
# Environment the entrypoint reads:
#   TGP_SECRET          required, 32 lowercase hex chars — the client-facing MTProxy secret
#   TGP_PUBLIC_HOSTNAME required, bare lowercase host (e.g. myproxy.onrender.com) —
#                       must match the host a client stores, it derives the bridge
#                       capability from it locally
#   TGP_CARRIER         optional, one of https | https-lanes | websocket | websocket-lanes
#                       (default: websocket — one multiplexed WSS carrier)
#   TGP_PAUSED          optional, "1" puts the container to idle sleep without a listener
#                       (the panel's pause button; the hostname stays the same)
#   PORT                public edge port. Render injects it; Railway healthchecks it
#                       (healthcheck probes $PORT), so the image pins a default of 8080 —
#                       matching EXPOSE below — and the panel also sets it as a service
#                       variable. Without it Railway's healthcheck has no port to probe
#                       and the deploy dies as "failed during the network process".
#   TGP_RELAY_PORT      optional, internal loopback port of tproxy-server (default 8082).
#                       Must differ from PORT; clients never see it.

ARG GO_IMAGE=golang:1.23-bookworm
ARG BUILD_IMAGE=debian:bookworm
ARG RUN_IMAGE=debian:bookworm-slim

# ── stage 1: build the official relay ───────────────────────────────────────────
FROM ${GO_IMAGE} AS relay
ARG TPROXY_COMMIT=c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8
WORKDIR /build
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL --proto '=https' --tlsv1.2 \
      "https://github.com/telegramdesktop/tproxy-server/archive/${TPROXY_COMMIT}.tar.gz" \
      -o src.tar.gz \
 && mkdir src && tar -xzf src.tar.gz -C src --strip-components=1 \
 && cd src \
 && go build -trimpath -ldflags "-s -w" -o /out/tproxy-server ./cmd/tproxy-server

# ── stage 2: build the stock MTProxy backend ────────────────────────────────────
# Same pinned commit and sha256 as deploy/install-mtproxy.sh of tproxy-server.
FROM ${BUILD_IMAGE} AS mtproxy
ARG MTPROXY_COMMIT=f36d8af769ffaeac36978d38c2c0f6d1104c2137
ARG MTPROXY_SHA256=919795c416b870670841a21d1930ad97a24c7b84b9eb8c6f9e3de32f2fdf4655
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl build-essential \
      libssl-dev zlib1g-dev \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL --proto '=https' --tlsv1.2 \
      "https://github.com/TelegramMessenger/MTProxy/archive/${MTPROXY_COMMIT}.tar.gz" \
      -o /tmp/mtproxy.tar.gz \
 && echo "${MTPROXY_SHA256}  /tmp/mtproxy.tar.gz" | sha256sum -c - \
 && mkdir -p /opt/MTProxy \
 && tar -xzf /tmp/mtproxy.tar.gz -C /opt/MTProxy --strip-components=1 \
 && make -C /opt/MTProxy -j"$(nproc)"

# ── stage 3: runtime ────────────────────────────────────────────────────────────
FROM ${RUN_IMAGE}
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl iproute2 libssl3 zlib1g socat \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --home /nonexistent --shell /usr/sbin/nologin mtproxy
COPY --from=relay   /out/tproxy-server            /usr/local/bin/tproxy-server
COPY --from=mtproxy /opt/MTProxy/objs/bin/mtproto-proxy /opt/mtproxy/mtproto-proxy
COPY site/ /srv/tproxy-site/
COPY entrypoint.sh /entrypoint.sh
# proxy-secret (128 bytes) + proxy-multi.conf (DC list incl. middle proxies) are fetched
# at build time and refreshed by the entrypoint at every start (bundled copies win when
# core.telegram.org is unreachable — a container restart refreshes them anyway).
RUN chmod 0755 /entrypoint.sh /usr/local/bin/tproxy-server /opt/mtproxy/mtproto-proxy \
 && curl -fsSL https://core.telegram.org/getProxySecret  -o /opt/mtproxy/proxy-secret \
 && curl -fsSL https://core.telegram.org/getProxyConfig -o /opt/mtproxy/proxy-multi.conf \
 && chmod 0644 /opt/mtproxy/proxy-secret /opt/mtproxy/proxy-multi.conf
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
