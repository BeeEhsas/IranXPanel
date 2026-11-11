# tproxy/ — the WEB-proxy endpoint the panel deploys

This folder is a complete single-container Telegram **WEB proxy** endpoint. The panel's
«وب‌پروکسی تلگرام» page builds a service from *this repository, this subdirectory* on
**Render or Railway** whenever you create a proxy with a platform selected, sets its
environment (`TGP_SECRET`, `TGP_PUBLIC_HOSTNAME`, `TGP_CARRIER`), and issues the
`https://t.me/webproxy?server=<host>&secret=<32hex>` link once the deploy is live.

## What runs in the container

| Piece | Source | Role |
| --- | --- | --- |
| `tproxy-server` | official `telegramdesktop/tproxy-server`, pinned commit `c8adb8b…` | the WEB-proxy relay Telegram Desktop 7.1+ talks to (HTTPS/WebSocket carriers, bridge page, capability checks) |
| `mtproto-proxy` | official `TelegramMessenger/MTProxy`, the same pinned commit + sha256 the upstream installer verifies | loopback backend on `127.0.0.1:2398`; the relay dials it per logical stream |
| `site/index.html` | this folder | the neutral page unauthenticated visitors get (active-probing cover) |
| `edge.go` | this folder | the in-container L7 edge (`tproxy-edge`): canonical `Host` rewrite + one-address XFF, WS/streaming passthrough |

TLS terminates at the platform edge, so the relay serves **plain HTTP/WebSocket on
`$PORT`** — the same job Caddy does in the official reference deployment. On
Railway/Render the front is `edge.go` (built as `tproxy-edge`), not a raw TCP pipe:
the relay accepts authenticated traffic only when it receives the canonical public
hostname in `Host` and **exactly one** address in `X-Forwarded-For` — PaaS edges
deliver neither (Railway rewrites `Host` and appends client-supplied XFF entries,
which Iranian carriers inject). The edge rewrites `Host` to `TGP_PUBLIC_HOSTNAME`
and collapses XFF to the platform edge's observed client IP on every request;
WebSocket upgrades and streaming bodies pass through untouched.

## Environment variables

| Variable | Meaning |
| --- | --- |
| `TGP_SECRET` | the client-facing 32-hex MTProxy secret (the panel rotates it on request) |
| `TGP_PUBLIC_HOSTNAME` | bare public host, e.g. `myproxy.onrender.com` — must match the host stored by the client, since the bridge capability is derived from it |
| `TGP_CARRIER` | `https`, `https-lanes`, `websocket`, `websocket-lanes` (default `websocket`) |
| `TGP_PAUSED` | `1` = idle without a listener (panel pause; hostname and links survive) |
| `PORT` | relay listen port (Render injects it; default `8080`) |

## Notes

* The container detects 1:1 NAT and passes `--nat-info <local>:<public>` to MTProxy
  (Render/Railway containers are always NATed; without it MTProxy silently serves no one).
* `proxy-secret` / `proxy-multi.conf` are fetched at build time and refreshed on every
  container start (bundled copies are used when `core.telegram.org` is unreachable).
* Deploy logs are the best debugging tool: the entrypoint prints NAT detection, the
  chosen carrier, and the relay's startup line.
* To update the proxies after pushing changes to this folder, use the panel's
  redeploy/sync actions — Render proxies are created with auto-deploy off so a secret
  rotation never triggers two builds.
* The hosting region is picked in the panel when the proxy is created (a region select
  next to the carrier): Render offers `frankfurt / oregon / ohio / virginia / singapore`
  and the choice is final at create time (Render cannot move a service afterwards);
  Railway offers `europe-west4-drams3a (Amsterdam) / us-west2 / us-east4-eqdc4a /
  asia-southeast1-eqsg3a` and can be changed later from the proxy's edit dialog —
  the service redeploys in the new region and keeps its domain, so issued links stay
  valid.
* Deploy problems now surface in the panel instead of sticking on «در حال ساخت»:
  before touching the platform the panel checks `tproxy/Dockerfile` on
  raw.githubusercontent.com and fails the row in seconds when the folder was never
  pushed; Railway's `source.repo` gets the `owner/repo` slug (a full GitHub URL is
  rejected by the API); if the platform reports no deployment at all, or the build
  ends in FAILED/CRASHED/SLEEPING/SKIPPED, the row turns red with that reason.
  Railway also needs its GitHub App installed for the repo (Account Settings →
  Integrations) — a build will never start without it.
* The panel itself auto-detects its host (Railway/Render marker env vars): it then
  only asks for that platform's API token and only offers that platform for new
  proxies. `TGPW_SELF_PLATFORM` overrides, unset = both platforms offered.
