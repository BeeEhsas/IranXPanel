<div align="center">

# ⚡ IranX Panel

**Single-file subscription panel — VLESS + WS + TLS and VLESS + XHTTP + TLS**

FastAPI + SQLite · No Docker · Railway / Render

[فارسی](README-fa.md) · **English**

</div>

---

## ✨ Features

- 🔑 **Password-only login** — the username is always `admin` and is never asked for
- 🆕 Password is chosen by you on the **first visit** (PBKDF2-SHA256, 200k rounds)
- ☰ **Hamburger drawer** with five separate sections
- 🔀 **Per-user transport**: WS + TLS, XHTTP + TLS, or both
- 👥 Full user CRUD with GB quota, expiry in days, enable/disable
- 📱 Device limit based on **distinct active source IPs**
- 🔄 UUID rotation (random or manual) to kill a leaked config
- 🧊 Clean IP manager — single and bulk add
- 🔗 Subscription link with an **info entry** showing username, remaining quota and days
- 🌗 Six themes · 🌐 Bilingual FA / EN
- 📊 24-hour traffic chart, transport split, event log

---

## ☰ Panel sections

| Section | Contents |
|---|---|
| 📊 **Dashboard** | Totals, 24h chart, WS/XHTTP split, live XHTTP session count |
| 👥 **Users** | Create, list, edit, configs, per-user IP list |
| 🧊 **Clean IP** | Single & bulk add, enable/disable, delete |
| ⚙️ **Panel settings** | Theme, language, change password, server info |
| 📜 **Events** | Login attempts, rejected connections, UUID rotations |

---

## 🔀 Two transports

Each user is set to one of three modes:

| Mode | Result in the subscription |
|---|---|
| 🔌 **WS + TLS** | only `type=ws` configs |
| 🚀 **XHTTP + TLS** | only `type=xhttp` configs (`mode=packet-up`) |
| 🔀 **Both** | both kinds, including one of each per Clean IP |

If a user is set to `ws` and connects with an XHTTP config, the connection is rejected (and vice versa).

**Paths**

- WebSocket → `wss://<domain>/<WS_PATH>` (default `/ws`)
- XHTTP → `https://<domain>/<XHTTP_PATH>/...` (default `/xh`)

The two must differ.

> ⚠️ **XHTTP is experimental.** It is implemented in `packet-up` mode: numbered POST
> requests for the uplink, one streamed GET for the downlink. If a proxy or CDN in the
> path buffers responses, the downlink will stall. WS is the more reliable route — if you
> hit trouble, switch the user to WS.

---

## 🚀 Deploy on Railway

1. Put these files in a GitHub repository.
2. railway.app → **New Project** → **Deploy from GitHub repo** → pick your repo.
3. Open the **Variables** tab and add:

| Variable | Example | Required |
|---|---|---|
| `SECRET_KEY` | a long random string | ✅ |
| `DOMAIN` | `myapp.up.railway.app` | ✅ |
| `WS_PATH` | `ws` | optional |
| `XHTTP_PATH` | `xh` | optional |
| `DEVICE_WINDOW` | `300` | optional |
| `SESSION_IDLE` | `90` | optional |
| `DB_PATH` | `/tmp/panel.db` | optional |
| `ADMIN_PASSWORD` | — | optional (skips the setup page) |

4. **Settings → Networking → Generate Domain**, put that value in `DOMAIN`, then redeploy.
5. Open `https://your-domain/` — the setup page appears, choose a password, done.

Start command (all platforms):

```
gunicorn -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:$PORT --timeout 0
```

---

## 🧊 Clean IP

**Single:** address + label → Add

**Bulk:** one per line, label after `#`:

```
104.16.132.229 # Irancell
172.67.72.14   # MCI
cdn.example.com # Backup
188.114.97.3
```

Every enabled Clean IP is appended to all subscriptions as an extra config — the
connection address becomes the Clean IP while `sni` and `host` stay on your real domain.

---

## 🔗 Subscription output

```
📊 ali_home | 20.50GB | 22Days
🌐 ali_home · WS · Default
⚡ ali_home · Irancell · WS
🌐 ali_home · XHTTP · Default
⚡ ali_home · Irancell · XHTTP
```

The first line is an **info entry**: a non-functional config whose name carries the
username, remaining quota and days left. It points at port 80 with `security=none` on a
path both inbounds ignore, so it can never actually be dialled — it only ever renders as a
label at the top of the user's config list.

The `subscription-userinfo` header is also set, so clients like Hiddify and Streisand show
quota and expiry in their own UI as well.

---

## 🔄 Killing a leaked config

Users → **Edit**:

- **New UUID** → fresh random UUID, plus the IP list is cleared
- or the **Custom UUID** field → any UUID you choose

Old configs stop working immediately. The subscription link does not change, so the user
only needs to update their subscription.

---

## 📱 How the device limit works

Every source IP is recorded in `user_ips` along with its protocol (ws or xhttp), and counts
as an active device for `DEVICE_WINDOW` seconds after its last connection. Once the limit is
reached, connections from a new IP are refused. The **IPs** button shows the exact list with
online/offline state and protocol per device.

> Several devices behind one home router share a single IP and count as one device — an
> inherent limitation of IP-based counting.

---

## 📁 Repository structure

| File | Purpose |
|---|---|
| `main.py` | Core: FastAPI backend, both inbounds, embedded UI |
| `requirements.txt` | Pinned Python dependencies |
| `Procfile` | Start command for Railway / Render / Heroku |
| `railway.json` | Railway deploy config |
| `render.yaml` | Render blueprint |
| `panel-config.toml` | Environment variable reference |
| `README.md` / `README-fa.md` | Docs |

`ui-preview-*.html` are offline UI previews with mock data. They are not needed to run the panel.

---

## ⚠️ Notes

- The database on `/tmp` is **ephemeral** and wiped on every redeploy. For persistence,
  create a Railway volume and set `DB_PATH=/data/panel.db`.
- Upgrading from an earlier version is safe — new columns (`transport`, `proto`) are added
  automatically via `ALTER TABLE`.
- **UDP is not supported** (TCP only). Set DNS to DoH in your client.
- TLS is terminated by the hosting platform, so no Xray core installation is needed.
- Your host bills you for the bandwidth your users consume — watch the billing dashboard.
- Intended for personal and educational use.

---

## 📄 License

MIT
