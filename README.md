<div align="center">

<img src="https://em-content.zobj.net/source/microsoft-teams/363/high-voltage_26a1.png" width="88" alt="IranX Panel" />

# IranX Panel

### A single-file VLESS subscription panel that runs anywhere

Manage users, quotas and subscription links from one Python file.
Two transports, six themes, bilingual UI — no Xray core, no Docker, no VPS.

<p>
  <img src="https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite" />
  <img src="https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge" alt="MIT" />
</p>

<p>
  <img src="https://img.shields.io/badge/Railway-ready-0B0D0E?style=flat-square&logo=railway&logoColor=white" alt="Railway" />
  <img src="https://img.shields.io/badge/Render-ready-46E3B7?style=flat-square&logo=render&logoColor=black" alt="Render" />
  <img src="https://img.shields.io/badge/VLESS-WS%20%2B%20TLS-6366f1?style=flat-square" alt="WS+TLS" />
  <img src="https://img.shields.io/badge/VLESS-XHTTP%20%2B%20TLS-d946ef?style=flat-square" alt="XHTTP+TLS" />
</p>

**English** · [فارسی](README-fa.md)

</div>

---

## Why this exists

Most panels want a VPS, a domain, a certificate and an Xray binary. This one wants a
free PaaS account. The platform terminates TLS for you, so `main.py` implements the VLESS
inbounds in pure Python and relays TCP — nothing to install, nothing to renew.

```
┌──────────┐   wss:// or https://   ┌─────────────┐   TCP   ┌────────────┐
│  client  │ ─────────────────────▶ │  IranX Panel│ ──────▶ │ destination│
└──────────┘   TLS ends at the PaaS └─────────────┘         └────────────┘
```

---

## Features

<table>
<tr>
<td width="50%" valign="top">

**Access & security**
- Password-only login — the username is always `admin`
- You choose the password on **first visit**
- PBKDF2-SHA256, 200 000 rounds
- Rate-limited login, JWT session cookie
- Event log: logins, rejections, UUID rotations

</td>
<td width="50%" valign="top">

**Users**
- Create, edit, enable/disable, delete
- GB quota per user (`0` = unlimited)
- Expiry in days
- Device limit from **distinct active IPs**
- UUID rotation to kill a leaked config

</td>
</tr>
<tr>
<td valign="top">

**Transports**
- `VLESS + WS + TLS`
- `VLESS + XHTTP + TLS` *(packet-up)*
- Chosen per user: one, the other, or both
- Wrong transport for a user is refused

</td>
<td valign="top">

**Interface**
- Hamburger drawer, five sections
- Six themes, remembered per browser
- Bilingual FA / EN, RTL aware
- 24-hour traffic chart, transport split
- QR code for every subscription

</td>
</tr>
</table>

---

## Quick start

<details open>
<summary><b>Deploy on Railway</b></summary>

<br>

**1.** Fork this repository, or upload these files to a repo of your own.

**2.** [railway.app](https://railway.app) → **New Project** → **Deploy from GitHub repo** → pick it.

**3.** Open the **Variables** tab:

| Variable | Example | |
|---|---|---|
| `SECRET_KEY` | a long random string | **required** |
| `DOMAIN` | `myapp.up.railway.app` | **required** |
| `WS_PATH` | `ws` | optional |
| `XHTTP_PATH` | `xh` | optional |
| `DEVICE_WINDOW` | `300` | optional |
| `SESSION_IDLE` | `90` | optional |
| `DB_PATH` | `/tmp/panel.db` | optional |
| `ADMIN_PASSWORD` | — | optional, skips the setup page |

**4.** **Settings → Networking → Generate Domain**, put that value in `DOMAIN`, redeploy.

**5.** Open `https://your-domain/` — the setup page appears. Choose a password. Done.

> [!TIP]
> On a Trial plan the first build can sit in `QUEUED` for ten minutes before it even
> starts. That is normal — wait it out before assuming something broke.

</details>

<details>
<summary><b>Deploy on Render</b></summary>

<br>

Render reads `render.yaml` automatically. Create a **Web Service**, connect the repo,
then add `SECRET_KEY` and `DOMAIN` under Environment.

</details>

<details>
<summary><b>Any other ASGI host</b></summary>

<br>

```bash
pip install -r requirements.txt
gunicorn -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:$PORT --timeout 0
```

Anything that terminates TLS and forwards WebSocket upgrades will work.

</details>

---

## The panel

| Section | What's in it |
|:--|:--|
| **Dashboard** | Totals, 24-hour chart, WS/XHTTP split, live XHTTP session count |
| **Users** | Create, list, edit, per-user configs and IP list |
| **Clean IP** | Single and bulk add, enable/disable, delete |
| **Panel settings** | Theme, language, change password, server info |
| **Events** | Login attempts, refused connections, UUID rotations |

---

## Transports

Each user is set to one mode:

| Mode | What lands in their subscription |
|:--|:--|
| `WS + TLS` | only `type=ws` configs |
| `XHTTP + TLS` | only `type=xhttp` configs, `mode=packet-up` |
| **Both** | both kinds, plus one of each per Clean IP |

```
WebSocket   wss://<domain>/<WS_PATH>          default /ws
XHTTP       https://<domain>/<XHTTP_PATH>/…   default /xh
```

The two paths must differ.

> [!WARNING]
> **XHTTP is experimental.** It is implemented as `packet-up`: numbered `POST` requests
> for the uplink, one streamed `GET` for the downlink, with a reorder buffer for
> out-of-order chunks. If any proxy or CDN in the path buffers responses, the downlink
> stalls. **WS is the reliable route** — if a user has trouble, switch them to WS.

---

## Clean IP

Add clean addresses once; they are appended to **every** user's subscription as extra
configs. The connection address becomes the clean IP while `sni` and `host` stay on your
real domain.

Bulk input takes one entry per line, label after `#`:

```
104.16.132.229  # Irancell
172.67.72.14    # MCI
cdn.example.com # Backup
188.114.97.3
```

Use ⏸ to disable an address without deleting it.

---

## Subscription output

The first entry is an **info config** — non-functional, present only so the client
displays the account state at the top of the list:

```
📊 ali_home | 20.50GB | 22Days
🌐 ali_home · WS · Default
⚡ ali_home · Irancell · WS
🌐 ali_home · XHTTP · Default
⚡ ali_home · Irancell · XHTTP
```

It points at port 80 with `security=none` on a path both inbounds ignore, so it can never
be dialled. The `subscription-userinfo` header is also set, so Hiddify and Streisand show
quota and expiry in their own UI as well.

---

## Killing a leaked config

**Users → Edit:**

- **New UUID** — fresh random UUID, and the IP list is cleared
- **Custom UUID** — any UUID you choose

Old configs stop working immediately. The subscription link is unchanged, so the user only
needs to refresh their subscription.

---

## How the device limit works

Every source IP is recorded with its protocol and counts as an active device for
`DEVICE_WINDOW` seconds after its last connection. Once the limit is reached, a new IP is
refused. The **IPs** button shows the exact list with online state and protocol per device.

> [!NOTE]
> Several devices behind one home router share a single IP and count as one device. That
> is inherent to IP-based counting, not a bug.

---

## Repository

```
main.py             core — FastAPI, both inbounds, embedded UI
requirements.txt    pinned dependencies
Procfile            start command for Railway / Render / Heroku
railway.json        Railway deploy config
render.yaml         Render blueprint
panel-config.toml   environment variable reference
```

---

## Good to know

- **The database on `/tmp` is ephemeral** and wiped on every redeploy. For persistence,
  attach a volume and set `DB_PATH=/data/panel.db`.
- **UDP is not supported** — TCP only. Set DNS to DoH in your client.
- Upgrading from an older version is safe: new columns are added automatically via
  `ALTER TABLE`.
- Your host bills you for the bandwidth your users consume. Watch the billing dashboard.
- Built for personal and educational use.

---

<div align="center">

**MIT** · issues and pull requests welcome

</div>
