<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:7C5CFF,50:2F83F6,100:22C58C&height=190&section=header&text=IranX%20Panel&fontSize=54&fontColor=ffffff&fontAlignY=36&desc=One%20Python%20file.%20Zero%20VPS.%20Full%20VLESS%20panel.&descAlignY=58&descSize=17" alt="IranX Panel" width="100%" />

<h3>⚡ A single-file VLESS subscription panel that runs anywhere</h3>

<p>
Manage users, quotas, device limits and subscription links from <b>one</b> Python file.<br/>
Two transports · six themes · bilingual UI — <b>no Xray core, no Docker, no VPS, no certificates.</b>
</p>

<p>
<img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
<img src="https://img.shields.io/badge/FastAPI-ASGI-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
<img src="https://img.shields.io/badge/VLESS-WS%20%2B%20XHTTP-7C5CFF?style=for-the-badge" alt="VLESS" />
<img src="https://img.shields.io/badge/License-MIT-22C58C?style=for-the-badge" alt="MIT" />
</p>

<p>
<img src="https://img.shields.io/badge/Railway-ready-0B0D0E?style=flat-square&logo=railway&logoColor=white" alt="Railway" />
<img src="https://img.shields.io/badge/Render-ready-46E3B7?style=flat-square&logo=render&logoColor=white" alt="Render" />
<img src="https://img.shields.io/badge/Cloudflare-relay%20optional-F38020?style=flat-square&logo=cloudflare&logoColor=white" alt="Cloudflare" />
<img src="https://img.shields.io/github/stars/BeeEhsas/IranXPanel?style=flat-square&color=FFD166" alt="Stars" />
<img src="https://img.shields.io/github/last-commit/BeeEhsas/IranXPanel?style=flat-square&color=2F83F6" alt="Last commit" />
</p>

<h3>
<a href="https://iranxpanel.cvtlwdm.workers.dev/">🚀 One-Click Auto Deployer</a>
&nbsp;·&nbsp;
<a href="#-quick-start">📦 Quick start</a>
&nbsp;·&nbsp;
<a href="README-fa.md">🇮🇷 فارسی</a>
</h3>

**English** · [فارسی](README-fa.md)

</div>

---

## 🚀 Install it without touching a terminal

<div align="center">

### <a href="https://iranxpanel.cvtlwdm.workers.dev/">🪄 IranX Deployer</a>

<a href="https://iranxpanel.cvtlwdm.workers.dev/">
<img src="https://img.shields.io/badge/Open%20IranX%20Deployer-Deploy%20in%202%20minutes-7C5CFF?style=for-the-badge&logo=rocket&logoColor=white" alt="Open IranX Deployer" />
</a>

<sub>https://iranxpanel.cvtlwdm.workers.dev/</sub>

</div>

The deployer is a **single web page** that builds the whole thing for you: it creates the
project on your hosting account, sets every environment variable, generates the domain,
and hands you back a working panel URL and password. No CLI, no `git clone`, no YAML.

| What it does | Detail |
|:--|:--|
| 🚄 **Railway or Render** | Pick your provider, paste an API token, press start |
| 🏷️ **Project name & workspace** | Loads your workspaces and server locations from the API |
| 🔑 **Panel password** | Type your own, or leave it blank for a generated one |
| ♻️ **Anti-sleep (Render Free)** | Pings itself every 10 minutes so the free service never sleeps |
| 🟠 **Cloudflare relay** | Optionally creates a Worker in *your own* Cloudflare account and points the configs at it instead of the host domain |
| 🔐 **Token hygiene** | The token is used in-memory for that single request — never stored, never logged |

<div align="center">

```mermaid
flowchart LR
    U["🧑 You"] -->|"API token"| D["🪄 IranX Deployer<br/>workers.dev page"]
    D -->|"create project + env vars"| H["🚄 Railway / 🎨 Render"]
    H -->|"builds main.py"| P["🛡️ IranX Panel<br/>https://your-app"]
    D -.->|"optional"| W["🟠 Cloudflare Worker<br/>relay in your account"]
    W -.-> P

    style U fill:#7C5CFF,stroke:#9B81FF,color:#fff
    style D fill:#2F83F6,stroke:#57A5FF,color:#fff
    style H fill:#0B0D0E,stroke:#46E3B7,color:#fff
    style P fill:#22c58c,stroke:#43E0A8,color:#fff
    style W fill:#F38020,stroke:#FFA257,color:#fff
```

</div>

> [!IMPORTANT]
> **One prerequisite for Railway:** Railway must be allowed to read a GitHub repo — even a
> public one. Go to **Account Settings → Integrations → GitHub** once and connect it.
> After the install finishes, delete the API token from your dashboard and create a fresh one.

> [!TIP]
> **Railway for anything serious.** Render's free plan sleeps after 15 minutes and wipes the
> `/tmp` database when it wakes — users and quotas disappear. Railway does not sleep and
> accepts a persistent disk.

---

## 💡 Why this exists

Most panels want a VPS, a domain, a certificate and an Xray binary. This one wants a
**free PaaS account**. The platform terminates TLS for you, so `main.py` implements the
VLESS inbounds in pure Python and relays TCP — nothing to install, nothing to renew.

<div align="center">

```mermaid
flowchart LR
    A["📱 Client<br/>v2rayNG · Hiddify"]
    B["🟠 Cloudflare relay<br/>optional"]
    C["🛡️ IranX Panel<br/>Railway · Render"]
    D["🌍 Destination"]

    A -->|"wss:// or https://"| B
    A -.->|"direct"| C
    B -->|"HTTPS"| C
    C -->|"TCP"| D

    style A fill:#7C5CFF,stroke:#9B81FF,color:#fff
    style B fill:#F38020,stroke:#FFA257,color:#fff
    style C fill:#2F83F6,stroke:#57A5FF,color:#fff
    style D fill:#22c58c,stroke:#43E0A8,color:#fff
```

</div>

TLS terminates at the platform's edge, so `main.py` only ever speaks plain VLESS over an
already-encrypted stream. The relay is optional — add it when the host's own domain is
unreachable from your network.

---

## ✨ Features

<table>
<tr>
<td width="50%" valign="top">

### 🔐 Access & security
- Password-only login — username is always `admin`
- You choose the password on **first visit**
- PBKDF2-SHA256, 200 000 rounds
- Rate-limited login, JWT session cookie
- Event log: logins, rejections, UUID rotations

</td>
<td width="50%" valign="top">

### 👥 Users
- Create, edit, enable/disable, delete
- GB quota per user (`0` = unlimited)
- Expiry in days
- Device limit from **distinct active IPs**
- UUID rotation to kill a leaked config

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🔀 Transports
- `VLESS + WS + TLS`
- `VLESS + XHTTP + TLS` *(packet-up)*
- Chosen per user: one, the other, or both
- Wrong transport for a user is refused

</td>
<td width="50%" valign="top">

### 🎨 Interface
- Hamburger drawer, five sections
- **Six themes**, remembered per browser
- Bilingual FA / EN, RTL aware
- 24-hour traffic chart, transport split
- QR code for every subscription

</td>
</tr>
</table>

---

## 🖼️ Screenshots

<div align="center">

<!-- Drop your images in docs/ with these names and the gallery below fills itself in -->

| 📊 Dashboard | 👥 Users |
|:--:|:--:|
| <img src="docs/dashboard.png" alt="Dashboard" width="420" /> | <img src="docs/users.png" alt="Users" width="420" /> |

| 🧊 Clean IP | 🎨 Themes |
|:--:|:--:|
| <img src="docs/clean-ip.png" alt="Clean IP" width="420" /> | <img src="docs/themes.png" alt="Themes" width="420" /> |

<sub>Six themes, light and dark, FA/EN with full RTL support.</sub>

</div>

---

## 📦 Quick start

<details open>
<summary><b>🪄 Option A — IranX Deployer (recommended)</b></summary>

<br/>

1. Open **[IranX Deployer](https://iranxpanel.cvtlwdm.workers.dev/)**
2. Choose **Railway** or **Render**
3. Paste your provider API token, pick a project name, load your workspace and location
4. Optionally set a panel password, enable anti-sleep, or add a Cloudflare relay
5. Press **Start** — you get the panel URL and login password at the end

</details>

<details>
<summary><b>🚄 Option B — Railway by hand</b></summary>

<br/>

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
<summary><b>🎨 Option C — Render</b></summary>

<br/>

Render reads `render.yaml` automatically. Create a **Web Service**, connect the repo,
then add `SECRET_KEY` and `DOMAIN` under Environment.

</details>

<details>
<summary><b>🐍 Option D — Any other ASGI host</b></summary>

<br/>

```bash
pip install -r requirements.txt
gunicorn -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:$PORT --timeout 0
```

Anything that terminates TLS and forwards WebSocket upgrades will work.

</details>

---

## 🧭 The panel

| Section | What's in it |
|:--|:--|
| 📊 **Dashboard** | Totals, 24-hour chart, WS/XHTTP split, live XHTTP session count |
| 👥 **Users** | Create, list, edit, per-user configs and IP list |
| 🧊 **Clean IP** | Single and bulk add, enable/disable, delete |
| ⚙️ **Panel settings** | Theme, language, change password, server info |
| 📝 **Events** | Login attempts, refused connections, UUID rotations |

---

## 🔀 Transports

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

## 🧊 Clean IP

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

## 📬 Subscription output

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

## 🔄 Killing a leaked config

**Users → Edit:**

- 🎲 **New UUID** — fresh random UUID, and the IP list is cleared
- ✍️ **Custom UUID** — any UUID you choose

Old configs stop working immediately. The subscription link is unchanged, so the user only
needs to refresh their subscription.

---

## 📱 How the device limit works

Every source IP is recorded with its protocol and counts as an active device for
`DEVICE_WINDOW` seconds after its last connection. Once the limit is reached, a new IP is
refused. The **IPs** button shows the exact list with online state and protocol per device.

> [!NOTE]
> Several devices behind one home router share a single IP and count as one device. That
> is inherent to IP-based counting, not a bug.

---

## 🗂️ Repository

```
main.py             core — FastAPI, both inbounds, embedded UI
requirements.txt    pinned dependencies
Procfile            start command for Railway / Render / Heroku
railway.json        Railway deploy config
render.yaml         Render blueprint
panel-config.toml   environment variable reference
```

---

## ℹ️ Good to know

- 💾 **The database on `/tmp` is ephemeral** and wiped on every redeploy. For persistence,
  attach a volume and set `DB_PATH=/data/panel.db`.
- 🚫 **UDP is not supported** — TCP only. Set DNS to DoH in your client.
- ⬆️ Upgrading from an older version is safe: new columns are added automatically via
  `ALTER TABLE`.
- 💳 Your host bills you for the bandwidth your users consume. Watch the billing dashboard.
- 📚 Built for personal and educational use.
- ⚠️ Cloudflare's free Workers plan allows 100 000 requests/day, and proxying general
  traffic through Workers is against Cloudflare's terms — use the relay responsibly.

---

<div align="center">

### ⭐ If this saved you a VPS bill, drop a star

<a href="https://iranxpanel.cvtlwdm.workers.dev/">
<img src="https://img.shields.io/badge/Deploy%20now-IranX%20Deployer-22C58C?style=for-the-badge&logo=rocket&logoColor=white" alt="Deploy now" />
</a>

**MIT** · issues and pull requests welcome

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:22C58C,50:2F83F6,100:7C5CFF&height=120&section=footer" width="100%" alt="" />

</div>
