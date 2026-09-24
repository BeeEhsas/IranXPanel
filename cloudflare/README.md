<div align="center">

# IranX Panel

### نصب دستی روی Cloudflare Workers + D1

[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?style=flat-square&logo=cloudflare&logoColor=white)](#)
[![D1 Database](https://img.shields.io/badge/D1-Database-005DAA?style=flat-square&logo=cloudflare&logoColor=white)](#)
[![VLESS WebSocket](https://img.shields.io/badge/VLESS-WebSocket-7C5CFF?style=flat-square&logo=protonmail&logoColor=white)](#)

**رابط فارسی:** [README-fa.md](README-fa.md) · **English:** [English](README.md)

</div>

---

## Overview

Deploy the IranX management panel manually in the Cloudflare Dashboard. This public repository contains only the ready-to-use Worker, the D1 schema, and installation documentation. The private Auto-Deployer is not part of this repository.

### What you need

- A Cloudflare account
- Approximately five minutes
- The three public files in this repository

### What you configure

You only need to:

1. Create the Worker and D1 database.
2. Connect the database to the Worker.
3. Open the panel and choose your admin password.

The panel generates its own session secret, detects its public `workers.dev` hostname, and uses sensible WebSocket path defaults. You do **not** need to create `SECRET_KEY`, `DOMAIN`, `RELAY_DOMAIN`, or any other environment variable.

---

## Installation

### 1 — Create the Worker

1. Open [Cloudflare Dashboard](https://dash.cloudflare.com/).
2. Go to **Workers & Pages**.
3. Create a Worker with a short name such as `iranx-panel`.
4. Open **Edit code** and replace the starter code with the entire contents of [`index.js`](index.js).
5. Open **Settings → Runtime → Compatibility flags**.
6. Enable:

```text
nodejs_compat
```

> `nodejs_compat` is required. Do not skip it.

### 2 — Create the D1 database

1. In Cloudflare Dashboard, open **Storage & Databases → D1 SQL Database**.
2. Create a database, for example `iranx-panel-db`.
3. Open its **Console**.
4. Open [`schema.sql`](schema.sql) locally, copy the entire file, paste it into the D1 Console, and run it.
5. Confirm that the panel tables are created before continuing.

### 3 — Connect D1 to the Worker

Return to the Worker's **Settings → Bindings → Add → D1 Database**.

Configure it as follows:

| Field | Value |
|---|---|
| Variable name | `DB` |
| D1 database | The database created in step 2 |

The variable name **must be exactly `DB`**.

### 4 — Deploy and set your password

1. Click **Deploy**.
2. Open the resulting `https://<worker>.<account>.workers.dev` address.
3. Enter your admin password twice.
4. Use at least 8 characters with an uppercase letter, a lowercase letter, and a number.

The admin username is always:

```text
admin
```

The password is hashed with PBKDF2-SHA256 and stored in D1. It is never placed in the public repository.

---

## Verify the installation

After setup, check the following:

- `/healthz` returns `{"ok":true,"platform":"cloudflare"}`.
- `/setup` opens only before the first password is set.
- The admin can create a user and download a subscription.
- The WebSocket endpoint is available at `/ws`.
- Generated subscription links use the Worker's public hostname automatically.

You can open the health endpoint directly:

```text
https://<worker>.<account>.workers.dev/healthz
```

---

## Security checklist

- Never commit Cloudflare API tokens, account IDs, passwords, or secret values.
- Use a unique administrator password.
- Do not share the D1 database binding with an unrelated Worker.
- Delete and recreate any credential that has appeared in a public commit or log.
- Review Cloudflare usage before inviting many users.

---

## Important limitations

- Workers Free has request and concurrency limits.
- `workers.dev` may be blocked on some networks, including some regions in Iran.
- The operational Cloudflare transport is VLESS over WebSocket.
- XHTTP is represented in the panel model but is not yet complete for production use on this Worker edition.
- Use must comply with Cloudflare's terms and applicable local laws.

---

## Repository contents

```text
.
├── index.js       # Ready-to-paste Cloudflare Worker
├── schema.sql     # D1 database schema
├── README.md      # English installation guide
└── README-fa.md   # Persian installation guide
```

The private Auto-Deployer source and generated Worker are intentionally excluded.
