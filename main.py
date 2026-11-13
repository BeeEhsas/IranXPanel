"""
IranX Panel v3  —  VLESS over WebSocket+TLS  and  VLESS over XHTTP+TLS
----------------------------------------------------------------------
Single-file FastAPI panel.  Deploy on Railway / Render / any ASGI host.

The hosting platform terminates TLS, so clients speak:
    wss://<domain>/<WS_PATH>                      →  type=ws
    https://<domain>/<XHTTP_PATH>/<session>       →  type=xhttp

XHTTP uplink shape depends on the client's `mode`, and all of them are served:
    stream-up   POST /<XHTTP_PATH>/<session>          one long-lived streamed body
    packet-up   POST /<XHTTP_PATH>/<session>/<seq>    one request per upload chunk

Request cost, when a Cloudflare Worker relay sits in front:
    ws          1 request per connection, for the whole life of the tunnel
    stream-up   2 requests per connection (one GET downlink + one POST uplink)
    packet-up   1 GET plus one POST per uploaded chunk — an active client can be
                hundreds of requests a minute, which drains a Worker's daily quota

XHTTP_MODE picks what the generated configs advertise; it defaults to stream-up.
Both uplink shapes stay accepted regardless, so configs already in the wild keep
working after an upgrade.

Both inbounds are implemented in pure Python and share one VLESS session core.

Login model:
  * username is always "admin" (never asked for)
  * on first visit you choose the password, stored hashed in SQLite
  * every later login needs the password only
"""

import html
import json
import os
import re
import time
import uuid
import base64
import asyncio
import hashlib
import gzip
import secrets
import struct
import socket
import sqlite3
import ipaddress
from urllib.parse import quote, unquote, urlencode
import urllib.request
import urllib.error
from contextlib import asynccontextmanager
from typing import Optional, Callable, Awaitable, Any

import jwt
from fastapi import (FastAPI, Request, WebSocket, HTTPException, Depends,
                     Cookie, Body)
from fastapi.responses import (HTMLResponse, JSONResponse, PlainTextResponse,
                               RedirectResponse, StreamingResponse, Response)
from starlette.requests import ClientDisconnect
from pydantic import BaseModel

# ────────────────────────────── CONFIG ──────────────────────────────

ADMIN_USERNAME = "admin"
SECRET_KEY     = os.getenv("SECRET_KEY", secrets.token_hex(32))
DOMAIN         = os.getenv("DOMAIN", "")

# When the host's own domain is unreachable from some networks, a relay (e.g. a
# Cloudflare Worker) can sit in front. The panel still runs on DOMAIN, but every config
# and subscription link it hands out points at RELAY_DOMAIN instead.
RELAY_DOMAIN   = os.getenv("RELAY_DOMAIN", "").replace("https://", "").replace("http://", "").strip("/")
# On Railway the deployer mounts a persistent volume at /data; prefer it automatically
# so the database survives redeploys even without an explicit DB_PATH (Railway wipes
# everything outside a volume on every deploy). /tmp stays the default on hosts that
# have no volume.
DB_PATH        = os.getenv("DB_PATH", "/data/panel.db" if os.path.isdir("/data") else "/tmp/panel.db")
WS_PATH        = os.getenv("WS_PATH", "ws").strip("/")
XHTTP_PATH     = os.getenv("XHTTP_PATH", "xh").strip("/")
PANEL_TITLE    = os.getenv("PANEL_TITLE", "IranX Panel")
BOOTSTRAP_PASS = os.getenv("ADMIN_PASSWORD", "")

DEVICE_WINDOW  = int(os.getenv("DEVICE_WINDOW", "300"))   # counts toward the device limit
IP_WINDOW      = int(os.getenv("IP_WINDOW", "300"))       # counts toward the IP limit
LIVE_WINDOW    = int(os.getenv("LIVE_WINDOW", "60"))      # shown as "connected right now"
SESSION_IDLE   = int(os.getenv("SESSION_IDLE", "90"))     # xhttp session reaper

# Self-ping, for hosts that idle a service out (Render's free plan does after ~15 min).
# Read the caveats in the README before switching this on.
KEEPALIVE       = os.getenv("KEEPALIVE", "").strip().lower() in ("1", "true", "yes", "on")
KEEPALIVE_MINS  = max(1, int(os.getenv("KEEPALIVE_MINUTES", "10")))

JWT_ALG, JWT_TTL, GB = "HS256", 60 * 60 * 12, 1024 ** 3
TRANSPORTS = ("ws", "xhttp", "both")

# XHTTP uplink shape advertised in generated configs.
#   stream-up  — the whole uplink is one long-lived POST: 2 requests per connection.
#   packet-up  — one POST per upload chunk: hundreds of requests a minute per client,
#                which is what drains a Cloudflare Worker relay's daily quota.
# The server accepts both shapes no matter what this is set to, so existing configs
# keep working; this only decides what new links tell clients to use.
XHTTP_MODES = ("stream-up", "packet-up")
XHTTP_MODE = os.getenv("XHTTP_MODE", "stream-up").strip().lower()
if XHTTP_MODE not in XHTTP_MODES:
    XHTTP_MODE = "stream-up"

# Transports whose request count scales with traffic rather than with connections.
COSTLY_TRANSPORTS = ("xhttp", "both")

# ────────────────────────────── DATABASE ──────────────────────────────

def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    UNIQUE NOT NULL,
    uuid         TEXT    UNIQUE NOT NULL,
    sub_token    TEXT    UNIQUE NOT NULL,
    note         TEXT    DEFAULT '',
    enabled      INTEGER DEFAULT 1,
    quota_bytes  INTEGER DEFAULT 0,
    used_bytes   INTEGER DEFAULT 0,
    expire_at    INTEGER DEFAULT 0,
    device_limit INTEGER DEFAULT 1,
    ip_limit     INTEGER DEFAULT 0,
    transport    TEXT    DEFAULT 'both',
    obfuscate    INTEGER DEFAULT 0,
    ech          INTEGER DEFAULT 0,
    fp           TEXT    DEFAULT 'unsafe',
    alpn         TEXT    DEFAULT '',
    ech_value    TEXT    DEFAULT '',
    obf_cs       TEXT    DEFAULT '',
    obf_fm       TEXT    DEFAULT '',
    reset_days   INTEGER DEFAULT 0,
    last_reset   INTEGER DEFAULT 0,
    created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS clean_ips (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    address  TEXT UNIQUE NOT NULL,
    remark   TEXT DEFAULT '',
    country  TEXT DEFAULT '',
    enabled  INTEGER DEFAULT 1,
    added_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS proxies (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT    DEFAULT 'socks5',
    host         TEXT    NOT NULL,
    port         INTEGER NOT NULL,
    username     TEXT    DEFAULT '',
    password     TEXT    DEFAULT '',
    remark       TEXT    DEFAULT '',
    country      TEXT    DEFAULT '',
    country_name TEXT    DEFAULT '',
    city         TEXT    DEFAULT '',
    isp          TEXT    DEFAULT '',
    exit_ip      TEXT    DEFAULT '',
    healthy      INTEGER DEFAULT 0,
    latency_ms   INTEGER DEFAULT 0,
    last_error   TEXT    DEFAULT '',
    checked_at   INTEGER DEFAULT 0,
    enabled      INTEGER DEFAULT 1,
    added_at     INTEGER NOT NULL,
    UNIQUE(kind, host, port, username)
);
-- Telegram WEB-proxy entries. Telegram's new client proxy type "WEB" tunnels MTProto
-- through an HTTPS/WebSocket front (a tproxy server), joined via
-- https://t.me/webproxy?server=<host>&secret=<32hex> links. The panel keeps the issuance
-- inventory: one row per endpoint handed out, each with its own secret and an optional
-- traffic/time budget. A row is either "external" (the endpoint already runs somewhere
-- and only its bare domain is stored) or "render"/"railway" — the panel then owns a real
-- service on that platform built from the repo's tproxy/ folder, stores the platform
-- service id + coordinates, and rotates/pauses/deletes it through the platform API.
-- Rotating a secret invalidates every link issued before it.
CREATE TABLE IF NOT EXISTS tg_web_proxies (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    label        TEXT    DEFAULT '',
    server       TEXT    DEFAULT '',
    secret       TEXT    UNIQUE NOT NULL,
    quota_bytes  INTEGER DEFAULT 0,
    used_bytes   INTEGER DEFAULT 0,
    expire_at    INTEGER DEFAULT 0,
    enabled      INTEGER DEFAULT 1,
    note         TEXT    DEFAULT '',
    created_at   INTEGER NOT NULL,
    platform     TEXT    DEFAULT 'external',
    service_id   TEXT    DEFAULT '',
    coords       TEXT    DEFAULT '',
    deploy_state TEXT    DEFAULT '',
    error        TEXT    DEFAULT '',
    usage_since  INTEGER DEFAULT 0,
    usage_checked INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS user_ips (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    ip         TEXT    NOT NULL,
    proto      TEXT    DEFAULT 'ws',
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    hits       INTEGER DEFAULT 1,
    UNIQUE(user_id, ip)
);
-- One row per detected client device. Identity is an opaque key derived from the
-- client IP plus its User-Agent, so the same phone always lands on the same row and a
-- second device (different app or different IP) gets its own. `device_limit` counts
-- these rows inside DEVICE_WINDOW.
--
-- Device limit and IP limit are two independent gates:
--   * device_limit identifies and registers every Nth device identity and only lets
--     those devices connect (0 = unlimited);
--   * ip_limit counts distinct source IPs observed in user_ips inside IP_WINDOW and
--     refuses a brand-new IP once the limit is reached (0 = unlimited).
CREATE TABLE IF NOT EXISTS devices (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    dkey       TEXT    NOT NULL,
    ip         TEXT    DEFAULT '',
    ua         TEXT    DEFAULT '',
    client     TEXT    DEFAULT '',
    platform   TEXT    DEFAULT '',
    proto      TEXT    DEFAULT 'ws',
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    hits       INTEGER DEFAULT 1,
    UNIQUE(user_id, dkey)
);
-- Outbound destination filter. The VLESS header carries the target host, so the panel
-- can refuse to dial a censored site before the connection is made.
CREATE TABLE IF NOT EXISTS filter_rules (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern  TEXT    NOT NULL,
    kind     TEXT    DEFAULT 'domain',   -- 'domain' = host or its subdomains, 'keyword' = anywhere
    note     TEXT    DEFAULT '',
    enabled  INTEGER DEFAULT 1,
    added_at INTEGER NOT NULL,
    UNIQUE(pattern)
);
CREATE TABLE IF NOT EXISTS traffic_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    ts      INTEGER NOT NULL,
    up      INTEGER DEFAULT 0,
    down    INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     INTEGER NOT NULL,
    event  TEXT,
    ip     TEXT,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_ips_user  ON user_ips(user_id, last_seen);
CREATE INDEX IF NOT EXISTS idx_dev_user  ON devices(user_id, last_seen);
CREATE INDEX IF NOT EXISTS idx_traf_user ON traffic_log(user_id, ts);
CREATE TABLE IF NOT EXISTS tg_platform_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    platform   TEXT    NOT NULL,            -- 'render' | 'railway'
    name       TEXT    DEFAULT '',          -- account/workspace label resolved from the token
    owner_id   TEXT    DEFAULT '',
    token      TEXT    NOT NULL,
    active     INTEGER DEFAULT 0,           -- one per platform is the deploy default
    created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tgpk_one_active
    ON tg_platform_keys(platform) WHERE active = 1;
"""


def now() -> int:
    return int(time.time())


def migrate():
    """Add columns that older databases may be missing."""
    wanted = {"users": [("transport", "TEXT DEFAULT 'both'"),
                        ("obfuscate", "INTEGER DEFAULT 0"),
                        ("ech", "INTEGER DEFAULT 0"),
                        ("fp", "TEXT DEFAULT 'unsafe'"),
                        ("alpn", "TEXT DEFAULT ''"),
                        ("ech_value", "TEXT DEFAULT ''"),
                        ("obf_cs", "TEXT DEFAULT ''"),
                        ("obf_fm", "TEXT DEFAULT ''"),
                        ("ip_limit", "INTEGER DEFAULT 0"),
                        ("reset_days", "INTEGER DEFAULT 0"),
                        ("last_reset", "INTEGER DEFAULT 0")],
              "user_ips": [("proto", "TEXT DEFAULT 'ws'")],
              "devices": [("device_name", "TEXT DEFAULT ''"),
                          ("client_version", "TEXT DEFAULT ''")],
              "clean_ips": [("country", "TEXT DEFAULT ''")],
              "tg_web_proxies": [("platform", "TEXT DEFAULT 'external'"),
                                 ("service_id", "TEXT DEFAULT ''"),
                                 ("coords", "TEXT DEFAULT ''"),
                                 ("deploy_state", "TEXT DEFAULT ''"),
                                 ("error", "TEXT DEFAULT ''"),
                                 ("usage_since", "INTEGER DEFAULT 0"),
                                 ("usage_checked", "INTEGER DEFAULT 0")],
              "proxies": [("country", "TEXT DEFAULT ''"),
                          ("country_name", "TEXT DEFAULT ''"),
                          ("city", "TEXT DEFAULT ''"),
                          ("isp", "TEXT DEFAULT ''"),
                          ("exit_ip", "TEXT DEFAULT ''"),
                          ("healthy", "INTEGER DEFAULT 0"),
                          ("latency_ms", "INTEGER DEFAULT 0"),
                          ("last_error", "TEXT DEFAULT ''"),
                          ("checked_at", "INTEGER DEFAULT 0")]}
    with db() as c:
        for table, cols in wanted.items():
            have = {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}
            for name, decl in cols:
                if name not in have:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
        # One-time backfill: turn legacy IP rows into device rows so history survives.
        if c.execute("SELECT COUNT(*) n FROM devices").fetchone()["n"] == 0:
            for r in c.execute("SELECT user_id,ip,proto,first_seen,last_seen,hits "
                               "FROM user_ips").fetchall():
                c.execute("""INSERT OR IGNORE INTO devices
                             (user_id,dkey,ip,proto,first_seen,last_seen,hits)
                             VALUES(?,?,?,?,?,?,?)""",
                          (r["user_id"], "ip:" + str(r["ip"]), r["ip"], r["proto"],
                           r["first_seen"], r["last_seen"], r["hits"]))


def init_db():
    d = os.path.dirname(DB_PATH)
    if d:
        os.makedirs(d, exist_ok=True)
    with db() as c:
        c.executescript(SCHEMA)
    migrate()
    if BOOTSTRAP_PASS and not get_setting("password_hash"):
        set_password(BOOTSTRAP_PASS)


def get_setting(key: str) -> Optional[str]:
    with db() as c:
        r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r else None


def set_setting(key: str, value: str):
    with db() as c:
        c.execute("""INSERT INTO settings(key,value) VALUES(?,?)
                     ON CONFLICT(key) DO UPDATE SET value=excluded.value""", (key, value))


def audit(event: str, ip: str = "", detail: str = ""):
    try:
        with db() as c:
            c.execute("INSERT INTO audit_log(ts,event,ip,detail) VALUES(?,?,?,?)",
                      (now(), event, ip, detail))
            c.execute("DELETE FROM audit_log WHERE id NOT IN "
                      "(SELECT id FROM audit_log ORDER BY id DESC LIMIT 300)")
    except Exception:
        pass


# ────────────────────────────── PASSWORD ──────────────────────────────

def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return dk.hex(), salt.hex()


def set_password(password: str):
    h, s = hash_password(password)
    set_setting("password_hash", h)
    set_setting("password_salt", s)
    set_setting("password_set_at", str(now()))


def verify_password(password: str) -> bool:
    h, s = get_setting("password_hash"), get_setting("password_salt")
    if not h or not s:
        return False
    calc, _ = hash_password(password, bytes.fromhex(s))
    return secrets.compare_digest(calc, h)


def password_is_set() -> bool:
    return bool(get_setting("password_hash"))


PASSWORD_RULE = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$")


# ────────────────────────────── AUTH ──────────────────────────────

def make_token() -> str:
    return jwt.encode({"sub": ADMIN_USERNAME, "exp": now() + JWT_TTL, "iat": now()},
                      SECRET_KEY, algorithm=JWT_ALG)


def valid_session(token: Optional[str]) -> bool:
    if not token:
        return False
    try:
        jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALG])
        return True
    except Exception:
        return False


def require_admin(session: Optional[str] = Cookie(default=None)):
    if not valid_session(session):
        raise HTTPException(401, "not authenticated")
    return True


_attempts: dict[str, list[float]] = {}


def rate_limited(ip: str, limit: int = 8, window: int = 300) -> bool:
    t = time.time()
    hits = [x for x in _attempts.get(ip, []) if t - x < window]
    hits.append(t)
    _attempts[ip] = hits
    return len(hits) > limit


def client_ip(req) -> str:
    fwd = req.headers.get("x-forwarded-for") or req.headers.get("cf-connecting-ip") or ""
    if fwd:
        first = fwd.split(",")[0].strip()
        try:
            ipaddress.ip_address(first)
            return first
        except ValueError:
            pass
    try:
        return req.client.host or "0.0.0.0"
    except Exception:
        return "0.0.0.0"


def user_agent(req) -> str:
    """The client app string, used to fingerprint devices. Truncated, best-effort."""
    try:
        return (req.headers.get("user-agent") or "")[:300]
    except Exception:
        return ""


# ────────────────────────────── TRAFFIC ──────────────────────────────

_pending: dict[int, list[int]] = {}
_lock = asyncio.Lock()


async def bump(uid: int, up: int, down: int):
    async with _lock:
        cur = _pending.setdefault(uid, [0, 0])
        cur[0] += up
        cur[1] += down


async def keepalive():
    """Hit our own PUBLIC url so a host with an idle timeout keeps the service running.

    It must travel through the public hostname: a request to localhost never reaches the
    platform's router, so it does not register as inbound traffic and the service still
    gets put to sleep. Uses urllib on a worker thread to avoid adding an HTTP dependency.
    """
    if not KEEPALIVE:
        return

    host = DOMAIN.replace("https://", "").replace("http://", "").strip("/")
    if not host:
        print("keepalive: DOMAIN is unset, staying off")
        return

    import urllib.request

    url = f"https://{host}/healthz"

    def hit():
        try:
            req = urllib.request.Request(url, headers={"user-agent": "iranx-keepalive"})
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status
        except Exception as e:
            return f"error: {e}"

    loop = asyncio.get_running_loop()
    print(f"keepalive: on, every {KEEPALIVE_MINS} min -> {url}")
    while True:
        await asyncio.sleep(KEEPALIVE_MINS * 60)
        result = await loop.run_in_executor(None, hit)
        if result != 200:                      # stay quiet unless something is wrong
            print("keepalive:", result)


async def flusher():
    while True:
        await asyncio.sleep(10)
        async with _lock:
            snap = {k: v for k, v in _pending.items() if v[0] or v[1]}
            _pending.clear()
        if not snap:
            continue
        try:
            with db() as c:
                for uid, (up, down) in snap.items():
                    c.execute("UPDATE users SET used_bytes=used_bytes+? WHERE id=?",
                              (up + down, uid))
                    c.execute("INSERT INTO traffic_log(user_id,ts,up,down) VALUES(?,?,?,?)",
                              (uid, now(), up, down))
                c.execute("DELETE FROM traffic_log WHERE ts<?", (now() - 86400 * 7,))
        except Exception as e:
            print("flush error:", e)


# ────────────────────────────── USER LOGIC ──────────────────────────────

def user_status(row) -> tuple[bool, str]:
    if not row["enabled"]:
        return False, "disabled"
    if row["expire_at"] and now() > row["expire_at"]:
        return False, "expired"
    if row["quota_bytes"] and row["used_bytes"] >= row["quota_bytes"]:
        return False, "quota"
    return True, "ok"


def apply_auto_reset(uid: int, reset_days: int, last_reset: int) -> bool:
    """Zero a user's usage counter once its reset cycle has fully elapsed.

    reset_days == 0 means the feature is off for that user. last_reset is the
    anchor of the current cycle (set when the cycle is chosen or the usage is
    reset by hand), so a 30-day cycle always starts on the day it was enabled.
    """
    try:
        reset_days = int(reset_days or 0)
        last_reset = int(last_reset or 0)
    except (TypeError, ValueError):
        return False
    if reset_days <= 0:
        return False
    if not last_reset:                     # safety net: start the first cycle now
        with db() as c:
            c.execute("UPDATE users SET last_reset=? WHERE id=?", (now(), uid))
        return False
    if now() - last_reset < reset_days * 86400:
        return False
    with db() as c:
        c.execute("UPDATE users SET used_bytes=0, last_reset=? WHERE id=?",
                  (now(), uid))
    audit("auto_reset", "", f"user {uid} · {reset_days}d cycle")
    return True


def maybe_auto_reset(row):
    """Run the auto-reset check for one user row; returns a fresh row if it fired."""
    try:
        rd, lr = row["reset_days"], row["last_reset"]
    except (IndexError, KeyError):
        return row
    if not rd:
        return row
    if now() - (lr or 0) < rd * 86400:
        return row
    if apply_auto_reset(row["id"], rd, lr):
        with db() as c:
            fresh = c.execute("SELECT * FROM users WHERE id=?",
                              (row["id"],)).fetchone()
        return fresh or row
    return row


async def resetter():
    """Hourly sweep so usage cycles fire even when a user never reconnects."""
    while True:
        try:
            with db() as c:
                rows = c.execute("SELECT * FROM users WHERE reset_days>0").fetchall()
            for r in rows:
                maybe_auto_reset(r)
        except Exception as e:
            print("resetter error:", e)
        await asyncio.sleep(3600)


# ── device fingerprinting ──
# VLESS over WS/XHTTP is plain HTTP underneath, so the only stable hints we get are the
# client IP and the request User-Agent. The pair becomes one opaque key per device, and we
# remember the parsed app + platform so the panel can show "who" is connected.
UA_CLIENTS = (
    ("v2rayng", "v2rayNG"), ("v2raytun", "v2rayTun"), ("happ", "Happ"),
    ("incy", "Incy"), ("v2rayn", "v2rayN"),
    ("nekobox", "NekoBox"), ("nekoray", "NekoRay"), ("streisand", "Streisand"),
    ("hiddify", "Hiddify"), ("shadowrocket", "Shadowrocket"), ("quantumult", "Quantumult"),
    ("stash", "Stash"), ("clash", "Clash"), ("sing-box", "sing-box"), ("singbox", "sing-box"),
    ("karing", "Karing"), ("foxray", "Foxray"), ("v2box", "V2Box"), ("matsuri", "Matsuri"),
    ("napsternetv", "NapsternetV"), ("sagernet", "SagerNet"), ("exclave", "Exclave"),
    ("kitsunebi", "Kitsunebi"), ("surge", "Surge"), ("passwall", "PassWall"),
    ("hysteria", "Hysteria"), ("xray", "Xray"), ("v2ray", "V2Ray"),
    ("okhttp", "OkHttp"), ("go-http-client", "Go HTTP"), ("dart", "Dart"),
    ("python", "Python"), ("curl", "cURL"), ("wget", "Wget"),
)


def parse_ua(ua: str) -> tuple[str, str]:
    """Best-effort (client, platform) from a User-Agent string."""
    u = (ua or "").lower()
    client = ""
    for token, name in UA_CLIENTS:
        if token in u:
            client = name
            break
    platform = ""
    if "android" in u:
        platform = "Android"
    elif any(k in u for k in ("iphone", "ipad", "ios")):
        platform = "iOS"
    elif any(k in u for k in ("macintosh", "mac os", "darwin")):
        platform = "macOS"
    elif "windows" in u:
        platform = "Windows"
    elif "linux" in u:
        platform = "Linux"
    if not client and u.startswith("mozilla"):
        client = "Browser"
    return client, platform


# ── clients that actually identify themselves ──
# A device limit is only meaningful when the panel can tell two devices apart. That needs
# the app to send a User-Agent that names it (and, in most of these, the phone model too).
# The six apps below are the ones that do; everything else either sends one fixed UA for
# every install (v2rayNG, NekoBox …) or nothing at all (Clash, sing-box, browsers, curl),
# which makes a per-device cap unenforceable. So when a user has a device limit, the
# subscription link is only handed to these apps (see device_sub_gate()).
DEVICE_AWARE_CLIENTS = (
    (r"v2box", "V2Box"),
    (r"v2raytun", "v2rayTun"),
    (r"happ(?![a-z])", "Happ"),
    (r"incy", "Incy"),
    (r"shadowrocket", "Shadowrocket"),
    (r"streisand", "Streisand"),
)
DEVICE_AWARE_RE = [(re.compile(rx, re.I), name) for rx, name in DEVICE_AWARE_CLIENTS]


def device_aware_client(ua: str) -> str:
    """Name of the client when its User-Agent identifies the device, else ''."""
    u = ua or ""
    if not u:
        return ""
    for rx, name in DEVICE_AWARE_RE:
        if rx.search(u):
            return name
    return ""


def hwid_of(headers) -> str:
    """The device identifier the standards-compliant clients send on subscription
    requests (XTLS subscription standard: x-hwid, x-device-os, x-ver-os,
    x-device-model — v2rayTun since 2.3.5, Happ, v2rayA, Securify …)."""
    # Only stable per-install identifiers count. Device model is shared by many
    # phones and is not an identity; accepting it here lets users evade the cap.
    for h in ("x-hwid", "x-device-id", "x-hardware-id"):
        v = ""
        try:
            v = (headers.get(h) or "").strip()
        except AttributeError:
            v = ""
        if v:
            return v[:120]
    return ""


def device_gate_on() -> bool:
    """Subscriptions of limited users are restricted to device-aware apps (default on)."""
    return (get_setting("device_gate") or "1") == "1"


def device_gate_traffic() -> bool:
    """Also refuse proxied traffic from apps that cannot be identified (default off)."""
    return (get_setting("device_gate_traffic") or "0") == "1"


def needs_device_gate(row) -> bool:
    """A user needs the gate only when a device limit is actually set on the account."""
    try:
        return int(row["device_limit"] or 0) > 0
    except (KeyError, IndexError, TypeError):
        return False


def device_key(ip: str, ua: str) -> str:
    """Opaque per-device identity: stable for one client+IP, distinct for others."""
    seed = f"{(ip or '').strip()}|{(ua or '').strip().lower()}"
    return hashlib.sha1(seed.encode()).hexdigest()[:16]


def hwid_fingerprint(hwid: str) -> str:
    """One-way stable identifier; raw client HWIDs are never stored."""
    return "hwid:" + hashlib.sha256((hwid or "").strip().lower().encode()).hexdigest()[:40]


def register_hwid_device(uid: int, hwid: str, limit: int, ip: str, ua: str,
                         headers=None, proto: str = "sub") -> tuple[bool, int]:
    """Persist a client-reported HWID and enforce a persistent per-account cap.

    Unlike the legacy IP+UA heuristic, these slots do not expire on a rolling
    window. A device is freed only when an admin removes it from the device list.
    """
    if limit <= 0:
        return True, 0
    hwid = (hwid or "").strip()
    if not hwid:
        return False, 0
    dkey = hwid_fingerprint(hwid)
    client, platform = parse_ua(ua)
    headers = headers or {}
    def _header(*names):
        for name in names:
            try:
                value = (headers.get(name) or "").strip()
            except AttributeError:
                value = ""
            if value:
                return value[:120]
        return ""
    device_name = _header("x-device-model", "x-device-name", "x-hardware-model")
    client_version = _header("x-app-version", "x-client-version", "x-ver-app")
    if not client_version:
        match = re.search(r"(?i)(?:v2box|v2raytun|happ|incy|shadowrocket|streisand)[/\s-]v?([0-9]+(?:\.[0-9A-Za-z_-]+)+)", ua or "")
        client_version = match.group(1) if match else ""
    ts = now()
    with db() as c:
        # Serialize simultaneous first fetches so two new HWIDs cannot both take
        # the final slot. SQLite's write transaction is short and local.
        c.execute("BEGIN IMMEDIATE")
        known = c.execute("SELECT id FROM devices WHERE user_id=? AND dkey=?",
                          (uid, dkey)).fetchone()
        if not known:
            n = c.execute("SELECT COUNT(*) n FROM devices WHERE user_id=? AND dkey LIKE 'hwid:%'",
                          (uid,)).fetchone()["n"]
            if n >= limit:
                return False, int(n)
            c.execute("""INSERT INTO devices(user_id,dkey,ip,ua,client,platform,proto,
                                             first_seen,last_seen,hits,device_name,client_version)
                         VALUES(?,?,?,?,?,?,?,?,?,1,?,?)""",
                      (uid, dkey, (ip or "")[:80], (ua or "")[:300], client,
                       platform, proto, ts, ts, device_name, client_version))
            return True, int(n) + 1
        c.execute("""UPDATE devices SET last_seen=?,ip=?,ua=?,client=?,platform=?,
                     proto=?,hits=hits+1,device_name=?,client_version=?
                     WHERE user_id=? AND dkey=?""",
                  (ts, (ip or "")[:80], (ua or "")[:300], client, platform,
                   proto, device_name, client_version, uid, dkey))
        n = c.execute("SELECT COUNT(*) n FROM devices WHERE user_id=? AND dkey LIKE 'hwid:%'",
                      (uid,)).fetchone()["n"]
        return True, int(n)


def device_label(client: str, platform: str, ip: str) -> str:
    if client and platform:
        return f"{client} · {platform}"
    if client:
        return client
    if platform:
        return platform
    return ip or "?"


def active_devices(uid: int, window: Optional[int] = None) -> int:
    """Distinct devices seen inside a window. Defaults to the enforcement window."""
    w = DEVICE_WINDOW if window is None else window
    with db() as c:
        r = c.execute("SELECT COUNT(*) n FROM devices WHERE user_id=? AND last_seen>?",
                      (uid, now() - w)).fetchone()
    return r["n"] if r else 0


def live_devices(uid: int) -> int:
    return active_devices(uid, LIVE_WINDOW)


def touch_device(uid: int, dkey: str, ip: str, ua: str, proto: str):
    client, platform = parse_ua(ua)
    with db() as c:
        c.execute("""INSERT INTO devices(user_id,dkey,ip,ua,client,platform,proto,
                                         first_seen,last_seen,hits)
                     VALUES(?,?,?,?,?,?,?,?,?,1)
                     ON CONFLICT(user_id,dkey) DO UPDATE
                     SET last_seen=excluded.last_seen, ip=excluded.ip, ua=excluded.ua,
                         client=excluded.client, platform=excluded.platform,
                         proto=excluded.proto, hits=hits+1""",
                  (uid, dkey, ip, (ua or "")[:300], client, platform, proto, now(), now()))


def device_allowed(uid: int, dkey: str, limit: int) -> bool:
    """A known device always passes; a brand-new one only while a slot is free."""
    if limit <= 0:
        return True
    with db() as c:
        known = c.execute("SELECT 1 FROM devices WHERE user_id=? AND dkey=? AND last_seen>?",
                          (uid, dkey, now() - DEVICE_WINDOW)).fetchone()
    return bool(known) or active_devices(uid) < limit


def active_ips(uid: int, window: Optional[int] = None) -> int:
    """Distinct source IPs seen inside a window. Defaults to the IP enforcement window."""
    w = IP_WINDOW if window is None else window
    with db() as c:
        r = c.execute("SELECT COUNT(*) n FROM user_ips WHERE user_id=? AND last_seen>?",
                      (uid, now() - w)).fetchone()
    return r["n"] if r else 0


def live_ips(uid: int) -> int:
    return active_ips(uid, LIVE_WINDOW)


def touch_ip(uid: int, ip: str, proto: str):
    """Record the source IP: user_ips keeps only the raw IP identity of a connection."""
    if not (ip or "").strip():
        return
    with db() as c:
        c.execute("""INSERT INTO user_ips(user_id,ip,proto,first_seen,last_seen,hits)
                     VALUES(?,?,?,?,?,1)
                     ON CONFLICT(user_id,ip) DO UPDATE
                     SET last_seen=excluded.last_seen, proto=excluded.proto, hits=hits+1""",
                  (uid, ip, proto, now(), now()))


def ip_allowed(uid: int, ip: str, limit: int) -> bool:
    """A known IP always passes; a brand-new one only while a slot is free."""
    if limit <= 0:
        return True
    with db() as c:
        known = c.execute("SELECT 1 FROM user_ips WHERE user_id=? AND ip=? AND last_seen>?",
                          (uid, ip, now() - IP_WINDOW)).fetchone()
    return bool(known) or active_ips(uid) < limit


def transport_allowed(row, proto: str) -> bool:
    t = (row["transport"] or "both").lower()
    return t == "both" or t == proto


# ══════════════════════════ VLESS CORE ══════════════════════════

class ByteStream:
    """Async buffered byte reader fed by an internal queue."""

    def __init__(self):
        self.buf = bytearray()
        self.q: asyncio.Queue = asyncio.Queue()
        self.eof = False

    def feed(self, data: bytes):
        self.q.put_nowait(data)

    def feed_eof(self):
        self.q.put_nowait(None)

    async def pull(self) -> bool:
        if self.eof:
            return False
        item = await self.q.get()
        if item is None:
            self.eof = True
            return False
        self.buf.extend(item)
        return True

    async def read_exact(self, n: int) -> Optional[bytes]:
        while len(self.buf) < n:
            if not await self.pull():
                return None
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def take_all(self) -> bytes:
        out = bytes(self.buf)
        self.buf.clear()
        return out


class WSStream(ByteStream):
    """Same interface, but pulls frames straight off a WebSocket."""

    def __init__(self, ws: WebSocket):
        super().__init__()
        self.ws = ws

    async def pull(self) -> bool:
        try:
            msg = await self.ws.receive()
        except Exception:
            self.eof = True
            return False
        if msg.get("type") == "websocket.disconnect":
            self.eof = True
            return False
        data = msg.get("bytes")
        if data is None and msg.get("text") is not None:
            data = msg["text"].encode()
        if data:
            self.buf.extend(data)
        return True


async def parse_vless(stream: ByteStream):
    head = await stream.read_exact(18)
    if not head or head[0] != 0:
        return None
    uid = str(uuid.UUID(bytes=head[1:17]))
    alen = head[17]
    if alen and await stream.read_exact(alen) is None:
        return None
    meta = await stream.read_exact(4)
    if not meta:
        return None
    cmd = meta[0]
    port = struct.unpack("!H", meta[1:3])[0]
    at = meta[3]
    # Mux sessions (command 0x03) come in two shapes. Classic clients dial the
    # placeholder v1.mux.cool:9527 (port 0x2537, address type 1..3) and the mux
    # frames follow the address. Xray-core 2025+ sends NO address at all: the
    # bytes right after the command byte are already the first mux frame (its
    # 2-byte metadata length). For mux the header address is ignored anyway —
    # every sub-stream carries its own target — so when the trio does not look
    # like a placeholder address, hand back a placeholder and leave the mux
    # frames untouched in the stream.
    if cmd == 3 and not (port == 0x2537 and at in (1, 2, 3)):
        # only the command byte belongs to the VLESS header here — bytes 1..3 we
        # just read are the opening bytes of the first mux frame, put them back
        try:
            stream.buf[0:0] = meta[1:]
        except Exception:
            pass
        return (uid, cmd, "v1.mux.cool", 9527)
    if at == 1:
        raw = await stream.read_exact(4)
        host = str(ipaddress.IPv4Address(raw)) if raw else None
    elif at == 2:
        ln = await stream.read_exact(1)
        if not ln:
            return None
        raw = await stream.read_exact(ln[0])
        host = raw.decode(errors="ignore") if raw else None
    elif at == 3:
        raw = await stream.read_exact(16)
        host = str(ipaddress.IPv6Address(raw)) if raw else None
    else:
        return None
    return (uid, cmd, host, port) if host else None


BLOCKED = [ipaddress.ip_network(x) for x in
           ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "169.254.0.0/16", "::1/128", "fc00::/7")]


# ════════════════════════ OUTBOUND PROXY (socks5 / socks4 / http) ════════════
#
#  Every VLESS session dials its target through dial_target(). When a proxy is
#  marked active, that dial is wrapped in a proxy handshake, so the destination
#  site sees the proxy's IP instead of the Railway/Render one.
#
#  "strict" (the default) means a broken proxy fails the session instead of
#  silently falling back to the platform IP, which would leak the real exit.

PROXY_KINDS = ("socks5", "socks4", "http")
IP_CHECK_HOST = "ip-api.com"
IP_CHECK_PATH = "/json/?fields=status,message,country,countryCode,city,isp,query"


def proxy_strict() -> bool:
    return (get_setting("proxy_strict") or "1") == "1"


def active_proxy():
    """The proxy every outbound connection should ride, or None for direct."""
    pid = get_setting("active_proxy") or ""
    if not pid.isdigit():
        return None
    with db() as c:
        return c.execute("SELECT * FROM proxies WHERE id=? AND enabled=1",
                         (int(pid),)).fetchone()


def proxy_by_id(pid: int):
    """One enabled proxy, looked up by the id carried in the inbound path."""
    with db() as c:
        return c.execute("SELECT * FROM proxies WHERE id=? AND enabled=1",
                         (int(pid),)).fetchone()


def sub_proxies():
    """Every enabled proxy, fastest first.

    These are exactly the proxies a subscription lists. Membership depends only on
    `enabled`: a proxy leaves the users' subscriptions when the admin disables or
    deletes it in the panel, never because a health check failed or a live
    connection broke. Health is reported in the UI, but it no longer filters here.
    """
    with db() as c:
        return c.execute("""SELECT * FROM proxies WHERE enabled=1
                            ORDER BY latency_ms IS NULL, latency_ms, id""").fetchall()


def preferred_proxy():
    """Fallback for the plain inbound path used by older subscriptions."""
    rows = sub_proxies()
    return rows[0] if rows else active_proxy()


def _addr_bytes(host: str) -> bytes:
    """SOCKS5 address field: literal IPv4/IPv6 when possible, else a hostname."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        h = host.encode()[:255]
        return b"\x03" + bytes([len(h)]) + h
    return (b"\x01" if ip.version == 4 else b"\x04") + ip.packed


async def _socks5(reader, writer, host, port, user, pwd):
    writer.write(b"\x05\x02\x00\x02" if user else b"\x05\x01\x00")
    await writer.drain()
    ver, method = await reader.readexactly(2)
    if ver != 5:
        raise OSError("socks5: not a socks5 proxy")
    if method == 0x02:
        if not user:
            raise OSError("socks5: proxy wants a username/password")
        u, p = user.encode()[:255], (pwd or "").encode()[:255]
        writer.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        await writer.drain()
        if (await reader.readexactly(2))[1] != 0:
            raise OSError("socks5: username/password rejected")
    elif method != 0x00:
        raise OSError("socks5: no shared auth method")

    writer.write(b"\x05\x01\x00" + _addr_bytes(host) + port.to_bytes(2, "big"))
    await writer.drain()
    head = await reader.readexactly(4)
    if head[1] != 0:
        raise OSError("socks5: target refused (code %d)" % head[1])
    atyp = head[3]
    if atyp == 1:
        await reader.readexactly(4)
    elif atyp == 4:
        await reader.readexactly(16)
    elif atyp == 3:
        await reader.readexactly((await reader.readexactly(1))[0])
    await reader.readexactly(2)          # bound port


async def _socks4(reader, writer, host, port, user):
    """SOCKS4, falling back to SOCKS4a when the target is a hostname."""
    try:
        packed, tail = ipaddress.IPv4Address(host).packed, b""
    except ipaddress.AddressValueError:
        packed, tail = b"\x00\x00\x00\x01", host.encode()[:255] + b"\x00"
    writer.write(b"\x04\x01" + port.to_bytes(2, "big") + packed +
                 (user or "").encode()[:255] + b"\x00" + tail)
    await writer.drain()
    resp = await reader.readexactly(8)
    if resp[1] != 0x5a:
        raise OSError("socks4: target refused (code 0x%02x)" % resp[1])


async def _http_connect(reader, writer, host, port, user, pwd):
    req = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n" % (host, port, host, port)
    if user:
        cred = base64.b64encode(("%s:%s" % (user, pwd or "")).encode()).decode()
        req += "Proxy-Authorization: Basic %s\r\n" % cred
    req += "Proxy-Connection: keep-alive\r\n\r\n"
    writer.write(req.encode())
    await writer.drain()

    head = b""
    while b"\r\n\r\n" not in head:
        chunk = await reader.read(2048)
        if not chunk:
            raise OSError("http proxy: connection closed during CONNECT")
        head += chunk
        if len(head) > 32768:
            raise OSError("http proxy: response header too long")
    first = head.split(b"\r\n", 1)[0].decode("latin1")
    parts = first.split(" ")
    if len(parts) < 2 or not parts[1].startswith("2"):
        raise OSError("http proxy: %s" % first)


async def open_via_proxy(px, host: str, port: int, timeout: float = 15.0):
    """Open a TCP leg to host:port through one proxy row."""
    kind = (px["kind"] or "socks5").lower()
    if kind not in PROXY_KINDS:
        raise OSError("unsupported proxy kind: %s" % kind)
    user = px["username"] or ""
    pwd = px["password"] or ""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(px["host"], int(px["port"])), timeout=timeout)
    try:
        if kind == "socks5":
            await asyncio.wait_for(_socks5(reader, writer, host, port, user, pwd),
                                   timeout=timeout)
        elif kind == "socks4":
            await asyncio.wait_for(_socks4(reader, writer, host, port, user),
                                   timeout=timeout)
        else:
            await asyncio.wait_for(_http_connect(reader, writer, host, port, user, pwd),
                                   timeout=timeout)
    except Exception:
        try:
            writer.close()
        except Exception:
            pass
        raise
    return reader, writer


# ───────────────────────── DNS & direct dialing ─────────────────────────
#
# Two things used to break "the site does not open / DNS_PROBE_FINISHED" style
# pages even though the tunnel itself was up:
#
#   1. The host resolved a target to an IPv6 address it could not actually reach
#      (common on Render/Railway) and the single open_connection() call just hung
#      until it timed out. resolve_addrs() caches the lookup and orders IPv4
#      first, and dial_direct() walks every candidate instead of only the first.
#   2. DNS itself is UDP, and UDP was refused outright, so the client got no
#      answer at all for names it wanted to resolve through the tunnel.
#      dns_forward() relays those queries upstream over TCP:53, which uses the
#      very same wire format with a 2-byte length prefix.

_DNS_TTL = 300.0
_dns_cache: dict[tuple[str, int], tuple[float, list]] = {}

DNS_UPSTREAMS = [h.strip() for h in
                 os.getenv("DNS_UPSTREAM", "1.1.1.1,8.8.8.8,9.9.9.9").split(",")
                 if h.strip()]


async def resolve_addrs(host: str, port: int) -> list:
    """Resolve once, cache for _DNS_TTL, and put IPv4 before IPv6."""
    key = (host, port)
    hit = _dns_cache.get(key)
    if hit and (time.time() - hit[0]) < _DNS_TTL:
        return hit[1]
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=6)
    infos = sorted(infos, key=lambda i: 0 if i[0] == socket.AF_INET else 1)
    addrs = [(i[0], i[4]) for i in infos]
    if addrs:
        _dns_cache[key] = (time.time(), addrs)
    return addrs


async def dial_direct(host: str, port: int, timeout: float = 12):
    """Open a TCP connection, trying each resolved address (IPv4 first)."""
    try:
        addrs = await resolve_addrs(host, port)
    except Exception:
        addrs = []
    if not addrs:
        # Resolution failed here; let asyncio try its own way before giving up.
        return await asyncio.wait_for(asyncio.open_connection(host, port),
                                      timeout=timeout)
    tries = addrs[:4]
    per_try = max(3.0, timeout / len(tries))
    last = None
    for family, sockaddr in tries:
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(sockaddr[0], sockaddr[1], family=family),
                timeout=per_try)
        except Exception as exc:
            last = exc
    raise last or OSError("connect failed %s:%s" % (host, port))


async def dns_forward(payload: bytes, timeout: float = 6):
    """Answer one tunnelled DNS query by relaying it upstream over TCP:53."""
    framed = struct.pack("!H", len(payload)) + payload
    for up in (DNS_UPSTREAMS or ["1.1.1.1"]):
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(up, 53), timeout=timeout)
            writer.write(framed)
            await writer.drain()
            head = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
            ln = struct.unpack("!H", head)[0]
            return await asyncio.wait_for(reader.readexactly(ln), timeout=timeout)
        except Exception:
            continue
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
    return None


async def dial_target(host: str, port: int, direct: bool = False,
                      pid: int | None = None):
    """The single outbound path for user traffic.

    The inbound path decides the exit: "-d" leaves from the host's own IP, "-p<id>"
    leaves through that one proxy, and the plain path follows the fastest enabled
    proxy so subscriptions handed out earlier keep working.
    """
    px = None
    if not direct:
        px = proxy_by_id(pid) if pid else preferred_proxy()
    if px:
        try:
            return await open_via_proxy(px, host, port, timeout=15)
        except Exception as exc:
            audit("proxy-fail", "", "%s %s:%s \u2192 %s" %
                  (px["kind"], px["host"], px["port"], exc))
            mark_proxy_down(px["id"], str(exc))
            if proxy_strict():
                raise
    return await dial_direct(host, port, timeout=12)


def mark_proxy_down(pid: int, err: str):
    """Record a failure without dropping the proxy from anyone's subscription.

    `healthy` is deliberately left untouched: a temporary outage used to remove the
    proxy from every user's config list, and only an admin disabling or deleting it
    should do that now. The error text and timestamp still land in the panel.
    """
    with db() as c:
        c.execute("UPDATE proxies SET last_error=?, checked_at=? WHERE id=?",
                  (err[:200], now(), pid))


async def probe_proxy(px) -> dict:
    """Health check: ride the proxy to an IP-echo service and read the exit IP.

    Plain HTTP on purpose \u2014 no TLS stack needed on top of the proxied socket,
    and the response carries the country, city and ISP of the exit node.
    """
    start = time.perf_counter()
    reader, writer = await open_via_proxy(px, IP_CHECK_HOST, 80, timeout=12)
    try:
        writer.write(("GET " + IP_CHECK_PATH + " HTTP/1.1\r\n"
                      "Host: " + IP_CHECK_HOST + "\r\n"
                      "User-Agent: IranXPanel/3\r\n"
                      "Accept: application/json\r\n"
                      "Connection: close\r\n\r\n").encode())
        await writer.drain()
        raw = b""
        while len(raw) < 65536:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=8)
            except asyncio.TimeoutError:
                break            # some proxies never forward the server's close
            if not chunk:
                break
            raw += chunk
            head, _, body = raw.partition(b"\r\n\r\n")
            if body.rstrip().endswith(b"}"):
                break            # the JSON answer is already complete
    finally:
        try:
            writer.close()
        except Exception:
            pass

    ms = int((time.perf_counter() - start) * 1000)
    body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else raw
    data = {}
    match = re.search(rb"\{.*\}", body, re.S)      # tolerate chunked bodies
    if match:
        try:
            data = json.loads(match.group(0).decode("utf-8", "replace"))
        except Exception:
            data = {}
    if not data:
        raise OSError("proxy answered, but the IP echo was unreadable")
    if (data.get("status") or "success") != "success":
        raise OSError("ip lookup failed: %s" % (data.get("message") or "unknown"))

    return {"latency_ms": ms,
            "exit_ip": str(data.get("query") or ""),
            "country": str(data.get("countryCode") or "").upper()[:2],
            "country_name": str(data.get("country") or ""),
            "city": str(data.get("city") or ""),
            "isp": str(data.get("isp") or "")}


async def run_proxy_test(pid: int) -> dict:
    """Probe one stored proxy and persist what came back."""
    with db() as c:
        px = c.execute("SELECT * FROM proxies WHERE id=?", (pid,)).fetchone()
    if not px:
        raise HTTPException(404, "proxy not found")
    try:
        res = await probe_proxy(px)
    except Exception as exc:
        msg = str(exc) or exc.__class__.__name__
        mark_proxy_down(pid, msg)
        return {"ok": False, "error": msg[:200], "id": pid}
    with db() as c:
        c.execute("""UPDATE proxies SET healthy=1, latency_ms=?, exit_ip=?, country=?,
                            country_name=?, city=?, isp=?, last_error='', checked_at=?
                     WHERE id=?""",
                  (res["latency_ms"], res["exit_ip"], res["country"],
                   res["country_name"], res["city"], res["isp"], now(), pid))
    res.update({"ok": True, "id": pid, "flag": flag_of(res["country"])})
    return res


def blocked(host: str) -> bool:
    try:
        a = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(a in n for n in BLOCKED)


# ────────────────────────────── CONTENT FILTER ──────────────────────────────
#
# The VLESS header carries the destination host, so the panel can refuse to dial a
# censored site (or porn) before any connection is made. Enforced on the plain TCP
# path AND on every mux sub-stream, which is the one clients actually use with the
# WS transport (mux=1). DNS sub-streams are left alone: refusing the dial is what
# actually stops the page from loading.

PORN_KEYWORDS = (
    "porn", "xxx", "xnxx", "xvideos", "xhamster", "redtube", "youporn", "pornhub",
    "brazzers", "onlyfans", "livejasmin", "chaturbate", "stripchat", "bongacams",
    "cam4", "beeg", "spankbang", "tnaflix", "hqporner", "eporner", "txxx",
    "daftsex", "hclips", "tube8", "porntrex", "javhd", "javbus", "18porn", "hentai",
    "nhentai", "e-hentai", "rule34", "fapello", "erome", "escort", "hardcore",
    "blowjob", "cumshot", "milf-porn", "nude", "nudes", "xxxvideo",
)

_FILTER_CACHE = {"ts": 0.0, "domains": frozenset(), "keywords": frozenset()}


def filter_on() -> bool:
    return get_setting("filter_enabled") == "1"


def porn_on() -> bool:
    return get_setting("block_porn") == "1"


def load_filter_rules(force: bool = False):
    """Domains + keywords, cached a few seconds so the hot path stays cheap."""
    t = time.time()
    if not force and t - _FILTER_CACHE["ts"] < 5:
        return _FILTER_CACHE
    doms, kws = set(), set()
    try:
        with db() as c:
            for r in c.execute("SELECT pattern,kind FROM filter_rules WHERE enabled=1"):
                p = (r["pattern"] or "").strip().lower().lstrip("*.").strip(".")
                if p:
                    (kws if r["kind"] == "keyword" else doms).add(p)
    except Exception:
        pass
    _FILTER_CACHE["ts"] = t
    _FILTER_CACHE["domains"] = frozenset(doms)
    _FILTER_CACHE["keywords"] = frozenset(kws)
    return _FILTER_CACHE


def host_blocked(host: str) -> str:
    """'' when allowed, else a short reason used in the audit log."""
    if not filter_on():
        return ""
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return ""
    rules = load_filter_rules()
    for d in rules["domains"]:
        if h == d or h.endswith("." + d):
            return "site:" + d
    for k in rules["keywords"]:
        if k in h:
            return "keyword:" + k
    if porn_on():
        for k in PORN_KEYWORDS:
            if k in h:
                return "porn:" + k
    return ""


def lookup_user(uid_str: str):
    with db() as c:
        return c.execute("SELECT * FROM users WHERE uuid=?", (uid_str,)).fetchone()


def authorize(uid_str: str, ip: str, proto: str, ua: str = ""):
    """Returns (row, None) on success or (None, reason)."""
    row = lookup_user(uid_str)
    if not row:
        return None, "unknown uuid"
    row = maybe_auto_reset(row)
    ok, reason = user_status(row)
    if not ok:
        return None, reason
    if not transport_allowed(row, proto):
        return None, f"{proto} not allowed"
    # With HWID registration enabled, never fall back to IP+UA for the device
    # quota: doing so would create fake identities and make the limit inconsistent.
    # Proxy transports do not carry subscription HTTP headers, so this layer cannot
    # cryptographically bind a live tunnel to the registered subscription HWID.
    if not (needs_device_gate(row) and device_gate_on()):
        dkey = device_key(ip, ua)
        if not device_allowed(row["id"], dkey, row["device_limit"]):
            return None, "device limit"
        if (needs_device_gate(row) and device_gate_traffic()
                and not device_aware_client(ua or "")):
            return None, "device not identifiable by this app"
        touch_device(row["id"], dkey, ip, ua, proto)
    if not ip_allowed(row["id"], ip, row["ip_limit"]):
        return None, "ip limit"
    touch_ip(row["id"], ip, proto)
    return row, None


async def relay_session(stream: ByteStream,
                        send: Callable[[bytes], Awaitable[None]],
                        ip: str, proto: str, direct: bool = False,
                        pid: int | None = None, ua: str = "") -> None:
    """Shared VLESS handling: authenticate, dial the target, pump both ways."""
    parsed = await parse_vless(stream)
    if not parsed:
        raise ValueError("bad vless header")
    uid_str, cmd, host, port = parsed

    row, reason = authorize(uid_str, ip, proto, ua)
    if not row:
        audit("reject", ip, f"{proto}: {reason}")
        raise PermissionError(reason)

    # Register this tunnel in the live dashboard registry. The key is the client IP plus
    # the VLESS uuid so each concurrent connection shows up as its own row; removed on
    # every exit path below via finally.
    _live_key = f"{ip}:{row['uuid']}:{id(stream)}"
    proxy_tag = f"proxy#{pid}" if pid is not None else ("direct" if direct else "host")
    _client, _platform = parse_ua(ua)
    await live_register(_live_key, {
        "ip": ip,
        "user": row["name"],
        "uuid": row["uuid"],
        "transport": proto,
        "route": proxy_tag,
        "mux": cmd == 3,
        "client": _client,
        "platform": _platform,
        "since": int(time.time()),
    })
    try:
        return await _relay_session_body(stream, send, row, ip, proto, direct, pid, cmd, host, port)
    finally:
        await live_unregister(_live_key)



async def relay_dns(stream: ByteStream, send, row) -> None:
    """Serve tunnelled DNS: each datagram arrives length-prefixed on the stream."""
    uid = row["id"]
    while True:
        hdr = await stream.read_exact(2)
        if not hdr:
            return
        ln = struct.unpack("!H", hdr)[0]
        if ln == 0:
            continue
        query = await stream.read_exact(ln)
        if not query:
            return
        await bump(uid, ln, 0)
        answer = await dns_forward(query)
        if answer:
            await send(struct.pack("!H", len(answer)) + answer)
            await bump(uid, 0, len(answer))


async def _relay_session_body(stream, send, row, ip, proto, direct, pid, cmd, host, port):
    """The authenticated relay work, pulled out so relay_session can wrap it in a
    try/finally that keeps the live registry accurate on every exit path."""
    # VLESS command 0x03 is mux.cool: one session carries many sub-streams, so the
    # whole tunnel is a single connection (one Cloudflare request) instead of one per
    # target. The address fields in the header are a placeholder for mux and ignored.
    if cmd == 3:
        await send(b"\x00\x00")            # VLESS response header, then mux frames
        await relay_mux(stream, send, row, ip, direct, pid)
        return

    if cmd == 2:
        # UDP. Full UDP is still out of scope, but DNS is what actually breaks
        # browsing, so :53 is answered here instead of being refused.
        if port != 53:
            raise ValueError("only TCP and UDP/53 are supported")
        await send(b"\x00\x00")           # VLESS response header
        await relay_dns(stream, send, row)
        return

    if cmd != 1:
        raise ValueError("only TCP supported")
    if blocked(host) or port == 0:
        raise PermissionError("blocked destination")
    why = host_blocked(host)
    if why:
        audit("filtered", ip, f"{host} ({why})")
        raise PermissionError("blocked by filter")

    reader, writer = await dial_target(host, port, direct, pid)

    await send(b"\x00\x00")            # VLESS response header

    leftover = stream.take_all()
    if leftover:
        writer.write(leftover)
        await writer.drain()
        await bump(row["id"], len(leftover), 0)

    uid = row["id"]

    async def up():
        try:
            while True:
                chunk = stream.take_all()
                if not chunk:
                    if not await stream.pull():
                        break
                    continue
                writer.write(chunk)
                await writer.drain()
                await bump(uid, len(chunk), 0)
        except Exception:
            pass

    async def down():
        try:
            while True:
                data = await reader.read(32768)
                if not data:
                    break
                await send(data)
                await bump(uid, 0, len(data))
        except Exception:
            pass

    t1, t2 = asyncio.create_task(up()), asyncio.create_task(down())
    _done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
    try:
        writer.close()
    except Exception:
        pass

# ══════════════════════════ mux.cool ══════════════════════════
#
#  When a client enables Mux it opens ONE VLESS session (VLESS command 0x02) and rides
#  every target through it as numbered sub-streams. Behind a Cloudflare Worker relay this
#  is the whole game: one WebSocket = one Upgrade = one billed request, no matter how many
#  sites the client visits. Without Mux each destination is its own connection, its own
#  Upgrade, its own request — which is why request usage climbs during normal browsing.
#
#  Frame on the wire (mux.cool, the shape xray/v2ray speak):
#     2 bytes   metadata length L
#     L bytes   metadata:  sid(2) status(1) option(1)
#                          + for New: network(1) port(2) atype(1) addr(..)  [+ 8B XUDP id]
#     if option & 0x01 (has data):  2 bytes data length  +  data
#  status: 1 New, 2 Keep, 3 End, 4 KeepAlive.  network: 1 TCP, 2 UDP.
#  addr type: 1 IPv4, 2 domain(len-prefixed), 3 IPv6.  Ports/addr are port-then-address.

MUX_NEW, MUX_KEEP, MUX_END, MUX_KEEPALIVE = 1, 2, 3, 4
MUX_OPT_DATA = 0x01
MUX_MAX_FRAME = 65535          # the data-length field is 2 bytes


async def relay_mux(stream: ByteStream,
                    send: Callable[[bytes], Awaitable[None]],
                    row, ip: str, direct: bool, pid: int | None) -> None:
    """Serve a mux.cool tunnel: read framed sub-streams, dial each, pump both ways."""
    uid = row["id"]
    subs: dict[int, dict] = {}
    send_lock = asyncio.Lock()

    async def send_frame(sid: int, status: int, data: bytes | None = None):
        meta = struct.pack("!HBB", sid, status, MUX_OPT_DATA if data else 0)
        out = struct.pack("!H", len(meta)) + meta
        if data:
            out += struct.pack("!H", len(data)) + data
        async with send_lock:
            await send(out)

    async def pump_down(sid: int, reader):
        """Forward one target's replies back as Keep frames until it closes."""
        try:
            while True:
                chunk = await reader.read(16384)
                if not chunk:
                    break
                await bump(uid, 0, len(chunk))
                for i in range(0, len(chunk), MUX_MAX_FRAME):
                    await send_frame(sid, MUX_KEEP, chunk[i:i + MUX_MAX_FRAME])
        except Exception:
            pass
        finally:
            if subs.pop(sid, None):
                await send_frame(sid, MUX_END)

    async def mux_dns(sid: int, query: bytes):
        """Answer a DNS query that arrived on a UDP sub-stream."""
        try:
            await bump(uid, len(query), 0)
            answer = await dns_forward(query)
            if answer and sid in subs:
                await send_frame(sid, MUX_KEEP, answer)
                await bump(uid, 0, len(answer))
        except Exception:
            pass

    async def close_sub(sid: int):
        s = subs.pop(sid, None)
        if not s:
            return
        task = s.get("task")
        if task:
            task.cancel()
        try:
            s["writer"].close()
        except Exception:
            pass

    try:
        while True:
            hdr = await stream.read_exact(2)
            if not hdr:
                break
            meta_len = struct.unpack("!H", hdr)[0]
            if meta_len == 0:
                continue                       # spec allows an empty keepalive tick
            meta = await stream.read_exact(meta_len)
            if not meta or len(meta) < 4:
                break
            sid = struct.unpack("!H", meta[0:2])[0]
            status, option = meta[2], meta[3]

            target = None
            if status == MUX_NEW and len(meta) >= 8:
                net_type = meta[4]
                port = struct.unpack("!H", meta[5:7])[0]
                atype, p = meta[7], 8
                host = None
                try:
                    if atype == 1:
                        host = str(ipaddress.IPv4Address(meta[p:p + 4]))
                    elif atype == 2:
                        ln = meta[p]; p += 1
                        host = meta[p:p + ln].decode(errors="ignore")
                    elif atype == 3:
                        host = str(ipaddress.IPv6Address(meta[p:p + 16]))
                except Exception:
                    host = None
                target = (net_type, host, port)

            data = b""
            if option & MUX_OPT_DATA:
                dl = await stream.read_exact(2)
                if not dl:
                    break
                dlen = struct.unpack("!H", dl)[0]
                if dlen:
                    data = await stream.read_exact(dlen) or b""

            if status == MUX_NEW:
                if not target:
                    await send_frame(sid, MUX_END)
                    continue
                net_type, host, port = target
                if net_type == 2 and port == 53:
                    # Tunnelled DNS: answer it instead of refusing it, otherwise the
                    # client reports a DNS failure for every site it opens.
                    subs[sid] = {"writer": None, "dns": True}
                    if data:
                        asyncio.create_task(mux_dns(sid, data))
                    continue
                # Any other UDP sub-stream is still refused, without tearing the
                # tunnel down.
                if net_type != 1 or not host or port == 0 or blocked(host):
                    await send_frame(sid, MUX_END)
                    continue
                why = host_blocked(host)
                if why:
                    audit("filtered", ip, f"{host} ({why})")
                    await send_frame(sid, MUX_END)
                    continue
                try:
                    reader, writer = await dial_target(host, port, direct, pid)
                except Exception:
                    await send_frame(sid, MUX_END)
                    continue
                subs[sid] = {"writer": writer}
                if data:
                    writer.write(data)
                    await writer.drain()
                    await bump(uid, len(data), 0)
                subs[sid]["task"] = asyncio.create_task(pump_down(sid, reader))

            elif status == MUX_KEEP:
                s = subs.get(sid)
                if s and data and s.get("dns"):
                    asyncio.create_task(mux_dns(sid, data))
                elif s and data:
                    try:
                        s["writer"].write(data)
                        await s["writer"].drain()
                        await bump(uid, len(data), 0)
                    except Exception:
                        await close_sub(sid)

            elif status == MUX_END:
                await close_sub(sid)
            # MUX_KEEPALIVE: nothing to do
    finally:
        for sid in list(subs):
            await close_sub(sid)


# ══════════════════════════ XHTTP (packet-up) ══════════════════════════
#
#  Downlink :  GET  /<XHTTP_PATH>/<session>          → streamed response body
#  Uplink   :  POST /<XHTTP_PATH>/<session>          → one streamed body   (stream-up)
#              POST /<XHTTP_PATH>/<session>/<seq>    → one ordered chunk   (packet-up)
#
#  Both uplink shapes are served side by side on every route variant (plain, -d and
#  -p<id>): which one a client uses is its own choice of `mode`, and a panel upgrade
#  must not break links already handed out.
#  packet-up chunks may arrive out of order, so each session keeps a reorder buffer.
#  stream-up needs no buffer — the bytes arrive in order on a single request.

class XSession:
    def __init__(self, sid: str, ip: str):
        self.sid = sid
        self.ip = ip
        self.ua = ""
        self.stream = ByteStream()
        self.out: asyncio.Queue = asyncio.Queue()
        self.next_seq = 0
        self.hold: dict[int, bytes] = {}
        self.touched = time.time()
        self.worker: Optional[asyncio.Task] = None
        self.closed = False
        self.uplink_open = False      # a stream-up POST is currently attached
        self.downlink_open = False    # the GET downlink is currently attached

    def touch(self):
        self.touched = time.time()

    async def send(self, data: bytes):
        await self.out.put(data)

    def feed(self, data: bytes):
        """Append in-order uplink bytes (stream-up)."""
        self.touch()
        self.stream.feed(data)

    def push(self, seq: int, data: bytes):
        """Insert an uplink chunk, forwarding everything now contiguous (packet-up)."""
        self.touch()
        if seq < self.next_seq:
            return
        self.hold[seq] = data
        while self.next_seq in self.hold:
            self.stream.feed(self.hold.pop(self.next_seq))
            self.next_seq += 1
        if len(self.hold) > 128:              # runaway gap, give up
            self.close()

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.stream.feed_eof()
        self.out.put_nowait(None)
        if self.worker:
            self.worker.cancel()


SESSIONS: dict[str, XSession] = {}
SID_RE = re.compile(r"^[A-Za-z0-9._\-]{4,64}$")

# ── Live connection registry (both WS and XHTTP) ──
# Every active tunnel registers here on connect and removes itself on close, so a
# single endpoint can show who is online right now (IP, transport, which proxy, and
# the user behind it) without polling the session dicts separately.
LIVE: dict[str, dict] = {}
_live_lock = asyncio.Lock()

async def live_register(key: str, info: dict):
    async with _live_lock:
        LIVE[key] = info

async def live_unregister(key: str):
    async with _live_lock:
        LIVE.pop(key, None)

def live_snapshot() -> list[dict]:
    """A cheap, lock-free copy for the dashboard endpoint."""
    return list(LIVE.values())
SID_RE = re.compile(r"^[A-Za-z0-9._\-]{4,64}$")


def get_session(sid: str, ip: str, direct: bool = False,
                pid: int | None = None, ua: str = "") -> XSession:
    s = SESSIONS.get(sid)
    if s is None or s.closed:
        s = XSession(sid, ip)
        s.direct = direct
        s.pid = pid
        s.ua = ua
        SESSIONS[sid] = s
        s.worker = asyncio.create_task(run_session(s))
    if ua and not s.ua:
        s.ua = ua
    s.touch()
    return s


async def run_session(s: XSession):
    try:
        await relay_session(s.stream, s.send, s.ip, "xhttp",
                            getattr(s, "direct", False),
                            getattr(s, "pid", None),
                            getattr(s, "ua", ""))
    except Exception:
        pass
    finally:
        s.close()
        SESSIONS.pop(s.sid, None)


async def reaper():
    """Drop sessions nothing is attached to any more.

    A stream-up tunnel can sit idle for a long time with its uplink POST and downlink
    GET still open; reaping those would force a reconnect and undo the whole point of
    the mode, so only detached sessions are considered.
    """
    while True:
        await asyncio.sleep(20)
        cutoff = time.time() - SESSION_IDLE
        for sid, s in list(SESSIONS.items()):
            if s.uplink_open or s.downlink_open:
                s.touch()
                continue
            if s.touched < cutoff:
                s.close()
                SESSIONS.pop(sid, None)


NOBUF_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "X-Accel-Buffering": "no",
    "Content-Type": "application/octet-stream",
}


# ────────────────────────────── APP ──────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    tgw_adopt_building_rows()   # restart during a build — re-watch the platform rows
    tasks = [
        asyncio.create_task(flusher()),
        asyncio.create_task(reaper()),
        asyncio.create_task(keepalive()),
        asyncio.create_task(resetter()),
        asyncio.create_task(tg_autobackup()),
        asyncio.create_task(detect_own_country()),
    ]
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(title=PANEL_TITLE, docs_url=None, redoc_url=None, lifespan=lifespan)


# ── XHTTP plumbing shared by every route variant ──
#
#  Each variant (plain, "-d" direct, "-p<id>" per-proxy) offers the same three
#  endpoints, so a client picks its own `mode` without the route caring.

def _xhttp_downlink(s: XSession) -> StreamingResponse:
    s.downlink_open = True

    async def gen():
        try:
            while True:
                item = await s.out.get()
                if item is None:
                    break
                yield item
        except asyncio.CancelledError:
            pass
        finally:
            s.downlink_open = False
            s.close()

    return StreamingResponse(gen(), headers=NOBUF_HEADERS)


async def _xhttp_uplink_stream(s: XSession, request: Request) -> Response:
    """Read the request body incrementally instead of buffering it.

    This is what makes stream-up cheap: the client opens one POST and keeps writing
    into it, so a relay in front of the panel sees a single request per connection
    rather than one per chunk. `request.stream()` hands us each piece as it lands.
    """
    if s.uplink_open:                     # one streamed uplink per session
        raise HTTPException(409, "uplink already attached")
    s.uplink_open = True
    try:
        async for chunk in request.stream():
            if not chunk:
                continue
            s.feed(chunk)
            if s.closed:
                break
    except (asyncio.CancelledError, ClientDisconnect):
        pass
    finally:
        s.uplink_open = False
        s.close()                         # the tunnel dies with its uplink
    return Response(status_code=200, headers=NOBUF_HEADERS)


async def _xhttp_uplink_packet(s: XSession, seq: str, request: Request) -> Response:
    body = await request.body()
    if body:
        s.push(int(seq), body)
    return Response(status_code=200, headers=NOBUF_HEADERS)


# ── XHTTP, default route ──
@app.get("/" + XHTTP_PATH + "/{session}")
async def xhttp_down(session: str, request: Request):
    if not SID_RE.match(session):
        raise HTTPException(404)
    return _xhttp_downlink(get_session(session, client_ip(request),
                                       ua=user_agent(request)))


@app.post("/" + XHTTP_PATH + "/{session}")
async def xhttp_up_stream(session: str, request: Request):
    if not SID_RE.match(session):
        raise HTTPException(404)
    return await _xhttp_uplink_stream(
        get_session(session, client_ip(request), ua=user_agent(request)), request)


@app.post("/" + XHTTP_PATH + "/{session}/{seq}")
async def xhttp_up(session: str, seq: str, request: Request):
    if not SID_RE.match(session) or not seq.isdigit():
        raise HTTPException(404)
    return await _xhttp_uplink_packet(
        get_session(session, client_ip(request), ua=user_agent(request)), seq, request)


# ── XHTTP, no-proxy variant ──
#  Same protocol on "<XHTTP_PATH>-d"; session keys are namespaced so a direct and a
#  proxied session can never collide.

@app.get("/" + XHTTP_PATH + "-d/{session}")
async def xhttp_down_direct(session: str, request: Request):
    if not SID_RE.match(session):
        raise HTTPException(404)
    return _xhttp_downlink(get_session("d." + session, client_ip(request), True,
                                       ua=user_agent(request)))


@app.post("/" + XHTTP_PATH + "-d/{session}")
async def xhttp_up_direct_stream(session: str, request: Request):
    if not SID_RE.match(session):
        raise HTTPException(404)
    return await _xhttp_uplink_stream(
        get_session("d." + session, client_ip(request), True, ua=user_agent(request)), request)


@app.post("/" + XHTTP_PATH + "-d/{session}/{seq}")
async def xhttp_up_direct(session: str, seq: str, request: Request):
    if not SID_RE.match(session) or not seq.isdigit():
        raise HTTPException(404)
    return await _xhttp_uplink_packet(
        get_session("d." + session, client_ip(request), True, ua=user_agent(request)),
        seq, request)


# ── XHTTP, per-proxy variants ──
#  "<XHTTP_PATH>-p<id>" always leaves through proxy <id>. Session keys are namespaced
#  per route, so the same client id on two routes never shares a session.

@app.get("/" + XHTTP_PATH + "-p{pid}/{session}")
async def xhttp_down_proxy(pid: int, session: str, request: Request):
    if not SID_RE.match(session) or pid <= 0:
        raise HTTPException(404)
    return _xhttp_downlink(
        get_session("p%d.%s" % (pid, session), client_ip(request), False, pid,
                    ua=user_agent(request)))


@app.post("/" + XHTTP_PATH + "-p{pid}/{session}")
async def xhttp_up_proxy_stream(pid: int, session: str, request: Request):
    if not SID_RE.match(session) or pid <= 0:
        raise HTTPException(404)
    return await _xhttp_uplink_stream(
        get_session("p%d.%s" % (pid, session), client_ip(request), False, pid,
                    ua=user_agent(request)), request)


@app.post("/" + XHTTP_PATH + "-p{pid}/{session}/{seq}")
async def xhttp_up_proxy(pid: int, session: str, seq: str, request: Request):
    if not SID_RE.match(session) or not seq.isdigit() or pid <= 0:
        raise HTTPException(404)
    return await _xhttp_uplink_packet(
        get_session("p%d.%s" % (pid, session), client_ip(request), False, pid,
                    ua=user_agent(request)),
        seq, request)


# ── WebSocket inbound (catch-all, validated inside) ──
@app.websocket("/{path:path}")
async def vless_ws(websocket: WebSocket, path: str):
    p = path.strip("/")
    direct = p == WS_PATH + "-d"          # the platform-exit variant
    pid = None
    m = re.match(r"^" + re.escape(WS_PATH) + r"-p([1-9][0-9]{0,8})$", p)
    if m:
        pid = int(m.group(1))             # this route rides one named proxy
    if p != WS_PATH and not direct and pid is None:
        await websocket.close(code=1008)
        return
    ip = client_ip(websocket)
    ua = user_agent(websocket)
    await websocket.accept()
    stream = WSStream(websocket)

    async def send(data: bytes):
        await websocket.send_bytes(data)

    try:
        await relay_session(stream, send, ip, "ws", direct, pid, ua)
    except PermissionError:
        try:
            await websocket.close(code=1008)
        except Exception:
            pass
        return
    except Exception:
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
        return
    try:
        await websocket.close()
    except Exception:
        pass


# ────────────────────────────── HELPERS ──────────────────────────────

def base_domain(request: Request) -> str:
    """The host clients should connect to — the relay when there is one."""
    if RELAY_DOMAIN:
        return RELAY_DOMAIN
    if DOMAIN:
        return DOMAIN.replace("https://", "").replace("http://", "").strip("/")
    return request.headers.get("host", "localhost")


def origin_domain(request: Request) -> str:
    """The panel's own host, ignoring any relay. Used for links back to the panel."""
    if DOMAIN:
        return DOMAIN.replace("https://", "").replace("http://", "").strip("/")
    return request.headers.get("host", "localhost")


def fmt_bytes(b: int) -> str:
    if not b:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i, n = 0, float(b)
    while n >= 1024 and i < len(units) - 1:
        n /= 1024
        i += 1
    return f"{n:.1f} {units[i]}" if i else f"{int(n)} {units[i]}"


def ws_uri(row, address: str, host: str, label: str, direct: bool = False,
           pid: int | None = None) -> str:
    path = WS_PATH + ("-d" if direct else ("-p%d" % pid if pid else ""))
    # Mux is advertised here (and only here): VLESS over WS carries mux.cool fine,
    # so a client opens ONE connection for all its browsing = ONE Cloudflare Worker
    # request no matter how many sites it visits. XHTTP below deliberately omits it
    # because standard clients (v2rayNG/NekoBox/Streisand) reject mux on xhttp and
    # silently fail to connect when it is forced on.
    _a = user_alpn(row, "http/1.1")
    alpn_part = "" if _a == "-" else f"&alpn={quote(_a, safe='')}"
    return (f"vless://{row['uuid']}@{address}:443"
            f"?encryption=none&security=tls&sni={host}&{tls_extras(row)}{alpn_part}"
            f"&type=ws&host={host}&path=%2F{path}&mux=1"
            f"#{quote(label)}")


# ───────────────── optional per-user obfuscation (cs + fm) ─────────────────
#
# Users with obfuscate = 1 get this link shape instead of the plain one: a
# cipher-suite mask (cs=), a two-stage TLS-hello fragmenter (fm=) and fp=unsafe.
# The structure below is kept byte-for-byte as specified — do not "tidy" it, the
# parameter order and the exact JSON spacing are part of what clients expect.
# Everyone else keeps the plain config, so links handed out earlier never change.

OBF_CIPHERS = (
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
)
OBF_CS = ":".join(OBF_CIPHERS)

# Written out literally (not via json.dumps) so the spacing matches the reference
# link exactly: ", " and ": " inside each object, no space between the two stages.
OBF_FM = ('{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", '
          '"lengths": ["0", "104", "1"], "delays": ["0"], "maxSplit": "0"}},'
          '{"type": "fragment", "settings": {"packets": "1-1", "lengths": '
          '["114", "1"], "delays": ["1"], "maxSplit": "11"}}]}')


# ───────────────── optional per-user anti-censorship extras ─────────────────
#
# ECH (Encrypted Client Hello) hides the SNI from a censor. It is opt-in per user:
# enabled, every link this panel issues for them carries one extra parameter holding
# the public "ECH config list" record published for Cloudflare's ECH-capable domains;
# disabled, the link is byte-for-byte what it used to be, so configs already
# installed keep working unchanged.
ECH_VALUE = "cloudflare-ech.com+udp://1.1.1.1"

# TLS Client Hello fingerprints a user may pick. "unsafe" is the panel default and
# stays first, so links issued before this setting existed stay unchanged; a client
# that does not know a name simply ignores it.
FINGERPRINTS = ("unsafe", "chrome", "firefox", "safari", "ios", "android",
                "edge", "ie", "qq", "random")

# ALPN values offered in the panel. "" means "this transport's own default"
# (http/1.1 for ws, none for xhttp) — i.e. exactly what every link carried before
# this setting existed, so an untouched account keeps its links as they were.
# "-" means "no alpn parameter at all": the link builders omit alpn= entirely and
# the client core negotiates ALPN by itself (what v2rayNG/Hiddify users expect
# when they clear the field).
ALPN_CHOICES = ("", "http/1.1", "h2", "h2,http/1.1", "-")


def _pick_choice(value, allowed, default: str) -> str:
    """Keep a stored choice only if it is one this panel still recognises."""
    try:
        v = str(value or "").strip().lower()
    except Exception:
        return default
    return v if v in allowed else default


def ech_on(row) -> bool:
    """True when this user asked for the ECH config list in their links."""
    try:
        return bool(row["ech"])
    except Exception:
        return False


def _row_str(row, col: str) -> str:
    try:
        return (row[col] or "").strip()
    except Exception:
        return ""


def ech_value(row) -> str:
    """This user's custom ECH config list, or the panel default when unset."""
    return _row_str(row, "ech_value") or ECH_VALUE


def obf_cs(row) -> str:
    """Custom cipher-suite mask for the obfuscated link, else the default list."""
    return _row_str(row, "obf_cs") or OBF_CS


def obf_fm(row) -> str:
    """Custom fragment JSON for the obfuscated link, else the default shape."""
    return _row_str(row, "obf_fm") or OBF_FM


def user_fp(row) -> str:
    """This user's TLS fingerprint, or the panel default when unset/unknown."""
    try:
        f = row["fp"]
    except Exception:
        f = None
    return _pick_choice(f, FINGERPRINTS, "unsafe")


def user_alpn(row, default: str) -> str:
    """This user's ALPN when they set one, else the transport's own default.

    An empty stored value means "this transport's own default" (http/1.1 for ws,
    none for xhttp) — never an empty ``alpn=`` parameter, which would break every
    link a user already has installed. A stored "-" means "omit the parameter
    completely"; the link builders turn that into no ``alpn=`` at all.
    """
    try:
        a = row["alpn"]
    except Exception:
        a = None
    v = str(a or "").strip().lower()
    if not v:
        return default
    return v if v in ALPN_CHOICES else default


def tls_extras(row) -> str:
    """Per-user TLS parameters appended to every link: fp, and ech when enabled."""
    out = [f"fp={quote(user_fp(row), safe='')}"]
    if ech_on(row):
        out.append(f"ech={quote(ech_value(row), safe='')}")
    return "&".join(out)


def obf_on(row) -> bool:
    """True when this user asked for the obfuscated link shape."""
    try:
        return bool(row["obfuscate"])
    except Exception:
        return False


def ws_uri_obf(row, address: str, host: str, label: str, direct: bool = False,
               pid: int | None = None) -> str:
    """The obfuscated WS link. No mux here: fragmenting plus mux confuses clients."""
    path = WS_PATH + ("-d" if direct else ("-p%d" % pid if pid else ""))
    _a = user_alpn(row, "")
    alpn_part = f"&alpn={quote(_a, safe='')}" if _a and _a != "-" else ""
    return (f"vless://{row['uuid']}@{address}:443"
            f"?cs={quote(obf_cs(row), safe='')}"
            f"&path={quote('/' + path, safe='')}"
            f"&security=tls&encryption=none"
            f"&fm={quote(obf_fm(row), safe='')}"
            f"&insecure=0&host={host}&{tls_extras(row)}{alpn_part}&type=ws&allowInsecure=0"
            f"&sni={host}"
            f"#{quote(label)}")


def xhttp_uri(row, address: str, host: str, label: str, direct: bool = False,
              pid: int | None = None) -> str:
    # NOTE: deliberately NO &mux=1 here. mux.cool is not supported on xhttp by the
    # common clients; adding it makes the config refuse to connect. Keep mux on the
    # WS variant only (see ws_uri).
    path = XHTTP_PATH + ("-d" if direct else ("-p%d" % pid if pid else ""))
    _a = user_alpn(row, "")
    alpn_part = f"&alpn={quote(_a, safe='')}" if _a and _a != "-" else ""
    return (f"vless://{row['uuid']}@{address}:443"
            f"?encryption=none&security=tls&sni={host}&{tls_extras(row)}{alpn_part}"
            f"&type=xhttp&host={host}&path=%2F{path}&mode={XHTTP_MODE}"
            f"#{quote(label)}")


# ─────────────────────── country flags in config names ───────────────────────

COUNTRY_WORDS = {
    "germany": "DE", "deutschland": "DE", "\u0622\u0644\u0645\u0627\u0646": "DE", "frankfurt": "DE",
    "netherlands": "NL", "holland": "NL", "\u0647\u0644\u0646\u062f": "NL", "amsterdam": "NL",
    "france": "FR", "\u0641\u0631\u0627\u0646\u0633\u0647": "FR", "paris": "FR",
    "england": "GB", "britain": "GB", "london": "GB", "\u0627\u0646\u06af\u0644\u06cc\u0633": "GB",
    "finland": "FI", "\u0641\u0646\u0644\u0627\u0646\u062f": "FI", "sweden": "SE", "\u0633\u0648\u0626\u062f": "SE",
    "poland": "PL", "\u0644\u0647\u0633\u062a\u0627\u0646": "PL", "austria": "AT", "\u0627\u062a\u0631\u06cc\u0634": "AT",
    "switzerland": "CH", "\u0633\u0648\u0626\u06cc\u0633": "CH", "spain": "ES", "\u0627\u0633\u067e\u0627\u0646\u06cc\u0627": "ES",
    "italy": "IT", "\u0627\u06cc\u062a\u0627\u0644\u06cc\u0627": "IT", "romania": "RO", "\u0631\u0648\u0645\u0627\u0646\u06cc": "RO",
    "turkey": "TR", "turkiye": "TR", "\u062a\u0631\u06a9\u06cc\u0647": "TR", "istanbul": "TR",
    "russia": "RU", "\u0631\u0648\u0633\u06cc\u0647": "RU", "emirates": "AE", "dubai": "AE", "\u0627\u0645\u0627\u0631\u0627\u062a": "AE",
    "qatar": "QA", "\u0642\u0637\u0631": "QA", "oman": "OM", "\u0639\u0645\u0627\u0646": "OM",
    "armenia": "AM", "\u0627\u0631\u0645\u0646\u0633\u062a\u0627\u0646": "AM", "georgia": "GE", "\u06af\u0631\u062c\u0633\u062a\u0627\u0646": "GE",
    "india": "IN", "\u0647\u0646\u062f": "IN", "singapore": "SG", "\u0633\u0646\u06af\u0627\u067e\u0648\u0631": "SG",
    "japan": "JP", "\u0698\u0627\u067e\u0646": "JP", "korea": "KR", "\u06a9\u0631\u0647": "KR",
    "canada": "CA", "\u06a9\u0627\u0646\u0627\u062f\u0627": "CA", "america": "US", "usa": "US", "\u0622\u0645\u0631\u06cc\u06a9\u0627": "US",
    "iran": "IR", "\u0627\u06cc\u0631\u0627\u0646": "IR", "australia": "AU", "\u0627\u0633\u062a\u0631\u0627\u0644\u06cc\u0627": "AU",
    "brazil": "BR", "\u0628\u0631\u0632\u06cc\u0644": "BR", "denmark": "DK", "\u062f\u0627\u0646\u0645\u0627\u0631\u06a9": "DK",
    "norway": "NO", "\u0646\u0631\u0648\u0698": "NO", "belgium": "BE", "\u0628\u0644\u0698\u06cc\u06a9": "BE",
    "czech": "CZ", "\u0686\u06a9": "CZ", "hungary": "HU", "\u0645\u062c\u0627\u0631\u0633\u062a\u0627\u0646": "HU",
    "lithuania": "LT", "latvia": "LV", "estonia": "EE", "ireland": "IE", "\u0627\u06cc\u0631\u0644\u0646\u062f": "IE",
    "ukraine": "UA", "\u0627\u0648\u06a9\u0631\u0627\u06cc\u0646": "UA", "kazakhstan": "KZ", "\u0642\u0632\u0627\u0642\u0633\u062a\u0627\u0646": "KZ",
    "hongkong": "HK", "hong kong": "HK", "\u0647\u0646\u06af\u200c\u06a9\u0646\u06af": "HK",
    "cloudflare": "", "cdn": "",
    # Iranian carriers and cities: clean-IP remarks are usually written in Persian
    "\u0627\u06cc\u0631\u0627\u0646\u0633\u0644": "IR", "\u0647\u0645\u0631\u0627\u0647 \u0627\u0648\u0644": "IR",
    "\u0647\u0645\u0631\u0627\u0647\u0627\u0648\u0644": "IR", "\u0631\u0627\u06cc\u062a\u0644": "IR",
    "\u0627\u062e\u062a\u0635\u0627\u0635\u06cc": "IR", "\u062a\u0647\u0631\u0627\u0646": "IR",
    "\u0645\u0634\u0647\u062f": "IR", "\u0634\u06cc\u0631\u0627\u0632": "IR", "\u062a\u0628\u0631\u06cc\u0632": "IR",
    "\u0627\u0635\u0641\u0647\u0627\u0646": "IR", "\u06a9\u0631\u062c": "IR", "\u0627\u0647\u0648\u0627\u0632": "IR",
    "frankfurt am main": "DE", "munich": "DE", "berlin": "DE",
    "los angeles": "US", "new york": "US", "ashburn": "US", "seattle": "US", "dallas": "US",
    "paris": "FR", "marseille": "FR", "warsaw": "PL", "milan": "IT", "madrid": "ES",
    "stockholm": "SE", "helsinki": "FI", "tallinn": "EE", "riga": "LV", "vilnius": "LT",
    "zurich": "CH", "vienna": "AT", "prague": "CZ", "budapest": "HU", "bucharest": "RO",
    "sofia": "BG", "athens": "GR", "lisbon": "PT", "dublin": "IE", "oslo": "NO",
    "copenhagen": "DK", "brussels": "BE", "reykjavik": "IS", "kiev": "UA", "kyiv": "UA",
    "moscow": "RU", "almaty": "KZ", "tbilisi": "GE", "yerevan": "AM", "baku": "AZ",
    "istanbul": "TR", "ankara": "TR", "tel aviv": "IL", "riyadh": "SA", "jeddah": "SA",
    "dubai": "AE", "doha": "QA", "muscat": "OM", "kuwait": "KW", "manama": "BH",
    "amman": "JO", "beirut": "LB", "cairo": "EG", "casemate": "MA", "tunis": "TN",
    "mumbai": "IN", "delhi": "IN", "karachi": "PK", "dhaka": "BD", "colombo": "LK",
    "kathmandu": "NP", "jakarta": "ID", "kuala lumpur": "MY", "bangkok": "TH",
    "hanoi": "VN", "manila": "PH", "hong kong": "HK", "taipei": "TW", "seoul": "KR",
    "tokyo": "JP", "osaka": "JP", "sydney": "AU", "melbourne": "AU", "auckland": "NZ",
    "toronto": "CA", "montreal": "CA", "sao paulo": "BR", "buenos aires": "AR",
    "santiago": "CL", "lima": "PE", "mexico city": "MX", "johannesburg": "ZA",
    "lagos": "NG", "nairobi": "KE", "addis ababa": "ET",
}

ISO2_RE = re.compile(r"(?:^|[\s\-_\[\(#|])([A-Za-z]{2})(?:$|[\s\-_\]\)#|])")


def flag_of(code: str) -> str:
    """ISO alpha-2 -> flag emoji.

    Maps each A-Z letter to its Regional Indicator Symbol (U+1F1E6..U+1F1FF),
    so "DE" becomes the German flag glyph. Falls back to the bare two-letter
    code when the input is not a clean alpha-2 (e.g. unknown or empty).
    """
    c = re.sub(r"[^A-Za-z]", "", code or "")[:2].upper()
    if len(c) != 2:
        return ""
    return "".join(chr(0x1F1E6 + (ord(ch) - ord("A"))) for ch in c)


def guess_country(text: str) -> str:
    """Best-effort country code from a free-text label such as 'DE Frankfurt'."""
    low = (text or "").strip().lower()
    if not low:
        return ""
    for word, code in COUNTRY_WORDS.items():
        if word and word in low:
            return code
    m = ISO2_RE.search(" " + low + " ")
    return m.group(1).upper() if m else ""


def cip_flag(cip) -> str:
    """Flag for one clean IP: the stored country wins, otherwise guess it."""
    try:
        stored = cip["country"]
    except (KeyError, IndexError):
        stored = ""
    return flag_of(stored) or flag_of(guess_country(cip["remark"] or ""))


def main_flag() -> str:
    """Country of the panel's own exit: the saved setting, else the auto-detected one."""
    return flag_of(get_setting("main_country") or get_setting("detected_country") or "")


def _detect_own_country_sync() -> str:
    """Ask ip-api which country this host sits in. Blocking, ~1 s, best effort."""
    try:
        req = urllib.request.Request(
            "http://" + IP_CHECK_HOST + IP_CHECK_PATH,
            headers={"User-Agent": "IranXPanel/4"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        cc = str(data.get("countryCode") or "").upper()
        return cc if re.fullmatch(r"[A-Z]{2}", cc) else ""
    except Exception:
        return ""


async def detect_own_country():
    """Cache the host's country once (and refresh weekly) so configs can carry a flag."""
    while True:
        try:
            if not (get_setting("detected_country") or ""):
                cc = await asyncio.to_thread(_detect_own_country_sync)
                if cc:
                    set_setting("detected_country", cc)
        except Exception:
            pass
        await asyncio.sleep(7 * 86400)


def proxy_flag() -> str:
    """Flag of the active proxy: with one armed, that is the real exit country."""
    if (get_setting("flag_source") or "proxy") != "proxy":
        return ""
    px = active_proxy()
    if not px:
        return ""
    try:
        return flag_of(px["country"] or "")
    except Exception:
        return ""


BOLTS = ("\u26a1\ufe0f", "\u26a1", "\U0001f5f2\ufe0f", "\U0001f5f2")


def clean_label(text: str) -> str:
    """Strip lightning bolts from every name the panel emits.

    They came from the subscription profile title, and can also be inherited from
    a proxy remark or a clean-IP note; clients then paint that bolt on the whole
    group. Nothing this panel hands out carries one any more.
    """
    out = str(text or "")
    for b in BOLTS:
        out = out.replace(b, "")
    return " ".join(out.split())


def build_configs(row, host: str, clean_ips) -> list[dict]:
    t = (row["transport"] or "both").lower()
    kinds = []
    ws_builder = ws_uri_obf if obf_on(row) else ws_uri
    if t in ("ws", "both"):
        kinds.append(("WS", ws_builder))
    if t in ("xhttp", "both"):
        kinds.append(("XHTTP", xhttp_uri))

    # Every route sits in the same subscription, side by side: first the host's own
    # exit (Render / Railway) flagged with the server country, then one route per
    # enabled proxy flagged with that proxy's exit country. A proxy shows up here as
    # soon as it is added and stays until it is disabled or deleted — a failed health
    # check or a dropped connection never removes it.
    #
    # Names carry only the flag, the account or clean-IP name, and the proxy's
    # location — no transport tag and no "PX" marker.
    server_flag = main_flag() or ""
    by_proxy_flag = (get_setting("flag_source") or "proxy") == "proxy"
    routes = [(server_flag, "", True, None)]
    for px in sub_proxies():
        try:
            pflag = flag_of(px["country"] or "") or flag_of(guess_country(px["remark"] or ""))
        except Exception:
            pflag = ""
        mark = (pflag or "") if by_proxy_flag else server_flag
        try:
            spot = px["city"] or px["country_name"] or px["remark"] or px["host"]
        except Exception:
            spot = px["host"]
        spot = str(spot or "")[:20]
        routes.append((mark, (" \u00b7 " + spot) if spot else "", False, px["id"]))

    out = []
    for mark, suffix, direct, pid in routes:
        for tag, fn in kinds:
            # The panel domain resolves to the host itself, so it only makes sense for
            # the server's own exit; proxy routes ride the clean IPs instead.
            if direct:
                title = clean_label(f"{mark} {row['name']}{suffix}")
                out.append({"label": clean_label(f"{mark} {row['name']}{suffix} \u00b7 Default"),
                            "transport": tag,
                            "uri": fn(row, host, host, title, direct, pid)})
            for cip in clean_ips:
                note = cip["remark"] or cip["address"]
                cmark = (cip_flag(cip) or mark) if direct else mark
                out.append({"label": clean_label(f"{cmark} {note}{suffix}"),
                            "transport": tag,
                            "uri": fn(row, cip["address"], host,
                                      clean_label(f"{cmark} {row['name']} \u00b7 {note}{suffix}"),
                                      direct, pid)})
    return out


INFO_UUID = "494e464f-0000-0000-0000-000000000000"   # ascii "INFO"
LRM = "\u200e"                                            # keeps digits LTR in RTL clients


def info_uri(label: str, host: str) -> str:
    """A non-functional entry whose name carries the account info.

    It points at port 80 with security=none on a path the inbounds ignore, so a
    client can never actually dial it — it only ever shows up as a label.
    """
    return (f"vless://{INFO_UUID}@{host}:80"
            f"?encryption=none&host={host}&path=%2Finfo&security=none&type=ws"
            f"#{quote(label)}")


def info_label(row) -> str:
    """📊 name | 6.70GB | 26Days"""
    quota, used = row["quota_bytes"], row["used_bytes"]
    if quota:
        remain_gb = max(0, quota - used) / GB
        vol = f"{remain_gb:.2f}GB"
    else:
        vol = "\u267e\ufe0f"

    if row["expire_at"]:
        days = max(0, int((row["expire_at"] - now()) / 86400))
        exp = f"{days}Days"
    else:
        exp = "\u267e\ufe0f"

    return f"\U0001f4ca {row['name']} | {LRM}{vol} | {LRM}{exp}"


def build_info_lines(row, host: str) -> list[str]:
    return [info_uri(clean_label(info_label(row)), host)]


# ───────────── subscription container formats: Clash / sing-box ─────────────
#
# The classic subscription is a base64 list of vless:// URIs, which v2ray-family
# clients understand. Clash.Meta (mihomo) and sing-box need their own container,
# so the same generated configs are re-expressed here. The vless URIs the panel
# itself issued are parsed back into their parts — no second source of truth,
# so flags, labels, clean-IP routes and proxy routes stay identical everywhere.

def parse_vless_uri(uri: str) -> Optional[dict]:
    """Split one of our own vless:// URIs into its parts, or None if not ours."""
    try:
        rest = uri[len("vless://"):]
        frag = ""
        if "#" in rest:
            rest, frag = rest.split("#", 1)
        userinfo, hostpart = rest.split("@", 1)
        q = {}
        if "?" in hostpart:
            hostpart, query = hostpart.split("?", 1)
            for kv in query.split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    q[k] = unquote(v)
        addr, port = hostpart.rsplit(":", 1)
        return {"uuid": userinfo,
                "address": addr,
                "port": int(port),
                "sni": q.get("sni", ""),
                "host": q.get("host", ""),
                "path": q.get("path", ""),
                "net": q.get("type", "ws"),
                "mode": q.get("mode", "auto"),
                "fp": q.get("fp", ""),
                "ech": q.get("ech", ""),
                "alpn": [a for a in q.get("alpn", "").split(",") if a],
                "name": unquote(frag)}
        # NOTE: cs= / fm= (per-user obfuscation mask + fragment JSON) are Xray-only
        # dial-time parameters with no Clash.Meta or sing-box equivalent, so they are
        # intentionally not parsed here — they stay on the vless links only.
    except Exception:
        return None


def _config_proxies(configs) -> list[dict]:
    """Parsed vless URIs from build_configs(), minus the INFO placeholder."""
    out, seen = [], set()
    for c in configs or []:
        p = parse_vless_uri(c.get("uri", "") or "")
        if not p or p["uuid"] == INFO_UUID or not p["name"]:
            continue
        if p["name"] in seen:
            continue
        seen.add(p["name"])
        out.append(p)
    return out


def _xhttp_mode(mode: str) -> str:
    return mode if mode in ("auto", "packet-up", "stream-up") else "auto"


def _clash_proxies(configs) -> list[dict]:
    """Map parsed configs to Clash.Meta (mihomo) vless proxy dicts."""
    out = []
    for p in _config_proxies(configs):
        pr = {"name": p["name"], "type": "vless", "server": p["address"],
              "port": p["port"], "uuid": p["uuid"], "udp": True, "tls": True,
              "servername": p["sni"] or p["host"]}
        if p["fp"] and p["fp"] != "unsafe":
            pr["client-fingerprint"] = p["fp"]
        if p["alpn"]:
            pr["alpn"] = p["alpn"]
        if p.get("ech"):
            # per-user custom ECH config list (the ech= parameter on the vless URI)
            pr["ech-opts"] = {"enabled": True, "config": [p["ech"]]}
        if p["net"] == "xhttp":
            pr["network"] = "xhttp"
            pr["xhttp-opts"] = {"path": p["path"] or "/", "mode": _xhttp_mode(p["mode"])}
        else:
            pr["network"] = "ws"
            pr["ws-opts"] = {"path": p["path"] or "/"}
            if p["host"]:
                pr["ws-opts"]["headers"] = {"Host": p["host"]}
        out.append(pr)
    return out


def _yaml_str(v) -> str:
    s = str(v)
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _clash_yaml_line(key: str, v, indent: str = "    ") -> str:
    if isinstance(v, bool) or isinstance(v, int):
        return f"{indent}{key}: {str(v).lower() if isinstance(v, bool) else v}"
    return f"{indent}{key}: {_yaml_str(v)}"


def _clash_yaml(proxies: list[dict]) -> str:
    """Hand-rolled emitter: a fixed schema of scalars, lists and one-level maps.

    Every string is double-quoted and escaped, so emoji flags, Persian names and
    URLs land in the file exactly as generated — no PyYAML dependency needed.
    """
    names = [p["name"] for p in proxies]
    group = "\U0001f680 IranX"
    auto = "\u26a1 Auto"
    lines = [
        "# IranX Panel — Clash.Meta / mihomo configuration (auto-generated)",
        "# Keep this subscription URL private: it carries your account.",
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: warning",
        "unified-delay: true",
        "tcp-concurrent: true",
        "proxies:",
    ]
    for p in proxies:
        lines.append("  - " + _clash_yaml_line("name", p["name"]).strip())
        for k in ("type", "server", "port", "uuid", "udp", "tls", "servername",
                  "client-fingerprint", "network"):
            if k in p:
                lines.append(_clash_yaml_line(k, p[k]))
        if "alpn" in p:
            lines.append("    alpn: [" + ", ".join(_yaml_str(a) for a in p["alpn"]) + "]")
        if "ech-opts" in p:
            lines.append("    ech-opts:")
            lines.append(_clash_yaml_line("enabled", p["ech-opts"]["enabled"], indent="      "))
            lines.append("      config: ["
                         + ", ".join(_yaml_str(x) for x in p["ech-opts"]["config"]) + "]")
        if "ws-opts" in p:
            lines.append("    ws-opts:")
            lines.append(_clash_yaml_line("path", p["ws-opts"]["path"], indent="      "))
            if "headers" in p["ws-opts"]:
                lines.append("      headers:")
                for hk, hv in p["ws-opts"]["headers"].items():
                    lines.append(_clash_yaml_line(hk, hv, indent="        "))
        if "xhttp-opts" in p:
            lines.append("    xhttp-opts:")
            lines.append(_clash_yaml_line("path", p["xhttp-opts"]["path"], indent="      "))
            lines.append(_clash_yaml_line("mode", p["xhttp-opts"]["mode"], indent="      "))
    if not proxies:
        lines.append("  []")
    lines += [
        "proxy-groups:",
        "  - name: " + _yaml_str(group),
        "    type: select",
        "    proxies:",
    ]
    lines += ["      - " + _yaml_str(n) for n in names]
    lines.append("      - DIRECT")
    if proxies:
        lines += [
            "  - name: " + _yaml_str(auto),
            "    type: url-test",
            "    url: " + _yaml_str("http://www.gstatic.com/generate_204"),
            "    interval: 300",
            "    tolerance: 80",
            "    proxies:",
        ]
        lines += ["      - " + _yaml_str(n) for n in names]
    lines += [
        "rules:",
        "  - MATCH," + group,
    ]
    return "\n".join(lines) + "\n"


def _singbox_outbound(p: dict) -> dict:
    """Map one parsed config to a sing-box vless outbound."""
    ob = {"type": "vless", "tag": p["name"], "server": p["address"],
          "server_port": p["port"], "uuid": p["uuid"]}
    tls = {"enabled": True, "server_name": p["sni"] or p["host"], "insecure": False}
    if p["alpn"]:
        tls["alpn"] = p["alpn"]
    if p["fp"] and p["fp"] != "unsafe":
        tls["utls"] = {"enabled": True, "fingerprint": p["fp"]}
    if p.get("ech"):
        # per-user custom ECH config list (the ech= parameter on the vless URI)
        tls["ech"] = {"enabled": True, "config": [p["ech"]]}
    ob["tls"] = tls
    if p["net"] == "xhttp":
        ob["transport"] = {"type": "xhttp", "path": p["path"] or "/",
                           "mode": _xhttp_mode(p["mode"])}
    else:
        tr = {"type": "ws", "path": p["path"] or "/"}
        if p["host"]:
            tr["headers"] = {"Host": p["host"]}
        ob["transport"] = tr
    return ob


def _singbox_config(configs, title: str) -> dict:
    """A complete, standalone sing-box config around the user's outbounds.

    Kept intentionally small: one mixed inbound, a selector on top of the user's
    nodes, and a direct fallback. Apps that import subscriptions (Hiddify,
    Karing, Happ…) pick the outbounds; a bare sing-box run uses the file as-is.
    """
    nodes = [_singbox_outbound(p) for p in _config_proxies(configs)]
    # Tags must be unique for the selector to stay valid.
    seen, tags = {}, []
    for n in nodes:
        tag, i = n["tag"], 2
        while tag in seen:
            tag = f"{n['tag']} #{i}"
            i += 1
        n["tag"] = tag
        seen[tag] = True
        tags.append(tag)
    if tags:
        outbounds = ([{"type": "selector", "tag": "IranX",
                       "outbounds": tags + ["direct"],
                       "default": tags[0]}]
                     + nodes + [{"type": "direct", "tag": "direct"}])
        final = "IranX"
    else:
        outbounds = [{"type": "direct", "tag": "direct"}]
        final = "direct"
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [{"type": "mixed", "tag": "mixed-in",
                      "listen": "127.0.0.1", "listen_port": 2080}],
        "outbounds": outbounds,
        "route": {"rules": [], "final": final},
    }


DEVICE_GATE_HEADER = "x-iranx-device-gate"
DEVICE_GATE_APPS = tuple(name for _rx, name in DEVICE_AWARE_CLIENTS)


def device_gate_response(row) -> PlainTextResponse:
    """403 for a client that cannot identify its device on a limited account.

    Deliberately a plain-text body: subscription clients show it verbatim, so the user
    sees which apps they may use instead of a generic "download failed".
    """
    try:
        n = int(row["device_limit"] or 0)
    except (KeyError, IndexError, TypeError):
        n = 0
    lines = [
        "IRANX · DEVICE ID REQUIRED",
        "",
        ("This account allows %d device%s. To receive the subscription, "
         "your client must send a stable x-hwid or x-device-id header."
         % (n, "" if n == 1 else "s")),
        "",
        "A client name, User-Agent, IP address, or phone model is not enough.",
        "Each accepted HWID is registered and consumes one device slot.",
        "When all slots are used, ask the panel admin to remove an old device.",
        "",
        "A device ID is client-reported; this cannot prevent deliberate HWID spoofing "
        "or a client that copies its subscription and identifier.",
        "Set device limit to 0 to keep the account unrestricted.",
    ]
    return PlainTextResponse("\n".join(lines), status_code=403, headers={
        DEVICE_GATE_HEADER: "1",
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "no-store",
    })


def _sub_headers(row, request: Request) -> dict:
    """Header block shared by every subscription container format."""
    return {
        "profile-title": "base64:" + base64.b64encode(
            clean_label(row["name"]).encode()).decode(),
        "profile-update-interval": "12",
        "profile-web-page-url": f"https://{origin_domain(request)}/",
        "subscription-userinfo":
            f"upload=0; download={row['used_bytes']}; "
            f"total={row['quota_bytes']}; expire={row['expire_at']}",
    }


def sub_response_clash(row, d, ips, request: Request) -> PlainTextResponse:
    ok, _reason = user_status(row)
    h = _sub_headers(row, request)
    h["content-type"] = "text/yaml; charset=utf-8"
    h["cache-control"] = "no-store"
    return PlainTextResponse(_clash_yaml(_clash_proxies(
        build_configs(row, d, ips) if ok else [])), headers=h)


def sub_response_singbox(row, d, ips, request: Request) -> JSONResponse:
    ok, _reason = user_status(row)
    h = _sub_headers(row, request)
    return JSONResponse(_singbox_config(
        build_configs(row, d, ips) if ok else [], row["name"]), headers=h)


def row_out(r) -> dict:
    r = maybe_auto_reset(r)            # refresh a stale cycle right on panel load
    d = dict(r)
    d["devices_now"] = active_devices(r["id"])
    d["devices_live"] = live_devices(r["id"])
    d["ips_now"] = active_ips(r["id"])
    d["ips_live"] = live_ips(r["id"])
    ok, reason = user_status(r)
    d["active"], d["status"] = ok, reason
    return d


# ─────────────── Telegram WEB-proxy (t.me/webproxy) ───────────────

TG_SECRET_RE = re.compile(r"^[0-9a-f]{32}$")


def tg_clean_server(s: str) -> str:
    """WEB-proxy links take a bare host (optionally host/path) — no scheme, no port."""
    s = (s or "").strip().lower()
    s = re.sub(r"^https?://", "", s)
    return s.strip("/").strip()


def tgweb_status(r) -> tuple[bool, str]:
    """Same four states the users table uses: active / disabled / expired / quota."""
    if not r["enabled"]:
        return False, "disabled"
    if r["expire_at"] and r["expire_at"] < now():
        return False, "expired"
    if r["quota_bytes"] and r["used_bytes"] >= r["quota_bytes"]:
        return False, "quota"
    return True, "active"


def tgweb_region_meta(r) -> dict | None:
    """Display metadata for the row's hosting region (coords.region), or None."""
    try:
        coords = json.loads(r["coords"] or "{}")
    except Exception:
        coords = {}
    rid = (coords.get("region") or "").strip()
    if not rid:
        return None
    for m in TGW_REGIONS.get(r["platform"] or "", []):
        if m["id"] == rid:
            return {"id": rid, "fa": m["fa"], "en": m["en"], "flag": m["flag"]}
    return {"id": rid, "fa": rid, "en": rid, "flag": ""}


def tgweb_out(r) -> dict:
    d = dict(r)
    if d.get("server"):
        d["link"] = "https://t.me/webproxy?server=%s&secret=%s" % (d["server"], d["secret"])
    else:
        d["link"] = ""
    d["active"], d["status"] = tgweb_status(r)
    d["region"] = tgweb_region_meta(r)
    return d


# ─────────────── Telegram WEB-proxy: platform deployment engine ───────────────
# The panel can host a proxy itself: it creates a real service on Render or Railway
# from the IranXPanel repo's tproxy/ folder (a container running the official
# telegramdesktop/tproxy-server relay + MTProxy backend), injects the proxy's secret
# through env vars, waits for the deploy to go live and only then hands out the
# t.me/webproxy link. Base URLs are env-overridable so tests can point the panel at a
# mock; every call is stdlib-urllib inside asyncio.to_thread (the panel has no httpx).

RENDER_API = os.environ.get("TGPW_RENDER_API", "https://api.render.com/v1")
RAILWAY_API = os.environ.get("TGPW_RAILWAY_API", "https://backboard.railway.app/graphql/v2")
TGWEB_REPO = "https://github.com/BeeEhsas/IranXPanel"
TGWEB_ROOT = "tproxy"                 # subdirectory of the repo that holds the Dockerfile
TGW_CARRIERS = ("websocket", "websocket-lanes", "https", "https-lanes")
TGW_BUILD_TIMEOUT = 900               # seconds a platform build may take before "failed"
TGW_STATE_BUILDING, TGW_STATE_LIVE, TGW_STATE_FAILED = "building", "live", "failed"
# Hosting regions — official lists (Render OpenAPI `serviceDetails.region` enum;
# Railway docs "Region Identifier" column). Render: chosen once at create time, a
# service cannot move to another region afterwards. Railway: the region can be
# changed any time — the service redeploys in place and keeps its domain.
# Order = display order; the first entry of each list is that platform's default.
TGW_REGIONS = {
    "render": [
        {"id": "frankfurt", "fa": "فرانکفورت، آلمان", "en": "Frankfurt, Germany",
         "flag": "DE"},
        {"id": "oregon", "fa": "اورگان، آمریکا", "en": "Oregon, USA",
         "flag": "US"},
        {"id": "ohio", "fa": "اوهایو، آمریکا", "en": "Ohio, USA",
         "flag": "US"},
        {"id": "virginia", "fa": "ویرجینیا، آمریکا", "en": "Virginia, USA",
         "flag": "US"},
        {"id": "singapore", "fa": "سنگاپور", "en": "Singapore",
         "flag": "SG"},
    ],
    "railway": [
        {"id": "europe-west4-drams3a", "fa": "آمستردام، هلند",
         "en": "Amsterdam, Netherlands", "flag": "NL"},
        {"id": "us-west2", "fa": "کالیفرنیا، آمریکا", "en": "California, USA",
         "flag": "US"},
        {"id": "us-east4-eqdc4a", "fa": "ویرجینیا، آمریکا", "en": "Virginia, USA",
         "flag": "US"},
        {"id": "asia-southeast1-eqsg3a", "fa": "سنگاپور", "en": "Singapore",
         "flag": "SG"},
    ],
}
TGW_DEFAULT_REGION = {"render": "frankfurt", "railway": "europe-west4-drams3a"}
TGW_STATE_NONE = "none"              # platform has no deployment registered (yet)
# The platform this panel itself runs on — Railway/Render inject marker env vars at
# runtime. The panel only asks for that platform's token (TGPW_SELF_PLATFORM overrides,
# empty string = hosted somewhere else → both platforms stay available).
TGW_SELF_ENV = {"railway": ("RAILWAY_PROJECT_ID", "RAILWAY_ENVIRONMENT_ID",
                            "RAILWAY_SERVICE_NAME", "RAILWAY_PUBLIC_DOMAIN"),
                "render": ("RENDER_SERVICE_ID", "RENDER_PROJECT_ID",
                           "RENDER_EXTERNAL_URL", "IS_RENDER")}
# watcher tuning (env-overridable so tests can speed it up)
TGW_POLL = float(os.environ.get("TGPW_TGW_POLL", "10") or 10)
TGW_NODEPLOY_AFTER = float(os.environ.get("TGPW_TGW_NODEPLOY", "90") or 90)
TGW_ERR_LIMIT = int(os.environ.get("TGPW_TGW_ERRS", "3") or 3)
# Build pre-flight: a repo whose tproxy/ folder was never pushed can never build —
# fail the row in seconds with the real reason instead of after a platform timeout.
TGW_PREFLIGHT = os.environ.get("TGPW_PREFLIGHT", "1") != "0"
GITHUB_RAW = os.environ.get("TGPW_GITHUB_RAW", "https://raw.githubusercontent.com")
GITHUB_PAGE = os.environ.get("TGPW_GITHUB_PAGE", "https://github.com")


def tgw_self_platform() -> str:
    p = os.environ.get("TGPW_SELF_PLATFORM", "").strip().lower()
    if p in TGW_SELF_ENV:
        return p
    for plat, keys in TGW_SELF_ENV.items():
        if any(os.environ.get(k) for k in keys):
            return plat
    return ""


def tgw_github_slug(repo_url: str) -> str:
    """Railway's source.repo takes \"owner/repo\", not a full GitHub URL."""
    m = re.match(r"^https://github\.com/([^/\s]+?)/([^/\s]+?)(?:\.git)?/?$",
                 (repo_url or "").strip())
    return ("%s/%s" % (m.group(1), m.group(2))) if m else ""


# Railway's edge (Cloudflare WAF) answers Python's default "Python-urllib/3.x"
# signature with a bare HTTP 403 "error code: 1010" — before the API ever sees the
# token, which made a healthy token look rejected. Every outbound platform call
# therefore presents an application User-Agent; Render and GitHub accept it too.
PLATFORM_UA = "IranXPanel/2.0 (+https://github.com/BeeEhsas/IranXPanel)"


def _http_probe(url: str) -> int:
    """GET a URL and return just the HTTP status (−1 on transport trouble)."""
    req = urllib.request.Request(url, method="GET")
    req.add_header("accept", "text/plain, text/html, */*")
    req.add_header("user-agent", PLATFORM_UA)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return int(getattr(resp, "status", 200))
    except urllib.error.HTTPError as e:
        return int(e.code)
    except Exception:
        return -1


async def tgw_repo_state(repo_url: str, branch: str) -> str:
    """'ok' = raw.githubusercontent serves tproxy/Dockerfile; 'missing' = the repo is
    public but the file is not on that branch; 'unknown' = private repo or non-GitHub
    URL — cannot verify, let the platform decide."""
    m = re.match(r"^https://github\.com/([^/\s]+?)/([^/\s]+?)(?:\.git)?/?$",
                 (repo_url or "").strip())
    if not m:
        return "unknown"
    owner, name = m.group(1), m.group(2)
    if await _call(_http_probe, "%s/%s/%s/%s/tproxy/Dockerfile"
                   % (GITHUB_RAW, owner, name, branch or "main")) == 200:
        return "ok"
    if await _call(_http_probe, "%s/%s/%s" % (GITHUB_PAGE, owner, name)) == 200:
        return "missing"
    return "unknown"


def tgw_region_ids(platform: str) -> set:
    return {r["id"] for r in TGW_REGIONS.get(platform, [])}


def tgw_default_region(platform: str) -> str:
    """Effective default region; TGPW_RENDER_REGION (if valid) still wins for Render
    so existing deployments keep their configured default."""
    if platform == "render":
        env = os.environ.get("TGPW_RENDER_REGION", "").strip().lower()
        if env in tgw_region_ids("render"):
            return env
    return TGW_DEFAULT_REGION.get(platform, "")


class PlatformError(Exception):
    """Short, user-presentable failure from a platform API call."""


def _http_json(method: str, url: str, token: str = "", body=None, timeout: int = 40):
    """One stdlib HTTP round-trip returning parsed JSON. Raises PlatformError on
    non-2xx with the platform's own message when it has one."""
    req = urllib.request.Request(url, method=method)
    req.add_header("accept", "application/json")
    req.add_header("user-agent", PLATFORM_UA)
    if token:
        req.add_header("authorization", "Bearer " + token)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(req, data=data, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return json.loads(raw) if raw.strip() else None
    except urllib.error.HTTPError as e:
        try:
            raw = e.read().decode("utf-8", "replace")
        except Exception:
            raw = ""
        payload = {}
        if raw.strip():
            try:
                payload = json.loads(raw)
            except Exception:
                payload = {}
        msg = (payload.get("message") if isinstance(payload, dict) else None) \
            or (payload.get("errors", [{}])[0].get("message")
                if isinstance(payload, dict) and payload.get("errors") else None) \
            or {401: "token rejected", 402: "plan does not allow this operation",
                403: "platform refused the call (HTTP 403, no error body) — usually a "
                     "plan/domain limit (Railway Trial: only 2 service domains per "
                     "workspace) or an account block, not a bad token",
                404: "service not found", 429: "rate limited"}.get(e.code, "HTTP %s" % e.code)
        # A non-JSON body on a mapped code means an edge/WAF block answered, not the
        # API ("error code: 1010" = Cloudflare signature ban) — surface what it said,
        # otherwise the generic 403 text sends the user hunting for a token problem.
        if isinstance(payload, dict) and not payload and raw.strip():
            snippet = " ".join(raw.split())[:120]
            if snippet and snippet.lower() not in msg.lower():
                msg += " — edge said: %s" % snippet
        raise PlatformError(msg)
    except urllib.error.URLError as e:
        raise PlatformError("connection failed: %s" % getattr(e, "reason", e))
    except TimeoutError:
        raise PlatformError("timeout")
    except json.JSONDecodeError:
        raise PlatformError("non-JSON response")


async def _call(fn, *a, **kw):
    return await asyncio.to_thread(fn, *a, **kw)


# ── Render REST client ────────────────────────────────────────────────────────

async def render_owners(token: str) -> list[dict]:
    rows = await _call(_http_json, "GET", RENDER_API + "/owners?limit=20", token)
    owners = [(r.get("owner") or r) for r in (rows or []) if isinstance(r, dict)]
    out = [{"id": o.get("id"), "name": o.get("name") or o.get("email") or o.get("id"),
            "is_team": o.get("type") == "team"} for o in owners if o.get("id")]
    if not out:
        raise PlatformError("no workspace found on this Render account")
    return out


def render_pick_owner(owners: list[dict]) -> dict:
    return next((o for o in owners if not o["is_team"]), owners[0])


async def render_create_service(token: str, owner_id: str, name: str, env: dict,
                                repo: str, branch: str, region: str = "") -> str:
    """Create a web service built from repo:tproxy/ (Dockerfile) — not from an image,
    so nothing has to be published to a registry first."""
    payload = {
        "type": "web_service",
        "name": name,
        "ownerId": owner_id,
        "autoDeploy": "no",
        "repo": repo,
        "branch": branch or "main",
        "rootDir": TGWEB_ROOT,
        "envVars": [{"key": k, "value": v} for k, v in env.items()],
        "serviceDetails": {
            "runtime": "docker",
            "region": region or tgw_default_region("render"),
            "plan": os.environ.get("TGPW_RENDER_PLAN", "free"),
            "healthCheckPath": "/",
        },
    }
    d = await _call(_http_json, "POST", RENDER_API + "/services", token, payload)
    svc = (d or {}).get("service") or d or {}
    if not svc.get("id"):
        raise PlatformError("Render did not return a service id")
    return svc["id"]


async def render_service(token: str, service_id: str) -> dict:
    d = await _call(_http_json, "GET", RENDER_API + "/services/" + service_id, token)
    return (d or {}).get("service") or d or {}


async def render_get_env(token: str, service_id: str) -> dict:
    rows = await _call(_http_json, "GET",
                       RENDER_API + "/services/%s/env-vars?limit=100" % service_id, token)
    out = {}
    for r in rows or []:
        v = r.get("envVar") or r
        if isinstance(v, dict) and v.get("key"):
            out[v["key"]] = v.get("value") or ""
    return out


async def render_put_env(token: str, service_id: str, env: dict):
    """Render's env-var PUT replaces the whole list — callers must merge first."""
    await _call(_http_json, "PUT", RENDER_API + "/services/%s/env-vars" % service_id,
                token, [{"key": k, "value": str(v)} for k, v in env.items()])


async def render_trigger_deploy(token: str, service_id: str):
    try:
        await _call(_http_json, "POST", RENDER_API + "/services/%s/deploys" % service_id,
                    token, {"clearCache": "do_not_clear"})
    except PlatformError:
        pass  # some deploys start on their own; the status poll below decides the outcome


async def render_deploy_status(token: str, service_id: str) -> str:
    rows = await _call(_http_json, "GET",
                       RENDER_API + "/services/%s/deploys?limit=1" % service_id, token)
    dep = ((rows or [{}])[0].get("deploy")) if isinstance(rows, list) else None
    st = (dep or {}).get("status", "")
    if st in ("live",):
        return TGW_STATE_LIVE
    if st in ("build_failed", "update_failed", "canceled", "pre_deploy_failed",
              "deactivated", "cron_canceled"):
        return TGW_STATE_FAILED
    if not st:
        return TGW_STATE_NONE        # no deploy registered (nothing was ever triggered)
    return TGW_STATE_BUILDING  # created / queued / build_in_progress / update_in_progress


async def render_delete_service(token: str, service_id: str):
    await _call(_http_json, "DELETE", RENDER_API + "/services/" + service_id, token)


# ── Railway GraphQL client ────────────────────────────────────────────────────

async def railway_gql(token: str, query: str, variables: dict | None = None) -> dict:
    body = {"query": query, "variables": variables or {}}
    d = await _call(_http_json, "POST", RAILWAY_API, token, body)
    if isinstance(d, dict) and d.get("errors"):
        raise PlatformError(d["errors"][0].get("message", "Railway error"))
    return (d or {}).get("data") or {}


async def railway_owners(token: str) -> list[dict]:
    """Workspaces: the field exposing them on `me` has moved between schema versions,
    so try the known shapes in order (same strategy the deployer worker uses)."""
    last = ""
    for q in ("query { me { workspaces { id name } } }",
              "query { me { workspaces { edges { node { id name } } } } }",
              "query { me { teams { edges { node { id name } } } } }"):
        try:
            d = await railway_gql(token, q)
            root = (d.get("me") or {}).get("workspaces") or (d.get("me") or {}).get("teams")
            if not root:
                continue
            rows = root if isinstance(root, list) else [e["node"] for e in root.get("edges", [])]
            out = [{"id": w["id"], "name": w.get("name") or "workspace",
                    "is_team": False} for w in rows if w.get("id")]
            if out:
                return out
        except PlatformError as e:
            last = str(e)
    raise PlatformError(last or "could not read any workspace from this Railway account")


async def railway_create_project(token: str, workspace_id: str, name: str) -> dict:
    """Returns {projectId, environmentId}. workspaceId is required on the current
    schema; older deployments took teamId or nothing, so keep the fallbacks."""
    q = """mutation projectCreate($input: ProjectCreateInput!) {
             projectCreate(input: $input) { id
               environments { edges { node { id name } } } } }"""
    shapes = ([{"name": name, "workspaceId": workspace_id},
               {"name": name, "teamId": workspace_id}] if workspace_id
              else [{"name": name}])
    p = None
    err = ""
    for inp in shapes:
        try:
            p = (await railway_gql(token, q, {"input": inp})).get("projectCreate")
            break
        except PlatformError as e:
            err = str(e)
    if not p:
        raise PlatformError(err or "projectCreate failed")
    envs = [e["node"] for e in (p.get("environments") or {}).get("edges", [])]
    env = next((e for e in envs if e.get("name") == "production"), envs[0] if envs else None)
    if not env:
        raise PlatformError("project created but no environment returned")
    return {"projectId": p["id"], "environmentId": env["id"]}


async def railway_create_service(token: str, project_id: str, name: str) -> str:
    """Create the service with NO source attached — configure everything first and
    trigger exactly one deploy at the end (Railway queues a build per change)."""
    d = await railway_gql(
        token,
        """mutation serviceCreate($input: ServiceCreateInput!) {
             serviceCreate(input: $input) { id } }""",
        {"input": {"projectId": project_id, "name": name}})
    sid = (d.get("serviceCreate") or {}).get("id")
    if not sid:
        raise PlatformError("serviceCreate failed")
    return sid


async def railway_read_instance(token: str, service_id: str,
                                environment_id: str) -> dict:
    """Read the service instance's settings back — region is what we verify."""
    d = await railway_gql(
        token,
        """query serviceInstance($serviceId: String!, $environmentId: String!) {
             serviceInstance(serviceId: $serviceId, environmentId: $environmentId) {
               region rootDirectory } }""",
        {"serviceId": service_id, "environmentId": environment_id})
    return d.get("serviceInstance") or {}


def _http_headers_get(url: str, headers: dict | None = None,
                      timeout: int = 12) -> dict:
    """One stdlib GET returning the RESPONSE HEADERS lower-cased. Railway's edge
    stamps its routing headers even on non-2xx answers (a paused service returns
    4xx/5xx but the edge headers still tell where it lives), so only transport
    failures raise."""
    req = urllib.request.Request(url, method="GET")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    req.add_header("user-agent", PLATFORM_UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        return {k.lower(): v for k, v in (e.headers or {}).items()}
    except Exception as e:
        raise PlatformError("edge probe failed: %s" % e)


async def railway_real_region(token: str, service_id: str, environment_id: str,
                              host: str = "") -> str:
    """The region the deployment ACTUALLY runs in. The instance's `region` field is
    only the stored setting and can disagree with placement (the reported "the
    panel shows Amsterdam but the IP test says US"). Railway's edge stamps every
    answer with x-railway-upstream-zone — the origin zone the request was routed
    to — which is the ground truth (format "railway/<region code>"). The probe
    must hit the ORIGIN host (*.up.railway.app); relay/custom domains never carry
    the header. Falls back to the instance read when the probe fails."""
    if (host or "").strip():
        try:
            h = await _call(_http_headers_get, "https://" + host.strip().rstrip("/")
                            + "/", {"x-railway-debug": "true"}, 10)
            zone = (h.get("x-railway-upstream-zone") or "").strip()
            if zone:
                return zone.split("/", 1)[-1].strip()
        except PlatformError:
            pass
    return ((await railway_read_instance(token, service_id, environment_id))
            .get("region") or "").strip()


async def railway_set_region(token: str, service_id: str, environment_id: str,
                             region: str):
    """Move an existing instance to another region — Railway redeploys in place and
    keeps the domain, so every issued link stays valid.

    Railway keeps TWO region slots that must agree: the instance's `region` field is
    only the stored setting, while actual placement follows `multiRegionConfig`.
    Writing `region` alone is accepted and echoed back by every read, yet the
    service keeps running in the account's default region — the exact silent
    failure behind "the panel shows Amsterdam but the IP test says US" (proven by
    the edge's x-railway-upstream-zone header still reporting the old zone). The
    primary write therefore sets BOTH; the plain write is kept as a fallback for
    older schemas that reject multiRegionConfig. Every write is verified by
    reading the instance back: a confirmed wrong region raises, so the UI never
    claims a region the service is not in."""
    q = """mutation serviceInstanceUpdate($serviceId: String!, $environmentId: String!,
             $input: ServiceInstanceUpdateInput!) {
             serviceInstanceUpdate(serviceId: $serviceId, environmentId: $environmentId,
               input: $input) }"""

    async def write(payload: dict):
        await railway_gql(token, q,
                          {"serviceId": service_id, "environmentId": environment_id,
                           "input": payload})

    payloads = [{"region": region,
                 "multiRegionConfig": {region: {"numReplicas": 1}}},
                {"region": region}]
    last_err = None
    for payload in payloads:
        try:
            await write(payload)
        except PlatformError as e:
            last_err = e                # try the next-known payload shape
            continue
        for attempt in (1, 2):
            real = ((await railway_read_instance(token, service_id, environment_id))
                    .get("region") or "").strip()
            if not real or real == region:
                return                  # applied — or nothing readable yet (pre-deploy)
            await write(payload)
        real = ((await railway_read_instance(token, service_id, environment_id))
                .get("region") or "").strip()
        if real and real != region:
            raise PlatformError("Railway kept the service in region %s (requested %s) — "
                                "this plan/account may not allow that region"
                                % (real, region))
        return                          # set, not yet readable — tgw_refresh_platform
                                        # re-checks the real zone after the deploy lands
    raise PlatformError("region update rejected: %s" % (last_err or "all known "
                                                        "payload shapes refused"))


async def railway_configure_instance(token: str, service_id: str, environment_id: str,
                                     repo: str, region: str = ""):
    """Attach the repo source (rootDirectory = the tproxy folder) + healthcheck + the
    region to build in. `repo` must already be the \"owner/repo\" slug Railway expects.

    The region is sent as its own serviceInstanceUpdate (region + multiRegionConfig
    together — see railway_set_region for why both are required): bundling it with
    the source attach made Railway silently drop it, and writing `region` alone
    stored the setting without ever moving the service out of the default region
    (the reported "chose Amsterdam, got US West"). After the write the instance is
    read back: a confirmed wrong region fails the create before a single build is
    wasted; an unreadable (null) region stays unknown here and is re-checked after
    the deploy goes live (tgw_refresh_platform self-heal via the edge's
    upstream-zone header)."""
    try:
        await railway_gql(
            token,
            """mutation serviceInstanceUpdate($serviceId: String!, $environmentId: String!,
                 $input: ServiceInstanceUpdateInput!) {
                 serviceInstanceUpdate(serviceId: $serviceId, environmentId: $environmentId,
                   input: $input) }""",
            {"serviceId": service_id, "environmentId": environment_id,
             "input": {"source": {"repo": repo}, "rootDirectory": TGWEB_ROOT,
                       "healthcheckPath": "/"}})
    except PlatformError:
        # Older schema: the root directory is part of the source payload.
        try:
            await railway_gql(
                token,
                """mutation serviceInstanceUpdate($serviceId: String!, $environmentId: String!,
                     $input: ServiceInstanceUpdateInput!) {
                     serviceInstanceUpdate(serviceId: $serviceId, environmentId: $environmentId,
                       input: $input) }""",
                {"serviceId": service_id, "environmentId": environment_id,
                 "input": {"source": {"repo": repo, "rootDirectory": TGWEB_ROOT},
                           "healthcheckPath": "/"}})
        except PlatformError as e2:
            raise PlatformError("repo attach failed: %s (Railway needs GitHub access to "
                                "the repo — Account Settings → Integrations)" % e2)
    if region:
        try:
            await railway_set_region(token, service_id, environment_id, region)
        except PlatformError as e:
            raise PlatformError("region not applied: %s" % e)


async def railway_upsert_vars(token: str, project_id: str, environment_id: str,
                              service_id: str, env: dict):
    await railway_gql(
        token,
        """mutation variableCollectionUpsert($input: VariableCollectionUpsertInput!) {
             variableCollectionUpsert(input: $input) }""",
        {"input": {"projectId": project_id, "environmentId": environment_id,
                   "serviceId": service_id,
                   "variables": {k: str(v) for k, v in env.items()}}})


async def railway_create_domain(token: str, environment_id: str, service_id: str,
                                target_port: int = 0) -> str:
    """Generate the service's *.up.railway.app domain.

    target_port pins the domain's route. Railway's healthcheck probes the service's
    PORT variable (or the domain's target port); a domain created BEFORE the first
    deploy exists has nothing to auto-detect from, so without an explicit port the
    deployment can sit in the healthcheck phase until the 5-minute timeout kills it
    ("Deployment failed during the network process") even though the container is
    perfectly healthy. 8080 is what the tproxy image EXPOSEs and listens on."""
    q = """mutation serviceDomainCreate($input: ServiceDomainCreateInput!) {
             serviceDomainCreate(input: $input) { domain } }"""
    base = {"environmentId": environment_id, "serviceId": service_id}
    shapes = ([dict(base, targetPort=int(target_port)), base] if target_port else [base])
    d, err = None, ""
    for inp in shapes:
        try:
            d = await railway_gql(token, q, {"input": inp})
            break
        except PlatformError as e:
            err = str(e)
    dom = ((d or {}).get("serviceDomainCreate") or {}).get("domain") or ""
    if not dom:
        raise PlatformError(
            "Railway did not return a public domain (%s). Note: the Trial plan allows "
            "only 2 service domains per workspace — the panel project plus proxy "
            "projects use them up. Delete a proxy row in the panel (this removes its "
            "Railway project) and try again, or upgrade to Hobby." % (err or "empty response"))
    return dom.lower()


async def railway_trigger_deploy(token: str, service_id: str, environment_id: str,
                                 project_id: str = ""):
    """Ask Railway to build+deploy the service. The mutation has had three names across
    schema versions; if none is accepted that is a hard failure — no build would ever
    start and the row would sit in 'building' forever."""
    last = ""
    for m in ("serviceInstanceDeployV2", "serviceInstanceDeploy",
              "environmentTriggersDeploy"):
        try:
            if m == "environmentTriggersDeploy":
                await railway_gql(
                    token,
                    "mutation environmentTriggersDeploy($input: EnvironmentTriggersDeployInput!) "
                    "{ environmentTriggersDeploy(input: $input) }",
                    {"input": {"projectId": project_id, "serviceId": service_id,
                               "environmentId": environment_id}})
            else:
                await railway_gql(
                    token,
                    "mutation %s($serviceId: String!, $environmentId: String!) "
                    "{ %s(serviceId: $serviceId, environmentId: $environmentId) }" % (m, m),
                    {"serviceId": service_id, "environmentId": environment_id})
            return
        except PlatformError as e:
            last = str(e)
    raise PlatformError("deploy trigger failed: %s" % (last or "all known trigger "
                                                       "mutations rejected"))


# ── platform traffic metrics (used_bytes for hosted proxies) ──────────────────
# The panel itself sees none of a proxy's traffic, so usage is read from the host:
# Railway aggregates per-service network GB in its `usage` query, Render exposes an
# hourly bandwidth-sources endpoint. Both are summed over the row's accounting
# window (creation, or the last manual reset) —Railway reports GB, Render bytes.

TGW_USAGE_MIN = 60              # s between metric refreshes per row (list view)
RAILWAY_GB = 10 ** 9            # Railway's *_GB measurements are decimal GB
RENDER_BW_EPOCH = 1741478400    # Render serves bandwidth-sources from 2025-03-09


def _iso(ts: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(ts)))


async def railway_usage_bytes(token: str, project_id: str, service_id: str,
                              since_ts: int) -> int:
    """NETWORK_RX + NETWORK_TX for one service since `since_ts`, in bytes."""
    if not project_id:
        return 0
    start = max(0, int(since_ts or 0))
    if start >= now():
        return 0
    d = await railway_gql(
        token,
        """query usage($projectId: String!, $startDate: DateTime!, $endDate: DateTime!) {
             usage(projectId: $projectId, startDate: $startDate, endDate: $endDate,
                   measurements: [NETWORK_RX_GB, NETWORK_TX_GB],
                   groupBy: [SERVICE_ID]) {
               measurement tags { serviceId } value } }""",
        {"projectId": project_id, "startDate": _iso(start), "endDate": _iso(now())})
    total = 0.0
    for u in d.get("usage") or []:
        if ((u.get("tags") or {}).get("serviceId") or "") == service_id:
            total += float(u.get("value") or 0)
    return int(round(total * RAILWAY_GB))


async def render_usage_bytes(token: str, service_id: str, since_ts: int) -> int:
    """Sum Render's hourly bandwidth-sources (trafficSource=total) since `since_ts`."""
    end = now()
    start = max(int(since_ts or 0), RENDER_BW_EPOCH)
    if start >= end:
        return 0
    d = await _call(_http_json, "GET",
                    RENDER_API + "/metrics/bandwidth-sources?resource=%s&startTime=%d"
                    "&endTime=%d" % (service_id, start, end), token)
    total = 0.0
    for row in (d or {}).get("data") or []:
        if ((row.get("labels") or {}).get("trafficSource") or "") != "total":
            continue
        for pt in row.get("values") or []:
            total += float(pt.get("value") or 0)
    return int(round(total))


async def tgw_refresh_platform(row, force: bool = False):
    """Pull live platform facts into a deployed row: the traffic counter and — for
    Railway — the deployment's REAL running region, which self-heals rows whose
    stored region never actually applied on the platform (reported as "chose
    Amsterdam, got US West"). The real region comes from the edge's
    x-railway-upstream-zone header when the origin host is known, falling back to
    the instance read. Best effort: any failure leaves the row as it was. The list
    view calls this throttled; the row's sync button forces it."""
    if row["platform"] not in ("render", "railway") or not row["service_id"]:
        return row
    if row["deploy_state"] not in (TGW_STATE_LIVE, "suspended"):
        return row
    if not force and now() - (row["usage_checked"] or 0) < TGW_USAGE_MIN:
        return row
    used, coords_dirty = None, False
    try:
        coords = json.loads(row["coords"] or "{}")
    except Exception:
        coords = {}
    try:
        since = row["usage_since"] or row["created_at"]
        if row["platform"] == "render":
            used = await render_usage_bytes(tg_key_active("render"),
                                            row["service_id"], since)
        else:
            token = tg_key_active("railway")
            used = await railway_usage_bytes(token, coords.get("projectId", ""),
                                             row["service_id"], since)
            try:
                # The REAL running region — the edge's upstream-zone header first
                # (the stored `region` field alone has already lied once), then the
                # instance read. Self-heals rows placed in the wrong region.
                real = await railway_real_region(token, row["service_id"],
                                                 coords.get("environmentId", ""),
                                                 row["server"] or "")
            except PlatformError:
                real = None          # read failed — keep the stored region
            if real and real != (coords.get("region") or ""):
                coords["region"] = real
                coords_dirty = True
    except Exception:
        used = None                  # metrics are best-effort; never break the list
    with db() as c:
        sets, vals = ["usage_checked=?"], [now()]
        if used is not None:
            sets.append("used_bytes=?")
            vals.append(int(used))
        if coords_dirty:
            sets.append("coords=?")
            vals.append(json.dumps(coords))
        c.execute("UPDATE tg_web_proxies SET %s WHERE id=?" % ",".join(sets),
                  vals + [row["id"]])
    with db() as c:
        return c.execute("SELECT * FROM tg_web_proxies WHERE id=?",
                         (row["id"],)).fetchone()


TGW_RL_LIVE = ("SUCCESS", "COMPLETE")
TGW_RL_FAILED = ("FAILED", "CRASHED", "REMOVED", "CANCELLED", "CANCELED", "DELETED",
                 "SKIPPED", "SLEEPING", "TIMEOUT")


async def railway_deploy_status(token: str, project_id: str, service_id: str,
                                environment_id: str) -> str:
    """Map the service's latest deployment to our state. DeploymentListInput has moved
    fields between schema versions (environmentId) — try the known shapes in order;
    an empty list means no deployment was ever started (TGW_STATE_NONE)."""
    last = ""
    for inp in ({"projectId": project_id, "serviceId": service_id,
                 "environmentId": environment_id},
                {"projectId": project_id, "serviceId": service_id}):
        try:
            d = await railway_gql(
                token,
                """query deployments($input: DeploymentListInput!) {
                     deployments(input: $input, first: 1) {
                       edges { node { status } } } }""",
                {"input": inp})
            st = (((d.get("deployments") or {}).get("edges") or [{}])[0]
                  .get("node") or {}).get("status", "")
            if st in TGW_RL_LIVE:
                return TGW_STATE_LIVE
            if st in TGW_RL_FAILED:
                return TGW_STATE_FAILED
            if not st:
                return TGW_STATE_NONE
            return TGW_STATE_BUILDING     # QUEUED / WAITING / BUILDING / DEPLOYING
        except PlatformError as e:
            last = str(e)
    raise PlatformError(last or "deployments query failed")


async def railway_delete_service(token: str, service_id: str):
    try:
        await railway_gql(token, "mutation serviceDelete($id: String!) "
                                 "{ serviceDelete(id: $id) }", {"id": service_id})
    except PlatformError:
        pass  # best effort — the row is deleted regardless


async def railway_delete_project(token: str, project_id: str):
    try:
        await railway_gql(token, "mutation projectDelete($id: String!) "
                                 "{ projectDelete(id: $id) }", {"id": project_id})
    except PlatformError:
        pass  # best effort


# ── orchestration: create / rotate / pause / delete / sync ────────────────────

TGW_DEPLOY_TASKS: dict[int, asyncio.Task] = {}


def tgw_settings_tokens() -> tuple[str, str]:
    return (tg_key_active("render"), tg_key_active("railway"))


# ── multi-account platform keys (tg_platform_keys) ────────────────────────────
# One row per saved platform API key. Exactly one row per platform is "active";
# the deploy code reads that active token. The legacy single-key settings
# (tgweb_<platform>_token) are kept as a fallback for databases created before
# this table existed, and are mirrored on every change so nothing that still
# reads them breaks.

def tg_key_rows(platform: str) -> list[dict]:
    with db() as c:
        rows = c.execute(
            "SELECT id, platform, name, owner_id, token, active, created_at "
            "FROM tg_platform_keys WHERE platform=? ORDER BY id", (platform,)).fetchall()
    out = []
    for r in rows:
        tok = r["token"] or ""
        out.append({"id": r["id"], "platform": r["platform"],
                    "name": r["name"] or "",
                    "owner_id": r["owner_id"] or "",
                    "active": bool(r["active"]),
                    "token_hint": ("••••" + tok[-4:]) if tok else "",
                    "created_at": r["created_at"]})
    return out


async def tg_key_resolve(platform: str, token: str) -> tuple[str, str]:
    """Return (account_name, owner_id) for a platform token, or raise PlatformError."""
    token = (token or "").strip()
    if platform == "render":
        owners = await render_owners(token)
        o = render_pick_owner(owners)
        return (o.get("name") or o.get("id") or "Render account", o.get("id") or "")
    owners = await railway_owners(token)
    ws = next((o for o in owners if not o.get("is_team")), owners[0] if owners else {})
    return (ws.get("name") or ws.get("id") or "Railway workspace", ws.get("id") or "")


def tg_key_add(platform: str, name: str, owner_id: str, token: str) -> int:
    with db() as c:
        cur = c.execute("INSERT INTO tg_platform_keys(platform,name,owner_id,token,active,created_at) "
                        "VALUES(?,?,?,?,?,?)", (platform, name, owner_id, token.strip(), 0, now()))
        kid = cur.lastrowid
        if c.execute("SELECT COUNT(*) n FROM tg_platform_keys WHERE platform=?",
                     (platform,)).fetchone()["n"] == 1:
            c.execute("UPDATE tg_platform_keys SET active=1 WHERE id=?", (kid,))
    return kid


def tg_key_set_active(platform: str, kid: int):
    with db() as c:
        c.execute("UPDATE tg_platform_keys SET active=0 WHERE platform=?", (platform,))
        c.execute("UPDATE tg_platform_keys SET active=1 WHERE id=?", (kid,))


def tg_key_delete(kid: int):
    with db() as c:
        row = c.execute("SELECT platform, active FROM tg_platform_keys WHERE id=?",
                        (kid,)).fetchone()
        if not row:
            return
        platform = row["platform"]
        c.execute("DELETE FROM tg_platform_keys WHERE id=?", (kid,))
        if row["active"]:
            nxt = c.execute("SELECT id FROM tg_platform_keys WHERE platform=? "
                            "ORDER BY id DESC LIMIT 1", (platform,)).fetchone()
            if nxt:
                c.execute("UPDATE tg_platform_keys SET active=1 WHERE id=?", (nxt["id"],))


def tg_key_active(platform: str) -> str:
    """Token the deploy code uses for this platform: the active stored key, else the
    legacy single-key setting (so pre-existing databases keep working)."""
    with db() as c:
        r = c.execute("SELECT token FROM tg_platform_keys WHERE platform=? AND active=1",
                      (platform,)).fetchone()
    if r:
        return r["token"] or ""
    return get_setting("tgweb_%s_token" % platform) or ""


def tgw_repo_url() -> str:
    return (get_setting("tgweb_repo") or TGWEB_REPO).strip().rstrip("/")


def tgw_branch() -> str:
    return (get_setting("tgweb_branch") or "main").strip() or "main"


def tgw_slug(label: str, pid_hint: str = "") -> str:
    """Platform service name: ascii, lowercase, short."""
    base = re.sub(r"[^a-z0-9]+", "-", (label or "").lower()).strip("-")[:20]
    tail = pid_hint or secrets.token_hex(3)
    return ("tgp-" + (base + "-" if base else "") + tail)[:58]


async def tgw_await_live(check, pid: int, hint: str = ""):
    """Poll a platform until the deploy is live/failed, then persist the outcome.
    Consecutive poll errors and a 'no deployment was ever started' state fail the row
    early with a real message instead of silently looping to the timeout."""
    deadline = time.time() + TGW_BUILD_TIMEOUT
    nodeploy_since, errors = None, 0
    while time.time() < deadline:
        await asyncio.sleep(TGW_POLL)
        try:
            state = await check()
            errors = 0
        except PlatformError as e:
            errors += 1
            if errors >= TGW_ERR_LIMIT:
                with db() as c:
                    c.execute("UPDATE tg_web_proxies SET deploy_state=?,error=? WHERE id=?",
                              (TGW_STATE_FAILED, str(e)[:300], pid))
                return
            continue
        except Exception as e:      # never let the watcher itself die
            errors += 1
            if errors >= TGW_ERR_LIMIT:
                with db() as c:
                    c.execute("UPDATE tg_web_proxies SET deploy_state=?,error=? WHERE id=?",
                              (TGW_STATE_FAILED, ("internal: %s" % e)[:300], pid))
                return
            continue
        if state == TGW_STATE_NONE:  # nothing registered yet — give it a grace window
            if nodeploy_since is None:
                nodeploy_since = time.time()
            elif time.time() - nodeploy_since > TGW_NODEPLOY_AFTER:
                with db() as c:
                    c.execute("UPDATE tg_web_proxies SET deploy_state=?,error=? WHERE id=?",
                              (TGW_STATE_FAILED,
                               "no deploy was started on the platform — check the repo/"
                               "branch in the platform settings and the platform's "
                               "dashboard for errors"[:300], pid))
                return
            continue
        nodeploy_since = None
        if state == TGW_STATE_BUILDING and time.time() < deadline:
            continue
        with db() as c:
            if state == TGW_STATE_FAILED:
                row = c.execute("SELECT error FROM tg_web_proxies WHERE id=?",
                                (pid,)).fetchone()
                if row and (row["error"] or "").strip():
                    c.execute("UPDATE tg_web_proxies SET deploy_state=? WHERE id=?",
                              (state, pid))
                    return
                c.execute("UPDATE tg_web_proxies SET deploy_state=?,error=? WHERE id=?",
                          (state, hint or "build failed — check the platform's "
                           "dashboard logs", pid))
                return
            c.execute("UPDATE tg_web_proxies SET deploy_state=? WHERE id=?", (state, pid))
        return
    with db() as c:
        c.execute("UPDATE tg_web_proxies SET deploy_state=?,error=? WHERE id=?",
                  (TGW_STATE_FAILED, "build timeout — check the platform's dashboard "
                   "logs for the real error", pid))


async def tgweb_deploy(pid: int):
    """Create the service on the chosen platform, wait for its public hostname and
    the first deploy, then store everything the link needs. Runs in the background."""
    with db() as c:
        row = c.execute("SELECT * FROM tg_web_proxies WHERE id=?", (pid,)).fetchone()
        if not row:
            return
        platform = row["platform"]
        try:
            coords = json.loads(row["coords"] or "{}")
        except Exception:
            coords = {}
    # the carrier and the region ride in coords (chosen at create time)
    carrier = coords.get("carrier", "websocket")
    region = coords.get("region") or tgw_default_region(platform)
    repo, branch = tgw_repo_url(), tgw_branch()
    proj, token = None, ""   # filled per-platform below; the cleanup path needs them
    try:
        if TGW_PREFLIGHT and (await tgw_repo_state(repo, branch)) == "missing":
            raise PlatformError(
                "tproxy/Dockerfile not found in %s (branch %s) — push the tproxy "
                "folder to GitHub first, then sync this proxy" % (repo, branch))
        if platform == "render":
            token = tg_key_active("render")
            owners = await render_owners(token)
            owner = render_pick_owner(owners)
            name = tgw_slug(row["label"], str(pid))
            env = {"TGP_SECRET": row["secret"], "TGP_CARRIER": carrier, "TGP_PAUSED": "0"}
            sid = await render_create_service(token, owner["id"], name, env, repo,
                                              branch, region)
            # Render derives the hostname from the name — poll until the URL exists.
            host = ""
            for _ in range(12):
                svc = await render_service(token, sid)
                host = (svc.get("serviceDetails") or {}).get("url") or ""
                host = re.sub(r"^https?://", "", host).strip("/").lower()
                if host:
                    break
                await asyncio.sleep(3)
            if not host:
                raise PlatformError("Render did not return the service URL")
            env["TGP_PUBLIC_HOSTNAME"] = host
            await render_put_env(token, sid, env)
            coords.update({"ownerId": owner["id"], "name": name})
            with db() as c:
                c.execute("""UPDATE tg_web_proxies
                             SET service_id=?, server=?, coords=?, deploy_state=?
                             WHERE id=?""",
                          (sid, host, json.dumps(coords), TGW_STATE_BUILDING, pid))
            await render_trigger_deploy(token, sid)
            check = lambda: render_deploy_status(token, sid)
            hint = ("Render build failed — open the service's Events/Logs page in the "
                    "Render dashboard (repo %s, branch %s)" % (repo, branch))
        elif platform == "railway":
            token = tg_key_active("railway")
            slug = tgw_github_slug(repo)
            if not slug:
                raise PlatformError("Railway builds from GitHub — the repo must look "
                                    "like https://github.com/owner/repo (got %s)" % repo)
            owners = await railway_owners(token)
            ws = next((o for o in owners if not o["is_team"]), owners[0])
            name = tgw_slug(row["label"], str(pid))
            proj = await railway_create_project(token, ws["id"], name)
            sid = await railway_create_service(token, proj["projectId"], name)
            await railway_configure_instance(token, sid, proj["environmentId"], slug,
                                             region)
            host = await railway_create_domain(token, proj["environmentId"], sid,
                                               target_port=8080)
            # PORT is load-bearing: Railway healthchecks the PORT variable, and unlike
            # Render it does not inject one for us. Without it the deploy sits in the
            # healthcheck phase for 5 minutes and dies as "failed during the network
            # process" even though the relay is listening and answering "/".
            await railway_upsert_vars(token, proj["projectId"], proj["environmentId"], sid,
                                      {"TGP_SECRET": row["secret"], "TGP_CARRIER": carrier,
                                       "TGP_PUBLIC_HOSTNAME": host, "TGP_PAUSED": "0",
                                       "PORT": "8080"})
            coords.update({"projectId": proj["projectId"],
                           "environmentId": proj["environmentId"]})
            with db() as c:
                c.execute("""UPDATE tg_web_proxies
                             SET service_id=?, server=?, coords=?, deploy_state=?
                             WHERE id=?""",
                          (sid, host, json.dumps(coords), TGW_STATE_BUILDING, pid))
            await railway_trigger_deploy(token, sid, proj["environmentId"],
                                         proj["projectId"])
            check = lambda: railway_deploy_status(token, proj["projectId"], sid,
                                                  proj["environmentId"])
            hint = ("Railway build failed — open the deployment logs in the Railway "
                    "dashboard; make sure tproxy/ is pushed to %s (branch %s) and "
                    "Railway's GitHub app can read the repo" % (slug, branch))
        else:
            raise PlatformError("unknown platform")
    except PlatformError as e:
        await tgw_cleanup_orphan(platform, token, proj, pid)
        with db() as c:
            c.execute("UPDATE tg_web_proxies SET deploy_state=?, error=? WHERE id=?",
                      (TGW_STATE_FAILED, str(e)[:300], pid))
        TGW_DEPLOY_TASKS.pop(pid, None)
        return
    except Exception as e:  # never leave a row stuck in building
        await tgw_cleanup_orphan(platform, token, proj, pid)
        with db() as c:
            c.execute("UPDATE tg_web_proxies SET deploy_state=?, error=? WHERE id=?",
                      (TGW_STATE_FAILED, ("internal: %s" % e)[:300], pid))
        TGW_DEPLOY_TASKS.pop(pid, None)
        return
    TGW_DEPLOY_TASKS.pop(pid, None)
    await tgw_await_live(check, pid, hint)


def tgw_spawn(pid: int):
    old = TGW_DEPLOY_TASKS.get(pid)
    if old and not old.done():
        return
    TGW_DEPLOY_TASKS[pid] = asyncio.create_task(tgweb_deploy(pid))


async def tgw_cleanup_orphan(platform: str, token: str, proj: dict | None, pid: int):
    """A Railway create that died before its service was persisted still leaves a full
    project behind — Trial accounts only get 5 projects and 2 service domains, so an
    orphaned attempt per failure adds up fast. Remove it, best effort."""
    if platform != "railway" or not proj or not token:
        return
    try:
        with db() as c:
            row = c.execute("SELECT service_id FROM tg_web_proxies WHERE id=?",
                            (pid,)).fetchone()
        if row and not (row["service_id"] or "").strip():
            await railway_delete_project(token, proj.get("projectId", ""))
    except Exception:
        pass


def tgw_spawn_watch(pid: int):
    """After a rotate/resume the platform is rebuilding in place — watch it until
    live/failed and persist the outcome (the create flow has its own watcher)."""
    with db() as c:
        row = c.execute("SELECT * FROM tg_web_proxies WHERE id=?", (pid,)).fetchone()
    if not row or row["platform"] == "external":
        return
    hint = "build failed — check the platform's dashboard logs"
    repo, branch = tgw_repo_url(), tgw_branch()
    if row["platform"] == "render":
        token = tg_key_active("render")
        check = lambda: render_deploy_status(token, row["service_id"])
        hint = ("Render build failed — open the service's Events/Logs page in the "
                "Render dashboard (repo %s, branch %s)" % (repo, branch))
    else:
        try:
            coords = json.loads(row["coords"] or "{}")
        except Exception:
            coords = {}
        token = tg_key_active("railway")
        check = lambda: railway_deploy_status(token, coords.get("projectId", ""),
                                              row["service_id"],
                                              coords.get("environmentId", ""))
        hint = ("Railway build failed — open the deployment logs in the Railway "
                "dashboard; make sure tproxy/ is pushed to the repo (branch %s) and "
                "Railway's GitHub app can read it" % branch)
    old = TGW_DEPLOY_TASKS.get(pid)
    if old and not old.done():
        return
    TGW_DEPLOY_TASKS[pid] = asyncio.create_task(tgw_await_live(check, pid, hint))


def tgw_adopt_building_rows():
    """After a panel restart the in-memory deploy/watch tasks are gone — any row still
    marked 'building' would sit there forever. Re-adopt every one: rows that already
    have a service go back to watching; rows that died mid-create redo the deploy."""
    try:
        with db() as c:
            rows = c.execute("SELECT id, service_id FROM tg_web_proxies WHERE "
                             "platform IN ('render','railway') AND deploy_state=?",
                             (TGW_STATE_BUILDING,)).fetchall()
    except Exception:
        return
    for r in rows:
        try:
            if r["service_id"]:
                tgw_spawn_watch(r["id"])
            else:
                tgw_spawn(r["id"])
        except Exception:
            pass


async def tgweb_platform_sync(row) -> dict:
    """Re-read one row's deploy state (and hostname) from its platform. Cheap enough
    for the list view to call while a build is in flight; after a restart it also
    unsticks rows that were building when the panel went down."""
    pid = row["id"]
    platform = row["platform"]
    coords = {}
    try:
        coords = json.loads(row["coords"] or "{}")
    except Exception:
        pass
    state, error, server = row["deploy_state"], row["error"], row["server"]
    if platform in ("render", "railway") and not row["service_id"]:
        if row["deploy_state"] == TGW_STATE_FAILED and pid not in TGW_DEPLOY_TASKS:
            # The create died before any service existed (edge block, token glitch…).
            # There is nothing on the platform to re-read, so without a re-run this row
            # can never recover — the refresh button is the retry: same path as a
            # fresh add, one click, no duplicate while a task is still in flight.
            with db() as c:
                c.execute("UPDATE tg_web_proxies SET deploy_state=?, error='' WHERE id=?",
                          (TGW_STATE_BUILDING, pid))
            tgw_spawn(pid)
            with db() as c:
                row = c.execute("SELECT * FROM tg_web_proxies WHERE id=?",
                                (pid,)).fetchone()
        return tgweb_out(row)     # create still in flight — there is no platform truth yet
    try:
        if platform == "render":
            token = tg_key_active("render")
            svc = await render_service(token, row["service_id"])
            host = re.sub(r"^https?://", "", (svc.get("serviceDetails") or {}).get("url") or "",
                          ).strip("/").lower()
            if host:
                server = host
            st = svc.get("suspended")
            state = "suspended" if st == "suspended" else await render_deploy_status(
                token, row["service_id"])
            if state == TGW_STATE_NONE:
                state, error = row["deploy_state"], row["error"]   # no news — keep as-is
            elif state == TGW_STATE_FAILED:
                error = row["error"] or error      # never blur an existing reason
            else:
                error = ""
        elif platform == "railway":
            token = tg_key_active("railway")
            st = await railway_deploy_status(token, coords.get("projectId", ""),
                                             row["service_id"],
                                             coords.get("environmentId", ""))
            if st == TGW_STATE_NONE:
                state, error = row["deploy_state"], row["error"]   # no news — keep as-is
            elif st == TGW_STATE_FAILED:
                state, error = st, (row["error"] or error)
            else:
                state, error = st, ""
        else:
            state = TGW_STATE_LIVE if server else TGW_STATE_FAILED
    except PlatformError as e:
        state, error = TGW_STATE_FAILED, str(e)[:300]
    with db() as c:
        cur = c.execute("SELECT deploy_state, error FROM tg_web_proxies WHERE id=?",
                        (pid,)).fetchone()
        prev_err = ((cur or row)["error"] or "").strip()
        if state == TGW_STATE_FAILED and prev_err:
            error = prev_err            # never blur an already-recorded failure reason
        c.execute("UPDATE tg_web_proxies SET deploy_state=?, error=?, server=? WHERE id=?",
                  (state, error, server, pid))
    with db() as c:
        row = c.execute("SELECT * FROM tg_web_proxies WHERE id=?",
                        (pid,)).fetchone()
    row = await tgw_refresh_platform(row, force=True)   # real region + traffic usage
    with db() as c:
        return tgweb_out(c.execute("SELECT * FROM tg_web_proxies WHERE id=?",
                                   (pid,)).fetchone())


async def tgweb_platform_rotate(row) -> str:
    """Push a fresh secret into the platform service (env var) and redeploy it."""
    new = secrets.token_hex(16)
    platform, coords = row["platform"], {}
    try:
        coords = json.loads(row["coords"] or "{}")
    except Exception:
        pass
    if platform == "render":
        token = tg_key_active("render")
        env = await render_get_env(token, row["service_id"])
        if "TGP_SECRET" not in env:
            raise PlatformError("service has no TGP_SECRET — not created by this panel?")
        env["TGP_SECRET"] = new
        await render_put_env(token, row["service_id"], env)
        await render_trigger_deploy(token, row["service_id"])
    elif platform == "railway":
        token = tg_key_active("railway")
        # PORT rides along on every redeploy so proxies created before the PORT fix
        # are healed here too (a rotate is the user's one-click repair for them).
        await railway_upsert_vars(token, coords.get("projectId", ""),
                                  coords.get("environmentId", ""), row["service_id"],
                                  {"TGP_SECRET": new, "PORT": "8080"})
        await railway_trigger_deploy(token, row["service_id"],
                                     coords.get("environmentId", ""))
    else:
        raise PlatformError("not a platform proxy")
    with db() as c:
        c.execute("UPDATE tg_web_proxies SET secret=?, deploy_state=?, error='' WHERE id=?",
                  (new, TGW_STATE_BUILDING, row["id"]))
    return new


async def tgweb_platform_pause(row, paused: bool):
    """Pause = the endpoint stops listening but keeps its hostname, so resuming later
    keeps every issued link valid. Render has suspend/resume; Railway gets a redeploy
    with TGP_PAUSED."""
    platform, coords = row["platform"], {}
    try:
        coords = json.loads(row["coords"] or "{}")
    except Exception:
        pass
    if platform == "render":
        token = tg_key_active("render")
        if paused:
            try:
                await _call(_http_json, "POST",
                            RENDER_API + "/services/%s/suspend" % row["service_id"], token)
            except PlatformError:
                # plan without suspend → idle the container instead
                env = await render_get_env(token, row["service_id"])
                env["TGP_PAUSED"] = "1"
                await render_put_env(token, row["service_id"], env)
                await render_trigger_deploy(token, row["service_id"])
            state = "suspended"
        else:
            try:
                await _call(_http_json, "POST",
                            RENDER_API + "/services/%s/resume" % row["service_id"], token)
                # resume clears the suspend flag; make sure the listener is not parked
                env = await render_get_env(token, row["service_id"])
                if env.get("TGP_PAUSED") == "1":
                    env["TGP_PAUSED"] = "0"
                    await render_put_env(token, row["service_id"], env)
                    await render_trigger_deploy(token, row["service_id"])
            except PlatformError:
                pass
            state = TGW_STATE_BUILDING
        with db() as c:
            c.execute("UPDATE tg_web_proxies SET deploy_state=? WHERE id=?",
                      (state, row["id"]))
    elif platform == "railway":
        token = tg_key_active("railway")
        await railway_upsert_vars(token, coords.get("projectId", ""),
                                  coords.get("environmentId", ""), row["service_id"],
                                  {"TGP_PAUSED": "1" if paused else "0",
                                   "PORT": "8080"})
        await railway_trigger_deploy(token, row["service_id"],
                                     coords.get("environmentId", ""))
        with db() as c:
            c.execute("UPDATE tg_web_proxies SET deploy_state=? WHERE id=?",
                      (TGW_STATE_BUILDING, row["id"]))
    else:
        raise PlatformError("not a platform proxy")


async def tgweb_platform_delete(row):
    """Delete the proxy's remote service — completely. A Railway proxy owns its whole
    project (service + domain + deployments), and projectDelete is what actually frees
    it — serviceDelete alone leaves an empty project shell behind and keeps consuming
    the Trial plan's 2-domains-per-workspace quota. serviceDelete stays the fallback
    for rows that predate project tracking or whose project is already gone."""
    platform = row["platform"]
    try:
        if platform == "render":
            token = tg_key_active("render")
            await render_delete_service(token, row["service_id"])
        elif platform == "railway":
            token = tg_key_active("railway")
            try:
                coords = json.loads(row["coords"] or "{}")
            except Exception:
                coords = {}
            project_id = str(coords.get("projectId") or "").strip()
            if project_id:
                # raw call — railway_delete_project() swallows PlatformError, which
                # would defeat the serviceDelete fallback below
                try:
                    await railway_gql(token, "mutation projectDelete($id: String!) "
                                             "{ projectDelete(id: $id) }",
                                      {"id": project_id})
                except Exception:
                    # project already gone / token scope — still strip the service shell
                    await railway_delete_service(token, row["service_id"])
            else:
                await railway_delete_service(token, row["service_id"])
    except (PlatformError, Exception):
        pass  # best effort — the inventory row is removed regardless


# ────────────���───────────────── MODELS ──────────────────────────────

class SetupIn(BaseModel):
    password: str
    confirm: str


class LoginIn(BaseModel):
    password: str


class ChangePassIn(BaseModel):
    current: str
    new: str


class UserIn(BaseModel):
    name: str
    quota_gb: float = 0
    expire_days: int = 0
    reset_days: int = 0
    device_limit: int = 1
    ip_limit: int = 0
    transport: str = "both"
    note: str = ""
    enabled: bool = True
    obfuscate: bool = False
    ech: bool = False
    fp: str = "unsafe"
    alpn: str = ""
    ech_value: str = ""
    obf_cs: str = ""
    obf_fm: str = ""


class UserPatch(BaseModel):
    name: Optional[str] = None
    quota_gb: Optional[float] = None
    expire_days: Optional[int] = None
    reset_days: Optional[int] = None
    device_limit: Optional[int] = None
    ip_limit: Optional[int] = None
    transport: Optional[str] = None
    note: Optional[str] = None
    enabled: Optional[bool] = None
    obfuscate: Optional[bool] = None
    ech: Optional[bool] = None
    fp: Optional[str] = None
    alpn: Optional[str] = None
    ech_value: Optional[str] = None
    obf_cs: Optional[str] = None
    obf_fm: Optional[str] = None
    uuid: Optional[str] = None


class CleanIpIn(BaseModel):
    address: str
    remark: str = ""
    country: str = ""


class TgWebIn(BaseModel):
    server: str = ""          # external mode: bare host; platform mode: ignored
    label: str = ""
    secret: str = ""          # empty → a fresh 32-hex secret is generated
    quota_gb: float = 0       # 0 = unlimited
    expire_days: int = 0      # 0 = never expires
    note: str = ""
    enabled: bool = True
    platform: str = "external"   # external | render | railway
    carrier: str = "websocket"   # TGP_CARRIER for platform builds
    region: str = ""             # hosting region; empty → the platform's default


class TgWebPatch(BaseModel):
    server: Optional[str] = None
    label: Optional[str] = None
    secret: Optional[str] = None
    quota_gb: Optional[float] = None
    expire_days: Optional[int] = None
    note: Optional[str] = None
    enabled: Optional[bool] = None
    carrier: Optional[str] = None   # external mode: TGP_CARRIER of a platform proxy
    region: Optional[str] = None    # Railway only — Render cannot move a service later


class TgWebSettingsIn(BaseModel):
    """Platform credentials for self-hosted proxies. Empty strings leave a value
    unchanged; repo/branch are stored as-is."""
    render_token: str = ""
    railway_token: str = ""
    repo: Optional[str] = None
    branch: Optional[str] = None


class TgKeyIn(BaseModel):
    """A single platform API key to store. Optional name is the account label the
    admin wants (defaults to the account/workspace name resolved from the API)."""
    token: str = ""
    name: str = ""


class DeviceGateIn(BaseModel):
    """Subscription device gate: restrict limited accounts to device-aware apps."""
    gate: Optional[bool] = None
    traffic: Optional[bool] = None


class CountryIn(BaseModel):
    country: str = ""


class CleanIpBulkIn(BaseModel):
    text: str


class ProxyIn(BaseModel):
    kind: str = "socks5"
    host: str
    port: int
    username: str = ""
    password: str = ""
    remark: str = ""


class ProxyPatch(BaseModel):
    enabled: Optional[bool] = None
    remark: Optional[str] = None
    country: Optional[str] = None


class ProxyModeIn(BaseModel):
    strict: Optional[bool] = None
    flag_source: Optional[str] = None


class RestoreIn(BaseModel):
    data: Any                      # the parsed backup object, or the raw JSON text
    mode: str = "merge"            # merge | replace
    restore_password: bool = False
    force: bool = False            # accept a file whose checksum does not match


class TgIn(BaseModel):
    bot_token: str = ""            # empty = keep the stored one
    chat_id: str = ""
    auto: Optional[bool] = None


# ────────────────────────────── SETUP & AUTH ──────────────────────────────

@app.get("/api/state")
async def state(session: Optional[str] = Cookie(default=None)):
    return {"needs_setup": not password_is_set(), "logged_in": valid_session(session)}


@app.post("/api/setup")
async def api_setup(body: SetupIn, request: Request):
    if password_is_set():
        raise HTTPException(409, "password already set")
    if body.password != body.confirm:
        raise HTTPException(400, "passwords do not match")
    if not PASSWORD_RULE.match(body.password):
        raise HTTPException(400, "min 8 chars with upper, lower and a digit")
    set_password(body.password)
    audit("setup", client_ip(request))
    resp = JSONResponse({"ok": True})
    resp.set_cookie("session", make_token(), httponly=True, samesite="lax",
                    secure=True, max_age=JWT_TTL)
    return resp


@app.post("/api/login")
async def api_login(body: LoginIn, request: Request):
    ip = client_ip(request)
    if not password_is_set():
        raise HTTPException(409, "setup required")
    if rate_limited(ip):
        audit("login_ratelimited", ip)
        raise HTTPException(429, "too many attempts, wait 5 minutes")
    if not verify_password(body.password):
        audit("login_fail", ip)
        raise HTTPException(401, "wrong password")
    audit("login_ok", ip)
    resp = JSONResponse({"ok": True})
    resp.set_cookie("session", make_token(), httponly=True, samesite="lax",
                    secure=True, max_age=JWT_TTL)
    return resp


@app.post("/api/change-password")
async def change_password(body: ChangePassIn, request: Request, _=Depends(require_admin)):
    if not verify_password(body.current):
        raise HTTPException(401, "current password is wrong")
    if not PASSWORD_RULE.match(body.new):
        raise HTTPException(400, "min 8 chars with upper, lower and a digit")
    set_password(body.new)
    audit("password_changed", client_ip(request))
    return {"ok": True}


@app.post("/api/logout")
async def api_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("session")
    return resp


# ────────────────────────────── USERS ──────────────────────────────

NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{2,32}$")


@app.get("/api/users")
async def list_users(_=Depends(require_admin)):
    with db() as c:
        rows = c.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    return [row_out(r) for r in rows]


@app.post("/api/users")
async def create_user(body: UserIn, _=Depends(require_admin)):
    name = body.name.strip()
    if not NAME_RE.match(name):
        raise HTTPException(400, "name: 2-32 chars, letters/numbers/_.- only")
    tr = body.transport.lower()
    if tr not in TRANSPORTS:
        raise HTTPException(400, "transport must be ws, xhttp or both")
    expire = now() + body.expire_days * 86400 if body.expire_days > 0 else 0
    reset_days = min(365, max(0, int(body.reset_days or 0)))
    try:
        with db() as c:
            cur = c.execute(
                """INSERT INTO users(name,uuid,sub_token,note,enabled,quota_bytes,
                                     used_bytes,expire_at,device_limit,ip_limit,transport,
                                     obfuscate,ech,fp,alpn,ech_value,obf_cs,obf_fm,
                                     reset_days,last_reset,created_at)
                   VALUES(?,?,?,?,?,?,0,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (name, str(uuid.uuid4()), secrets.token_urlsafe(16), body.note,
                 1 if body.enabled else 0, int(body.quota_gb * GB), expire,
                 max(0, body.device_limit), max(0, body.ip_limit), tr,
                 1 if body.obfuscate else 0,
                 1 if body.ech else 0,
                 _pick_choice(body.fp, FINGERPRINTS, "unsafe"),
                 _pick_choice(body.alpn, ALPN_CHOICES, ""),
                 (body.ech_value or "").strip()[:2000],
                 (body.obf_cs or "").strip()[:4000],
                 (body.obf_fm or "").strip()[:4000],
                 reset_days, now(), now()))
            row = c.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "this name already exists")
    return row_out(row)


@app.patch("/api/users/{uid}")
async def patch_user(uid: int, body: UserPatch, _=Depends(require_admin)):
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not row:
            raise HTTPException(404, "not found")
        sets, vals = [], []
        if body.name is not None:
            if not NAME_RE.match(body.name.strip()):
                raise HTTPException(400, "invalid name")
            sets.append("name=?"); vals.append(body.name.strip())
        if body.quota_gb is not None:
            sets.append("quota_bytes=?"); vals.append(int(body.quota_gb * GB))
        if body.expire_days is not None:
            sets.append("expire_at=?")
            vals.append(now() + body.expire_days * 86400 if body.expire_days > 0 else 0)
        if body.reset_days is not None:
            rd = min(365, max(0, int(body.reset_days or 0)))
            sets.append("reset_days=?"); vals.append(rd)
            # turning the cycle on (or changing it) starts a fresh one from today
            sets.append("last_reset=?"); vals.append(now())
        if body.device_limit is not None:
            sets.append("device_limit=?"); vals.append(max(0, body.device_limit))
        if body.ip_limit is not None:
            sets.append("ip_limit=?"); vals.append(max(0, body.ip_limit))
        if body.transport is not None:
            tr = body.transport.lower()
            if tr not in TRANSPORTS:
                raise HTTPException(400, "transport must be ws, xhttp or both")
            sets.append("transport=?"); vals.append(tr)
        if body.note is not None:
            sets.append("note=?"); vals.append(body.note)
        if body.enabled is not None:
            sets.append("enabled=?"); vals.append(1 if body.enabled else 0)
        if body.obfuscate is not None:
            sets.append("obfuscate=?"); vals.append(1 if body.obfuscate else 0)
        if body.ech is not None:
            sets.append("ech=?"); vals.append(1 if body.ech else 0)
        if body.fp is not None:
            sets.append("fp=?")
            vals.append(_pick_choice(body.fp, FINGERPRINTS, "unsafe"))
        if body.alpn is not None:
            sets.append("alpn=?")
            vals.append(_pick_choice(body.alpn, ALPN_CHOICES, ""))
        if body.ech_value is not None:
            sets.append("ech_value=?"); vals.append((body.ech_value or "").strip()[:2000])
        if body.obf_cs is not None:
            sets.append("obf_cs=?"); vals.append((body.obf_cs or "").strip()[:4000])
        if body.obf_fm is not None:
            sets.append("obf_fm=?"); vals.append((body.obf_fm or "").strip()[:4000])
        if body.uuid is not None:
            try:
                clean = str(uuid.UUID(body.uuid.strip()))
            except Exception:
                raise HTTPException(400, "invalid UUID format")
            sets.append("uuid=?"); vals.append(clean)
        if sets:
            vals.append(uid)
            try:
                c.execute(f"UPDATE users SET {','.join(sets)} WHERE id=?", vals)
            except sqlite3.IntegrityError:
                raise HTTPException(409, "name or UUID already used")
        row = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return row_out(row)


@app.post("/api/users/{uid}/reset-traffic")
async def reset_traffic(uid: int, _=Depends(require_admin)):
    with db() as c:
        c.execute("UPDATE users SET used_bytes=0, last_reset=? WHERE id=?",
                  (now(), uid))
    return {"ok": True}


@app.post("/api/users/{uid}/new-uuid")
async def rotate_uuid(uid: int, _=Depends(require_admin)):
    new = str(uuid.uuid4())
    with db() as c:
        c.execute("UPDATE users SET uuid=? WHERE id=?", (new, uid))
        c.execute("DELETE FROM user_ips WHERE user_id=?", (uid,))
        c.execute("DELETE FROM devices WHERE user_id=?", (uid,))
    audit("uuid_rotated", "", f"user {uid}")
    return {"ok": True, "uuid": new}


@app.post("/api/users/{uid}/new-sub-token")
async def rotate_sub(uid: int, _=Depends(require_admin)):
    with db() as c:
        c.execute("UPDATE users SET sub_token=? WHERE id=?",
                  (secrets.token_urlsafe(16), uid))
    return {"ok": True}


@app.post("/api/users/{uid}/clear-ips")
async def clear_ips(uid: int, _=Depends(require_admin)):
    with db() as c:
        c.execute("DELETE FROM user_ips WHERE user_id=?", (uid,))
        c.execute("DELETE FROM devices WHERE user_id=?", (uid,))
    return {"ok": True}


@app.delete("/api/users/{uid}/devices/{did}")
async def delete_device(uid: int, did: int, _=Depends(require_admin)):
    """Forget one detected device so it frees a slot (and stops being recognised)."""
    with db() as c:
        c.execute("DELETE FROM devices WHERE id=? AND user_id=?", (did, uid))
    return {"ok": True}


@app.delete("/api/users/{uid}/ips/{ip_id}")
async def delete_ip(uid: int, ip_id: int, _=Depends(require_admin)):
    """Forget one recorded source IP so it frees an IP-limit slot."""
    with db() as c:
        c.execute("DELETE FROM user_ips WHERE id=? AND user_id=?", (ip_id, uid))
    return {"ok": True}


@app.get("/api/users/{uid}/ips")
async def user_ips(uid: int, history: int = 0, _=Depends(require_admin)):
    """Live view by default: only devices still connected. history=1 returns everything."""
    live_cut = now() - LIVE_WINDOW
    count_cut = now() - DEVICE_WINDOW
    ip_cut = now() - IP_WINDOW
    cols = "id,dkey,ip,ua,client,platform,proto,first_seen,last_seen,hits,device_name,client_version"
    ip_cols = "id,ip,proto,first_seen,last_seen,hits"
    with db() as c:
        if history:
            rows = c.execute(f"""SELECT {cols} FROM devices
                                 WHERE user_id=? ORDER BY last_seen DESC LIMIT 200""",
                             (uid,)).fetchall()
        else:
            rows = c.execute(f"""SELECT {cols} FROM devices
                                 WHERE user_id=? AND last_seen>?
                                 ORDER BY last_seen DESC""", (uid, live_cut)).fetchall()
        total = c.execute("SELECT COUNT(*) n FROM devices WHERE user_id=?",
                          (uid,)).fetchone()["n"]
        # The IP limit is a separate gate from the device identity one, so the raw
        # source addresses are returned alongside the device list.
        if history:
            iprows = c.execute(f"""SELECT {ip_cols} FROM user_ips
                                   WHERE user_id=? ORDER BY last_seen DESC LIMIT 200""",
                               (uid,)).fetchall()
        else:
            iprows = c.execute(f"""SELECT {ip_cols} FROM user_ips
                                   WHERE user_id=? AND last_seen>?
                                   ORDER BY last_seen DESC""", (uid, live_cut)).fetchall()
        ip_total = c.execute("SELECT COUNT(*) n FROM user_ips WHERE user_id=?",
                             (uid,)).fetchone()["n"]
        urow = c.execute("SELECT device_limit, ip_limit FROM users WHERE id=?",
                         (uid,)).fetchone()
    return {
        "live": live_devices(uid),
        "counted": active_devices(uid),
        "total_seen": total,
        "limit": (urow["device_limit"] if urow else 0),
        "live_window": LIVE_WINDOW,
        "device_window": DEVICE_WINDOW,
        "ip_limit": (urow["ip_limit"] if urow else 0),
        "ip_counted": active_ips(uid),
        "ip_total_seen": ip_total,
        "ip_window": IP_WINDOW,
        "history": bool(history),
        "rows": [
            {**dict(r),
             "label": r["device_name"] or device_label(r["client"], r["platform"], r["ip"]),
             "online": r["last_seen"] > live_cut,
             "counted": r["last_seen"] > count_cut}
            for r in rows
        ],
        "ip_rows": [
            {**dict(r),
             "online": r["last_seen"] > live_cut,
             "counted": r["last_seen"] > ip_cut}
            for r in iprows
        ],
    }


@app.get("/api/users/{uid}/config")
async def user_config(uid: int, request: Request, _=Depends(require_admin)):
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        ips = c.execute("SELECT * FROM clean_ips WHERE enabled=1 ORDER BY id").fetchall()
    if not row:
        raise HTTPException(404, "not found")
    d = base_domain(request)
    return {"uuid": row["uuid"], "transport": row["transport"],
            "sub_link": f"https://{d}/sub/{row['sub_token']}",
            "configs": build_configs(row, d, ips)}


@app.delete("/api/users/{uid}")
async def delete_user(uid: int, _=Depends(require_admin)):
    with db() as c:
        c.execute("DELETE FROM users WHERE id=?", (uid,))
        c.execute("DELETE FROM user_ips WHERE user_id=?", (uid,))
        c.execute("DELETE FROM devices WHERE user_id=?", (uid,))
        c.execute("DELETE FROM traffic_log WHERE user_id=?", (uid,))
    return {"ok": True}


# ────────────────────────────── CLEAN IPs ──────────────────────────────

ADDR_RE = re.compile(r"^[A-Za-z0-9._\-\[\]:]{3,253}$")


def valid_address(a: str) -> bool:
    a = a.strip()
    if not ADDR_RE.match(a):
        return False
    try:
        ipaddress.ip_address(a.strip("[]"))
        return True
    except ValueError:
        return "." in a and not a.startswith(".") and not a.endswith(".")


@app.get("/api/clean-ips")
async def list_clean_ips(_=Depends(require_admin)):
    with db() as c:
        rows = c.execute("SELECT * FROM clean_ips ORDER BY id DESC").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["country"] = (d.get("country") or "").upper()
        d["flag"] = cip_flag(r)
        out.append(d)
    return out


@app.get("/api/main-country")
async def read_main_country(_=Depends(require_admin)):
    code = (get_setting("main_country") or "").upper()
    return {"country": code, "flag": flag_of(code)}


@app.post("/api/main-country")
async def write_main_country(body: CountryIn, _=Depends(require_admin)):
    code = re.sub(r"[^A-Za-z]", "", body.country or "")[:2].upper()
    set_setting("main_country", code)
    return {"ok": True, "country": code, "flag": flag_of(code)}


@app.post("/api/clean-ips")
async def add_clean_ip(body: CleanIpIn, _=Depends(require_admin)):
    addr = body.address.strip()
    if not valid_address(addr):
        raise HTTPException(400, "invalid IP or domain")
    try:
        remark = body.remark.strip()[:40]
        code = re.sub(r"[^A-Za-z]", "", body.country or "")[:2].upper() or guess_country(remark)
        with db() as c:
            c.execute("INSERT INTO clean_ips(address,remark,country,enabled,added_at) "
                      "VALUES(?,?,?,1,?)", (addr, remark, code, now()))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "already in the list")
    return {"ok": True}


@app.post("/api/clean-ips/bulk")
async def bulk_clean_ips(body: CleanIpBulkIn, _=Depends(require_admin)):
    added = dup = bad = 0
    with db() as c:
        for raw in re.split(r"[\n,;]+", body.text):
            raw = raw.strip()
            if not raw:
                continue
            addr, remark = (raw.split("#", 1) + [""])[:2] if "#" in raw else (raw, "")
            addr, remark = addr.strip(), remark.strip()[:40]
            if not valid_address(addr):
                bad += 1
                continue
            try:
                c.execute("INSERT INTO clean_ips(address,remark,country,enabled,added_at) "
                          "VALUES(?,?,?,1,?)",
                          (addr, remark, guess_country(remark), now()))
                added += 1
            except sqlite3.IntegrityError:
                dup += 1
    return {"added": added, "duplicates": dup, "invalid": bad}


@app.patch("/api/clean-ips/{cid}")
async def toggle_clean_ip(cid: int, _=Depends(require_admin)):
    with db() as c:
        r = c.execute("SELECT enabled FROM clean_ips WHERE id=?", (cid,)).fetchone()
        if not r:
            raise HTTPException(404, "not found")
        c.execute("UPDATE clean_ips SET enabled=? WHERE id=?",
                  (0 if r["enabled"] else 1, cid))
    return {"ok": True}


@app.delete("/api/clean-ips/{cid}")
async def delete_clean_ip(cid: int, _=Depends(require_admin)):
    with db() as c:
        c.execute("DELETE FROM clean_ips WHERE id=?", (cid,))
    return {"ok": True}


@app.delete("/api/clean-ips")
async def clear_clean_ips(_=Depends(require_admin)):
    with db() as c:
        c.execute("DELETE FROM clean_ips")
    return {"ok": True}


# ────────────────────────────── PROXIES ──────────────────────────────

def proxy_out(r) -> dict:
    """Public shape of a proxy row \u2014 credentials are never echoed back."""
    d = dict(r)
    d.pop("password", None)
    d["has_auth"] = bool(r["username"])
    d["flag"] = flag_of(r["country"] or "") or flag_of(guess_country(r["remark"] or ""))
    d["label"] = "%s://%s:%s" % (r["kind"], r["host"], r["port"])
    return d


@app.get("/api/proxies")
async def list_proxies(_=Depends(require_admin)):
    with db() as c:
        rows = c.execute("SELECT * FROM proxies ORDER BY id DESC").fetchall()
    act = get_setting("active_proxy") or ""
    return {"proxies": [proxy_out(r) for r in rows],
            "sub_ids": [r["id"] for r in sub_proxies()],
            "active_id": int(act) if act.isdigit() else 0,
            "strict": proxy_strict(),
            "flag_source": get_setting("flag_source") or "proxy"}


@app.post("/api/proxies")
async def add_proxy(body: ProxyIn, _=Depends(require_admin)):
    kind = (body.kind or "socks5").strip().lower()
    if kind not in PROXY_KINDS:
        raise HTTPException(400, "kind must be socks5, socks4 or http")
    host = (body.host or "").strip().lstrip("[").rstrip("]")
    if not host or len(host) > 255 or " " in host:
        raise HTTPException(400, "invalid proxy host")
    if not 1 <= int(body.port) <= 65535:
        raise HTTPException(400, "invalid proxy port")
    if kind == "socks4" and body.password:
        raise HTTPException(400, "socks4 has no password field \u2014 leave it empty")
    with db() as c:
        try:
            cur = c.execute("""INSERT INTO proxies(kind,host,port,username,password,
                                                   remark,country,added_at)
                               VALUES(?,?,?,?,?,?,?,?)""",
                            (kind, host, int(body.port), body.username.strip(),
                             body.password, body.remark.strip()[:80],
                             guess_country(body.remark or ""), now()))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "this proxy is already in the list")
        pid = cur.lastrowid
    audit("proxy-add", "", "%s %s:%s" % (kind, host, body.port))
    return await run_proxy_test(pid)          # a fresh proxy is tested at once


PROXY_URI_RE = re.compile(
    r"^(?:(?P<kind>socks5h?|socks4a?|https?)://)?"
    r"(?:(?P<user>[^:@/\s]*)(?::(?P<pw>[^@/\s]*))?@)?"
    r"(?P<host>\[[0-9A-Fa-f:]+\]|[^:@/\s]+)[:\s]+(?P<port>\d{1,5})"
    r"/?$", re.I)

KIND_ALIASES = {"socks5h": "socks5", "socks4a": "socks4", "https": "http"}


def parse_proxy_uri(line: str) -> dict:
    """One pasted line -> proxy fields.

    Accepted: socks5://1.2.3.4:1080, socks5://user:pass@host:1080#label,
    http://host:8080, and a bare 1.2.3.4:1080 (assumed socks5).
    """
    raw = (line or "").strip()
    if not raw or raw.startswith("#") or raw.startswith("//"):
        return {}
    remark = ""
    if "#" in raw:
        raw, remark = raw.split("#", 1)
        raw, remark = raw.strip(), remark.strip()[:80]
    m = PROXY_URI_RE.match(raw)
    if not m:
        raise ValueError("unreadable — use kind://host:port")
    kind = (m.group("kind") or "socks5").lower()
    kind = KIND_ALIASES.get(kind, kind)
    if kind not in PROXY_KINDS:
        raise ValueError("kind must be socks5, socks4 or http")
    port = int(m.group("port"))
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    user, pw = m.group("user") or "", m.group("pw") or ""
    if kind == "socks4":
        pw = ""                       # socks4 carries a user id only
    return {"kind": kind,
            "host": m.group("host").strip("[]"),
            "port": port,
            "username": user,
            "password": pw,
            "remark": remark}


class ProxyBulkIn(BaseModel):
    text: str = ""


@app.post("/api/proxies/bulk")
async def add_proxies_bulk(body: ProxyBulkIn, _=Depends(require_admin)):
    """Adds a pasted list (one proxy per line) and health-tests each entry."""
    results = []
    for line in (body.text or "").splitlines()[:50]:
        if not line.strip():
            continue
        shown = line.strip()[:60]
        try:
            fields = parse_proxy_uri(line)
        except ValueError as exc:
            results.append({"ok": False, "label": shown, "error": str(exc)})
            continue
        if not fields:
            continue
        shown = "%s://%s:%s" % (fields["kind"], fields["host"], fields["port"])
        try:
            res = await add_proxy(ProxyIn(**fields), None)
            res["label"] = shown
            results.append(res)
        except HTTPException as exc:
            results.append({"ok": False, "label": shown, "error": str(exc.detail)})
    return {"results": results}


@app.post("/api/proxies/{pid}/test")
async def test_proxy(pid: int, _=Depends(require_admin)):
    return await run_proxy_test(pid)


@app.post("/api/proxies/test-all")
async def test_all_proxies(_=Depends(require_admin)):
    with db() as c:
        ids = [r["id"] for r in c.execute("SELECT id FROM proxies ORDER BY id")]
    out = await asyncio.gather(*(run_proxy_test(i) for i in ids),
                               return_exceptions=True)
    return {"results": [r for r in out if isinstance(r, dict)]}


@app.post("/api/proxies/{pid}/activate")
async def activate_proxy(pid: int, _=Depends(require_admin)):
    """Arm one proxy (or pass 0 to go back to the platform IP)."""
    if pid == 0:
        set_setting("active_proxy", "")
        audit("proxy-off", "", "direct outbound")
        return {"ok": True, "active_id": 0}
    with db() as c:
        px = c.execute("SELECT * FROM proxies WHERE id=?", (pid,)).fetchone()
    if not px:
        raise HTTPException(404, "proxy not found")
    if not px["enabled"]:
        raise HTTPException(400, "enable the proxy before arming it")
    res = await run_proxy_test(pid)
    if not res.get("ok"):
        raise HTTPException(400, "proxy failed its health check: %s" % res.get("error"))
    set_setting("active_proxy", str(pid))
    audit("proxy-on", "", "%s %s:%s (%s)" %
          (px["kind"], px["host"], px["port"], res.get("country") or "?"))
    return {"ok": True, "active_id": pid, "country": res.get("country"),
            "flag": res.get("flag"), "exit_ip": res.get("exit_ip")}


@app.get("/api/device-gate")
async def get_device_gate(_=Depends(require_admin)):
    return {"ok": True, "gate": device_gate_on(), "traffic": device_gate_traffic(),
            "apps": list(DEVICE_GATE_APPS)}


@app.post("/api/device-gate")
async def set_device_gate(body: DeviceGateIn, _=Depends(require_admin)):
    if body.gate is not None:
        set_setting("device_gate", "1" if body.gate else "0")
    if body.traffic is not None:
        set_setting("device_gate_traffic", "1" if body.traffic else "0")
    audit("device-gate", "", "gate=%s traffic=%s" % (device_gate_on(), device_gate_traffic()))
    return {"ok": True, "gate": device_gate_on(), "traffic": device_gate_traffic(),
            "apps": list(DEVICE_GATE_APPS)}


@app.post("/api/proxies/mode")
async def set_proxy_mode(body: ProxyModeIn, _=Depends(require_admin)):
    if body.strict is not None:
        set_setting("proxy_strict", "1" if body.strict else "0")
    if body.flag_source is not None:
        src = body.flag_source if body.flag_source in ("proxy", "entry") else "proxy"
        set_setting("flag_source", src)
    return {"ok": True, "strict": proxy_strict(),
            "flag_source": get_setting("flag_source") or "proxy"}


@app.patch("/api/proxies/{pid}")
async def patch_proxy(pid: int, body: ProxyPatch, _=Depends(require_admin)):
    sets, args = [], []
    if body.enabled is not None:
        sets.append("enabled=?"); args.append(1 if body.enabled else 0)
    if body.remark is not None:
        sets.append("remark=?"); args.append(body.remark.strip()[:80])
    if body.country is not None:
        sets.append("country=?")
        args.append(re.sub(r"[^A-Za-z]", "", body.country)[:2].upper())
    if not sets:
        return {"ok": True}
    args.append(pid)
    with db() as c:
        c.execute("UPDATE proxies SET %s WHERE id=?" % ",".join(sets), args)
    if body.enabled is False and (get_setting("active_proxy") or "") == str(pid):
        set_setting("active_proxy", "")      # never keep a disabled proxy armed
    return {"ok": True}


@app.delete("/api/proxies/{pid}")
async def delete_proxy(pid: int, _=Depends(require_admin)):
    with db() as c:
        c.execute("DELETE FROM proxies WHERE id=?", (pid,))
    if (get_setting("active_proxy") or "") == str(pid):
        set_setting("active_proxy", "")
    audit("proxy-del", "", "id=%d" % pid)
    return {"ok": True}


# ─────────────────── Telegram WEB-proxy inventory ───────────────────

@app.get("/api/tgweb")
async def list_tgweb(_=Depends(require_admin)):
    with db() as c:
        rows = c.execute("SELECT * FROM tg_web_proxies ORDER BY id DESC").fetchall()
    out = []
    for r in rows:
        if r["platform"] in ("render", "railway") and r["service_id"]:
            # throttled best-effort refresh of the traffic counter + real region
            r = await tgw_refresh_platform(r)
        out.append(tgweb_out(r))
    return out


@app.get("/api/tgweb/regions")
async def get_tgweb_regions(_=Depends(require_admin)):
    """Official region lists per hosting platform + the effective defaults, plus the
    platform this panel itself runs on ('' = hosted elsewhere)."""
    return {"render": TGW_REGIONS["render"], "railway": TGW_REGIONS["railway"],
            "default": {"render": tgw_default_region("render"),
                        "railway": tgw_default_region("railway")},
            "self": tgw_self_platform()}


@app.get("/api/tgweb/settings")
async def get_tgweb_settings(_=Depends(require_admin)):
    """Platform credentials. Tokens are never returned — each saved key appears as a
    row with an account name, a masked hint stub, and whether it is the active one."""
    rt, rw = tgw_settings_tokens()
    return {
        "render_token_set": bool(rt),
        "render_token_hint": ("••••" + rt[-4:]) if rt else "",
        "railway_token_set": bool(rw),
        "railway_token_hint": ("••••" + rw[-4:]) if rw else "",
        "render_keys": tg_key_rows("render"),
        "railway_keys": tg_key_rows("railway"),
        "repo": tgw_repo_url(),
        "branch": tgw_branch(),
    }


@app.post("/api/tgweb/settings")
async def set_tgweb_settings(body: TgWebSettingsIn, _=Depends(require_admin)):
    if body.repo is not None:
        set_setting("tgweb_repo", (body.repo or "").strip().rstrip("/")
                    or TGWEB_REPO)   # keep scheme + case: it is a repo URL, not a host
    if body.branch is not None:
        set_setting("tgweb_branch", body.branch.strip() or "main")
    audit("tgweb-settings", "", "platform repo/branch updated")
    return await get_tgweb_settings()


@app.get("/api/tgweb/keys/{platform}")
async def list_tgweb_keys(platform: str, _=Depends(require_admin)):
    if platform not in ("render", "railway"):
        raise HTTPException(400, "platform must be render or railway")
    return tg_key_rows(platform)


@app.post("/api/tgweb/keys/{platform}")
async def add_tgweb_key(platform: str, body: TgKeyIn, _=Depends(require_admin)):
    """Store a new platform API key. The account is resolved live from the platform
    so the panel can show WHICH account it belongs to, and the first key saved for a
    platform becomes the active deploy key automatically."""
    if platform not in ("render", "railway"):
        raise HTTPException(400, "platform must be render or railway")
    token = (body.token or "").strip()
    if not token:
        raise HTTPException(400, "API key is required")
    try:
        name, owner_id = await tg_key_resolve(platform, token)
    except PlatformError as e:
        raise HTTPException(400, "could not validate this key: %s" % e)
    label = (body.name or "").strip() or name
    kid = tg_key_add(platform, label, owner_id, token)
    return {"ok": True, "id": kid, "account": label, "owner_id": owner_id}


@app.post("/api/tgweb/keys/{platform}/{kid}/active")
async def activate_tgweb_key(platform: str, kid: int, _=Depends(require_admin)):
    if platform not in ("render", "railway"):
        raise HTTPException(400, "platform must be render or railway")
    row = tg_key_rows(platform)
    if not any(k["id"] == kid for k in row):
        raise HTTPException(404, "key not found")
    tg_key_set_active(platform, kid)
    audit("tgweb-key", str(kid), "platform key set active")
    return {"ok": True, "id": kid}


@app.delete("/api/tgweb/keys/{platform}/{kid}")
async def delete_tgweb_key(platform: str, kid: int, _=Depends(require_admin)):
    if platform not in ("render", "railway"):
        raise HTTPException(400, "platform must be render or railway")
    tg_key_delete(kid)
    audit("tgweb-key", str(kid), "platform key deleted")
    return {"ok": True}


@app.post("/api/tgweb")
async def add_tgweb(body: TgWebIn, _=Depends(require_admin)):
    platform = body.platform if body.platform in ("external", "render", "railway") \
        else "external"
    if platform == "external":
        server = tg_clean_server(body.server)
        if not server:
            raise HTTPException(400, "server is required (bare host, no https:// or port)")
    else:
        tok = tg_key_active(platform)
        if not tok:
            raise HTTPException(
                400, "no %s token stored — save it in the platform settings first"
                     % platform.capitalize())
        server = ""
    carrier = body.carrier if body.carrier in TGW_CARRIERS else "websocket"
    region = ""
    if platform in TGW_REGIONS:
        reg = (body.region or "").strip().lower()
        if reg and reg not in tgw_region_ids(platform):
            raise HTTPException(400, "invalid region for %s" % platform)
        region = reg or tgw_default_region(platform)
    sec = (body.secret or "").strip().lower()
    if sec:
        if not TG_SECRET_RE.match(sec):
            raise HTTPException(400, "secret must be 32 hex characters")
    else:
        sec = secrets.token_hex(16)
    expire = now() + body.expire_days * 86400 if body.expire_days > 0 else 0
    coords0 = {"carrier": carrier}
    if region:
        coords0["region"] = region
    try:
        with db() as c:
            cur = c.execute(
                """INSERT INTO tg_web_proxies(label,server,secret,quota_bytes,
                                              used_bytes,expire_at,enabled,note,created_at,
                                              platform,coords,deploy_state)
                   VALUES(?,?,?,?,0,?,?,?,?,?,?,?)""",
                ((body.label or "").strip()[:80], server, sec,
                 int(body.quota_gb * GB), expire,
                 1 if body.enabled else 0, (body.note or "").strip()[:300], now(),
                 platform, json.dumps(coords0),
                 TGW_STATE_BUILDING if platform != "external" else ""))
            pid = cur.lastrowid
            row = c.execute("SELECT * FROM tg_web_proxies WHERE id=?",
                            (pid,)).fetchone()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "this secret is already in use")
    if platform != "external":
        tgw_spawn(pid)   # create the service on the platform in the background
    audit("tgweb-added", "", "%s %s" % (platform, server or "deploying"))
    return tgweb_out(row)


@app.get("/api/tgweb/{pid}/sync")
async def sync_tgweb(pid: int, _=Depends(require_admin)):
    """Re-read one row's deploy state from its platform (or validate an external row)."""
    with db() as c:
        row = c.execute("SELECT * FROM tg_web_proxies WHERE id=?", (pid,)).fetchone()
    if not row:
        raise HTTPException(404, "not found")
    if row["platform"] == "external":
        return tgweb_out(row)
    return await tgweb_platform_sync(row)


@app.patch("/api/tgweb/{pid}")
async def patch_tgweb(pid: int, body: TgWebPatch, _=Depends(require_admin)):
    with db() as c:
        row0 = c.execute("SELECT * FROM tg_web_proxies WHERE id=?", (pid,)).fetchone()
        if not row0:
            raise HTTPException(404, "not found")
        sets, vals = [], []
        if body.server is not None:
            server = tg_clean_server(body.server)
            if not server:
                raise HTTPException(400, "invalid server")
            sets.append("server=?"); vals.append(server)
        if body.label is not None:
            sets.append("label=?"); vals.append((body.label or "").strip()[:80])
        if body.secret is not None:
            sec = (body.secret or "").strip().lower()
            if not TG_SECRET_RE.match(sec):
                raise HTTPException(400, "secret must be 32 hex characters")
            sets.append("secret=?"); vals.append(sec)
        if body.quota_gb is not None:
            sets.append("quota_bytes=?"); vals.append(int(body.quota_gb * GB))
        if body.expire_days is not None:
            sets.append("expire_at=?")
            vals.append(now() + body.expire_days * 86400
                        if body.expire_days > 0 else 0)
        if body.note is not None:
            sets.append("note=?"); vals.append((body.note or "").strip()[:300])
        coords, move_region = {}, None
        try:
            coords = json.loads(row0["coords"] or "{}")
        except Exception:
            coords = {}
        coords_dirty = False
        if body.carrier is not None:
            if body.carrier not in TGW_CARRIERS:
                raise HTTPException(400, "invalid carrier")
            coords["carrier"] = body.carrier
            coords_dirty = True
        if body.region is not None:
            plat0 = row0["platform"] or "external"
            reg = (body.region or "").strip().lower()
            if plat0 == "external":
                raise HTTPException(400, "external proxies have no hosting region")
            if reg not in tgw_region_ids(plat0):
                raise HTTPException(400, "invalid region for %s" % plat0)
            if plat0 == "render":
                raise HTTPException(400, "Render cannot change a service's region "
                                         "after creation")
            if coords.get("region") != reg:
                coords["region"] = reg
                coords_dirty = True
                move_region = reg
            elif plat0 == "railway" and row0["service_id"]:
                # coords may already SAY this region while the service actually runs
                # elsewhere — the stored `region` field used to lie (the reported
                # "panel shows Amsterdam, IP test says US"). Re-selecting the same
                # region must still move the service when the real zone disagrees.
                try:
                    real = await railway_real_region(
                        tg_key_active("railway"),
                        row0["service_id"], coords.get("environmentId", ""),
                        row0["server"] or "")
                except PlatformError:
                    real = ""
                if real and real != reg:
                    move_region = reg
        if coords_dirty:
            sets.append("coords=?"); vals.append(json.dumps(coords))
        if body.enabled is not None:
            sets.append("enabled=?"); vals.append(1 if body.enabled else 0)
        if sets:
            vals.append(pid)
            try:
                c.execute("UPDATE tg_web_proxies SET %s WHERE id=?" % ",".join(sets), vals)
            except sqlite3.IntegrityError:
                raise HTTPException(409, "this secret is already in use")
        row = c.execute("SELECT * FROM tg_web_proxies WHERE id=?", (pid,)).fetchone()
    if move_region and row["platform"] == "railway":
        # Railway redeploys the instance in the new region — same domain, same links.
        # The move is verified server-side; if Railway refuses it, the stored coords
        # are rolled back so the UI never claims a region the service is not in.
        try:
            coords_before = json.loads(row0["coords"] or "{}")
        except Exception:
            coords_before = {}
        token = tg_key_active("railway")
        try:
            await railway_set_region(token, row["service_id"],
                                     coords.get("environmentId", ""), move_region)
        except PlatformError as e:
            with db() as c:
                c.execute("UPDATE tg_web_proxies SET coords=? WHERE id=?",
                          (json.dumps(coords_before), pid))
            raise HTTPException(502, "region change failed: %s" % e)
        with db() as c:
            c.execute("UPDATE tg_web_proxies SET deploy_state=? WHERE id=?",
                      (TGW_STATE_BUILDING, pid))
            row = c.execute("SELECT * FROM tg_web_proxies WHERE id=?", (pid,)).fetchone()
        tgw_spawn_watch(pid)
        audit("tgweb-region", "", "proxy %d -> %s" % (pid, move_region))
    if body.enabled is not None and row["platform"] != "external":
        # a real pause: park the platform service (hostname survives), not just the badge
        try:
            await tgweb_platform_pause(row, paused=not body.enabled)
        except PlatformError as e:
            raise HTTPException(502, "platform toggle failed: %s" % e)
        with db() as c:
            row = c.execute("SELECT * FROM tg_web_proxies WHERE id=?", (pid,)).fetchone()
        if row["deploy_state"] == TGW_STATE_BUILDING:
            tgw_spawn_watch(pid)   # resume / TGP_PAUSED redeploy — watch until live
    return tgweb_out(row)


@app.post("/api/tgweb/{pid}/rotate")
async def rotate_tgweb(pid: int, _=Depends(require_admin)):
    """Issue a fresh secret — every link generated before stops working. Platform
    proxies get the new secret pushed into their service and redeployed."""
    with db() as c:
        row = c.execute("SELECT * FROM tg_web_proxies WHERE id=?", (pid,)).fetchone()
    if not row:
        raise HTTPException(404, "not found")
    if row["platform"] != "external":
        try:
            new = await tgweb_platform_rotate(row)
        except PlatformError as e:
            raise HTTPException(502, "rotate failed: %s" % e)
        tgw_spawn_watch(pid)   # the service redeploys — keep the badge honest
        audit("tgweb-rotate", "", "proxy %d (platform)" % pid)
        return {"ok": True, "secret": new}
    new = secrets.token_hex(16)
    with db() as c:
        cur = c.execute("UPDATE tg_web_proxies SET secret=? WHERE id=?", (new, pid))
        if cur.rowcount == 0:
            raise HTTPException(404, "not found")
    audit("tgweb-rotate", "", "proxy %d" % pid)
    return {"ok": True, "secret": new}


@app.post("/api/tgweb/{pid}/reset-traffic")
async def reset_tgweb_traffic(pid: int, _=Depends(require_admin)):
    with db() as c:
        cur = c.execute("UPDATE tg_web_proxies SET used_bytes=0, usage_since=? "
                        "WHERE id=?", (now(), pid))
        if cur.rowcount == 0:
            raise HTTPException(404, "not found")
    return {"ok": True}


@app.delete("/api/tgweb/{pid}")
async def delete_tgweb(pid: int, _=Depends(require_admin)):
    with db() as c:
        row = c.execute("SELECT * FROM tg_web_proxies WHERE id=?", (pid,)).fetchone()
        if not row:
            raise HTTPException(404, "not found")
        if row["platform"] != "external" and row["service_id"]:
            await tgweb_platform_delete(row)   # best effort: remove the remote service
        c.execute("DELETE FROM tg_web_proxies WHERE id=?", (pid,))
    audit("tgweb-del", "", "proxy %d" % pid)
    return {"ok": True}


# ────────────────────────── BACKUP & RESTORE ──────────────────────────
#
# One portable file holds everything an admin configured: users (with their UUIDs and
# subscription tokens, so existing client configs keep working), clean IPs, proxies
# (credentials included — the file is as sensitive as the panel password), the panel
# password hash, panel settings, and the environment the panel was running under.
#
# Format: a single JSON document, extension .ixpbak, wrapped as
#     {"format": "iranx-panel-backup", "version": 2, "checksum": "...", "payload": {...}}
# The checksum is a SHA-256 over the canonical payload, so a truncated or edited file is
# caught before anything is written. Restores are transactional: either the whole payload
# lands or the database is left exactly as it was.

BACKUP_FORMAT = "iranx-panel-backup"
BACKUP_VERSION = 6          # v1 no proxies, v2 no obfuscate, v3 no ech/fp/alpn, v5 no custom ech/obf, v6 no ip_limit

# Runtime settings that live in the environment, not the database. They are recorded for
# reference and shown on restore, because a new host needs them set by hand — the panel
# cannot rewrite its own platform variables.
ENV_KEYS = ("DOMAIN", "RELAY_DOMAIN", "WS_PATH", "XHTTP_PATH", "XHTTP_MODE",
            "DEVICE_WINDOW", "IP_WINDOW", "LIVE_WINDOW", "SESSION_IDLE", "PANEL_TITLE",
            "KEEPALIVE", "KEEPALIVE_MINUTES")

USER_FIELDS = ("name", "uuid", "sub_token", "note", "enabled", "quota_bytes",
               "used_bytes", "expire_at", "device_limit", "ip_limit", "transport",
               "obfuscate", "ech", "fp", "alpn", "ech_value", "obf_cs", "obf_fm",
               "reset_days", "last_reset", "created_at")
CIP_FIELDS = ("address", "remark", "country", "enabled", "added_at")
# Health columns are deliberately included: a restore then shows the same list state the
# old panel had, and the next test run refreshes it anyway.
PROXY_FIELDS = ("kind", "host", "port", "username", "password", "remark", "country",
                "country_name", "city", "isp", "exit_ip", "healthy", "latency_ms",
                "last_error", "checked_at", "enabled", "added_at")


def _canon(obj) -> bytes:
    """Stable serialisation so the checksum does not depend on key order."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()


def _checksum(payload) -> str:
    return hashlib.sha256(_canon(payload)).hexdigest()


def current_env() -> dict:
    return {
        "DOMAIN": DOMAIN,
        "RELAY_DOMAIN": RELAY_DOMAIN,
        "WS_PATH": WS_PATH,
        "XHTTP_PATH": XHTTP_PATH,
        "XHTTP_MODE": XHTTP_MODE,
        "DEVICE_WINDOW": str(DEVICE_WINDOW),
        "IP_WINDOW": str(IP_WINDOW),
        "LIVE_WINDOW": str(LIVE_WINDOW),
        "SESSION_IDLE": str(SESSION_IDLE),
        "PANEL_TITLE": PANEL_TITLE,
        "KEEPALIVE": "1" if KEEPALIVE else "0",
        "KEEPALIVE_MINUTES": str(KEEPALIVE_MINS),
    }


def build_backup(include_password: bool = True, include_traffic: bool = False,
                 include_proxy_creds: bool = True) -> dict:
    with db() as c:
        users = [dict(r) for r in c.execute("SELECT * FROM users ORDER BY id")]
        cips = [dict(r) for r in c.execute("SELECT * FROM clean_ips ORDER BY id")]
        proxies = [dict(r) for r in c.execute("SELECT * FROM proxies ORDER BY id")]
        settings = {r["key"]: r["value"] for r in c.execute("SELECT * FROM settings")}
        traffic = ([dict(r) for r in c.execute(
            "SELECT user_id, ts, up, down FROM traffic_log ORDER BY id")]
            if include_traffic else [])

    if not include_password:
        settings = {k: v for k, v in settings.items() if not k.startswith("password")}

    prox_out = []
    for p in proxies:
        row = {k: p.get(k) for k in PROXY_FIELDS}
        if not include_proxy_creds:
            row["username"] = ""
            row["password"] = ""
        prox_out.append(row)

    payload = {
        "created_at": now(),
        "panel_version": 3,
        "env": current_env(),
        "users": [{k: u[k] for k in USER_FIELDS} for u in users],
        "clean_ips": [{k: ci.get(k) for k in CIP_FIELDS} for ci in cips],
        "proxies": prox_out,
        "settings": settings,
        "traffic_log": traffic,
    }
    return {
        "format": BACKUP_FORMAT,
        "version": BACKUP_VERSION,
        "checksum": _checksum(payload),
        "payload": payload,
    }


def parse_backup(raw, force: bool = False) -> dict:
    """Validate an uploaded backup and return its payload."""
    if isinstance(raw, (str, bytes)):
        try:
            raw = json.loads(raw)
        except Exception:
            raise HTTPException(400, "not a valid backup file (JSON could not be parsed)")
    if not isinstance(raw, dict):
        raise HTTPException(400, "not a valid backup file")
    if raw.get("format") != BACKUP_FORMAT:
        raise HTTPException(400, "this file is not an IranX Panel backup")
    ver = raw.get("version")
    if not isinstance(ver, int) or ver > BACKUP_VERSION:
        raise HTTPException(400, f"backup version {ver} is newer than this panel supports")

    payload = raw.get("payload")
    if not isinstance(payload, dict):
        raise HTTPException(400, "backup has no payload")

    supplied = raw.get("checksum")
    if supplied and supplied != _checksum(payload) and not force:
        raise HTTPException(400, "checksum mismatch — the file looks corrupted or edited. "
                                 "Restore again with force to use it anyway.")

    for key in ("users", "clean_ips", "proxies"):
        if not isinstance(payload.get(key, []), list):
            raise HTTPException(400, "backup structure is invalid")
    return payload


def _clean_user(u: dict) -> Optional[dict]:
    """Coerce one backup user row into something safe to insert, or None to skip it."""
    if not isinstance(u, dict):
        return None
    name = str(u.get("name", "")).strip()
    if not NAME_RE.match(name):
        return None
    try:
        uid = str(uuid.UUID(str(u.get("uuid", "")).strip()))
    except Exception:
        return None

    def num(key, default=0):
        try:
            return max(0, int(u.get(key, default) or 0))
        except (TypeError, ValueError):
            return default

    tr = str(u.get("transport", "both")).lower()
    token = str(u.get("sub_token", "") or "").strip()
    return {
        "name": name,
        "uuid": uid,
        # A missing or absurd token would break the subscription URL, so mint a new one.
        "sub_token": token if re.fullmatch(r"[A-Za-z0-9_\-]{8,64}", token) else secrets.token_urlsafe(16),
        "note": str(u.get("note", "") or "")[:200],
        "enabled": 1 if u.get("enabled", 1) else 0,
        "quota_bytes": num("quota_bytes"),
        "used_bytes": num("used_bytes"),
        "expire_at": num("expire_at"),
        "device_limit": num("device_limit", 1),
        # Missing in v5 (and older) backups: 0 = unlimited IPs.
        "ip_limit": num("ip_limit", 0),
        "transport": tr if tr in TRANSPORTS else "both",
        # Missing in v2 backups: default off, exactly like a fresh user.
        "obfuscate": 1 if u.get("obfuscate") else 0,
        # Missing in v3 backups: the same defaults a brand-new user gets.
        "ech": 1 if u.get("ech") else 0,
        "fp": _pick_choice(u.get("fp"), FINGERPRINTS, "unsafe"),
        "alpn": _pick_choice(u.get("alpn"), ALPN_CHOICES, ""),
        # Missing in v4 (and older) backups: empty means "use the panel default".
        "ech_value": str(u.get("ech_value") or "").strip()[:2000],
        "obf_cs": str(u.get("obf_cs") or "").strip()[:4000],
        "obf_fm": str(u.get("obf_fm") or "").strip()[:4000],
        # Missing in v6 (and older) backups: 0 = no automatic reset.
        "reset_days": min(365, num("reset_days")),
        "last_reset": num("last_reset"),
        "created_at": num("created_at") or now(),
    }


def _clean_proxy(p: dict) -> Optional[dict]:
    """Coerce one backup proxy row, or None to skip it."""
    if not isinstance(p, dict):
        return None
    kind = str(p.get("kind", "socks5")).strip().lower()
    if kind not in PROXY_KINDS:
        return None
    host = str(p.get("host", "")).strip().lstrip("[").rstrip("]")
    if not host or len(host) > 255 or " " in host:
        return None
    try:
        port = int(p.get("port"))
    except (TypeError, ValueError):
        return None
    if not 1 <= port <= 65535:
        return None

    def num(key, default=0):
        try:
            return max(0, int(p.get(key, default) or 0))
        except (TypeError, ValueError):
            return default

    return {
        "kind": kind,
        "host": host,
        "port": port,
        "username": str(p.get("username", "") or "")[:128],
        "password": str(p.get("password", "") or "")[:256],
        "remark": str(p.get("remark", "") or "")[:60],
        "country": re.sub(r"[^A-Za-z]", "", str(p.get("country", "") or ""))[:2].upper(),
        "country_name": str(p.get("country_name", "") or "")[:60],
        "city": str(p.get("city", "") or "")[:60],
        "isp": str(p.get("isp", "") or "")[:80],
        "exit_ip": str(p.get("exit_ip", "") or "")[:45],
        "healthy": 1 if p.get("healthy") else 0,
        "latency_ms": num("latency_ms"),
        "last_error": str(p.get("last_error", "") or "")[:200],
        "checked_at": num("checked_at"),
        "enabled": 1 if p.get("enabled", 1) else 0,
        "added_at": num("added_at") or now(),
    }


def apply_backup(payload: dict, mode: str = "merge",
                 restore_password: bool = False) -> dict:
    """Write a validated payload into the database inside one transaction."""
    users = [x for x in (_clean_user(u) for u in payload.get("users", [])) if x]
    skipped_users = len(payload.get("users", [])) - len(users)

    proxies = [x for x in (_clean_proxy(p) for p in payload.get("proxies", [])) if x]
    skipped_proxies = len(payload.get("proxies", [])) - len(proxies)

    cips, skipped_cips = [], 0
    for ci in payload.get("clean_ips", []):
        if not isinstance(ci, dict):
            skipped_cips += 1
            continue
        addr = str(ci.get("address", "")).strip()
        if not valid_address(addr):
            skipped_cips += 1
            continue
        try:
            added = int(ci.get("added_at") or 0)
        except (TypeError, ValueError):
            added = 0
        cips.append((addr, str(ci.get("remark", "") or "")[:40],
                     re.sub(r"[^A-Za-z]", "", str(ci.get("country", "") or ""))[:2].upper(),
                     1 if ci.get("enabled", 1) else 0, added or now()))

    stats = {"users_added": 0, "users_updated": 0, "users_skipped": skipped_users,
             "clean_ips_added": 0, "clean_ips_skipped": skipped_cips,
             "proxies_added": 0, "proxies_updated": 0, "proxies_skipped": skipped_proxies,
             "password_restored": False, "traffic_rows": 0, "mode": mode}

    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if mode == "replace":
            conn.execute("DELETE FROM user_ips")
            conn.execute("DELETE FROM devices")
            conn.execute("DELETE FROM traffic_log")
            conn.execute("DELETE FROM users")
            conn.execute("DELETE FROM clean_ips")
            conn.execute("DELETE FROM proxies")
            # active_proxy points at an id that no longer exists after a wipe.
            conn.execute("DELETE FROM settings WHERE key='active_proxy'")

        # name and uuid are both UNIQUE, so a row can collide on either one.
        for u in users:
            existing = conn.execute(
                "SELECT id FROM users WHERE name=? OR uuid=?", (u["name"], u["uuid"])
            ).fetchone()
            if existing:
                conn.execute(
                    """UPDATE users SET name=?, uuid=?, sub_token=?, note=?, enabled=?,
                           quota_bytes=?, used_bytes=?, expire_at=?, device_limit=?,
                           ip_limit=?, transport=?, obfuscate=?, ech=?, fp=?, alpn=?,
                           ech_value=?, obf_cs=?, obf_fm=?, reset_days=?, last_reset=?
                           WHERE id=?""",
                    (u["name"], u["uuid"], u["sub_token"], u["note"], u["enabled"],
                     u["quota_bytes"], u["used_bytes"], u["expire_at"],
                     u["device_limit"], u["ip_limit"], u["transport"], u["obfuscate"],
                     u["ech"], u["fp"], u["alpn"],
                     u["ech_value"], u["obf_cs"], u["obf_fm"],
                     u["reset_days"], u["last_reset"], existing["id"]))
                stats["users_updated"] += 1
                continue
            try:
                conn.execute(
                    """INSERT INTO users(name,uuid,sub_token,note,enabled,quota_bytes,
                                         used_bytes,expire_at,device_limit,ip_limit,transport,
                                         obfuscate,ech,fp,alpn,ech_value,obf_cs,obf_fm,
                                         reset_days,last_reset,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (u["name"], u["uuid"], u["sub_token"], u["note"], u["enabled"],
                     u["quota_bytes"], u["used_bytes"], u["expire_at"],
                     u["device_limit"], u["ip_limit"], u["transport"], u["obfuscate"],
                     u["ech"], u["fp"], u["alpn"],
                     u["ech_value"], u["obf_cs"], u["obf_fm"],
                     u["reset_days"], u["last_reset"], u["created_at"]))
                stats["users_added"] += 1
            except sqlite3.IntegrityError:
                # sub_token is UNIQUE too; retry once with a fresh one.
                try:
                    conn.execute(
                        """INSERT INTO users(name,uuid,sub_token,note,enabled,quota_bytes,
                                             used_bytes,expire_at,device_limit,ip_limit,transport,
                                             obfuscate,ech,fp,alpn,ech_value,obf_cs,obf_fm,
                                             reset_days,last_reset,created_at)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (u["name"], u["uuid"], secrets.token_urlsafe(16), u["note"],
                         u["enabled"], u["quota_bytes"], u["used_bytes"], u["expire_at"],
                         u["device_limit"], u["ip_limit"], u["transport"], u["obfuscate"],
                         u["ech"], u["fp"], u["alpn"],
                         u["ech_value"], u["obf_cs"], u["obf_fm"],
                         u["reset_days"], u["last_reset"], u["created_at"]))
                    stats["users_added"] += 1
                except sqlite3.IntegrityError:
                    stats["users_skipped"] += 1

        for addr, remark, country, enabled, added in cips:
            try:
                conn.execute("INSERT INTO clean_ips(address,remark,country,enabled,added_at) "
                             "VALUES(?,?,?,?,?)", (addr, remark, country, enabled, added))
                stats["clean_ips_added"] += 1
            except sqlite3.IntegrityError:
                conn.execute("UPDATE clean_ips SET remark=?, country=?, enabled=? "
                             "WHERE address=?", (remark, country, enabled, addr))

        # proxies are UNIQUE(kind, host, port, username)
        for p in proxies:
            existing = conn.execute(
                "SELECT id FROM proxies WHERE kind=? AND host=? AND port=? AND username=?",
                (p["kind"], p["host"], p["port"], p["username"])).fetchone()
            cols = ("password", "remark", "country", "country_name", "city", "isp",
                    "exit_ip", "healthy", "latency_ms", "last_error", "checked_at",
                    "enabled")
            if existing:
                conn.execute(
                    "UPDATE proxies SET " + ",".join(f"{c}=?" for c in cols) + " WHERE id=?",
                    tuple(p[c] for c in cols) + (existing["id"],))
                stats["proxies_updated"] += 1
                continue
            try:
                fields = PROXY_FIELDS
                conn.execute(
                    "INSERT INTO proxies(" + ",".join(fields) + ") VALUES("
                    + ",".join("?" * len(fields)) + ")",
                    tuple(p[f] for f in fields))
                stats["proxies_added"] += 1
            except sqlite3.IntegrityError:
                stats["proxies_skipped"] += 1

        settings = payload.get("settings") or {}
        if isinstance(settings, dict):
            for k, v in settings.items():
                if not isinstance(k, str) or not isinstance(v, (str, int, float)):
                    continue
                if k.startswith("password") and not restore_password:
                    continue
                # A proxy id from the old database means nothing here; the arming state
                # is rebuilt below once the new ids are known.
                if k == "active_proxy":
                    continue
                conn.execute("""INSERT INTO settings(key,value) VALUES(?,?)
                                ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                             (k, str(v)))
            if restore_password and settings.get("password_hash") and settings.get("password_salt"):
                stats["password_restored"] = True

            # Re-arm the proxy that was active in the backup, matched by its address
            # rather than by its old row id.
            old_active = str(settings.get("active_proxy") or "")
            if old_active.isdigit():
                src = payload.get("proxies") or []
                idx = int(old_active) - 1        # rows were exported ordered by id
                want = None
                for candidate in src:
                    if isinstance(candidate, dict) and str(candidate.get("id", "")) == old_active:
                        want = candidate
                        break
                if want is None and 0 <= idx < len(src) and isinstance(src[idx], dict):
                    want = src[idx]
                if want:
                    cp = _clean_proxy(want)
                    if cp:
                        row = conn.execute(
                            "SELECT id FROM proxies WHERE kind=? AND host=? AND port=? "
                            "AND username=?",
                            (cp["kind"], cp["host"], cp["port"], cp["username"])).fetchone()
                        if row:
                            conn.execute(
                                """INSERT INTO settings(key,value) VALUES('active_proxy',?)
                                   ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                                (str(row["id"]),))
                            stats["active_proxy_id"] = row["id"]

        for row in payload.get("traffic_log") or []:
            if not isinstance(row, dict):
                continue
            try:
                conn.execute("INSERT INTO traffic_log(user_id,ts,up,down) VALUES(?,?,?,?)",
                             (int(row["user_id"]), int(row["ts"]),
                              int(row.get("up", 0)), int(row.get("down", 0))))
                stats["traffic_rows"] += 1
            except (KeyError, TypeError, ValueError, sqlite3.Error):
                pass

        conn.commit()
    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(500, f"restore failed, nothing was changed: {e}")
    finally:
        conn.close()
    return stats


@app.get("/api/backup")
async def download_backup(request: Request, password: int = 1, traffic: int = 0,
                          proxy_creds: int = 1, _=Depends(require_admin)):
    doc = build_backup(include_password=bool(password),
                       include_traffic=bool(traffic),
                       include_proxy_creds=bool(proxy_creds))
    body = json.dumps(doc, ensure_ascii=False, indent=1).encode()
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    host = (origin_domain(request).split(":")[0] or "panel").replace("/", "")
    p = doc["payload"]
    audit("backup_download", client_ip(request),
          f"{len(p['users'])} users, {len(p['clean_ips'])} clean ips, "
          f"{len(p['proxies'])} proxies")
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{host}-{stamp}.ixpbak"',
                 "Cache-Control": "no-store"})


@app.get("/api/backup/info")
async def backup_info(_=Depends(require_admin)):
    """What a backup taken right now would contain."""
    with db() as c:
        u = c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
        ci = c.execute("SELECT COUNT(*) n FROM clean_ips").fetchone()["n"]
        px = c.execute("SELECT COUNT(*) n FROM proxies").fetchone()["n"]
        tl = c.execute("SELECT COUNT(*) n FROM traffic_log").fetchone()["n"]
    return {"users": u, "clean_ips": ci, "proxies": px, "traffic_rows": tl,
            "env": current_env(), "format": BACKUP_FORMAT, "version": BACKUP_VERSION}


@app.post("/api/restore/preview")
async def restore_preview(body: RestoreIn, _=Depends(require_admin)):
    """Validate a file and describe it without touching the database."""
    payload = parse_backup(body.data, force=body.force)
    env = payload.get("env") or {}
    live = current_env()
    prox = payload.get("proxies") or []
    return {
        "ok": True,
        "created_at": payload.get("created_at"),
        "users": len(payload.get("users", [])),
        "clean_ips": len(payload.get("clean_ips", [])),
        "proxies": len(prox),
        "proxies_with_creds": sum(1 for p in prox
                                  if isinstance(p, dict) and p.get("username")),
        "traffic_rows": len(payload.get("traffic_log") or []),
        "has_password": bool((payload.get("settings") or {}).get("password_hash")),
        "env": env,
        # Paths and mode are platform variables the panel cannot set for itself; the UI
        # surfaces the differences so the admin knows what to change on the new host.
        "env_diff": {k: {"backup": env.get(k), "current": live.get(k)}
                     for k in ENV_KEYS if env.get(k) not in (None, live.get(k))},
    }


@app.post("/api/restore")
async def restore_backup(body: RestoreIn, request: Request, _=Depends(require_admin)):
    mode = (body.mode or "merge").lower()
    if mode not in ("merge", "replace"):
        raise HTTPException(400, "mode must be merge or replace")
    payload = parse_backup(body.data, force=body.force)
    stats = apply_backup(payload, mode, body.restore_password)
    audit("restore", client_ip(request),
          f"mode={mode} +{stats['users_added']}/~{stats['users_updated']} users, "
          f"+{stats['clean_ips_added']} clean ips, "
          f"+{stats['proxies_added']}/~{stats['proxies_updated']} proxies")
    return {"ok": True, **stats}


# ─────────────────────── TELEGRAM BACKUP ──────────────────────
#
# A copy of the panel lands in a Telegram chat of the admin's choosing: on
# demand from the settings card, or once a day from a background task. This
# matters on Railway/Render, where the SQLite file lives in /tmp and dies with
# the container — the chat becomes the off-site copy. The .ixpbak file sent is
# the same JSON document the manual download produces, so /api/restore eats it
# unchanged. Token and chat id can also come from TELEGRAM_BOT_TOKEN /
# TELEGRAM_CHAT_ID environment variables; settings take precedence.

TG_BACKUP_EVERY = 86400          # one automatic backup per day
TG_CHECK_EVERY   = 1800          # how often the background task looks


def tg_config() -> tuple[str, str]:
    token = (get_setting("tg_bot_token")
             or os.environ.get("TELEGRAM_BOT_TOKEN", "")).strip()
    chat = (get_setting("tg_chat_id")
            or os.environ.get("TELEGRAM_CHAT_ID", "")).strip()
    return token, chat


def _tg_api(token: str, method: str, *, fields: dict | None = None,
            data: bytes | None = None, filename: str = "",
            timeout: int = 90) -> dict:
    """Blocking Bot-API call (stdlib only): JSON body, or multipart with a file."""
    import urllib.request
    url = f"https://api.telegram.org/bot{token}/{method}"
    if data is None:
        body = urlencode(fields or {}).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
    else:
        boundary = "----IranXPanel" + secrets.token_hex(8)
        parts = []
        for k, v in (fields or {}).items():
            parts.append((f'--{boundary}\r\nContent-Disposition: form-data; '
                          f'name="{k}"\r\n\r\n{v}\r\n').encode())
        parts.append((f'--{boundary}\r\nContent-Disposition: form-data; '
                      f'name="document"; filename="{filename}"\r\n'
                      f'Content-Type: application/octet-stream\r\n\r\n').encode()
                     + data + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        body = b"".join(parts)
        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    req = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


async def tg_send_backup(admin_ip: str = "") -> dict:
    """Build a full backup and push it to the configured chat. Never raises."""
    token, chat = tg_config()
    if not token or not chat:
        return {"ok": False, "error": "telegram not configured"}
    doc = build_backup(include_password=True, include_traffic=False,
                       include_proxy_creds=True)
    body = json.dumps(doc, ensure_ascii=False).encode()
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    fname = f"iranx-backup-{stamp}.ixpbak"
    p = doc["payload"]
    caption = (f"🗄 IranX Panel backup · {stamp} UTC\n"
               f"👥 {len(p['users'])} users · 🧹 {len(p['clean_ips'])} clean IPs · "
               f"🔗 {len(p['proxies'])} proxies\n"
               "🔒 Contains the panel password — keep it private.")
    try:
        res = await asyncio.to_thread(_tg_api, token, "sendDocument",
                                      fields={"chat_id": chat, "caption": caption},
                                      data=body, filename=fname)
    except Exception as e:
        audit("tg_backup_fail", admin_ip, str(e)[:200])
        return {"ok": False, "error": str(e)[:200]}
    if not res.get("ok"):
        desc = str(res.get("description") or "telegram error")[:200]
        audit("tg_backup_fail", admin_ip, desc)
        return {"ok": False, "error": desc}
    set_setting("tg_last_backup", str(now()))
    audit("tg_backup_ok", admin_ip, fname)
    return {"ok": True, "file": fname}


async def tg_autobackup():
    """Daily automatic backup, whenever the admin switched it on in settings."""
    while True:
        await asyncio.sleep(TG_CHECK_EVERY)
        try:
            token, chat = tg_config()
            if not token or not chat or get_setting("tg_auto") != "1":
                continue
            last = int(get_setting("tg_last_backup") or 0)
            if now() - last < TG_BACKUP_EVERY:
                continue
            await tg_send_backup()
        except Exception as e:
            print("tg_autobackup error:", e)


@app.get("/api/telegram")
async def tg_status(_=Depends(require_admin)):
    token, chat = tg_config()
    return {"chat_id": chat,
            "auto": get_setting("tg_auto") == "1",
            "token_set": bool(token),
            "token_from_env": bool(os.environ.get("TELEGRAM_BOT_TOKEN")),
            "last_backup": int(get_setting("tg_last_backup") or 0)}


@app.post("/api/telegram")
async def tg_save(body: TgIn, request: Request, _=Depends(require_admin)):
    if body.bot_token and body.bot_token.strip():
        set_setting("tg_bot_token", body.bot_token.strip())
    if body.chat_id is not None:
        set_setting("tg_chat_id", body.chat_id.strip())
    if body.auto is not None:
        set_setting("tg_auto", "1" if body.auto else "0")
    audit("tg_config", client_ip(request))
    return {"ok": True}


@app.post("/api/telegram/test")
async def tg_test(_=Depends(require_admin)):
    token, chat = tg_config()
    if not token or not chat:
        return {"ok": False, "error": "telegram not configured"}
    try:
        res = await asyncio.to_thread(
            _tg_api, token, "sendMessage",
            fields={"chat_id": chat,
                    "text": "✅ IranX Panel — Telegram backup is wired up. "
                            "Backup files will arrive in this chat."})
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}
    if not res.get("ok"):
        return {"ok": False, "error": str(res.get("description") or "error")[:200]}
    return {"ok": True}


@app.post("/api/telegram/backup")
async def tg_backup_now(request: Request, _=Depends(require_admin)):
    return await tg_send_backup(admin_ip=client_ip(request))


# ─────────────────────────────── STATS ──────────────────────────────


@app.get("/api/live")
async def live_dashboard(_=Depends(require_admin)):
    """Live connections right now: every WS and XHTTP tunnel currently open,
    with the user, transport, route, and how long it has been up."""
    now = int(time.time())
    rows = []
    for c in live_snapshot():
        rows.append({
            "ip": c.get("ip"),
            "user": c.get("user"),
            "uuid": c.get("uuid"),
            "transport": c.get("transport"),
            "route": c.get("route"),
            "mux": bool(c.get("mux")),
            "connected_for": now - int(c.get("since", now)),
        })
    # relay_session already registers both WS and XHTTP tunnels in LIVE, so the
    # registry alone is the source of truth — no need to also walk SESSIONS.
    return {"count": len(rows), "connections": rows}

@app.get("/api/stats")
async def stats(_=Depends(require_admin)):
    with db() as c:
        tot = c.execute("SELECT COUNT(*) n, COALESCE(SUM(used_bytes),0) b FROM users").fetchone()
        act = c.execute("SELECT COUNT(*) n FROM users WHERE enabled=1").fetchone()
        onl = c.execute("SELECT COUNT(DISTINCT user_id) n FROM devices WHERE last_seen>?",
                        (now() - DEVICE_WINDOW,)).fetchone()
        dev = c.execute("SELECT COUNT(*) n FROM devices WHERE last_seen>?",
                        (now() - DEVICE_WINDOW,)).fetchone()
        liv = c.execute("SELECT COUNT(*) n FROM devices WHERE last_seen>?",
                        (now() - LIVE_WINDOW,)).fetchone()
        lu = c.execute("SELECT COUNT(DISTINCT user_id) n FROM devices WHERE last_seen>?",
                       (now() - LIVE_WINDOW,)).fetchone()
        ipt = c.execute("SELECT COUNT(*) n FROM user_ips WHERE last_seen>?",
                        (now() - IP_WINDOW,)).fetchone()
        cip = c.execute("SELECT COUNT(*) n FROM clean_ips WHERE enabled=1").fetchone()
        byp = c.execute("SELECT proto, COUNT(*) n FROM devices WHERE last_seen>? "
                        "GROUP BY proto", (now() - DEVICE_WINDOW,)).fetchall()
        series = c.execute("""SELECT ts/3600*3600 h, SUM(up) up, SUM(down) down
                              FROM traffic_log WHERE ts>? GROUP BY h ORDER BY h""",
                           (now() - 86400,)).fetchall()
    return {"users": tot["n"], "active_users": act["n"], "online_users": onl["n"],
            "live_users": lu["n"], "online_devices": dev["n"], "live_devices": liv["n"],
            "counted_ips": ipt["n"],
            "total_bytes": tot["b"], "clean_ips": cip["n"],
            "by_proto": {r["proto"]: r["n"] for r in byp},
            "xhttp_sessions": len(SESSIONS),
            "series": [dict(r) for r in series],
            "ws_path": WS_PATH, "xhttp_path": XHTTP_PATH,
            "xhttp_mode": XHTTP_MODE,
            "device_window": DEVICE_WINDOW, "ip_window": IP_WINDOW, "live_window": LIVE_WINDOW,
            "keepalive": KEEPALIVE, "keepalive_mins": KEEPALIVE_MINS,
            "relay_domain": RELAY_DOMAIN}


@app.get("/api/logs")
async def logs(_=Depends(require_admin)):
    with db() as c:
        rows = c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 80").fetchall()
    return [dict(r) for r in rows]


# ────────────────────────────── CONTENT FILTER ──────────────────────────────

class FilterRuleIn(BaseModel):
    pattern: str = ""
    kind: str = "domain"
    note: str = ""
    bulk: str = ""


class FilterModeIn(BaseModel):
    enabled: Optional[bool] = None
    block_porn: Optional[bool] = None


@app.get("/api/filter")
async def get_filter(_=Depends(require_admin)):
    with db() as c:
        rows = c.execute("""SELECT id,pattern,kind,note,enabled,added_at
                            FROM filter_rules ORDER BY id DESC LIMIT 1000""").fetchall()
    return {"enabled": filter_on(), "block_porn": porn_on(),
            "porn_keywords": len(PORN_KEYWORDS),
            "rules": [dict(r) for r in rows]}


@app.post("/api/filter/mode")
async def set_filter_mode(body: FilterModeIn, _=Depends(require_admin)):
    if body.enabled is not None:
        set_setting("filter_enabled", "1" if body.enabled else "0")
    if body.block_porn is not None:
        set_setting("block_porn", "1" if body.block_porn else "0")
    audit("filter_mode", "", f"enabled={filter_on()} porn={porn_on()}")
    return {"ok": True, "enabled": filter_on(), "block_porn": porn_on()}


@app.post("/api/filter/rules")
async def add_filter_rules(body: FilterRuleIn, _=Depends(require_admin)):
    kind = body.kind if body.kind in ("domain", "keyword") else "domain"
    raw = body.bulk or body.pattern or ""
    items = []
    for line in str(raw).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        note = ""
        if "#" in line:
            line, note = line.split("#", 1)
            line, note = line.strip(), note.strip()
        for token in line.replace(",", " ").split():
            token = token.strip().lower().lstrip("*.").strip(".")
            if token:
                items.append((token, kind, note))
    added = 0
    with db() as c:
        for pat, k, note in items:
            cur = c.execute("""INSERT OR IGNORE INTO filter_rules(pattern,kind,note,enabled,added_at)
                               VALUES(?,?,?,1,?)""", (pat, k, note, now()))
            added += cur.rowcount or 0
    load_filter_rules(force=True)
    return {"ok": True, "added": added}


@app.patch("/api/filter/rules/{rid}")
async def toggle_filter_rule(rid: int, _=Depends(require_admin)):
    with db() as c:
        c.execute("UPDATE filter_rules SET enabled=1-enabled WHERE id=?", (rid,))
    load_filter_rules(force=True)
    return {"ok": True}


@app.delete("/api/filter/rules/{rid}")
async def delete_filter_rule(rid: int, _=Depends(require_admin)):
    with db() as c:
        c.execute("DELETE FROM filter_rules WHERE id=?", (rid,))
    load_filter_rules(force=True)
    return {"ok": True}


@app.delete("/api/filter/rules")
async def clear_filter_rules(kind: str = "", _=Depends(require_admin)):
    with db() as c:
        if kind in ("domain", "keyword"):
            c.execute("DELETE FROM filter_rules WHERE kind=?", (kind,))
        else:
            c.execute("DELETE FROM filter_rules")
    load_filter_rules(force=True)
    return {"ok": True}


# ────────────────────────────── SUBSCRIPTION ──────────────────────────────


# ══════════════════════════ SUBSCRIPTION PAGE ══════════════════════════
# Self-contained: QR encoder + HTML renderer for /sub/<token> in a browser.

"""Minimal, dependency-free QR code encoder (byte mode) returning SVG.

Only what the subscription page needs: encode a UTF-8 string, pick the smallest
version that fits, render as a compact SVG path.
"""

# (ec_per_block, [(num_blocks, data_codewords), ...]) keyed by (version, level)
_EC: dict[tuple[int, str], tuple[int, list[tuple[int, int]]]] = {
    (1, "L"): (7, [(1, 19)]),   (1, "M"): (10, [(1, 16)]),
    (2, "L"): (10, [(1, 34)]),  (2, "M"): (16, [(1, 28)]),
    (3, "L"): (15, [(1, 55)]),  (3, "M"): (26, [(1, 44)]),
    (4, "L"): (20, [(1, 80)]),  (4, "M"): (18, [(2, 32)]),
    (5, "L"): (26, [(1, 108)]), (5, "M"): (24, [(2, 43)]),
    (6, "L"): (18, [(2, 68)]),  (6, "M"): (16, [(4, 27)]),
    (7, "L"): (20, [(2, 78)]),  (7, "M"): (18, [(4, 31)]),
    (8, "L"): (24, [(2, 97)]),  (8, "M"): (22, [(2, 38), (2, 39)]),
    (9, "L"): (30, [(2, 116)]), (9, "M"): (22, [(3, 36), (2, 37)]),
    (10, "L"): (18, [(2, 68), (2, 69)]),   (10, "M"): (26, [(4, 43), (1, 44)]),
    (11, "L"): (20, [(4, 81)]),            (11, "M"): (30, [(1, 50), (4, 51)]),
    (12, "L"): (24, [(2, 92), (2, 93)]),   (12, "M"): (22, [(6, 36), (2, 37)]),
    (13, "L"): (26, [(4, 107)]),           (13, "M"): (22, [(8, 37), (1, 38)]),
    (14, "L"): (30, [(3, 115), (1, 116)]), (14, "M"): (24, [(4, 40), (5, 41)]),
    (15, "L"): (22, [(5, 87), (1, 88)]),   (15, "M"): (24, [(5, 41), (5, 42)]),
    (16, "L"): (24, [(5, 98), (1, 99)]),   (16, "M"): (28, [(7, 45), (3, 46)]),
    (17, "L"): (28, [(1, 107), (5, 108)]), (17, "M"): (28, [(10, 46), (1, 47)]),
    (18, "L"): (30, [(5, 120), (1, 121)]), (18, "M"): (26, [(9, 43), (4, 44)]),
    (19, "L"): (28, [(3, 113), (4, 114)]), (19, "M"): (26, [(3, 44), (11, 45)]),
    (20, "L"): (28, [(3, 107), (5, 108)]), (20, "M"): (26, [(3, 41), (13, 42)]),
    (21, "L"): (28, [(4, 116), (4, 117)]), (21, "M"): (26, [(17, 42)]),
    (22, "L"): (28, [(2, 111), (7, 112)]), (22, "M"): (28, [(17, 46)]),
    (23, "L"): (30, [(4, 121), (5, 122)]), (23, "M"): (28, [(4, 47), (14, 48)]),
    (24, "L"): (30, [(6, 117), (4, 118)]), (24, "M"): (28, [(6, 45), (14, 46)]),
    (25, "L"): (26, [(8, 106), (4, 107)]), (25, "M"): (28, [(8, 47), (13, 48)]),
    (26, "L"): (28, [(10, 114), (2, 115)]), (26, "M"): (28, [(19, 46), (4, 47)]),
    (27, "L"): (30, [(8, 122), (4, 123)]), (27, "M"): (28, [(22, 45), (3, 46)]),
    (28, "L"): (30, [(3, 117), (10, 118)]), (28, "M"): (28, [(3, 45), (23, 46)]),
    (29, "L"): (30, [(7, 116), (7, 117)]), (29, "M"): (28, [(21, 45), (7, 46)]),
    (30, "L"): (30, [(5, 115), (10, 116)]), (30, "M"): (28, [(19, 47), (10, 48)]),
}

_ALIGN: dict[int, list[int]] = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
    7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
    11: [6, 30, 54], 12: [6, 32, 58], 13: [6, 34, 62], 14: [6, 26, 46, 66],
    15: [6, 26, 48, 70], 16: [6, 26, 50, 74], 17: [6, 30, 54, 78],
    18: [6, 30, 56, 82], 19: [6, 30, 58, 86], 20: [6, 34, 62, 90],
    21: [6, 28, 50, 72, 94], 22: [6, 26, 50, 74, 98], 23: [6, 30, 54, 78, 102],
    24: [6, 28, 54, 80, 106], 25: [6, 32, 58, 84, 110], 26: [6, 30, 58, 86, 114],
    27: [6, 34, 62, 90, 118], 28: [6, 26, 50, 74, 98, 122],
    29: [6, 30, 54, 78, 102, 126], 30: [6, 26, 52, 78, 104, 130],
}

# ── GF(256) ──────────────────────────────────────────────────────────────
_EXP = [1] * 512
_LOG = [0] * 256
_x = 1
for _i in range(1, 255):
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
    _EXP[_i] = _x
    _LOG[_x] = _i
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _gen_poly(n: int) -> list[int]:
    g = [1]
    for i in range(n):
        g2 = [0] * (len(g) + 1)
        for j, c in enumerate(g):
            g2[j] ^= c
            g2[j + 1] ^= _mul(c, _EXP[i])
        g = g2
    return g


def _rs(data: list[int], n: int) -> list[int]:
    g = _gen_poly(n)
    rem = [0] * n
    for d in data:
        factor = d ^ rem[0]
        rem = rem[1:] + [0]
        if factor:
            for i, c in enumerate(g[1:]):
                rem[i] ^= _mul(c, factor)
    return rem


def _bch(data: int, gen: int, gen_bits: int) -> int:
    rem = data
    while rem.bit_length() >= gen_bits:
        rem ^= gen << (rem.bit_length() - gen_bits)
    return rem


def _capacity(version: int, level: str) -> int:
    ecb, groups = _EC[(version, level)]
    return sum(n * d for n, d in groups)


def _bitstream(payload: bytes, version: int, level: str) -> list[int]:
    count_bits = 8 if version < 10 else 16
    bits: list[int] = [0, 1, 0, 0]
    for i in range(count_bits - 1, -1, -1):
        bits.append((len(payload) >> i) & 1)
    for byte in payload:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    total = _capacity(version, level) * 8
    bits += [0] * min(4, total - len(bits))
    while len(bits) % 8:
        bits.append(0)
    pads = (0xEC, 0x11)
    k = 0
    while len(bits) < total:
        for i in range(7, -1, -1):
            bits.append((pads[k % 2] >> i) & 1)
        k += 1
    return bits


def _codewords(payload: bytes, version: int, level: str) -> list[int]:
    bits = _bitstream(payload, version, level)
    data = [int("".join(str(b) for b in bits[i:i + 8]), 2) for i in range(0, len(bits), 8)]
    ecb, groups = _EC[(version, level)]
    blocks: list[list[int]] = []
    pos = 0
    for count, dc in groups:
        for _ in range(count):
            blocks.append(data[pos:pos + dc])
            pos += dc
    ec_blocks = [_rs(b, ecb) for b in blocks]
    out: list[int] = []
    for i in range(max(len(b) for b in blocks)):
        for b in blocks:
            if i < len(b):
                out.append(b[i])
    for i in range(ecb):
        for b in ec_blocks:
            out.append(b[i])
    return out


def _blank(size: int) -> list[list[int | None]]:
    return [[None] * size for _ in range(size)]


def _place_function_patterns(m, version: int) -> None:
    size = len(m)

    def finder(r0: int, c0: int) -> None:
        for r in range(-1, 8):
            for c in range(-1, 8):
                rr, cc = r0 + r, c0 + c
                if not (0 <= rr < size and 0 <= cc < size):
                    continue
                inner = 2 <= r <= 4 and 2 <= c <= 4
                ring = r in (0, 6) and 0 <= c <= 6 or c in (0, 6) and 0 <= r <= 6
                m[rr][cc] = 1 if (inner or ring) else 0

    finder(0, 0)
    finder(0, size - 7)
    finder(size - 7, 0)

    for i in range(size):
        if m[6][i] is None:
            m[6][i] = 1 if i % 2 == 0 else 0
        if m[i][6] is None:
            m[i][6] = 1 if i % 2 == 0 else 0

    centers = _ALIGN[version]
    skip = {(centers[0], centers[0]), (centers[0], centers[-1]), (centers[-1], centers[0])} if centers else set()
    for r in centers:
        for c in centers:
            if (r, c) in skip:
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    edge = max(abs(dr), abs(dc))
                    m[r + dr][c + dc] = 1 if edge != 1 else 0

    m[size - 8][8] = 1  # dark module

    # reserve format areas
    for i in range(9):
        if m[8][i] is None:
            m[8][i] = 0
        if m[i][8] is None:
            m[i][8] = 0
    for i in range(8):
        if m[8][size - 1 - i] is None:
            m[8][size - 1 - i] = 0
        if m[size - 1 - i][8] is None:
            m[size - 1 - i][8] = 0

    if version >= 7:
        bits = (version << 12) | _bch(version << 12, 0x1F25, 13)
        for i in range(18):
            b = (bits >> i) & 1
            m[size - 11 + i % 3][i // 3] = b
            m[i // 3][size - 11 + i % 3] = b


def _reserved_mask(version: int) -> list[list[bool]]:
    size = version * 4 + 17
    m = _blank(size)
    _place_function_patterns(m, version)
    return [[m[r][c] is not None for c in range(size)] for r in range(size)]


def _mask_bit(mask: int, r: int, c: int) -> bool:
    if mask == 0:
        return (r + c) % 2 == 0
    if mask == 1:
        return r % 2 == 0
    if mask == 2:
        return c % 3 == 0
    if mask == 3:
        return (r + c) % 3 == 0
    if mask == 4:
        return (r // 2 + c // 3) % 2 == 0
    if mask == 5:
        return (r * c) % 2 + (r * c) % 3 == 0
    if mask == 6:
        return ((r * c) % 2 + (r * c) % 3) % 2 == 0
    return ((r + c) % 2 + (r * c) % 3) % 2 == 0


def _penalty(g: list[list[int]]) -> int:
    size = len(g)
    score = 0
    for line in list(g) + [list(col) for col in zip(*g)]:
        run, prev = 0, None
        for v in line:
            if v == prev:
                run += 1
            else:
                if run >= 5:
                    score += 3 + (run - 5)
                run, prev = 1, v
        if run >= 5:
            score += 3 + (run - 5)
    for r in range(size - 1):
        for c in range(size - 1):
            s = g[r][c] + g[r][c + 1] + g[r + 1][c] + g[r + 1][c + 1]
            if s in (0, 4):
                score += 3
    pat1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0]
    pat2 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1]
    for line in list(g) + [list(col) for col in zip(*g)]:
        for i in range(size - 10):
            window = line[i:i + 11]
            if window == pat1 or window == pat2:
                score += 40
    dark = sum(sum(row) for row in g)
    ratio = dark * 100 // (size * size)
    score += 10 * (abs(ratio - 50) // 5)
    return score


def encode(text: str, level: str = "M", force_mask: int | None = None) -> list[list[int]]:
    """Return the QR matrix (list of rows of 0/1) for `text`."""
    payload = text.encode("utf-8")
    version = None
    for v in range(1, 31):
        overhead = 4 + (8 if v < 10 else 16)
        if _capacity(v, level) * 8 >= overhead + len(payload) * 8:
            version = v
            break
    if version is None:
        if level != "L":
            return encode(text, "L")
        raise ValueError("data too long for QR")

    size = version * 4 + 17
    codewords = _codewords(payload, version, level)
    reserved = _reserved_mask(version)

    base = _blank(size)
    _place_function_patterns(base, version)

    bits = [(cw >> i) & 1 for cw in codewords for i in range(7, -1, -1)]
    idx = 0
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for r in rows:
            for c in (col, col - 1):
                if reserved[r][c]:
                    continue
                base[r][c] = bits[idx] if idx < len(bits) else 0
                idx += 1
        upward = not upward
        col -= 2

    ec_bits = {"L": 0b01, "M": 0b00, "Q": 0b11, "H": 0b10}[level]
    best = None
    for mask in (range(8) if force_mask is None else (force_mask,)):
        g = [[int(base[r][c]) ^ (1 if (not reserved[r][c] and _mask_bit(mask, r, c)) else 0)
              for c in range(size)] for r in range(size)]
        fmt_data = (ec_bits << 3) | mask
        fmt = ((fmt_data << 10) | _bch(fmt_data << 10, 0x537, 11)) ^ 0x5412
        for i in range(15):
            bit = (fmt >> i) & 1
            if i < 6:
                g[i][8] = bit
            elif i < 8:
                g[i + 1][8] = bit
            else:
                g[size - 15 + i][8] = bit
            if i < 8:
                g[8][size - 1 - i] = bit
            elif i == 8:
                g[8][7] = bit
            else:
                g[8][14 - i] = bit
        g[size - 8][8] = 1
        score = _penalty(g)
        if best is None or score < best[0]:
            best = (score, g)
    return best[1]


def svg(text: str, level: str = "M", quiet: int = 3, css_class: str = "qr") -> str:
    """Return a compact, self-contained SVG string for `text`."""
    g = encode(text, level)
    size = len(g)
    total = size + quiet * 2
    parts = []
    for r, row in enumerate(g):
        c = 0
        while c < size:
            if row[c]:
                start = c
                while c < size and row[c]:
                    c += 1
                parts.append(f"M{start + quiet} {r + quiet}h{c - start}v1h-{c - start}z")
            else:
                c += 1
    path = "".join(parts)
    return (
        f'<svg class="{css_class}" viewBox="0 0 {total} {total}" '
        f'xmlns="http://www.w3.org/2000/svg" shape-rendering="crispEdges" role="img">'
        f'<rect width="{total}" height="{total}" fill="#fff"/>'
        f'<path d="{path}" fill="#111"/></svg>'
    )


"""Subscription landing page for IranX Panel.

`render_sub_page()` returns one self-contained HTML page for `/sub/{token}`:
quota, remaining time, QR codes, per-config copy buttons, one-tap import into
the popular clients and direct client downloads.

Features: Vazirmatn Persian webfont, dark + light themes in the same teal-on-navy
visual language as the admin panel (3x-ui / Sanaei style), and a Persian/English
language switch. No new Python dependencies (QR codes come from the built-in
encoder).
"""

import html
import json
import time

qr_svg = svg


GH = ("https" + "://") + "github.com"
CDN = ("https" + "://") + "cdn.jsdelivr.net"
APPLE = ("https" + "://") + "apps.apple.com/app"

# Vazirmatn webfont (two CDN spellings, whichever resolves first wins; the page
# still looks right with the local fallback stack if both are unreachable).
FONT_CSS = [
    CDN + "/npm/@fontsource-variable/vazirmatn/index.min.css",
    CDN + "/npm/vazirmatn@33.003/Vazirmatn-font-face.css",
]


def _rel(repo: str) -> str:
    """Stable link to the newest release of a repo."""
    return GH + "/" + repo + "/releases/latest"


def _dl(repo: str, asset: str) -> str:
    """Direct download of a version-free asset name from the newest release."""
    return GH + "/" + repo + "/releases/latest/download/" + asset


def _pin(repo: str, tag: str, asset: str) -> str:
    """Direct download of a versioned asset (names that carry the version)."""
    return GH + "/" + repo + "/releases/download/" + tag + "/" + asset


# ── client catalogue (static links, nothing is fetched at runtime) ────────────
HID = "hiddify/hiddify-app"
V2NG = "2dust/v2rayNG"
V2NG_VER = "2.2.6"  # v2rayNG asset names contain the version, so it is pinned
EXC = "dyhkwong/Exclave"
NEKO = "MatsuriDayo/NekoBoxForAndroid"
NEKORAY = "MatsuriDayo/nekoray"

# Official app icons, served through jsDelivr (reachable where raw.github is not)
LOGO_V2NG = CDN + "/gh/2dust/v2rayNG@master/fastlane/metadata/android/en-US/images/icon.png"
LOGO_HID = CDN + "/gh/hiddify/hiddify-app@main/assets/images/logo.svg"
LOGO_EXC = CDN + "/gh/ExclaveNetwork/Exclave@dev/app/src/main/res/mipmap-xxxhdpi/ic_launcher.webp"
LOGO_NEKO = CDN + "/gh/MatsuriDayo/NekoBoxForAndroid@main/app/src/main/res/mipmap-xxxhdpi/ic_launcher.png"
LOGO_V2N = CDN + "/gh/2dust/v2rayN@master/v2rayN/v2rayN/Resources/NotifyMain.ico"


def _v2ng(arch: str) -> str:
    return _pin(V2NG, V2NG_VER, "v2rayNG_" + V2NG_VER + "_" + arch + ".apk")


CLIENTS: list[dict] = [
    # ─── Android ───
    {"os": "android", "name": "v2rayNG", "repo": V2NG, "accent": "#3b82f6",
     "logo": LOGO_V2NG, "scheme": "v2rayng",
     "builds": [
         {"label": "arm64-v8a", "url": _v2ng("arm64-v8a"), "note": ".apk"},
         {"label": "armeabi-v7a", "url": _v2ng("armeabi-v7a"), "note": ".apk"},
         {"label": "x86_64", "url": _v2ng("x86_64"), "note": ".apk"},
         {"label": "x86", "url": _v2ng("x86"), "note": ".apk"},
         {"label": "@ALL@", "url": _rel(V2NG), "note": "Releases"},
     ]},
    {"os": "android", "name": "Hiddify", "repo": HID, "accent": "#22c55e",
     "logo": LOGO_HID, "scheme": "hiddify",
     "builds": [
         {"label": "arm64", "url": _dl(HID, "Hiddify-Android-arm64.apk"), "note": ".apk"},
         {"label": "arm32", "url": _dl(HID, "Hiddify-Android-arm7.apk"), "note": ".apk"},
         {"label": "x86_64", "url": _dl(HID, "Hiddify-Android-x86_64.apk"), "note": ".apk"},
         {"label": "universal", "url": _dl(HID, "Hiddify-Android-universal.apk"), "note": ".apk"},
     ]},
    {"os": "android", "name": "Exclave", "repo": EXC, "accent": "#a855f7",
     "logo": LOGO_EXC, "scheme": "",
     "builds": [
         {"label": "arm64-v8a", "url": _rel(EXC), "note": "Releases"},
         {"label": "armeabi-v7a", "url": _rel(EXC), "note": "Releases"},
         {"label": "x86_64", "url": _rel(EXC), "note": "Releases"},
     ]},
    {"os": "android", "name": "NekoBox", "repo": NEKO, "accent": "#f97316",
     "logo": LOGO_NEKO, "scheme": "",
     "builds": [
         {"label": "arm64-v8a", "url": _rel(NEKO), "note": "Releases"},
         {"label": "armeabi-v7a", "url": _rel(NEKO), "note": "Releases"},
         {"label": "x86_64", "url": _rel(NEKO), "note": "Releases"},
     ]},
    {"os": "android", "name": "sing-box", "repo": "SagerNet/sing-box", "accent": "#0ea5e9",
     "logo": "", "scheme": "singbox",
     "builds": [{"label": "Google Play / GitHub", "url": _rel("SagerNet/sing-box"), "note": "Releases"}]},
    # ─── Windows ───
    {"os": "windows", "name": "Hiddify", "repo": HID, "accent": "#22c55e",
     "logo": LOGO_HID, "scheme": "hiddify",
     "builds": [
         {"label": "Setup x64", "url": _dl(HID, "Hiddify-Windows-Setup-x64.exe"), "note": ".exe"},
         {"label": "Portable x64", "url": _dl(HID, "Hiddify-Windows-Portable-x64.zip"), "note": ".zip"},
     ]},
    {"os": "windows", "name": "v2rayN", "repo": "2dust/v2rayN", "accent": "#3b82f6",
     "logo": LOGO_V2N, "scheme": "",
     "builds": [
         {"label": "windows x64", "url": _rel("2dust/v2rayN"), "note": "Releases"},
         {"label": "windows arm64", "url": _rel("2dust/v2rayN"), "note": "Releases"},
     ]},
    {"os": "windows", "name": "NekoRay", "repo": NEKORAY, "accent": "#f97316",
     "logo": "", "scheme": "",
     "builds": [{"label": "windows x64", "url": _rel(NEKORAY), "note": "Releases"}]},
    # ─── iOS ───
    {"os": "ios", "name": "Hiddify", "repo": "App Store", "accent": "#22c55e",
     "logo": LOGO_HID, "scheme": "hiddify",
     "builds": [{"label": "iPhone / iPad", "url": APPLE + "/hiddify-proxy-vpn/id6596777532", "note": "App Store"}]},
    {"os": "ios", "name": "Streisand", "repo": "App Store", "accent": "#3b82f6",
     "logo": "", "scheme": "streisand",
     "builds": [{"label": "iPhone / iPad", "url": APPLE + "/streisand/id6450534064", "note": "App Store"}]},
    {"os": "ios", "name": "Shadowrocket", "repo": "App Store", "accent": "#a855f7",
     "logo": "", "scheme": "shadowrocket",
     "builds": [{"label": "iPhone / iPad", "url": APPLE + "/shadowrocket/id932747118", "note": "App Store"}]},
    {"os": "ios", "name": "V2Box", "repo": "App Store", "accent": "#0ea5e9",
     "logo": "", "scheme": "v2box",
     "builds": [{"label": "iPhone / iPad", "url": APPLE + "/v2box-v2ray-client/id6446814690", "note": "App Store"}]},
    {"os": "ios", "name": "FoXray", "repo": "App Store", "accent": "#f97316",
     "logo": "", "scheme": "",
     "builds": [{"label": "iPhone / iPad", "url": APPLE + "/foxray/id6448898396", "note": "App Store"}]},
    # ─── macOS ───
    {"os": "macos", "name": "Hiddify", "repo": HID, "accent": "#22c55e",
     "logo": LOGO_HID, "scheme": "hiddify",
     "builds": [
         {"label": "Apple Silicon / Intel", "url": _dl(HID, "Hiddify-MacOS.dmg"), "note": ".dmg"},
         {"label": "@ALL@", "url": _rel(HID), "note": "Releases"},
     ]},
    {"os": "macos", "name": "V2Box", "repo": "App Store", "accent": "#0ea5e9",
     "logo": "", "scheme": "v2box",
     "builds": [{"label": "macOS", "url": APPLE + "/v2box-v2ray-client/id6446814690", "note": "App Store"}]},
    {"os": "macos", "name": "NekoRay", "repo": NEKORAY, "accent": "#f97316",
     "logo": "", "scheme": "",
     "builds": [{"label": "macOS", "url": _rel(NEKORAY), "note": "Releases"}]},
    # ─── Linux ───
    {"os": "linux", "name": "Hiddify", "repo": HID, "accent": "#22c55e",
     "logo": LOGO_HID, "scheme": "hiddify",
     "builds": [
         {"label": "AppImage x64", "url": _dl(HID, "Hiddify-Linux-x64.AppImage"), "note": ".AppImage"},
         {"label": ".deb x64", "url": _dl(HID, "Hiddify-Debian-x64.deb"), "note": ".deb"},
         {"label": ".rpm x64", "url": _dl(HID, "Hiddify-rpm-x64.rpm"), "note": ".rpm"},
     ]},
    {"os": "linux", "name": "NekoRay", "repo": NEKORAY, "accent": "#f97316",
     "logo": "", "scheme": "",
     "builds": [{"label": "linux x64", "url": _rel(NEKORAY), "note": "Releases"}]},
    {"os": "linux", "name": "v2rayA", "repo": "v2rayA/v2rayA", "accent": "#3b82f6",
     "logo": "", "scheme": "",
     "builds": [
         {"label": "amd64 (.deb/.rpm)", "url": _rel("v2rayA/v2rayA"), "note": "Releases"},
         {"label": "arm64 (.deb/.rpm)", "url": _rel("v2rayA/v2rayA"), "note": "Releases"},
     ]},
]

OS_TABS = [
    ("android", "اندروید", "Android"),
    ("windows", "ویندوز", "Windows"),
    ("ios", "آی‌او‌اس", "iOS"),
    ("macos", "مک‌او‌اس", "macOS"),
    ("linux", "لینوکس", "Linux"),
]


def _fmt_bytes(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"


def render_sub_page(
    *,
    name: str,
    sub_link: str,
    configs: list,
    used_bytes: int = 0,
    quota_bytes: int = 0,
    expire_at: int = 0,
    active: bool = True,
    status: str = "",
    transport: str = "both",
    device_limit: int = 0,
    devices_now: int = 0,
    ip_limit: int = 0,
    ips_now: int = 0,
    panel_url: str = "",
    update_interval: int = 12,
    reset_days: int = 0,
    last_reset: int = 0,
) -> str:
    """Return the full HTML page for one subscription token."""
    now = int(time.time())
    quota_bytes = int(quota_bytes or 0)
    used_bytes = int(used_bytes or 0)
    expire_at = int(expire_at or 0)
    reset_days = min(365, max(0, int(reset_days or 0)))
    last_reset = int(last_reset or 0)

    remain_bytes = max(0, quota_bytes - used_bytes) if quota_bytes else 0
    pct = min(100, round(used_bytes * 100 / quota_bytes)) if quota_bytes else 0
    remain_secs = max(0, expire_at - now) if expire_at else 0

    cfgs = []
    for c in configs or []:
        c = dict(c)
        cfgs.append({"label": c.get("label", ""), "transport": c.get("transport", ""),
                     "uri": c.get("uri", "")})

    payload = {
        "name": name,
        "subLink": sub_link,
        "subLinkClash": sub_link + "?format=clash",
        "subLinkSingbox": sub_link + "?format=singbox",
        "panelUrl": panel_url,
        "active": bool(active),
        "status": status or ("" if active else "inactive"),
        "transport": (transport or "both").upper(),
        "used": used_bytes,
        "quota": quota_bytes,
        "usedText": _fmt_bytes(used_bytes),
        "quotaText": "∞" if not quota_bytes else _fmt_bytes(quota_bytes),
        "remainText": "∞" if not quota_bytes else _fmt_bytes(remain_bytes),
        "pct": pct,
        "expireAt": expire_at,
        "remainDays": remain_secs // 86400,
        "remainHours": remain_secs % 86400 // 3600,
        "deviceLimit": int(device_limit or 0),
        "devicesNow": int(devices_now or 0),
        "ipLimit": int(ip_limit or 0),
        "ipsNow": int(ips_now or 0),
        "updateInterval": int(update_interval or 12),
        "resetDays": reset_days,
        "nextResetAt": (last_reset + reset_days * 86400) if reset_days else 0,
        "configs": cfgs,
        "allConfigs": "\n".join(c["uri"] for c in cfgs if c["uri"]),
        "clients": CLIENTS,
        "osTabs": OS_TABS,
    }

    qrs = [qr_svg(sub_link, level="M", css_class="qrsvg")]
    for c in cfgs:
        try:
            qrs.append(qr_svg(c["uri"], level="L", css_class="qrsvg sm"))
        except Exception:
            qrs.append("")

    fonts = "\n".join(
        '<link rel="stylesheet" href="' + html.escape(u, quote=True) + '">' for u in FONT_CSS
    )
    data = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")
    qr_json = json.dumps(qrs, ensure_ascii=False).replace("</", "<\\/")
    return (_TEMPLATE
            .replace("__FONTS__", fonts)
            .replace("__TITLE__", html.escape(name or "Subscription"))
            .replace("__QRS__", qr_json)
            .replace("__DATA__", data))


_TEMPLATE = r"""
<!doctype html>
<html lang="en" dir="ltr" data-theme="gray">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<meta name="color-scheme" content="dark light">
<title>__TITLE__ &middot; IranX</title>
<link rel="icon" type="image/png" href="__LOGO__">
__FONTS__
<style>
/* ══════════════════════════════════════════════════════════════════
   IRANX SUBSCRIPTION v4 — RTL-first
   ══════════════════════════════════════════════════════════════════ */
:root,[data-theme="gray"]{
  --bg:#08090b; --s1:#0d0f12; --s2:#12151a; --s3:#171b21;
  --line:#1e232b; --line2:#2a313c;
  --tx:#e6e9ee; --tx2:#98a2b1; --tx3:#6b7583;
  --acid:#c6f24e; --brand:#22ef9d; --red:#e8112d; --gold:#e5b80b;
  --ok:#c6f24e; --warn:#ffcc66; --bad:#ff6b6b; --info:#5ce1e6;
  --cyan:#5ce1e6; --amber:#ffcc66;
  --ease:cubic-bezier(.22,.68,.32,1);
}
[data-theme="light"]{
  --bg:#f4f6f8; --s1:#ffffff; --s2:#f7f9fc; --s3:#eef1f6;
  --line:#e2e7ee; --line2:#d3dae3;
  --tx:#141a22; --tx2:#5a6472; --tx3:#8b95a3;
  --acid:#7aa800; --brand:#0c9470; --red:#d81f3a; --gold:#a67c00;
  --ok:#5f8c00; --warn:#a87000; --bad:#cf3346; --info:#1478b8;
  --cyan:#0d8f96; --amber:#a87000;
}

*{box-sizing:border-box}
html,body{margin:0;padding:0;max-width:100%;overflow-x:hidden}
body{
  background:var(--bg);color:var(--tx);min-height:100vh;
  padding:14px 13px 40px;
  /* همان پشتهٔ فونت پنل */
  font-family:'Vazirmatn','Vazir','IRANSansX',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,system-ui,sans-serif;
  font-size:13.5px;line-height:1.6;-webkit-font-smoothing:antialiased;
  -moz-osx-font-smoothing:grayscale;
  background-image:radial-gradient(circle at 50% -18%,rgba(34,239,157,.07),transparent 58%);
}
b,strong{font-weight:600}
button,input,select,textarea{font-family:inherit}
.flag{width:19px;height:14px;flex:0 0 19px;border-radius:3px;object-fit:cover;
  display:inline-block;vertical-align:-2px;background:var(--s3);
  box-shadow:0 0 0 1px var(--line2)}
.mono{font-family:'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace;
  font-variant-numeric:tabular-nums}
bdi{unicode-bidi:isolate}
.wrap{max-width:560px;margin:0 auto}

/* ── نوار بالا ── */
.top{display:flex;align-items:center;gap:8px;margin-bottom:13px;min-width:0}
.top .logo{width:30px;height:30px;flex:0 0 30px;border-radius:8px;object-fit:cover;
  background:#000;box-shadow:0 0 0 1px var(--line2)}
.brand{display:flex;flex-direction:column;line-height:1.25;min-width:0;flex:1 1 auto;
  overflow:hidden}
.brand b{font-size:12.5px;font-weight:700;white-space:nowrap;overflow:hidden;
  text-overflow:ellipsis}
.brand span{font-family:'JetBrains Mono',monospace;font-size:8px;letter-spacing:1px;
  color:var(--tx3);text-transform:uppercase;white-space:nowrap}
.top .tools{display:flex;align-items:center;gap:6px;flex:0 0 auto}
/* عرض کم: تگ ترنسپورت از هدر برداشته می‌شود تا نام اشتراک کامل بماند */
@media (max-width:470px){
  .top{gap:6px}
  #trTag{display:none!important}
  .brand b{font-size:12px}
  .chip{padding:5px 8px}
}
.tag{font-family:'JetBrains Mono',monospace;font-size:9.5px;font-weight:600;padding:4px 8px;
  border-radius:6px;background:var(--s2);border:1px solid var(--line2);color:var(--tx2);
  white-space:nowrap;direction:ltr}
.chip{display:inline-flex;align-items:center;gap:5px;font:inherit;font-size:10.5px;
  font-weight:600;padding:5px 9px;border-radius:6px;background:var(--s2);
  border:1px solid var(--line2);color:var(--tx2);cursor:pointer;transition:.15s;
  white-space:nowrap}
.chip:hover{border-color:var(--acid);color:var(--acid)}
.chip svg{width:12px;height:12px;flex:0 0 12px;stroke:currentColor;fill:none;
  stroke-width:2;stroke-linecap:round;stroke-linejoin:round}

/* ── کارت ── */
.card{border:1px solid var(--line);border-radius:12px;background:var(--s1);
  padding:14px;margin-bottom:11px;min-width:0}
.card.top0{margin-top:0}

/* ── سرصفحه‌ی کاربر ── */
.who{display:flex;align-items:center;gap:8px;min-width:0;flex-wrap:wrap}
.who .dot{width:7px;height:7px;flex:0 0 7px;border-radius:50%;background:var(--ok);
  box-shadow:0 0 0 4px rgba(198,242,78,.13)}
.who .dot.off{background:var(--bad);box-shadow:0 0 0 4px rgba(255,107,107,.13)}
.who h1{margin:0;font-size:17px;font-weight:700;line-height:1.35;min-width:0;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:58%}
html[lang="fa"] .who h1{font-size:16.5px;letter-spacing:0}
.st{margin-inline-start:auto;font-size:10.5px;font-weight:600;padding:4px 9px;
  border-radius:6px;white-space:nowrap;border:1px solid var(--line2);
  background:var(--s2);color:var(--tx2)}
.st.ok{color:var(--acid);border-color:rgba(198,242,78,.34);background:rgba(198,242,78,.1)}
.st.warn{color:var(--amber);border-color:rgba(255,204,102,.34);background:rgba(255,204,102,.1)}
.st.bad{color:var(--bad);border-color:rgba(255,107,107,.34);background:rgba(255,107,107,.1)}

.expline{margin:9px 0 0;font-size:11.5px;color:var(--tx3);display:flex;
  align-items:center;gap:6px;min-width:0;flex-wrap:wrap}
.expline svg{width:13px;height:13px;flex:0 0 13px;stroke:currentColor;fill:none;
  stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.expline bdi{font-weight:600;color:var(--tx2);white-space:nowrap}

/* ── شبکه‌ی آمار ── */
.stats{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:12px}
.stat{display:flex;align-items:flex-start;gap:8px;padding:10px 11px;border-radius:9px;
  background:var(--s2);border:1px solid var(--line);min-width:0}
.stat svg{width:15px;height:15px;flex:0 0 15px;margin-top:3px;stroke:var(--acid);
  fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.stat .txt{min-width:0;display:flex;flex-direction:column;gap:1px}
.stat b{font-size:13px;font-weight:700;line-height:1.35;white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis}
html[lang="fa"] .stat b{font-size:12.5px}
.stat b.mono{font-family:'Vazirmatn','Vazir',Tahoma,sans-serif;letter-spacing:0}
html[lang="en"] .stat b.mono{font-family:'JetBrains Mono',monospace;letter-spacing:-.3px}
.stat .lb{font-size:10px;color:var(--tx3);line-height:1.5;white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis}

/* ── مصرف ── */
.usg{display:flex;align-items:center;gap:14px;margin-top:13px;min-width:0}
.usg .side{flex:1 1 auto;min-width:0}
.usg .bar{height:7px;border-radius:4px;background:var(--s3);overflow:hidden;direction:ltr}
.usg .bar>i{display:block;height:100%;border-radius:4px;
  background:linear-gradient(90deg,var(--brand),var(--acid));
  transition:width .6s var(--ease)}
.usg .bar.hot>i{background:linear-gradient(90deg,var(--amber),var(--red))}
.usg .nums{display:flex;justify-content:space-between;gap:8px;margin-top:8px;
  font-size:10.5px;color:var(--tx3);flex-wrap:wrap}
.usg .nums span{white-space:nowrap;min-width:0}
.usg .nums bdi{font-family:'JetBrains Mono',monospace;font-weight:600;color:var(--tx2);
  direction:ltr}
.donutbox{position:relative;width:98px;height:98px;flex:0 0 98px}
.donut{width:100%;height:100%;transform:rotate(-90deg)}
.donut .bgc{fill:none;stroke:var(--s3);stroke-width:10}
.donut .fgc{fill:none;stroke:url(#dg);stroke-width:10;stroke-linecap:round;
  transition:stroke-dashoffset .7s var(--ease)}
.donut .fgc.hot{stroke:var(--bad)}
.dg1{stop-color:var(--brand)} .dg2{stop-color:var(--acid)}
.dcenter{position:absolute;inset:0;display:grid;place-content:center;text-align:center;gap:1px}
.dcenter b{font-family:'Vazirmatn',Tahoma,sans-serif;font-size:19px;font-weight:700;
  letter-spacing:0;line-height:1.2;white-space:nowrap}
html[lang="en"] .dcenter b{font-family:'JetBrains Mono',monospace;letter-spacing:-.8px}
.dcenter .pctsign{display:inline-block;font-size:12px;opacity:.75;margin-inline-start:1px}
.dcenter span{font-size:9.5px;color:var(--tx3);margin-top:2px}

.rchip{display:flex;align-items:center;gap:7px;margin-top:10px;padding:7px 10px;
  border-radius:7px;background:rgba(92,225,230,.07);border:1px solid rgba(92,225,230,.22);
  font-size:10.5px;color:var(--cyan);line-height:1.8;min-width:0}
.rchip[hidden]{display:none}
.rchip svg{width:13px;height:13px;flex:0 0 13px;stroke:currentColor;fill:none;
  stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round}
.rchip span{min-width:0}

/* ── دکمه‌ها ── */
.acts{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:13px}
.btn{font:inherit;font-size:12px;font-weight:600;padding:10px 12px;border-radius:8px;
  cursor:pointer;border:1px solid var(--acid);background:var(--acid);color:#08090b;
  transition:.15s;display:flex;align-items:center;justify-content:center;gap:6px;
  min-width:0;line-height:1.4}
.btn:hover{filter:brightness(1.06)}
.btn.alt{background:var(--s2);border-color:var(--line2);color:var(--tx2);font-size:11.5px}
.btn.alt:hover{border-color:var(--acid);color:var(--acid);background:rgba(198,242,78,.09);
  filter:none}
.btn span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.btn svg{width:13px;height:13px;flex:0 0 13px;stroke:currentColor;fill:none;
  stroke-width:2;stroke-linecap:round;stroke-linejoin:round}

/* ── QR ── */
.qrbox{display:flex;flex-direction:column;align-items:center;gap:9px}
#qrMain{width:146px;height:146px;background:#fff;border-radius:10px;padding:6px;
  display:grid;place-items:center}
#qrMain svg,#qrMain img{width:100%;height:100%;display:block}
.hint{font-size:11px;color:var(--tx3);line-height:1.9;margin:0;text-align:center}
/* راهنمای محدودیت دستگاه: وقتی صفر نیست، رنگ هشدار (یعنی گیت فعال است) */
.dev-device-hint{text-align:start;line-height:1.85}
.dev-device-hint.on{color:var(--amber)}

/* ── تیتر بخش‌ها ── */
h2{font-size:11px;color:var(--tx3);font-weight:700;margin:16px 0 8px;
  display:flex;align-items:center;gap:9px;letter-spacing:0;
  font-family:'Vazirmatn',Tahoma,sans-serif}
html[lang="en"] h2{font-family:'JetBrains Mono',monospace;letter-spacing:.6px}
h2::after{content:"";flex:1;height:1px;background:var(--line)}

/* ── کانفیگ‌ها ── */
#cfgs{display:flex;flex-direction:column;gap:7px}
.cfg{display:flex;align-items:center;gap:8px;padding:9px 11px;border-radius:9px;
  background:var(--s1);border:1px solid var(--line);flex-wrap:wrap;min-width:0}
.cfg .nm{flex:1 1 auto;min-width:0;font-size:11.5px;font-weight:600;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.cfg .tchip{font-family:'JetBrains Mono',monospace;font-size:8.5px;padding:2px 6px;
  border-radius:4px;border:1px solid var(--line2);color:var(--tx3);direction:ltr;
  flex:0 0 auto}
.cfg .ico{width:30px;height:30px;flex:0 0 30px;border-radius:8px;display:grid;
  place-items:center;cursor:pointer;border:1px solid var(--line2);background:var(--s2);
  color:var(--tx3);transition:.15s;padding:0}
.cfg .ico:hover{border-color:var(--acid);color:var(--acid);background:rgba(198,242,78,.1)}
.cfg .ico svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:2;
  stroke-linecap:round;stroke-linejoin:round}
.cfgqr{width:100%;display:flex;justify-content:center;padding-top:9px}
.cfgqr[hidden]{display:none}
.cfgqr svg{width:128px;height:128px;background:#fff;border-radius:8px;padding:5px}

/* ── برنامه‌ها ── */
.tabs{display:flex;gap:5px;margin-bottom:9px;flex-wrap:wrap}
.tab{font:inherit;font-size:11px;font-weight:600;padding:6px 11px;border-radius:7px;
  border:1px solid var(--line2);background:var(--s1);color:var(--tx3);cursor:pointer;
  transition:.14s;white-space:nowrap}
.tab[aria-selected="true"]{background:rgba(198,242,78,.12);
  border-color:rgba(198,242,78,.3);color:var(--acid)}
.apps{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.app{border:1px solid var(--line);border-radius:10px;background:var(--s1);padding:10px;
  display:flex;flex-direction:column;gap:7px;min-width:0}
.app .head{display:flex;align-items:center;gap:7px;min-width:0}
.app .mark{width:25px;height:25px;flex:0 0 25px;border-radius:7px;display:grid;
  place-items:center;font-size:11.5px;font-weight:700;color:#fff}
.app .logo{width:25px;height:25px;flex:0 0 25px;border-radius:7px;object-fit:cover}
.app .meta{min-width:0}
.app .nm{font-size:11px;font-weight:600;line-height:1.3;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.app .rp{font-family:'JetBrains Mono',monospace;font-size:8px;color:var(--tx3);
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.app .add{font:inherit;font-size:10px;font-weight:600;padding:6px 7px;border-radius:6px;
  border:1px solid var(--line2);background:var(--s2);color:var(--tx2);cursor:pointer;
  width:100%;transition:.14s;line-height:1.5}
.app .add:hover{border-color:var(--acid);color:var(--acid)}
.app .dl{display:flex;flex-direction:column;gap:2px}
.app .dl a{display:flex;justify-content:space-between;gap:6px;font-size:9.5px;
  color:var(--tx3);text-decoration:none;padding:3px 0;border-bottom:1px dotted var(--line);
  min-width:0}
.app .dl a:hover{color:var(--acid)}
.app .dl .sz{font-family:'JetBrains Mono',monospace;font-size:8.5px;opacity:.85;
  direction:ltr;flex:0 0 auto}

/* ── بنر / پاورقی / توست ── */
.banner{display:flex;gap:8px;align-items:flex-start;padding:10px 12px;border-radius:9px;
  background:rgba(255,107,107,.08);border:1px solid rgba(255,107,107,.26);
  color:#ffb3b3;font-size:11.5px;line-height:1.85;margin-bottom:11px;min-width:0}
.banner svg{width:15px;height:15px;flex:0 0 15px;stroke:var(--bad);fill:none;
  stroke-width:1.9;stroke-linecap:round;margin-top:3px}
.banner span{min-width:0}
footer{text-align:center;font-size:10px;color:var(--tx3);margin-top:20px;line-height:2;
  font-family:'JetBrains Mono',monospace;padding:0 6px}
.toast{position:fixed;bottom:14px;inset-inline:14px;margin:0 auto;max-width:420px;
  font-size:12px;font-weight:600;background:var(--acid);color:#08090b;padding:10px 14px;
  border-radius:9px;opacity:0;transform:translateY(70px);transition:.26s var(--ease);
  z-index:80;pointer-events:none;text-align:center;
  box-shadow:0 14px 34px -12px rgba(198,242,78,.5)}
.toast.on{transform:none;opacity:1}

@media(max-width:400px){
  body{padding:12px 11px 36px}
  .stats{grid-template-columns:1fr}
  .apps{grid-template-columns:1fr}
  .who h1{max-width:52%}
  .donutbox{width:88px;height:88px;flex-basis:88px}
}
@media(prefers-reduced-motion:reduce){
  *,*::before,*::after{animation-duration:.001ms!important;transition-duration:.001ms!important}
}
</style>
</head>
<body>
<div class="wrap">

  <div class="top">
    <img class="logo" src="__LOGO__" alt="">
    <div class="brand"><b id="bTitle">IranX</b><span>SUBSCRIPTION</span></div>
    <div class="tools">
      <span class="tag" id="trTag" hidden></span>
      <button class="chip" id="themeBtn" type="button"></button>
    </div>
  </div>

  <div id="banner"></div>

  <div class="card">
    <div class="who">
      <span class="dot" id="dot"></span>
      <h1 id="uname">&mdash;</h1>
      <span class="st" id="schip">&mdash;</span>
    </div>
    <p class="expline">
      <svg viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="16" rx="2.5"/>
        <path d="M8 3v4M16 3v4M3 10h18"/></svg>
      <span id="expLine">&mdash;</span>
    </p>

    <div class="stats">
      <div class="stat">
        <svg viewBox="0 0 24 24"><path d="M12 3c-4 4.5-6.5 7.8-6.5 11a6.5 6.5 0 0013 0c0-3.2-2.5-6.5-6.5-11z"/></svg>
        <span class="txt"><b id="sRemain">&mdash;</b><span class="lb" id="lRemain"></span></span>
      </div>
      <div class="stat">
        <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/></svg>
        <span class="txt"><b id="sDays">&mdash;</b><span class="lb" id="lDays"></span></span>
      </div>
      <div class="stat">
        <svg viewBox="0 0 24 24"><rect x="6.5" y="2.2" width="11" height="19.6" rx="2.8"/>
          <path d="M10.6 18.9h2.8"/></svg>
        <span class="txt"><b class="mono" id="sDev">&mdash;</b><span class="lb" id="lDev"></span></span>
      </div>
      <div class="stat">
        <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9.2"/>
          <path d="M2.8 12h18.4M12 2.8c2.6 2.6 3.9 5.8 3.9 9.2S14.6 18.6 12 21.2C9.4 18.6 8.1 15.4 8.1 12S9.4 5.4 12 2.8z"/></svg>
        <span class="txt"><b class="mono" id="sIp">&mdash;</b><span class="lb" id="lIp"></span></span>
      </div>
    </div>

    <div class="usg">
      <div class="side">
        <div class="bar" id="bar"><i style="width:0%"></i></div>
        <div class="nums"><span id="mUsed">&mdash;</span><span id="mQuota">&mdash;</span></div>
        <div class="rchip" id="resetChip" hidden>
          <svg viewBox="0 0 24 24"><path d="M20 11a8 8 0 10.4 4M20 4v7h-7"/></svg>
          <span id="resetTxt"></span>
        </div>
      </div>
      <div class="donutbox">
        <svg class="donut" viewBox="0 0 120 120" aria-hidden="true">
          <defs><linearGradient id="dg" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" class="dg1"/><stop offset="1" class="dg2"/></linearGradient></defs>
          <circle class="bgc" cx="60" cy="60" r="52"/>
          <circle class="fgc" id="dfg" cx="60" cy="60" r="52"
                  stroke-dasharray="326.726" stroke-dashoffset="326.726"/>
        </svg>
        <div class="dcenter"><b id="dPct">0</b><span id="dLbl"></span></div>
      </div>
    </div>

    <div class="acts">
      <button class="btn" id="copySub"></button>
      <button class="btn alt" id="copyAll"></button>
      <button class="btn alt" id="impHid"></button>
      <button class="btn alt" id="impV2"></button>
    </div>
  </div>

  <div class="card qrbox">
    <div id="qrMain"></div>
    <p class="hint" id="qrHint"></p>
  </div>

  <h2 id="hCfg"></h2>
  <div id="cfgs"></div>

  <h2 id="hApps"></h2>
  <div class="tabs" id="tabs" role="tablist"></div>
  <div class="apps" id="apps"></div>

  <footer><span id="fNote"></span><br><span id="upd"></span></footer>
</div>
<div class="toast" id="toast"></div>
<script>
const D = __DATA__, QRS = __QRS__;
const $ = (s)=>document.querySelector(s);
const esc = (s)=>String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

/* ── i18n ── */
const T = {
  en:{brand:"IranX · My subscription", remainVol:"Remaining data", remainTime:"Remaining time",
    devices:"Devices", ipAddr:"Allowed IPs", used:"Used", total:"Total", usage:"used",
    copySub:"Copy subscription link", copyAll:"Copy all configs", addTo:"Add to",
    configs:"Configs", downloads:"Download apps", noConfigs:"No active config.",
    showQr:"Show QR", copyCfg:"Copy config",
    scanHint:"Scan with your client app to add the subscription",
    footer:"This is your personal subscription link — do not share it",
    updEvery:(h)=>"Updates every "+h+"h", expires:"Expires", noExpiry:"No expiry",
    unlimited:"Unlimited", support:"please contact support",
    statusActive:"Active", statusExpired:"Subscription expired", statusQuota:"Out of data",
    statusDisabled:"Subscription disabled", statusInactive:"Subscription inactive",
    resetEveryN:(n)=>"Usage resets every "+n+" days", nextReset:"Next reset",
    days:"days", hours:"hours", left:"left", cfgCount:(n)=>n+" active configs",
    copiedSub:"Subscription link copied", copiedAll:"All configs copied", copiedCfg:"Config copied",
    noQr:"QR unavailable",
    importHint:"If the app did not open: the link is copied — use “Add from clipboard” inside the app",
    allVersions:"All versions", light:"Light", dark:"Gray", subName:"Subscription"}
};
let LANG="en", THEME="gray", current=(D.osTabs&&D.osTabs[0]?D.osTabs[0][0]:"android");
try{ THEME=localStorage.getItem("iranx_theme")||THEME; }catch(e){}
LANG="en";
if(THEME!=="light") THEME="gray";
const t = (k)=>T[LANG][k];
/* ارقام لاتین: صفرِ فارسی و ارقام عربی-هندی روی برخی فونت‌ها شبیه نقطه دیده
   می‌شوند و تراز هم به‌هم می‌ریزد. متن فارسی می‌ماند، فقط رقم‌ها لاتین. */
const num = (n)=>Number(n).toLocaleString("en-US");

const ICON_SUN='<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="4.2"/><path d="M12 2.5v2.6M12 18.9v2.6M2.5 12h2.6M18.9 12h2.6M5 5l1.8 1.8M17.2 17.2L19 19M19 5l-1.8 1.8M6.8 17.2L5 19"/></svg>';
const ICON_MOON='<svg viewBox="0 0 24 24"><path d="M20.5 14.5A8.5 8.5 0 1110 3.7a7 7 0 0010.5 10.8z"/></svg>';
const ICON_WARN='<svg viewBox="0 0 24 24"><path d="M12 3.5L2.5 20h19L12 3.5z"/><path d="M12 10v4.5M12 17.6v.2"/></svg>';
const ICON_QR='<svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><path d="M14 14h3v3h-3zM20 14v3M14 20h6"/></svg>';
const ICON_COPY='<svg viewBox="0 0 24 24"><rect x="9" y="9" width="11" height="11" rx="2.5"/><path d="M15 5.5A2.5 2.5 0 0012.5 3H6.5A2.5 2.5 0 004 5.5v6A2.5 2.5 0 006.5 14"/></svg>';

let tmr;
function toast(msg){ const el=$("#toast"); el.innerHTML=msg; el.classList.add("on");
  clearTimeout(tmr); tmr=setTimeout(()=>el.classList.remove("on"),2600); }
async function copy(text,msg){
  try{ await navigator.clipboard.writeText(text); }
  catch(e){ const ta=document.createElement("textarea"); ta.value=text;
    ta.style.position="fixed"; ta.style.opacity="0"; document.body.appendChild(ta);
    ta.select(); try{document.execCommand("copy");}catch(_){} ta.remove(); }
  if(msg) toast(msg);
}

function deepLink(kind){
  const n = encodeURIComponent(D.name || "IranX");
  let s = D.subLink;
  if(kind==="clash")   s = D.subLinkClash   || (s + "?format=clash");
  if(kind==="singbox") s = D.subLinkSingbox || (s + "?format=singbox");
  const e = encodeURIComponent(s);
  if(kind==="v2rayng")      return "v2rayng://install-sub?url="+e+"&name="+n;
  if(kind==="hiddify")      return "hiddify://import/"+s;
  if(kind==="singbox")      return "sing-box://import-remote-profile?url="+e+"#"+n;
  if(kind==="streisand")    return "streisand://import/"+s;
  if(kind==="shadowrocket") return "sub://"+btoa(s);
  if(kind==="v2box")        return "v2box://install-sub?url="+e+"&name="+n;
  if(kind==="clash")        return "clash://install-config?url="+e;
  return "";
}
async function addSub(kind){
  let s = D.subLink;
  if(kind==="clash")   s = D.subLinkClash   || (s + "?format=clash");
  if(kind==="singbox") s = D.subLinkSingbox || (s + "?format=singbox");
  await copy(s, "");
  const url = deepLink(kind);
  if(!url){ toast(t("copiedSub")); return; }
  const a = document.createElement("a");
  a.href = url; a.rel = "noopener"; a.style.display = "none";
  document.body.appendChild(a);
  try{ a.click(); }catch(e){ try{ location.href = url; }catch(_){} }
  a.remove();
  setTimeout(()=>toast(t("importHint")), 1200);
}

function statusInfo(){
  if(D.active) return {cls:"ok", key:"statusActive"};
  const m = {expired:["bad","statusExpired"], quota:["warn","statusQuota"],
             disabled:["bad","statusDisabled"]};
  const f = m[D.status] || ["bad","statusInactive"];
  return {cls:f[0], key:f[1]};
}
function fmtDate(ts){
  try{
    return new Intl.DateTimeFormat(LANG==="fa"?"fa-IR-u-nu-latn":"en-GB",
      {year:"numeric",month:"2-digit",day:"2-digit"}).format(new Date(ts*1000));
  }catch(e){ return new Date(ts*1000).toLocaleDateString(); }
}
const CIRC = 2*Math.PI*52;
function paintUsage(){
  const p = D.quota ? D.pct : 0;
  $("#dfg").style.strokeDashoffset = (CIRC*(1-p/100)).toFixed(1);
  $("#dfg").classList.toggle("hot", !!(D.quota && D.pct>=85));
  $("#dPct").innerHTML = D.quota
    ? `<bdi dir="ltr">${num(D.pct)}%</bdi>`
    : "∞";
  $("#dLbl").textContent = t("usage");
  $("#bar").firstElementChild.style.width = (D.quota ? p : 0) + "%";
  $("#bar").classList.toggle("hot", D.pct >= 85 && !!D.quota);
}

function paintApps(){
  $("#tabs").innerHTML = D.osTabs.map(([id,faName,en])=>
    `<button class="tab" role="tab" data-os="${esc(id)}" aria-selected="${id===current}">${esc(LANG==="fa"?faName:en)}</button>`).join("");
  $("#apps").innerHTML = D.clients.filter(a=>a.os===current).map(a=>{
    const mark = `<span class="mark" style="background:${esc(a.accent)}">${esc(a.name[0])}</span>`;
    const logo = a.logo
      ? `<img class="logo" src="${esc(a.logo)}" alt="" loading="lazy" onerror="this.replaceWith(Object.assign(document.createElement('span'),{className:'mark',style:'background:${esc(a.accent)}',textContent:'${esc(a.name[0])}'}))">`
      : mark;
    const add = a.scheme
      ? `<button class="add" data-add="${esc(a.scheme)}">${esc(t("addTo"))} ${esc(a.name)}</button>` : "";
    const dl = a.builds.map(b=>{
      const label = b.label==="@ALL@" ? t("allVersions") : b.label;
      return `<a href="${esc(b.url)}" target="_blank" rel="noopener"><span>${esc(label)}</span><span class="sz">${esc(b.note||"")}</span></a>`;
    }).join("");
    return `<div class="app"><div class="head">${logo}<div class="meta">`+
           `<div class="nm">${esc(a.name)}</div><div class="rp">${esc(a.repo)}</div>`+
           `</div></div>${add}<div class="dl">${dl}</div></div>`;
  }).join("");
}

function paintConfigs(){
  $("#cfgs").innerHTML = D.configs.length ? D.configs.map((c,i)=>`
  <div class="cfg">
    ${(()=>{const f=flagFromLabel(c.label);return flagImg(f.cc);})()}
    <span class="nm">${esc(flagFromLabel(c.label).text)}</span>
    <span class="tchip">${esc((c.transport||"").toUpperCase())}</span>
    <button class="ico" data-qr="${i}" title="${esc(t("showQr"))}" aria-label="${esc(t("showQr"))}">${ICON_QR}</button>
    <button class="ico" data-copy="${i}" title="${esc(t("copyCfg"))}" aria-label="${esc(t("copyCfg"))}">${ICON_COPY}</button>
    <div class="cfgqr" data-box="${i}" hidden></div>
  </div>`).join("") : `<div class="card"><p class="hint" style="margin:0">${esc(t("noConfigs"))}</p></div>`;
}

/* نام‌های کانفیگ با کد کشور شروع می‌شوند («IR ایرانسل») — پرچم SVG جایش می‌نشیند */
function flagFromLabel(label){
  const m=/^([A-Z]{2})\s+(.+)$/.exec(String(label||'').trim());
  if(!m) return {cc:'', text:String(label||'')};
  return {cc:m[1], text:m[2]};
}
function flagImg(cc){
  if(!cc) return '';
  return `<img class="flag" src="/flag/${cc}.svg" alt="${cc}" title="${cc}" width="19" height="14" loading="lazy" onerror="this.style.visibility='hidden'">`;
}

function render(){
  const h = document.documentElement;
  h.lang = LANG; h.dir = LANG==="fa" ? "rtl" : "ltr"; h.dataset.theme = THEME;
  $("#bTitle").textContent = t("brand");
  $("#themeBtn").innerHTML = (THEME==="light" ? ICON_MOON : ICON_SUN) +
    "<span>"+(THEME==="light" ? t("dark") : t("light"))+"</span>";
  const tr = D.transport === "BOTH" ? "WS + XHTTP" : D.transport;
  $("#trTag").textContent = tr || "";
  $("#trTag").hidden = !tr;
  $("#uname").textContent = D.name || t("subName");
  $("#lRemain").textContent = t("remainVol");
  $("#lDays").textContent = t("remainTime");
  $("#lDev").textContent = t("devices");
  $("#lIp").textContent = t("ipAddr");

  $("#sRemain").innerHTML = D.quota ? `<bdi>${esc(D.remainText)}</bdi>` : esc(t("unlimited"));
  $("#sDays").innerHTML = D.expireAt
    ? (D.remainDays > 0 ? `<bdi>${num(D.remainDays)}</bdi> ${esc(t("days"))}`
                        : `<bdi>${num(D.remainHours)}</bdi> ${esc(t("hours"))}`)
    : esc(t("unlimited"));
  $("#sDev").innerHTML = D.deviceLimit
    ? `<bdi>${num(D.devicesNow)} / ${num(D.deviceLimit)}</bdi>` : esc(t("unlimited"));
  $("#sIp").innerHTML = D.ipLimit
    ? `<bdi>${num(D.ipsNow)} / ${num(D.ipLimit)}</bdi>` : esc(t("unlimited"));

  $("#mUsed").innerHTML = esc(t("used"))+": <bdi>"+esc(D.usedText)+"</bdi>";
  $("#mQuota").innerHTML = esc(t("total"))+": <bdi>"+esc(D.quotaText)+"</bdi>";
  paintUsage();

  $("#expLine").innerHTML = D.expireAt
    ? esc(t("expires"))+": <bdi>"+esc(fmtDate(D.expireAt))+"</bdi>" +
      (D.active ? " · <bdi>"+num(D.remainDays)+"</bdi> "+esc(t("days"))+" "+esc(t("left")) : "")
    : esc(t("noExpiry"));

  const st = statusInfo();
  $("#schip").className = "st "+st.cls;
  $("#schip").textContent = t(st.key);
  $("#dot").classList.toggle("off", !D.active);
  $("#banner").innerHTML = D.active ? "" :
    `<div class="banner">${ICON_WARN}<span>${esc(t(st.key))} — ${esc(t("support"))}.</span></div>`;

  if(D.resetDays > 0){
    $("#resetChip").hidden = false;
    $("#resetTxt").textContent = t("resetEveryN")(num(D.resetDays)) +
      (D.nextResetAt ? " · "+t("nextReset")+": "+fmtDate(D.nextResetAt) : "");
  } else { $("#resetChip").hidden = true; }

  $("#copySub").textContent = t("copySub");
  $("#copyAll").textContent = t("copyAll");
  $("#impHid").textContent = t("addTo")+" Hiddify";
  $("#impV2").textContent  = t("addTo")+" v2rayNG";
  $("#qrHint").textContent = t("scanHint");
  $("#hCfg").textContent = t("configs");
  $("#hApps").textContent = t("downloads");
  $("#fNote").textContent = t("footer");
  $("#upd").textContent = t("updEvery")(num(D.updateInterval)) + " · " + t("cfgCount")(num(D.configs.length));
  $("#qrMain").innerHTML = QRS[0] || `<p class="hint">${esc(t("noQr"))}</p>`;
  paintConfigs();
  paintApps();
}

$("#copySub").onclick = ()=>copy(D.subLink, t("copiedSub"));
$("#copyAll").onclick = ()=>copy(D.allConfigs, t("copiedAll"));
$("#impHid").onclick = ()=>addSub("hiddify");
$("#impV2").onclick = ()=>addSub("v2rayng");
$("#themeBtn").onclick = ()=>{ THEME = THEME==="light" ? "gray" : "light";
  try{ localStorage.setItem("iranx_theme", THEME); }catch(e){} render(); };
$("#cfgs").addEventListener("click",(e)=>{
  const b=e.target.closest("button"); if(!b) return;
  if(b.dataset.copy!==undefined) copy(D.configs[+b.dataset.copy].uri, t("copiedCfg"));
  if(b.dataset.qr!==undefined){
    const i=+b.dataset.qr, box=$(`[data-box="${i}"]`);
    if(!box.innerHTML) box.innerHTML = QRS[i+1] || `<p class="hint">${esc(t("noQr"))}</p>`;
    box.hidden = !box.hidden;
  }
});
$("#tabs").addEventListener("click",(e)=>{
  const b=e.target.closest("button[data-os]"); if(!b) return;
  current=b.dataset.os; paintApps();
});
$("#apps").addEventListener("click",(e)=>{
  const b=e.target.closest("button[data-add]"); if(!b) return;
  addSub(b.dataset.add);
});
render();
</script>
</body>
</html>
"""


# ─────────────────────────── country flags (SVG) ───────────────────────────
# Emoji flags are still broken on a lot of Android builds and on Windows, so the
# panel ships real vector flags and serves them from /flag/<CC>.svg. The payload
# below is one gzipped JSON blob ({code: "<svg …/>"}) decoded once at import —
# about 130 KB in the file instead of ~320 KB of raw markup.
_FLAGS_B64 = (
    'H4sIAJps9WoC/+y9244syZUl9isOzss0IA/a/TIYDTDN6VYNwBIGGqEehH5JBouVlCLJViUn2Tr6edlay8w8IjLyHnmqiiK6ecoyPMLdfJvZvu+9/t9f/Zd/'
    '+tV/+NV/vH/4Yfm3u8Of7v/nf/nV7V/+8q//4de//utf/7r7q9/9+ccffu2MMb9uX/mXXy0Pf/z+r//4539rXzOLWeLi/+VX/+k//uvNX26X37fPvm0f3sYH'
    '/4358i+/+nW/8Ic/Hg7t2r/7L8a0G/Sv2fY1d/Fr//zPv/mn42+69k07volZ/Kdf/U+/+l9/+4FZ1yXNWY+nOhtS+cftqea2PqQn5vfPp18LF7/2n//J/saV'
    '02+689f45/9tvMbZDI1ZEonwmtc7e/Jv/slal06ebMxDu9035vE0//CHPxx/Mz39TWNciuH4y/7ky+Od/pd//MDSJLN4gzfaH/74r/8Nj/8jHnfzaJc9eEz2'
    'u0HP8fXzH/7u9Ie+bbzY5v1g45f2v7Yc3+Ae3+FdHt3phwXjFb9uv/0fPx7+/b+7+YfnJrKRyjqb6kZCfPduvt6dWb35rV50uf/Lj3/+v77fVkJ/r3/94+/5'
    '1PSqmzya5+/+4eTWvynWuH96fPdweneQB+/zLamUXjE9a95wh6dmoXf89Q9Hx+K/fmAL2bJY++hQnO1zWx6sPTm3/VLcxXbx27SL7UVwn6MXaCfgn9NvHr+A'
    'P9n///0jDLUs8dHUjYmu+uPZl4e2df+Pbe5Hq/T9/ncnzLO9TvnWt3eJJ5P8b7+98iR/v7fB7x9N8suLHKc8tDme88X//L9/Al/cY/99f5EvvjTNdk9+2W1f'
    'HlP9zTeXp+pd+/+3TXRjrO7BS1aM6fz4/e/Ptqr1S7pND/k2P6TbNbfBmh7W/E37J93mY27ENzma8T/998szzrFt//cS9+b3Ntp6TNx2u4f4FHFvfvf7E23A'
    'RX7fxcvf/127kcvj++1bi3N+v1qzy6vZGbs6swur3fm0urwrq9+FsOSdL6vbmcYP8s62z3xc+lXfPmu/bT91bW3bWbc7V3lxwcUVP13w0xU/bZ8FjxtXjMQ0'
    'fzjhC+acHn/685++f8wozM5NAep9Wpyte7PGXbBL2CW31l3mxLxGcZcyGFr7oF33WSNeAqPydcWv8EFax6XUbpfqYvjBil+t44YJm+IvP9786f4Pf/7xDtLk'
    '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'
)


def _load_flags() -> dict:
    try:
        raw = gzip.decompress(base64.b64decode(_FLAGS_B64)).decode("utf-8")
        return json.loads(raw)
    except Exception:
        return {}


FLAG_SVGS = _load_flags()


@app.get("/flag/{code}.svg")
def flag_svg(code: str):
    """Serve one embedded vector flag; long-cached because it never changes."""
    cc = re.sub(r"[^A-Za-z]", "", code or "")[:2].upper()
    svg = FLAG_SVGS.get(cc)
    if not svg:
        raise HTTPException(404, "unknown flag")
    return Response(svg, media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=31536000, immutable"})


@app.get("/sub/{token}")
async def subscription(token: str, request: Request):
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE sub_token=?", (token,)).fetchone()
        ips = c.execute("SELECT * FROM clean_ips WHERE enabled=1 ORDER BY id").fetchall()
    if not row:
        raise HTTPException(404, "not found")

    row = maybe_auto_reset(row)

    # ── HWID device registration gate ──
    # The device cap is based on a stable client-reported HWID, never an IP/UA pair
    # or a client-name allowlist (both are trivially spoofable). Human browser pages
    # remain viewable, but limited accounts do not receive subscription payloads
    # unless the client supplies a stable HWID and has an available registered slot.
    _ua = (request.headers.get("user-agent") or "")
    _qp = request.query_params
    _html_wanted = ("text/html" in (request.headers.get("accept") or "")
                    and "mozilla" in _ua.lower())
    _force_page = _qp.get("page") in ("1", "true")
    if needs_device_gate(row) and device_gate_on() and not _html_wanted and not _force_page:
        _hwid = hwid_of(request.headers)
        if not _hwid:
            audit("sub-hwid-missing", row["name"], _ua[:80] or "no user-agent")
            return device_gate_response(row)
        _ip = request.client.host if request.client else ""
        _ok, _count = register_hwid_device(row["id"], _hwid,
                                           int(row["device_limit"] or 0), _ip, _ua,
                                           headers=request.headers)
        if not _ok:
            audit("sub-hwid-limit", row["name"], "registered=%s limit=%s" %
                  (_count, row["device_limit"]))
            return device_gate_response(row)

    d = base_domain(request)
    lines = build_info_lines(row, d)
    if user_status(row)[0]:
        lines += [c["uri"] for c in build_configs(row, d, ips)]

    # browser? serve the subscription page, clients keep the base64 payload
    ua = (request.headers.get("user-agent") or "").lower()
    accept = request.headers.get("accept") or ""
    force_page = request.query_params.get("page") in ("1", "true")
    force_raw = request.query_params.get("raw") in ("1", "true")

    # ── container formats: Clash.Meta and sing-box ──
    # An explicit ?format= wins; otherwise the User-Agent decides, so a client
    # that was given the plain sub URL still gets a file it can parse.
    fmt = (request.query_params.get("format") or "").strip().lower()
    if not fmt and not force_raw and not force_page:
        if any(k in ua for k in ("clash", "mihomo", "stash", "flclash", "verge")):
            fmt = "clash"
        elif any(k in ua for k in ("sing-box", "singbox", "hiddify", "karing", "happ")):
            fmt = "singbox"
    if not force_raw:
        if fmt in ("clash", "meta", "yaml", "yml"):
            return sub_response_clash(row, d, ips, request)
        if fmt in ("singbox", "sing-box", "json"):
            return sub_response_singbox(row, d, ips, request)

    if not force_raw and (force_page or ("text/html" in accept and "mozilla" in ua)):
        ok, reason = user_status(row)
        return HTMLResponse(render_sub_page(
            name=row["name"],
            sub_link=("https" + "://") + d + "/sub/" + row["sub_token"],
            configs=build_configs(row, d, ips) if ok else [],
            used_bytes=row["used_bytes"],
            quota_bytes=row["quota_bytes"],
            expire_at=row["expire_at"],
            active=ok,
            status="" if ok else reason,
            transport=row["transport"],
            device_limit=row["device_limit"],
            devices_now=active_devices(row["id"]),
            ip_limit=row["ip_limit"],
            ips_now=active_ips(row["id"]),
            panel_url=("https" + "://") + origin_domain(request) + "/",
            reset_days=row["reset_days"],
            last_reset=row["last_reset"],
        ))

    body = base64.b64encode("\n".join(lines).encode()).decode()
    headers = _sub_headers(row, request)
    headers["content-type"] = "text/plain; charset=utf-8"
    return PlainTextResponse(body, headers=headers)


# ─────────��──────────────────── PAGES ──────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(session: Optional[str] = Cookie(default=None)):
    if not password_is_set():
        return RedirectResponse("/setup")
    return RedirectResponse("/panel" if valid_session(session) else "/login")


@app.get("/setup", response_class=HTMLResponse)
async def setup_page():
    if password_is_set():
        return RedirectResponse("/login")
    return HTMLResponse(AUTH_HTML.replace("{{TITLE}}", PANEL_TITLE).replace("{{MODE}}", "setup"),
                        headers={"cache-control": "no-store"})


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    if not password_is_set():
        return RedirectResponse("/setup")
    return HTMLResponse(AUTH_HTML.replace("{{TITLE}}", PANEL_TITLE).replace("{{MODE}}", "login"),
                        headers={"cache-control": "no-store"})


@app.get("/panel", response_class=HTMLResponse)
async def panel_page(session: Optional[str] = Cookie(default=None)):
    if not password_is_set():
        return RedirectResponse("/setup")
    if not valid_session(session):
        return RedirectResponse("/login")
    return HTMLResponse(PANEL_HTML.replace("{{TITLE}}", PANEL_TITLE),
                        headers={"cache-control": "no-store"})


@app.get("/healthz")
async def healthz():
    return {"ok": True}


# ════════════════════════════ FRONTEND ════════════════════════════

THEME_CSS = r"""
/* ══════════════════════════════════════════════════════════════════════
   IRANX PANEL — DESIGN SYSTEM v3  "NEON TERMINAL"
   رنگ‌های برند از لوگو: سبز #22EF9D · قرمز #E8112D · طلایی #E5B80B
   این فایل همه‌ی کلاس‌های قدیمی (card, stat, inp, btn, g4, urow …) را
   با ظاهر جدید پیاده می‌کند، پس هیچ‌کدام از توابع JS قدیمی نمی‌شکند.
   ══════════════════════════════════════════════════════════════════════ */

:root,[data-theme="gray"]{
  --bg:#08090b; --s1:#0d0f12; --s2:#12151a; --s3:#171b21;
  --line:#1e232b; --line2:#2a313c;
  --tx:#e6e9ee; --tx2:#98a2b1; --tx3:#6b7583;
  --acid:#c6f24e; --a1:#5ce1e6; --a2:#c6f24e;
  --brand:#22ef9d; --brand2:#e8112d; --gold:#e5b80b;
  --ok:#c6f24e; --warn:#ffcc66; --bad:#ff6b6b; --info:#5ce1e6;
  --cyan:#5ce1e6; --red:#ff6b6b; --amber:#ffcc66;
  --accent:#c6f24e;
  --ease:cubic-bezier(.22,.68,.32,1);
  --nav-w:290px; --bar-h:58px;
}
[data-theme="light"]{
  --bg:#f4f6f8; --s1:#ffffff; --s2:#f7f9fc; --s3:#eef1f6;
  --line:#e2e7ee; --line2:#d3dae3;
  --tx:#141a22; --tx2:#5a6472; --tx3:#8b95a3;
  --acid:#7aa800; --a1:#1478b8; --a2:#5f8c00; --brand:#0c9470; --brand2:#d81f3a; --gold:#a67c00;
  --ok:#5f8c00; --warn:#a87000; --bad:#cf3346; --info:#1478b8;
  --cyan:#0d8f96; --red:#cf3346; --amber:#a87000;
  --accent:#7aa800;
}


*{box-sizing:border-box}
html,body{overflow-x:hidden;max-width:100%}
html,body{margin:0;padding:0}
body{
  background:var(--bg); color:var(--tx); min-height:100vh;
  font-family:'Inter','Vazirmatn',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,system-ui,sans-serif;
  font-size:14px; line-height:1.55;
  -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale;
  background-image:radial-gradient(circle at 50% -20%,rgba(34,239,157,.07),transparent 58%);
}
html[lang="fa"] body{font-family:'Vazirmatn','Vazir','IRANSansX',Tahoma,'Segoe UI',system-ui,sans-serif;
  font-size:14.5px; line-height:1.8}
html[lang="fa"] b,html[lang="fa"] strong{font-weight:600}
.mono,code,.num{font-family:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-variant-numeric:tabular-nums;font-feature-settings:"tnum" 1}
.em{font-family:'Apple Color Emoji','Segoe UI Emoji','Noto Color Emoji','Twemoji Mozilla',sans-serif;
  font-style:normal;line-height:1}
:focus-visible{outline:2px solid var(--acid);outline-offset:2px;border-radius:4px}
::selection{background:rgba(198,242,78,.28)}
*::-webkit-scrollbar{width:8px;height:8px}
*::-webkit-scrollbar-track{background:transparent}
*::-webkit-scrollbar-thumb{background:var(--line2);border-radius:8px}

/* ───────── utilities (کلاس‌های قدیمی مارک‌آپ) ───────── */
.hidden{display:none !important}
.flex{display:flex}
.flex-1{flex:1;min-width:0}
.flex-wrap{flex-wrap:wrap}
.items-center{align-items:center}
.gap-2{gap:8px}
.gap-3{gap:12px}
.ms-auto{margin-inline-start:auto}
.mt-1{margin-top:4px}
.mt-2{margin-top:8px}
.mt-3{margin-top:12px}
.mt-4{margin-top:16px}
.mb-3{margin-bottom:12px}
.pt-3{padding-top:12px}
.p-4{padding:15px}
.w-full{width:100%}
.space-y-2>*+*{margin-top:8px}
.space-y-3>*+*{margin-top:12px}
.truncate{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.break-all{word-break:break-all}
.dim{color:var(--tx3)}
.text-xs{font-size:11px;line-height:1.75}
.text-sm{font-size:12.5px}
.text-base{font-size:13.5px}
.font-bold{font-weight:600}
.font-extrabold{font-weight:700}
.green{color:var(--ok)} .red{color:var(--bad)} .blue{color:var(--info)} .teal{color:var(--cyan)}
.g2{display:grid;grid-template-columns:repeat(2,1fr);gap:11px}
.g3{display:grid;grid-template-columns:repeat(3,1fr);gap:11px}
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:11px}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:8px}

/* ───────── shell: topbar ───────── */
.appbar{
  position:sticky; top:0; z-index:40; display:flex; align-items:center; gap:11px;
  height:var(--bar-h); padding:0 15px;
  background:color-mix(in srgb,var(--bg) 88%,transparent);
  backdrop-filter:blur(16px); border-bottom:1px solid var(--line);
}
.appbar .ttl{display:flex;flex-direction:column;gap:1px;min-width:0}
.appbar .ttl h1{
  margin:0; font-size:13.5px; font-weight:700; letter-spacing:-.2px;
  display:flex; align-items:center; gap:8px; white-space:nowrap;
}
.appbar .ttl h1::before{
  content:""; width:4px; height:16px; border-radius:2px; display:none;
}
.crumb{font-size:11px; color:var(--tx3); white-space:nowrap; line-height:1.2}
.path-pill{
  font-family:'JetBrains Mono',monospace; font-size:10px; color:var(--tx3);
  padding:3px 8px; border:1px solid var(--line2); border-radius:6px; white-space:nowrap;
  direction:ltr;
}
.logo{width:30px;height:30px;flex:0 0 30px;border-radius:8px;display:block;object-fit:cover;
  background:#000;box-shadow:0 0 0 1px var(--line2),0 6px 16px -8px rgba(34,239,157,.55)}
.logo.lg{width:40px;height:40px;flex:0 0 40px;border-radius:11px}

/* ───────── shell: drawer nav ───────── */
#app{min-height:100vh;display:flex;flex-direction:column;width:100%}
.content{padding:18px 16px 48px;width:100%;max-width:1440px;margin:0 auto;flex:1}

#nav{
  position:fixed; top:0; bottom:0; inset-inline-start:0; width:var(--nav-w); max-width:86vw;
  z-index:50; display:flex; flex-direction:column;
  background:linear-gradient(180deg,#0b0d10,#090a0d 60%,#08090b);
  border-inline-end:1px solid var(--line2);
  box-shadow:0 0 60px rgba(0,0,0,.65);
  transition:transform .32s var(--ease); will-change:transform;
}
[data-theme="light"] #nav{background:linear-gradient(180deg,#fff,#f7f9fc)}
html[dir="rtl"] #nav{transform:translateX(100%)}
html[dir="ltr"] #nav{transform:translateX(-100%)}
body.nav-open #nav{transform:translateX(0)}

#scrim{
  position:fixed; inset:0; background:rgba(4,5,7,.7); backdrop-filter:blur(2px);
  z-index:48; opacity:1; transition:opacity .28s var(--ease);
}
#scrim.hidden{display:block !important; opacity:0; pointer-events:none}

.side-brand{
  display:flex; align-items:center; gap:10px; padding:14px 15px;
  border-bottom:1px solid var(--line);
  background:linear-gradient(120deg,rgba(34,239,157,.07),transparent 60%);
}
.brand-logo{
  width:38px;height:38px;flex:0 0 38px;border-radius:11px;display:grid;place-items:center;
  background:#000;overflow:hidden;box-shadow:0 0 0 1px var(--line2),0 8px 20px -10px rgba(34,239,157,.6);
}
.brand-logo svg{width:19px;height:19px;stroke:#fff;fill:none;stroke-width:1.8}
.brand-text{display:flex;flex-direction:column;line-height:1.2;min-width:0}
.brand-text b{font-size:13.5px;font-weight:700;letter-spacing:-.2px}
.brand-text b i{font-style:normal;color:var(--brand2)}
.brand-text span{font-family:'JetBrains Mono',monospace;font-size:8.5px;letter-spacing:1.1px;
  color:var(--tx3);text-transform:uppercase}
.side-collapse{
  margin-inline-start:auto; width:28px;height:28px;flex:0 0 28px;border-radius:7px;
  display:grid;place-items:center;cursor:pointer;border:1px solid var(--line2);
  background:var(--s1);color:var(--tx3);
}
.side-collapse:hover{border-color:var(--bad);color:var(--bad)}
.side-collapse svg{width:12px;height:12px;stroke:currentColor;fill:none;stroke-width:2.2;
  stroke-linecap:round}

.side-nav{flex:1;overflow-y:auto;padding:8px 10px 16px;overscroll-behavior:contain}
.side-nav::before{
  content:"مرور کلی"; display:block; font-family:'JetBrains Mono',monospace;
  font-size:9px; letter-spacing:1.3px; text-transform:uppercase; color:var(--tx3);
  padding:10px 10px 6px; opacity:.9;
}
html[lang="en"] .side-nav::before{content:"OVERVIEW"}
.navi{
  display:flex; align-items:center; gap:11px; padding:9px 10px; border-radius:9px;
  color:var(--tx2); font-size:13px; font-weight:500; cursor:pointer;
  border:1px solid transparent; transition:.15s; position:relative; text-decoration:none;
}
.navi .ic{width:18px;height:18px;flex:0 0 18px;stroke:currentColor;fill:none;stroke-width:1.7;
  stroke-linecap:round;stroke-linejoin:round;opacity:.92}
.navi:hover{background:var(--s2);color:var(--tx);border-color:var(--line)}
.navi.on{background:rgba(198,242,78,.12);color:var(--acid);border-color:rgba(198,242,78,.3);
  font-weight:600}
.navi.on::before{content:"";position:absolute;inset-inline-start:-11px;top:50%;
  transform:translateY(-50%);width:2px;height:18px;border-radius:2px;background:var(--acid);
  box-shadow:0 0 10px var(--acid)}
.navi.on .ic{opacity:1}

.side-foot{border-top:1px solid var(--line);padding:11px 13px;display:flex;
  flex-direction:column;gap:9px}

/* ───────── cards ───────── */
.card{
  border:1px solid var(--line); border-radius:12px; background:var(--s1);
  overflow:hidden; position:relative;
}
.card-head{
  display:flex; align-items:center; gap:9px; padding:12px 15px;
  border-bottom:1px solid var(--line); flex-wrap:wrap;
}
.card-head b{font-weight:600}

/* stat tiles */
.stat{
  display:flex; align-items:center; gap:11px; padding:13px 14px;
  border:1px solid var(--line); border-radius:12px; background:var(--s1);
  position:relative; overflow:hidden; transition:.16s;
}
.stat:hover{border-color:var(--line2)}
.stat>.ico{
  width:34px;height:34px;flex:0 0 34px;border-radius:10px;display:grid;place-items:center;
  background:rgba(198,242,78,.12);color:var(--acid);
}
.stat b{display:block;font-family:'JetBrains Mono',monospace;font-size:19px;font-weight:700;
  letter-spacing:-.8px;line-height:1.15;font-variant-numeric:tabular-nums;direction:ltr}
.stat span{display:block;font-size:10.5px;color:var(--tx3);line-height:1.5;margin-top:1px}
.ic-lg{width:17px;height:17px}
.stat .ico svg{width:16px;height:16px;stroke:currentColor;fill:none;stroke-width:1.8;
  stroke-linecap:round;stroke-linejoin:round}

/* ───────── buttons ───────── */
.btn{
  font:inherit; font-size:12px; font-weight:600; padding:8px 13px; border-radius:8px;
  cursor:pointer; transition:.15s; display:inline-flex; align-items:center; gap:7px;
  border:1px solid var(--acid); background:var(--acid); color:#08090b; white-space:nowrap;
}
.btn:hover{filter:brightness(1.08)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn-soft{
  border:1px solid var(--line2); background:var(--s1); color:var(--tx2);
}
.btn-soft:hover{border-color:var(--acid);color:var(--acid);background:rgba(198,242,78,.1);
  filter:none}
.btn-danger{
  border:1px solid rgba(255,107,107,.34); background:rgba(255,107,107,.1); color:var(--bad);
}
.btn-danger:hover{background:rgba(255,107,107,.18);filter:none}
.icon-btn{
  width:30px;height:30px;flex:0 0 30px;border-radius:7px;display:inline-grid;place-items:center;
  cursor:pointer;border:1px solid var(--line2);background:var(--s1);color:var(--tx3);
  transition:.15s;padding:0;
}
.icon-btn:hover{border-color:var(--acid);color:var(--acid);background:rgba(198,242,78,.1)}
.icon-btn.danger:hover{border-color:var(--bad);color:var(--bad);background:rgba(255,107,107,.12)}
.icon-btn .ic{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:2;
  stroke-linecap:round;stroke-linejoin:round}

/* ───────── forms ───────── */
.fld{display:flex;flex-direction:column;gap:5px;min-width:0;justify-content:flex-start}
.fld>*{flex:0 0 auto}
.fld>label,.fld>span:first-child{font-size:11px;color:var(--tx3);font-weight:500;
  display:flex;align-items:center;gap:5px}
.inp{
  width:100%; background:var(--s2); border:1px solid var(--line2); border-radius:8px;
  color:var(--tx); font:inherit; font-size:12.5px; padding:8px 11px; transition:.15s;
  font-family:inherit; min-width:0;
}
.inp:hover{border-color:var(--line2);background:var(--s3)}
.inp:focus{outline:none;border-color:var(--acid);box-shadow:0 0 0 3px rgba(198,242,78,.14)}
.inp::placeholder{color:var(--tx3);opacity:.7}
.inp.mono{font-family:'JetBrains Mono',monospace;font-size:11.5px;direction:ltr;text-align:left}
textarea.inp{resize:vertical;min-height:76px;line-height:1.7}
select.inp{display:none}          /* با enhancer جایگزین می‌شود */

/* seg */
.seg{
  display:inline-flex;gap:2px;padding:3px;border-radius:9px;background:var(--s2);
  border:1px solid var(--line2);flex-wrap:wrap;
}
.seg button{
  font:inherit;font-size:11.5px;font-weight:600;padding:5px 11px;border-radius:6px;border:0;
  background:transparent;color:var(--tx3);cursor:pointer;transition:.14s;white-space:nowrap;
}
.seg button.on{background:var(--acid);color:#08090b}
.seg button:not(.on):hover{color:var(--tx)}

/* chip */
.chip{
  display:inline-flex;align-items:center;gap:5px;font-size:10.5px;font-weight:600;
  padding:3px 9px;border-radius:6px;background:var(--s2);border:1px solid var(--line2);
  color:var(--tx2);white-space:nowrap;
}
.chip.soft{background:rgba(198,242,78,.1);border-color:rgba(198,242,78,.28);color:var(--acid)}
.chip.danger{background:rgba(255,107,107,.1);border-color:rgba(255,107,107,.3);color:var(--bad)}
.chip.green{background:rgba(34,239,157,.1);border-color:rgba(34,239,157,.28);color:var(--brand)}
.chip.blue{background:rgba(92,225,230,.1);border-color:rgba(92,225,230,.28);color:var(--cyan)}
.chip.teal{background:rgba(92,225,230,.1);border-color:rgba(92,225,230,.28);color:var(--cyan)}
.chip.red{background:rgba(255,107,107,.1);border-color:rgba(255,107,107,.3);color:var(--bad)}

/* notice / kv / progress */
.notice{
  display:flex;gap:9px;padding:11px 13px;border-radius:9px;font-size:11.5px;line-height:1.9;
  background:rgba(255,204,102,.07);border:1px solid rgba(255,204,102,.24);color:#e8c98a;
}
.kv{display:flex;align-items:center;gap:9px;font-size:12px;padding:6px 0;
  border-bottom:1px dotted var(--line)}
.kv:last-child{border-bottom:0}
.kv span{color:var(--tx3);font-size:11px}
.kv b{margin-inline-start:auto;font-family:'JetBrains Mono',monospace;font-size:11.5px;
  font-weight:600;color:var(--tx2);direction:ltr}
.progress{height:6px;border-radius:3px;background:var(--s3);overflow:hidden;direction:ltr}
.progress>i{display:block;height:100%;border-radius:3px;
  background:linear-gradient(90deg,var(--brand),var(--acid))}
/* switch — هم برای <button class="sw"> و هم برای چک‌باکس معمولی */
.sw{
  position:relative;display:inline-flex;align-items:center;justify-content:flex-start;
  width:40px;height:22px;padding:0;border-radius:20px;cursor:pointer;
  background:var(--s3);border:1px solid var(--line2);transition:.2s var(--ease);
  font-size:0;color:transparent;flex:0 0 40px;
}
.sw::after{
  content:"";position:absolute;top:2px;inset-inline-start:2px;width:16px;height:16px;
  border-radius:50%;background:var(--tx3);transition:.2s var(--ease);
}
.sw.on,.sw[aria-pressed="true"]{background:rgba(198,242,78,.3);border-color:var(--acid)}
.sw.on::after,.sw[aria-pressed="true"]::after{
  transform:translateX(18px);background:var(--acid);box-shadow:0 0 10px rgba(198,242,78,.7)}
html[dir="rtl"] .sw.on::after,html[dir="rtl"] .sw[aria-pressed="true"]::after{
  transform:translateX(-18px)}
input[type="checkbox"]{
  accent-color:var(--acid);width:15px;height:15px;cursor:pointer;margin:0;flex:0 0 15px;
}
input[type="radio"]{accent-color:var(--acid)}
label>input[type="checkbox"]+span{font-size:12.5px;color:var(--tx2)}
.chip input[type="checkbox"]{width:13px;height:13px;flex:0 0 13px}

/* ───────── rows (users / live / proxies) ───────── */
.urow{
  display:flex;align-items:center;gap:11px;padding:11px 15px;
  border-bottom:1px solid var(--line);transition:.14s;
}
.urow:last-child{border-bottom:0}
.urow:hover{background:rgba(198,242,78,.03)}
.u-av{
  width:32px;height:32px;flex:0 0 32px;border-radius:9px;display:grid;place-items:center;
  font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;
  background:var(--s2);border:1px solid var(--line2);color:var(--acid);overflow:hidden;
}
.u-main{flex:1;min-width:0}
.u-main>b{display:block;font-size:12.5px;font-weight:600;line-height:1.3}
.u-main>.text-xs{display:block;line-height:1.5}
.u-dev{font-family:'JetBrains Mono',monospace;font-size:10.5px;color:var(--tx3);
  padding:2px 7px;border-radius:5px;background:var(--s2);border:1px solid var(--line)}
.u-actions{display:flex;gap:4px;align-items:center}

.lrow{display:flex;align-items:center;gap:9px;padding:9px 15px;border-bottom:1px solid var(--line);
  font-size:12px;transition:.14s}
.lrow:last-child{border-bottom:0}
.lrow:hover{background:rgba(198,242,78,.03)}
.lrow .mono{font-size:10.5px;color:var(--tx3)}
.prow{display:flex;align-items:center;gap:9px;padding:10px 15px;border-bottom:1px solid var(--line);
  font-size:12px}
.prow:last-child{border-bottom:0}
.prow:hover{background:rgba(198,242,78,.03)}

/* ───────── modal ───────── */
#modal{
  position:fixed;inset:0;z-index:70;display:grid;place-items:center;padding:16px;
  background:rgba(4,5,7,.72);backdrop-filter:blur(3px);
}
#modal.hidden{display:none}
.modal-card{
  width:100%;max-width:520px;max-height:86vh;overflow:auto;
  background:var(--s1);border:1px solid var(--line2);border-radius:14px;
  box-shadow:0 30px 70px -20px rgba(0,0,0,.9);animation:pop .2s var(--ease);
}
@keyframes pop{from{opacity:0;transform:translateY(10px) scale(.985)}to{opacity:1;transform:none}}
.modal-head{
  display:flex;align-items:center;gap:10px;padding:13px 16px;
  border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--s1);z-index:2;
}
.modal-head b{font-size:13.5px;font-weight:600}
#mBody{padding:15px 16px}

/* ───────── toast ───────── */
.toast{
  position:fixed;bottom:16px;left:50%;transform:translateX(-50%) translateY(70px);
  font-size:12px;font-weight:600;background:var(--acid);color:#08090b;
  padding:9px 16px;border-radius:8px;opacity:0;transition:.26s var(--ease);
  z-index:90;pointer-events:none;display:flex;align-items:center;gap:7px;
  box-shadow:0 14px 34px -12px rgba(198,242,78,.6);
}
.toast.on{transform:translateX(-50%) translateY(0);opacity:1}

/* ══════════════════ CUSTOM SELECT (بدون منوی مرورگر) ══════════════════ */
.sel{position:relative;width:100%}
.sel-btn{
  width:100%;display:flex;align-items:center;gap:8px;background:var(--s2);
  border:1px solid var(--line2);border-radius:8px;color:var(--tx);
  font:inherit;font-size:12.5px;padding:8px 11px;cursor:pointer;transition:.15s;
  font-family:inherit;text-align:start;min-height:36px;
}
.sel-btn:hover{border-color:var(--line2);background:var(--s3)}
.sel-btn .cur{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  display:flex;align-items:center;gap:7px}
.sel-btn .cur .em{font-size:13px}
.sel-btn .caret{width:13px;height:13px;flex:0 0 13px;stroke:var(--tx3);fill:none;
  stroke-width:2.2;stroke-linecap:round;transition:transform .2s var(--ease)}
.sel.open .sel-btn{border-color:var(--acid);box-shadow:0 0 0 3px rgba(198,242,78,.14)}
.sel.open .caret{transform:rotate(180deg);stroke:var(--acid)}
.sel-menu{
  position:absolute;top:calc(100% + 5px);inset-inline:0;z-index:60;
  background:var(--s1);border:1px solid var(--line2);border-radius:10px;padding:5px;
  box-shadow:0 22px 50px -14px rgba(0,0,0,.85),0 0 0 1px rgba(255,255,255,.03);
  max-height:270px;overflow-y:auto;overscroll-behavior:contain;
  -webkit-overflow-scrolling:touch;touch-action:pan-y;
  opacity:0;transform:translateY(-6px) scale(.985);pointer-events:none;
  transition:opacity .16s var(--ease),transform .16s var(--ease);transform-origin:top center;
}
.sel.open .sel-menu{opacity:1;transform:none;pointer-events:auto}
.sel.up .sel-menu{top:auto;bottom:calc(100% + 5px);transform-origin:bottom center}
.sopt{
  width:100%;display:flex;align-items:center;gap:9px;padding:8px 9px;border-radius:7px;
  border:0;background:none;color:var(--tx2);font:inherit;font-size:12.5px;cursor:pointer;
  text-align:start;transition:.12s;font-family:inherit;
}
.sopt:hover,.sopt.hl{background:var(--s3);color:var(--tx)}
.sopt .em{font-size:14px;flex:0 0 auto}
.sopt .tx{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sopt .tick{width:14px;height:14px;flex:0 0 14px;stroke:var(--acid);fill:none;stroke-width:2.4;
  stroke-linecap:round;stroke-linejoin:round;opacity:0;transition:.14s}
.sopt[aria-selected="true"]{color:var(--acid);font-weight:600}
.sopt[aria-selected="true"] .tick{opacity:1}
.sempty{padding:14px 10px;text-align:center;font-size:11.5px;color:var(--tx3)}

/* ───────── responsive ───────── */
@media(max-width:1180px){
  .g4{grid-template-columns:repeat(2,1fr)}
  .g3{grid-template-columns:1fr 1fr}
}
@media(max-width:900px){
  .g4{grid-template-columns:repeat(2,1fr)}
  .g3,.g2,.row2{grid-template-columns:1fr}
  .path-pill{display:none}
}
@media(max-width:640px){
  .appbar{padding:0 11px;gap:8px}
  .appbar .ttl h1{font-size:12.5px}
  .content{padding:14px 11px 40px}
  .g4{grid-template-columns:1fr 1fr}
  .p-4{padding:12px}
  .stat b{font-size:17px}
}
@media(prefers-reduced-motion:reduce){
  *,*::before,*::after{animation-duration:.001ms !important;animation-iteration-count:1 !important;
    transition-duration:.001ms !important}
}


/* ══════════════════════════════════════════════════════════════════
   COMPONENTS v4 — مارک‌آپ واقعی، بدون تکیه بر کلاس‌های مبهم قدیمی
   ══════════════════════════════════════════════════════════════════ */

/* ── هدر صفحه ── */
.ph{
  display:flex;align-items:flex-end;gap:12px;margin-bottom:16px;flex-wrap:wrap;
}
.ph h1{margin:0;font-size:22px;font-weight:700;letter-spacing:-.6px;line-height:1.2}
html[lang="fa"] .ph h1{letter-spacing:-.1px;font-size:21px}
.ph .sub{margin:3px 0 0;font-size:11.5px;color:var(--tx3);line-height:1.6}
.ph-t{min-width:0;flex:1}
.ph .sp{flex:1}
.ph .acts{display:flex;gap:8px;flex-wrap:wrap}

/* ── نوار آمار ── */
.strip{
  display:grid;grid-template-columns:repeat(3,1fr);
  border:1px solid var(--line);border-radius:12px;overflow:hidden;
  background:var(--s1);margin-bottom:14px;
}
.strip .cell{padding:13px 15px;border-inline-start:1px solid var(--line);
  border-bottom:1px solid var(--line);min-width:0}
.strip .cell:nth-child(3n+1){border-inline-start:0}
.strip .cell:nth-last-child(-n+3){border-bottom:0}
.strip .k{font-size:10.5px;letter-spacing:.4px;color:var(--tx3);
  display:flex;align-items:center;gap:6px;margin-bottom:7px;white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis}
.strip .k i{width:5px;height:5px;border-radius:1px;background:var(--acid);
  display:block;flex:0 0 5px}
.strip .v{font-family:'JetBrains Mono',monospace;font-size:21px;font-weight:700;
  letter-spacing:-1px;line-height:1.1;direction:ltr;
  font-variant-numeric:tabular-nums;white-space:nowrap;overflow:hidden;
  text-overflow:ellipsis}
.strip .v u{text-decoration:none;font-size:11px;color:var(--tx3);font-weight:500;
  margin-inline-start:2px}
.strip .d{margin-top:5px;font-size:10.5px;color:var(--tx3);display:flex;
  align-items:center;gap:5px;flex-wrap:wrap;line-height:1.5}
.strip .d b{color:var(--acid);font-weight:600;font-family:'JetBrains Mono',monospace}
.strip .d b.n{color:var(--bad)}

/* ── کارت کاربر (v4.3 — کارت‌های جدا، RTL امن) ── */
#rows{display:flex;flex-direction:column;gap:9px;padding:11px}
#rows>.empty{align-self:stretch}
.ucard{
  display:flex;flex-direction:column;gap:9px;min-width:0;
  padding:11px 12px;border:1px solid var(--line);border-radius:11px;
  background:var(--s2);transition:border-color .14s,background .14s;
}
.ucard:hover{border-color:var(--line2);background:var(--s3)}

.uc-top{display:flex;align-items:center;gap:7px;flex-wrap:wrap;min-width:0}
.uc-top .av{
  width:29px;height:29px;flex:0 0 29px;border-radius:9px;display:grid;place-items:center;
  background:var(--s1);border:1px solid var(--line2);color:var(--acid);
  font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700;
}
.uc-top .nm{
  font-size:13px;font-weight:600;line-height:1.4;min-width:0;flex:1 1 auto;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
}

/* ردیف ابزار: چیپ ترنسپورت کنار سه دکمه */
.uc-tools{display:flex;align-items:center;gap:8px;min-width:0}
/* وضعیت · ترنسپورت · دستگاه متصل: پشت سر هم، ته ردیف نام */
.uc-meta{display:inline-flex;align-items:center;gap:6px;flex:0 0 auto;
  margin-inline-start:auto;min-width:0}
.uc-meta .chip{white-space:nowrap}
.uc-top .uc-tsp{flex:0 0 auto;align-self:center}
.uc-tools{min-height:0}
.uc-tools .chip{flex:0 0 auto}
.uc-act{display:flex;gap:6px;align-items:center;flex:0 0 auto}
/* نماد بی‌نهایت بزرگ‌تر و هم‌تراز با عددها */
.inf{font-family:'Vazirmatn',Tahoma,sans-serif;font-style:normal;font-size:19px;
  font-weight:600;line-height:1;vertical-align:-2px;letter-spacing:0;
  display:inline-block;min-width:13px}
.uc-foot .inf{font-size:19px}
.uc-num .inf{font-size:18px}
.uc-act .icon-btn{width:31px;height:31px;flex:0 0 31px}
.uc-act .icon-btn svg{width:15px;height:15px}

.uc-bar{
  height:5px;border-radius:3px;background:var(--s3);overflow:hidden;direction:ltr;
}
.uc-bar>i{display:block;height:100%;border-radius:3px;
  background:linear-gradient(90deg,var(--brand),var(--acid));transition:width .3s}
.uc-bar.hot>i{background:linear-gradient(90deg,var(--amber),var(--red))}

.uc-foot{
  display:flex;align-items:center;gap:4px 12px;flex-wrap:wrap;
  font-size:11px;color:var(--tx3);line-height:1.8;min-width:0;
}
.uc-foot.uc-num{color:var(--tx2);font-size:11px}
.uc-foot>span,.uc-foot>bdi{display:inline-flex;align-items:center;gap:5px;min-width:0}
.uc-foot bdi.mono{font-family:'JetBrains Mono',monospace;font-size:10.5px;
  direction:ltr;unicode-bidi:isolate;color:var(--tx2);white-space:nowrap}
.uc-foot .pct{margin-inline-start:auto;color:var(--tx3)}
.uc-foot svg{width:14px;height:14px;flex:0 0 14px;stroke:currentColor;
  fill:none;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round;opacity:.85}
.uc-foot .warn{color:var(--amber)}
.uc-foot .gf{white-space:nowrap}
/* تاریخ باید با فونت فارسی نوشته شود، نه مونو */
.uc-foot .dt{
  font-family:inherit;font-size:11px;color:var(--tx2);font-weight:600;
  white-space:nowrap;unicode-bidi:isolate;
}
html[lang="fa"] .uc-foot .dt{font-family:'Vazirmatn','Vazir',Tahoma,sans-serif}

@media(max-width:560px){
  .uc-meta{gap:5px}
  .uc-foot{gap:3px 10px;font-size:10.5px}
  .uc-foot .dt{font-size:10.5px}
  /* چیپ‌های وضعیت وقتی کنار نام جا نشوند، از ابتدای خط بعد شروع شوند
     (margin:auto باعث می‌شد به لبهٔ مخالف بچسبند و ظاهر به‌هم بریزد) */
  .uc-meta{margin-inline-start:0}
  .uc-top .chip{font-size:10px;padding:3px 8px}
  /* ردیف‌های پایین کارت: لیبل بلند فارسی بتواند بشکند، سرریز نکند */
  .uc-foot .gf{white-space:normal;overflow-wrap:anywhere;line-height:1.6}
}

/* ── مودال / شیت تنظیمات کاربر ── */
.mwrap{
  position:fixed;inset:0;z-index:75;display:flex;align-items:flex-end;
  justify-content:center;background:rgba(4,5,7,.74);backdrop-filter:blur(3px);
  padding:0;
}
.mwrap.hidden{display:none}
@media(min-width:640px){ .mwrap{align-items:center;padding:18px} }

.sheet{
  width:100%;max-width:560px;max-height:92vh;display:flex;flex-direction:column;
  background:var(--s1);border:1px solid var(--line2);border-radius:16px 16px 0 0;
  box-shadow:0 -20px 60px -20px rgba(0,0,0,.9);animation:sheetUp .26s cubic-bezier(.22,.68,.32,1);
}
@media(min-width:640px){ .sheet{border-radius:14px;animation:pop .2s ease} }
@keyframes sheetUp{from{transform:translateY(28px);opacity:.6}to{transform:none;opacity:1}}

.sheet-head{
  display:flex;align-items:center;gap:10px;padding:14px 16px;
  border-bottom:1px solid var(--line);flex:0 0 auto;
}
.sheet-head b{font-size:14px;font-weight:600}
.sheet-head .x{
  margin-inline-start:auto;width:30px;height:30px;flex:0 0 30px;border-radius:8px;
  display:grid;place-items:center;cursor:pointer;border:1px solid var(--line2);
  background:var(--s2);color:var(--tx3);
}
.sheet-head .x:hover{border-color:var(--bad);color:var(--bad)}

/* تب‌های داخل شیت — مثل «Basics / Protocol / Stream / Security» */
.stabs{
  display:flex;gap:4px;padding:10px 14px 0;border-bottom:1px solid var(--line);
  overflow-x:auto;flex:0 0 auto;
}
.stabs::-webkit-scrollbar{height:0}
.stabs button{
  font:inherit;font-size:12px;font-weight:600;padding:8px 12px 10px;
  border:0;background:none;color:var(--tx3);cursor:pointer;white-space:nowrap;
  border-bottom:2px solid transparent;transition:.15s;
}
.stabs button:hover{color:var(--tx2)}
.stabs button.on{color:var(--acid);border-bottom-color:var(--acid)}

.sheet-body{padding:15px 16px;overflow-y:auto;flex:1 1 auto;min-height:0}
.pane{display:none}
.pane.on{display:block;animation:fadeIn .18s ease}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}

.sheet-foot{
  display:flex;align-items:center;gap:9px;padding:12px 16px;
  border-top:1px solid var(--line);flex:0 0 auto;flex-wrap:wrap;
  background:var(--s1);border-radius:0 0 14px 14px;
}
.sheet-foot .btn{flex:1;justify-content:center;min-width:120px}
.sheet-foot .err{width:100%;font-size:11.5px;color:var(--bad);margin:0;min-height:0}

/* ── اصلاح هم‌پوشانی متن ── */
.notice, .hint, .alert{
  min-width:0;overflow-wrap:anywhere;
}
.notice svg, .alert svg{flex:0 0 15px;width:15px;height:15px;margin-top:2px;
  stroke:currentColor;fill:none;stroke-width:1.9;stroke-linecap:round}
.notice>span, .alert>span{flex:1;min-width:0}
.notice b{min-width:0}
@media(max-width:560px){ .strip .k{white-space:normal;line-height:1.5}
  .strip .d{font-size:10px} }
.card .notice{margin:0 0 12px}
.card .hint{margin:10px 0 0}
.fld>span, .fld>label{min-width:0;overflow-wrap:anywhere}
.soft{
  background:var(--s2);border:1px solid var(--line);border-radius:10px;
}
.kv b{white-space:nowrap}

/* ورودی‌های شماره‌ای در RTL */
html[dir="rtl"] input[type="number"]{direction:ltr;text-align:right}

/* ── v4.1 افزوده‌ها ── */
body.locked{overflow:hidden}
.empty{
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  gap:9px;padding:34px 16px;color:var(--tx3);font-size:12px;text-align:center;
}
.empty svg{width:26px;height:26px;stroke:currentColor;fill:none;stroke-width:1.7;
  stroke-linecap:round;opacity:.65}
.chip.dot{position:relative;padding-inline-start:16px}
.chip.dot::before{
  content:'';position:absolute;inset-inline-start:7px;top:50%;margin-top:-2.5px;
  width:5px;height:5px;border-radius:50%;background:var(--brand);
  box-shadow:0 0 0 2px rgba(34,239,157,.18)
}
.icon-btn{
  width:29px;height:29px;flex:0 0 29px;border-radius:8px;display:grid;place-items:center;
  border:1px solid var(--line2);background:var(--s2);color:var(--tx3);cursor:pointer;
  transition:.14s;
}
.icon-btn:hover{border-color:var(--acid);color:var(--acid);background:var(--s3)}
.icon-btn svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:1.9;
  stroke-linecap:round;stroke-linejoin:round}
.btn svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:2.2;
  stroke-linecap:round;stroke-linejoin:round;flex:0 0 14px}

/* مودال عمومی (#modal) هم به شکل شیت دیده شود */
#modal .mwrap, #modal.mwrap{position:fixed;inset:0}
#modal{
  position:fixed;inset:0;z-index:80;align-items:center;justify-content:center;
  background:rgba(4,5,7,.74);backdrop-filter:blur(3px);padding:14px;
}
#modal>div{
  width:100%;max-width:520px;max-height:90vh;overflow-y:auto;
  background:var(--s1);border:1px solid var(--line2);border-radius:14px;
  box-shadow:0 30px 70px -24px rgba(0,0,0,.9);padding:16px;
  display:flex;flex-direction:column;gap:10px;
}
#modal .fld{margin:0}
@media(max-width:560px){
  .ph{align-items:flex-start;margin-bottom:13px}
  .ph h1{font-size:19px}
  .ph .sub{font-size:11px}
  .strip .cell{padding:11px 12px}
  .strip .v{font-size:18px}
  .sheet{max-height:94vh}
}

/* ── ردیف‌های سهم ترنسپورت ── */
#protoBox .prow{display:grid;grid-template-columns:1fr auto;gap:5px 8px;
  align-items:center;padding:2px 0}
#protoBox .lbl{display:inline-flex;align-items:center;gap:7px;font-size:11.5px;
  color:var(--tx2);white-space:nowrap;min-width:0;overflow:hidden;text-overflow:ellipsis}
#protoBox .lbl i{width:7px;height:7px;border-radius:50%;flex:0 0 7px;display:block}
#protoBox b{font-family:'JetBrains Mono',monospace;font-size:12.5px;font-weight:700;
  color:var(--tx);direction:ltr;font-variant-numeric:tabular-nums}
#protoBox .bar{grid-column:1/-1;height:4px;border-radius:2px;background:var(--s3);
  overflow:hidden;direction:ltr}
#protoBox .bar i{display:block;height:100%;border-radius:2px;min-width:2px}
.card-head .sub-unit{white-space:nowrap;flex:0 0 auto}

/* نوار آمار در دسکتاپ: شش ستون هم‌عرض */
@media(min-width:900px){
  .strip{grid-template-columns:repeat(6,1fr)}
  .strip .cell{border-bottom:0}
  .strip .cell:nth-child(3n+1){border-inline-start:1px solid var(--line)}
  .strip .cell:first-child{border-inline-start:0}
  .strip .v{font-size:19px}
}
/* دو کارت داشبورد هم‌ارتفاع نباشند */
section[data-pg="dash"] > .g{align-items:start}
#protoBox .bar i{background:var(--acid)}

/* ══════════════════════════════════════════════════════════════════
   v4.3 — اصلاحات RTL، سرریز منوها، مودال و اعداد
   ══════════════════════════════════════════════════════════════════ */

/* ── اعداد: جهت LTR با تراز راست در RTL ── */
.strip .v{direction:ltr;text-align:right;unicode-bidi:isolate;
  font-family:'Vazirmatn',Tahoma,sans-serif}
html[lang="en"] .strip .v{font-family:'JetBrains Mono',monospace}
html[dir="ltr"] .strip .v{text-align:left}
.strip .d{direction:rtl}
html[dir="ltr"] .strip .d{direction:ltr}

/* ── منوی کشویی: کارت نباید آن را ببرد ── */
.card:has(.sel.open){overflow:visible}
.card.sel-open{overflow:visible}
.sel-menu{z-index:70}

/* ── هشدارها: فاصله‌ی بالا و پایین حفظ شود ── */
.card .notice{margin-block:12px;margin-inline:0}
.card .notice:first-child{margin-block-start:0}
.notice{align-items:flex-start}
.notice>b,.notice>span{min-width:0}

/* ── مودال عمومی: هدر ثابت، بدنه‌ی اسکرول‌شونده، بدون فضای خالی ── */
#modal{align-items:center;justify-content:center;padding:12px}
#modal>div{
  max-height:86vh;max-width:520px;width:100%;padding:0;gap:0;
  display:flex;flex-direction:column;overflow:hidden;
  /* بدون این، کارت سفید در تم روشن نیمه‌شفاف دیده می‌شود */
  background:var(--s1);border:1px solid var(--line2);border-radius:14px;
  box-shadow:0 30px 70px -24px rgba(0,0,0,.55);
}
#modal .modal-head{
  flex:0 0 auto;position:sticky;top:0;z-index:3;
  padding:13px 15px;margin:0;
  background:var(--s1);border-bottom:1px solid var(--line);
  border-radius:14px 14px 0 0;
}
#modal .modal-head b{font-size:14px;font-weight:600;min-width:0;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#modal>div>#mBody{
  flex:1 1 auto;min-height:0;overflow-y:auto;
  padding:14px 15px 16px;display:flex;flex-direction:column;gap:10px;
  overscroll-behavior:contain;
}
#modal #mBody .btn.w-full{flex:0 0 auto}
#modal #mBody>.g2{gap:9px}

/* ── شیت ساخت کاربر: هدر ثابت ── */
.sheet-head{position:sticky;top:0;z-index:3;background:var(--s1)}
.stabs{position:sticky;top:51px;z-index:2;background:var(--s1)}

/* ── کارت‌های تنظیمات: فاصله‌ی عمودی یکنواخت ── */
[data-pg="settings"]>.card+.card{margin-top:12px}

/* ── لیبل‌های فارسی کوتاه‌نشده در گریدهای تنگ ── */
@media(max-width:560px){
  .g3{grid-template-columns:1fr}
  .fld>span,.fld>label{display:block;margin-bottom:5px}
}

/* ── v4.4 ── */
.uc-top .av,.u-av{border-radius:50%}
.uc-foot>span.dim,.lrow>.dim{color:var(--tx3)}
#rows .lrow{border:1px solid var(--line);border-radius:10px;background:var(--s2);
  margin-bottom:7px}
#rows .lrow:last-child{margin-bottom:0}

/* ── v4.4 ── */
/* آیکون هشدار به‌جای اموجی، فقط وقتی نوتیس خودش svg ندارد */
.notice:not(:has(svg))::before{
  content:"";flex:0 0 15px;width:15px;height:15px;margin-top:2px;
  background:currentColor;opacity:.85;
  -webkit-mask:url("data:image/svg+xml;charset=utf8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23000' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 3.2L2.6 19.8h18.8z'/%3E%3Cpath d='M12 9v4.4M12 16.6v.4'/%3E%3C/svg%3E") center/contain no-repeat;
  mask:url("data:image/svg+xml;charset=utf8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23000' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 3.2L2.6 19.8h18.8z'/%3E%3Cpath d='M12 9v4.4M12 16.6v.4'/%3E%3C/svg%3E") center/contain no-repeat;
}
/* چک‌باکس‌ها هم‌اندازه و هم‌رنگ برند */
input[type=checkbox]{-webkit-appearance:none;appearance:none;
  width:16px;height:16px;flex:0 0 16px;margin:0;cursor:pointer;
  border:1.5px solid var(--line2);border-radius:5px;background:var(--s2);
  display:inline-flex;align-items:center;justify-content:center;
  transition:background .15s,border-color .15s;vertical-align:-3px}
input[type=checkbox]:hover{border-color:var(--acid)}
input[type=checkbox]:checked{background:var(--acid);border-color:var(--acid)}
input[type=checkbox]:checked::after{content:"";width:9px;height:5px;
  border:1.8px solid #0b0d10;border-top:0;border-right:0;
  transform:rotate(-45deg) translate(1px,-1px)}
[data-theme=light] input[type=checkbox]:checked::after{border-color:#fff}
input[type=checkbox]:focus-visible{outline:2px solid var(--acid);outline-offset:2px}
/* دکمهٔ انتخاب فایل پشتیبان */
label.chip{display:inline-flex;align-items:center;gap:7px;line-height:1.5}
.file-pick{display:flex;align-items:center;justify-content:center;gap:8px;
  flex-wrap:wrap;cursor:pointer;text-align:center;line-height:1.6}
.file-pick:hover{border-color:var(--acid)}
.file-pick svg{width:15px;height:15px;flex:0 0 15px}
[data-theme="light"] .notice{
  background:rgba(168,112,0,.07);border-color:rgba(168,112,0,.3);color:#7d5a00;
}
[data-theme="light"] .notice::before{opacity:.75}

/* ── v4.5 ── */
/* فاصلهٔ کادرهای هشدار از همسایه‌ها (قبلاً با style="margin:0" چسبیده بود) */
.card p.notice{margin-block:12px}
.card p.notice:first-child{margin-block-start:0}
.card p.notice:last-child{margin-block-end:0}
/* دکمه‌های اکشن کارت کاربر: هم‌تراز با لبهٔ شروع کارت */
.uc-tools{justify-content:flex-start}

/* منوی کشویی: اسکرول داخل منو به صفحه سرایت نکند */
.sel-menu{overscroll-behavior:contain}

/* ── v4.7: پرچم SVG ── */
.flag{width:18px;height:13px;flex:0 0 18px;border-radius:3px;object-fit:cover;
  display:inline-block;vertical-align:-2px;background:var(--s3);
  box-shadow:0 0 0 1px var(--line2);pointer-events:none}
.flag.lg{width:21px;height:15px;flex:0 0 21px;border-radius:4px}
.sel-btn .cur{display:flex;align-items:center;gap:7px;min-width:0}
.sel-btn .cur .tx{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.sopt .tx{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* ردیف پراکسی: چیدمان ثابت، مستقل از این‌که پروکسی سالم است یا خراب */
.prow{display:flex;flex-wrap:wrap;align-items:flex-start;gap:8px 10px;
  padding:11px 15px}
.prow-main{display:flex;flex-direction:column;gap:6px;flex:1 1 210px;min-width:0}
.prow-head{display:flex;align-items:center;gap:7px;flex-wrap:wrap;min-width:0}
.prow-head .lbl{font-family:'JetBrains Mono',monospace;font-size:12px;min-width:0;
  overflow-wrap:anywhere}
.prow-meta{display:flex;flex-wrap:wrap;gap:4px 12px;font-size:11px;color:var(--tx3);
  line-height:1.7;min-width:0}
.prow-meta .err{color:var(--bad);overflow-wrap:anywhere}
.prow-act{display:flex;align-items:center;gap:6px;flex:0 0 auto;margin-inline-start:auto}
.prow-act .icon-btn{flex:0 0 auto}
@media (max-width:430px){
  .prow-act{margin-inline-start:0;flex:1 0 100%;justify-content:flex-end}
}

/* ردیف‌های ثابت پایین کارت کاربر: انقضا / سپس دستگاه + آی‌پی */
.uc-foot-1{margin-top:9px}
.uc-foot-2{margin-top:5px;gap:14px}
.uc-foot-2 .gf{flex:0 0 auto}

/* ── v4.8: موبایل — نوار آمار ۲ ستونه ──
   بعد از قاعدهٔ پایه و بلوک min-width:900px قرار می‌گیرد تا کسکید آن را خنثی نکند.
   ۳ ستون در ~۳۶۰px هر سلول را ~۱۰۰px می‌کند: لیبل فارسی دوکلمه‌ای و اعداد له می‌شوند. */
@media(max-width:640px){
  .strip{grid-template-columns:1fr 1fr}
  .strip .cell{border-inline-start:1px solid var(--line);
    border-bottom:1px solid var(--line)}
  .strip .cell:nth-child(2n+1){border-inline-start:0}
  .strip .cell:nth-last-child(-n+2){border-bottom:0}
  .strip .k{white-space:normal;line-height:1.45;font-size:10px}
  .strip .v{font-size:17px}
  .strip .d{font-size:10px}
}
"""


I18N_JS = r"""
const I18N={
 en:{dir:'ltr',
  unitBytes:'bytes',loadingLbl:'Loading…',noLive:'No live connections',
  phDash:'Live server, user and traffic overview',  phUsers:'Create, edit and monitor accounts',  phClean:'IPs that go into the subscription link',  phFilter:'Blocked and allowed domains',  phProxy:'Proxy pool and auto selection',  phLive:'Connections open right now',  phTgweb:'Build and manage Telegram web proxies',  phSettings:'Appearance, password, backup and server',  phLogs:'Latest panel events',  refreshLbl:'Refresh',  tabBasic:'Basics',  tabLimits:'Limits',  tabSecurity:'Security',  viewAll:'All',  r24:'24h',  cancel:'Cancel',  statHintUsers:'accounts',  statHintOnline:'online now',  statHintDev:'active devices',  statHintBytes:'since start',  statHintCip:'in subscription',  statHintLive:'live sessions',  zeroInfShort:'0 means unlimited.',  moreLbl:'Details',  noResult:'Nothing found',
  devGateTitle:'Device limit',
  devGateSub:'A device limit only works when the panel can tell devices apart, which needs an app that reports its identity. With a limit above 0, the subscription link is handed out only to the apps below; everything else is refused. Accounts with 0 (unlimited) are never restricted.',
  devGateOn:'Only device-aware apps may add limited subscriptions',
  devGateTraffic:'Also refuse proxy traffic from those apps',
  devGateTrafficHint:'Off by default. Turning it on blocks apps that copy configs by hand instead of using the subscription link.',
  devGateApps:'Accepted apps',
  devLimitHint:'0 = any app. 1 or more = only V2Box, v2rayTun, Happ, Incy, Shadowrocket and Streisand can add this link, because only they report the device.',
  setupTitle:'Set a password',setupSub:'First run — choose your panel password',
  loginTitle:'Sign in',loginSub:'Enter your password',
  password:'Password',confirm:'Confirm password',enter:'Sign in',save:'Save & enter',
  pwRule:'At least 8 chars with upper case, lower case and a digit',netErr:'Network error',
  navDash:'Dashboard',navUsers:'Users',navClean:'Clean IPs',
  navProxy:'Proxy',navLive:'Live connections',
  navSettings:'Panel settings',navLogs:'Events',menu:'Menu',
  totalUsers:'Total users',online:'Online users',devices:'Connected devices',
  traffic:'Total traffic',cleanIps:'Clean IPs',xSessions:'XHTTP sessions',liveTitle:'Live connections',liveEmpty:'No active connections',
  chart24:'Last 24 hours',protoSplit:'Connections per transport',
  newUser:'Create user',users:'Users',
  name:'Name',quota:'Quota (GB)',days:'Days',devLimit:'Devices',ipLimit:'IPs',
  transport:'Transport',trWs:'WS + TLS',trXhttp:'XHTTP + TLS',trBoth:'Both',
  add:'Add',zeroInf:'0 = unlimited. A device is identified by its IP and client signature; the IP cap is separate and ignores duplicates.',
  search:'Search…',noUsers:'No users yet',
  config:'Config',ipsBtn:'Devices & IPs',edit:'Edit',
  used:'Used',expiry:'Expires',never:'Never',
  subLink:'Subscription link',copySub:'Copy subscription link',
  singleCfg:'Individual configs',copy:'Copy',copied:'Copied ✓',
  devTitle:'Connected devices',noConn:'No connections recorded yet',
  clearIps:'Clear devices & IPs',delDevice:'Remove device',delDeviceWarn:'Remove this device from the list? (frees a slot)',unknownClient:'Unknown',devLimitLbl:'Allowed',onlineTag:'Online',offlineTag:'Offline',
  devSec:'Devices',ipSec:'IP addresses',ipCounted:'IPs counted toward the limit',ipsTotal:'Total IPs ever seen',delIp:'Remove IP',delIpWarn:'Remove this IP from the list? (frees a slot)',
  liveNow:'Connected now',noneNow:'No device connected right now',
  countedFor:'Counted toward the limit',totalSeen:'Total devices ever seen',
  showHistory:'Show history',showLive:'Show only connected',
  inLast:'in the last %ss',refresh:'Refresh',
  liveDevices:'Devices live now',
  editUser:'Edit',remainDays:'Days remaining',allowedDev:'Allowed devices',allowedIp:'Allowed IPs',
  active:'Enabled',saveBtn:'Save',resetTraffic:'Reset traffic',newUuid:'New UUID',
  customUuid:'Custom UUID',del:'Delete',
  obfLbl:'Obfuscation (Fragment + Cipher mask)',
  echLbl:'Anti-censorship (Ech)',
  fpLbl:'TLS fingerprint',alpnLbl:'ALPN',alpnDef:'This transport\'s default',alpnNone:'No ALPN (omit from link)',
  uuidWarn:'Rotate UUID? Existing configs will stop working.',delWarn:'Delete this user?',
  cleanTitle:'Clean IP manager',
  cleanHint:'Clean IPs or domains. Added to every subscription as extra configs.',
  addrPh:'e.g. 1.2.3.4 or cdn.example.com',remarkPh:'Label (optional)',
  bulkPh:'One per line:\n1.2.3.4 # Irancell\n5.6.7.8 # MCI',
  bulkAdd:'Bulk add',clearAll:'Delete all',
  pxTitle:'Outbound proxy',
  pxHint:'While a proxy is armed, user traffic leaves through it and sites see the proxy IP.',
  pxKind:'Type',pxHost:'Host / IP',pxPort:'Port',
  pxUser:'Username (optional)',pxPass:'Password (optional)',
  pxAdd:'Add & test',pxTestAll:'Test all',
  pxInSub:'in subscriptions',
  pxAutoNote:'Added proxies appear automatically in every user\'s subscription. The direct config always stays — a failed test removes nothing.',
  pxLineHint:'One proxy per line — e.g. socks5://1.1.1.1:5866 or http://user:pass@2.2.2.2:8080',
  pxAddLines:'Add list & test',
  pxAdvanced:'Enter fields manually',
  pxDirect:'Direct connection (no proxy)',
  pxActive:'Active',pxArm:'Activate',pxTest:'Health test',
  pxPause:'Pause this proxy',pxResume:'Enable this proxy',pxDel:'Delete',
  pxHealthy:'healthy',pxDown:'down',pxUntested:'untested',
  pxExitIp:'Exit IP',pxLatency:'Latency',
  pxNone:'No proxy added yet',
  pxStrict:'Strict mode',
  pxStrictHint:'If the proxy breaks, refuse the connection instead of leaking the server IP',
  pxFlagSrc:'Flag shown in config names',
  pxFlagProxy:'Proxy country',pxFlagEntry:'Entry server country',
  pxTesting:'Testing...',pxArmed:'Proxy armed',
  pxDelWarn:'Delete this proxy?',
  addedN:'added',dupN:'duplicates',invalidN:'invalid',noCleanIps:'List is empty',
  settings:'Settings',appearance:'Appearance',theme:'Theme',language:'Language',
  thDark:'Dark (black & blue)',thLight:'Light (white & blue)',thGray:'Gray',
  country:'Country',autoCountry:'Auto detect',mainCountry:'Main server country',
  flagsHint:'The country flag is prepended to every config name in the subscription.',
  savedOk:'Saved',save:'Save',
  changePw:'Change password',curPw:'Current password',newPw:'New password',
  pwChanged:'Password changed ✓',
  serverInfo:'Server info',wsPathLbl:'WebSocket path',xhPathLbl:'XHTTP path',
  xhModeLbl:'XHTTP mode',
  xhModeHint:'packet-up sends one request per upload chunk. Behind a Cloudflare relay pick stream-up so each connection costs only 2 requests.',
  trWarnTitle:'XHTTP request cost:',
  trWarn:'XHTTP costs several requests per connection. stream-up is 2 per connection; packet-up is one per upload chunk, which burns a Cloudflare Worker\'s daily quota fast. WS is a single request for the whole connection.',
  backupTitle:'Backup',
  backupHint:'All users with their UUIDs and tokens, clean IPs, proxies and settings are saved into one .ixpbak file.',
  bkInclPw:'include the panel password',
  bkInclProxyCreds:'include proxy usernames and passwords',
  bkInclTraffic:'include traffic history (larger file)',
  bkSecretWarn:'This file contains the panel password and your proxy credentials — treat it like a password.',
  btnBackupLbl:'Download backup',
  restoreTitle:'Restore',
  pickFile:'Choose an .ixpbak file',
  restoreHint:'Pick a .ixpbak file. Its contents are shown first; nothing is written until you confirm.',
  restoreMode:'Restore mode',
  bkMerge:'Merge — update matching entries, add the rest',
  bkReplace:'Replace — wipe current users, clean IPs and proxies first',
  bkRestorePwLbl:'also restore the panel password from the file',
  btnRestoreLbl:'Restore now',
  bkReading:'Reading file…',
  bkBadFile:'File cannot be read, or is not a backup from this panel',
  bkFrom:'Created',bkUsersN:'users',bkCipsN:'clean IPs',bkProxN:'proxies',
  bkTrafficN:'traffic rows',
  bkHasPw:'includes the panel password',bkNoPw:'no panel password',
  bkProxCreds:'proxies with credentials',
  bkEnvDiff:'These variables differ from this panel and must be set by hand in Railway/Render:',
  bkReplaceWarn:'All current users, clean IPs and proxies will be deleted and replaced by the file. Continue?',
  bkPwChanged:'The panel password was restored from the file — sign in with that file\'s password next time.',
  bkDone:'Restore complete',
  resetCycle:'Usage reset cycle',resetOff:'Off',reset1:'Daily (1 day)',reset3:'Every 3 days',
  reset7:'Weekly (7 days)',reset14:'Every 14 days (2 weeks)',reset30:'Monthly (30 days)',
  reset60:'Every 60 days (2 months)',reset90:'Every 90 days (3 months)',resetCustom:'Custom',customDays:'Days (1–365)',
  tgTitle:'Telegram backup',
  tgHint:'A full backup file is sent to your Telegram chat. Get the token from BotFather and the chat ID from userinfobot. For a group the ID starts with -100 and the bot must be a member.',
  tgTokenLbl:'Bot Token',tgChatLbl:'Chat ID',tgAutoLbl:'Automatic daily backup',
  tgTestBtn:'Test message',tgNowBtn:'Send backup now',
  tgWorking:'Contacting Telegram…',tgSent:'Sent to Telegram ✓',
  tgFromEnv:'set by environment variable',tgNotSet:'not set',
  bkAdded:'added',bkUpdated:'updated',bkSkipped:'skipped',
  relayLbl:'Relay domain',keepAliveLbl:'Keep-alive',relayNone:'none',
  onLbl:'on',offLbl:'off',
  devWinLbl:'Device counting window',seconds:'seconds',
  ipWinLbl:'IP counting window',
  envNote:'These come from environment variables and can be changed in Railway.',
  logout:'Sign out',logs:'Events',noLogs:'No events yet',
  navFilter:'Site filter',
  fltTitle:'Content filtering & censorship',
  fltHint:'Connections to the listed sites are refused. The destination is read from the VLESS header, so it is blocked before the connection opens.',
  fltEnable:'Filter enabled',
  fltEnableHint:'When off, nothing is blocked.',
  fltPorn:'Auto-block adult content',
  fltPornHint:'A built-in list of porn sites and keywords.',
  fltRules:'Blocking rules',
  fltKindDomain:'Domain (and subdomains)',
  fltKindKeyword:'Keyword (anywhere in the host)',
  fltAdd:'Add rule',
  fltBulk:'Bulk add (one per line)',
  fltClear:'Clear all rules',
  fltClearWarn:'Delete every filter rule?',
  fltList:'Current rules',
  fltNone:'No rules yet',
  fltAdded:'rules added',
  fltDupe:'duplicate',
  fltDomain:'domain',fltKeyword:'keyword',
  fltOn:'Filter is on',fltOff:'Filter is off',
  echValueLbl:'Custom ECH value',obfCsLbl:'Custom cipher mask (cs)',obfFmLbl:'Custom obfuscation value (fm)',
  optDefault:'Panel default',
  custLbl:'Custom ECH / obfuscation values (optional)',
  custHint:'These only apply when the matching toggle above is on: ECH needs the "ECH config" checkbox; cs and fm only ride the WS link with the "obfuscated link" checkbox. After saving, refresh the subscription in your client.',
  statusDisabled:'disabled',statusExpired:'expired',statusQuota:'quota used',
  navTgweb:'Telegram Web Proxy',
  tgwNew:'Create web proxy',
  tgwHint:'With this feature you can create a Telegram proxy with a secret of your choice: it deploys a Telegram web proxy using the WEB Proxy protocol on your own account and hands it over.',
  tgwPlatform:'Hosting',
  tgwPlRender:'Render',tgwPlRailway:'Railway',tgwPlExternal:'External',
  tgwCarrier:'Carrier',
  tgwRegion:'Hosting region',
  tgwRegionHostDefault:'Host default (no region set)',
  tgwRegionHint:'Changing the region redeploys the service in the new region on the same domain (a few minutes) — every issued link stays valid. The real region is read back from the host on every sync.',
  tgwRegionLock:"Render services can't move to another region after creation",
  tgwTokenMissing:'No API token stored for this platform — add it in Platform settings first',
  tgwSetBtn:'Platform settings',
  tgwSet:'Proxy hosting platform',
  tgwSetSub:'For the panel to build proxies itself, store an API token of the hosting platform here (Render: Account Settings → API Keys; Railway: Account Settings → Tokens). Tokens are stored only in this panel. Repo and branch use their defaults (the project repo, branch main) and each proxy is built from that repo\'s tproxy folder — so push the tproxy folder to GitHub first.',
  tgwSetSubSelf:'This panel is hosted on {p}; building a Telegram web proxy therefore needs the {p} API token — get it from your own account and paste it into the field below.',
  tgwRenderToken:'Render API token (rnd_…)',tgwRailwayToken:'Railway API token',
  tgwNoKeys:'No keys saved yet.',tgwActive:'Active',tgwUse:'Use',tgwAddKey:'Add',tgwNewKey:'Paste a new API key…',tgwKeyRequired:'Paste an API key first',tgwKeyAdded:'Key added ✓',tgwKeyDeleted:'Key deleted',tgwDelKeyQ:'Delete this API key? It can no longer deploy proxies.',
  tgwSetSaved:'Saved ✓',
  tgwBuildHint:'Builds usually take 2–4 minutes; if it takes longer, hit the ⟳ button to re-read the state from the platform',
  tgwBuilding:'Building',tgwLive:'Ready',tgwFailed:'Failed',tgwSuspended:'Suspended',
  tgwSync:'Check build status',tgwNoServer:'The link appears here once deployed',
  tgwRotateWarnPl:'Rotate the secret? All previous links stop working and the service on {p} redeploys (takes a few minutes).',
  tgwDelWarnPl:'Delete this proxy? Its service on {p} will be deleted from the platform as well.',
  tgwPauseWarn:'Pause this proxy? The service goes to sleep but keeps its hostname — turning it back on restores every link.',
  tgwServer:'Server (domain)',tgwLabel:'Label (optional)',tgwSecret:'Secret (32 hex chars)',
  tgwGen:'New secret',
  tgwZeroInf:'0 = unlimited. Each proxy quota and lifetime is recorded here; the list below shows the live status (active / expired / quota used).',
  tgwList:'Web proxies',tgwNone:'No web proxies yet',
  tgwLink:'Telegram join link',tgwCopyLink:'Copy link',tgwOpen:'Open in Telegram',
  tgwRotate:'Rotate this proxy secret',
  tgwRotateWarn:'Rotate the secret? All links previously issued for this proxy stop working.',
  tgwEdit:'Edit web proxy',tgwDelWarn:'Delete this web proxy?',
 }
};
let LANG='en';  /* فقط انگلیسی */
const THEMES=['gray','light'];
let THEME=localStorage.getItem('theme')||'gray';
if(!THEMES.includes(THEME)){THEME=(THEME==='light')?'light':'gray';localStorage.setItem('theme',THEME)}
const T=k=>I18N[LANG][k]||k;
function applyChrome(){
 document.documentElement.lang=LANG;
 document.documentElement.dir=I18N[LANG].dir;
 document.documentElement.dataset.theme=THEME;
}
function setLang(l){LANG='en';applyChrome();if(window.rerender)rerender()}
function setTheme(t){THEME=t;localStorage.setItem('theme',t);applyChrome();if(window.onTheme)onTheme()}
applyChrome();
"""

AUTH_HTML = r"""<!DOCTYPE html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}}</title>
<link rel="icon" type="image/png" href="__LOGO__">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>__THEME__
body{min-height:100vh;display:grid;place-items:center;padding:18px;position:relative}
.bg-glow{position:fixed;inset:0;pointer-events:none;
  background:
   radial-gradient(58% 55% at 50% -8%,rgba(34,239,157,.20),transparent 70%),
   radial-gradient(44% 44% at 90% 104%,rgba(198,242,78,.10),transparent 72%)}
.auth{position:relative;width:100%;max-width:392px;background:var(--s1);
  border:1px solid var(--line);border-radius:16px;padding:26px 24px;
  box-shadow:0 30px 70px -30px rgba(0,0,0,.9)}
.auth .top{display:flex;gap:7px;justify-content:flex-end;margin-bottom:16px}
.auth .brandlogo{width:64px;height:64px;margin:0 auto 16px;border-radius:17px;display:block;
  object-fit:cover;background:#000;
  box-shadow:0 0 0 1px var(--line2),0 16px 34px -14px rgba(34,239,157,.7)}
.auth h1{margin:0;text-align:center;font-size:18px;font-weight:700;letter-spacing:-.3px}
.auth .sub{margin:6px 0 20px;text-align:center;font-size:11.5px;color:var(--tx3);line-height:1.9}
.auth .go{width:100%;margin-top:8px;justify-content:center;padding:11px}
.auth .fldlabel{font-size:11px;color:var(--tx3);margin-bottom:4px;display:block}
.auth .foot{text-align:center;font-size:9.5px;color:var(--tx3);margin-top:16px;
  font-family:'JetBrains Mono',monospace;letter-spacing:.4px}
</style></head><body>
<script>__I18N__</script>
<div class="bg-glow"></div>
<div class="auth">
 <div class="top">
  <select id="thSel" class="hidden"><option value="light"></option><option value="gray"></option></select>
  <button class="icon-btn" type="button" title="theme" id="btnTh"
    onclick="setTheme(THEMES[(THEMES.indexOf(THEME)+1)%THEMES.length])">
   <svg class="ic" viewBox="0 0 24 24"><path d="M20.5 14.5A8.5 8.5 0 1110 3.7a7 7 0 0010.5 10.8z"/></svg></button>
 </div>
 <img class="brandlogo" src="__LOGO__" alt="IranX">
 <h1 id="h1"></h1>
 <p id="sub" class="sub"></p>
 <div class="space-y-2">
  <div>
   <span class="fldlabel" id="l1"></span>
   <input id="p1" type="password" class="inp" autocomplete="current-password">
  </div>
  <div id="p2wrap">
   <span class="fldlabel" id="l2"></span>
   <input id="p2" type="password" class="inp" autocomplete="new-password">
  </div>
  <p id="rule" class="text-xs dim hidden" style="margin:0"></p>
  <button id="go" class="btn go"></button>
  <p id="err" class="text-sm" style="text-align:center;color:var(--bad);min-height:18px;margin:0"></p>
 </div>
 <div class="foot">IranX · Xray Panel</div>
</div>
<script>
const MODE="{{MODE}}";
thSel.value=THEME;
function syncTags(){}
function paint(){
 h1.textContent  = MODE==='setup'?T('setupTitle'):T('loginTitle');
 sub.textContent = MODE==='setup'?T('setupSub'):T('loginSub');
 l1.textContent  = T('password'); l2.textContent = T('confirm');
 p1.placeholder  = T('password'); p2.placeholder = T('confirm');
 go.textContent  = MODE==='setup'?T('save'):T('enter');
 rule.textContent= T('pwRule');
 const isSetup = MODE==='setup';
 p2wrap.classList.toggle('hidden', !isSetup);
 rule.classList.toggle('hidden', !isSetup);
 thSel.value=THEME;
}
window.rerender=paint; paint();
async function submit(){
 err.textContent='';go.disabled=true;
 try{
  const url = MODE==='setup'?'/api/setup':'/api/login';
  const body= MODE==='setup'?{password:p1.value,confirm:p2.value}:{password:p1.value};
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body)});
  if(r.ok){location.href='/panel';return}
  const j=await r.json().catch(()=>({}));
  err.textContent=j.detail||T('netErr');
 }catch(e){err.textContent=T('netErr')}
 go.disabled=false;
}
go.onclick=submit;
[p1,p2].forEach(el=>el.addEventListener('keydown',e=>{if(e.key==='Enter')submit()}));
</script></body></html>"""


PANEL_HTML = r"""<!DOCTYPE html><html lang="en" dir="ltr" data-theme="dark"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>{{TITLE}}</title>
<link rel="icon" type="image/png" href="__LOGO__">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>__THEME__</style>
</head><body>
<script>__I18N__</script>

<!-- ══════════ SIDEBAR ══════════ -->
<aside id="nav" aria-label="ناوبری اصلی">
 <div class="side-brand">
  <div class="brand-logo"><img src="__LOGO__" alt="" style="width:100%;height:100%;object-fit:cover"></div>
  <div class="brand-text"><b>{{TITLE}}</b><span>Xray Panel</span></div>
  <button class="side-collapse" onclick="toggleNav()" aria-label="بستن منو">
   <svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></svg></button>
 </div>
 <nav class="side-nav">
  <a class="navi on" data-page="dash" onclick="go('dash')">
   <svg class="ic" viewBox="0 0 24 24"><rect x="3.5" y="3.5" width="7.2" height="7.2" rx="2"/><rect x="13.3" y="3.5" width="7.2" height="7.2" rx="2"/><rect x="3.5" y="13.3" width="7.2" height="7.2" rx="2"/><rect x="13.3" y="13.3" width="7.2" height="7.2" rx="2"/></svg>
   <span data-t="navDash"></span></a>
  <a class="navi" data-page="users" onclick="go('users')">
   <svg class="ic" viewBox="0 0 24 24"><circle cx="9" cy="8" r="3.2"/><path d="M3.6 19.6c0-3 2.4-4.9 5.4-4.9s5.4 1.9 5.4 4.9"/><path d="M16.2 5.4a3.1 3.1 0 010 5.4"/><path d="M17.4 14.9c2.1.6 3.6 2.2 3.6 4.7"/></svg>
   <span data-t="navUsers"></span></a>
  <a class="navi" data-page="clean" onclick="go('clean')">
   <svg class="ic" viewBox="0 0 24 24"><path d="M12 3.2l7 2.6v5.5c0 4.3-3 7.7-7 9.5-4-1.8-7-5.2-7-9.5V5.8l7-2.6z"/><path d="M8.9 12.2l2.2 2.2 4.1-4.4"/></svg>
   <span data-t="navClean"></span></a>
  <a class="navi" data-page="filter" onclick="go('filter')">
   <svg class="ic" viewBox="0 0 24 24"><path d="M3.6 5h16.8l-6.6 7.6V20l-3.8-2.2v-5.2z"/></svg>
   <span data-t="navFilter"></span></a>
  <a class="navi" data-page="live" onclick="go('live')">
   <svg class="ic" viewBox="0 0 24 24"><path d="M3 12h3.4l2.1-6 3.6 12 2.4-6H21"/></svg>
   <span data-t="navLive"></span></a>
  <a class="navi" data-page="proxy" onclick="go('proxy')">
   <svg class="ic" viewBox="0 0 24 24"><circle cx="6" cy="12" r="2.4"/><circle cx="18" cy="6" r="2.4"/><circle cx="18" cy="18" r="2.4"/><path d="M8.3 11.1l7.4-4.2M8.3 12.9l7.4 4.2"/></svg>
   <span data-t="navProxy"></span></a>
  <a class="navi" data-page="tgweb" onclick="go('tgweb')">
   <svg class="ic" viewBox="0 0 24 24"><path d="M20.6 5.4L3.7 11.9l6.1 2.2 2.2 6.1 8.6-14.8z"/><path d="M9.8 14.1l4.6-4.6"/></svg>
   <span data-t="navTgweb"></span></a>
  <a class="navi" data-page="settings" onclick="go('settings')">
   <svg class="ic" viewBox="0 0 24 24"><path d="M4 7.5h9M17.5 7.5H20M4 16.5h2.5M11 16.5h9"/><circle cx="15" cy="7.5" r="2.3"/><circle cx="8.5" cy="16.5" r="2.3"/></svg>
   <span data-t="navSettings"></span></a>
  <a class="navi" data-page="logs" onclick="go('logs')">
   <svg class="ic" viewBox="0 0 24 24"><rect x="3" y="4.5" width="18" height="15" rx="3"/><path d="M7.4 10l2.4 2-2.4 2M12.6 14h4"/></svg>
   <span data-t="navLogs"></span></a>
 </nav>
 <div class="side-foot">
  <label class="fld"><span class="text-xs dim" data-t="appearance"></span>
   <select id="thSel" onchange="setTheme(this.value)" class="inp">
    <option value="light" data-t="thLight"></option>
    <option value="gray" data-t="thGray"></option></select></label>
  <button onclick="logout()" id="btnOut" class="btn btn-danger" style="width:100%;justify-content:center"></button>
 </div>
</aside>

<div id="scrim" class="hidden" onclick="closeDrawer()"></div>

<!-- ══════════ APP ══════════ -->
<div id="app">
 <header class="appbar">
 <button class="icon-btn" onclick="toggleNav()" aria-label="منو" id="btnBurger" style="width:36px;height:36px;flex:0 0 36px">
  <svg class="ic" viewBox="0 0 24 24" style="width:17px;height:17px"><path d="M4 7h16M4 12h16M4 17h16"/></svg></button>
 <img class="logo" src="__LOGO__" alt="">
 <div class="ttl">
  <h1>{{TITLE}}</h1>
  <span id="crumb" class="crumb"></span>
 </div>
 <div class="flex-1"></div>
 <span id="pill" class="path-pill mono"></span>
 <button class="icon-btn" onclick="setTheme(THEMES[(THEMES.indexOf(THEME)+1)%THEMES.length])"
         title="تم" aria-label="تغییر تم" style="width:34px;height:34px;flex:0 0 34px">
  <svg class="ic" viewBox="0 0 24 24" style="width:16px;height:16px"><path d="M20.5 14.5A8.5 8.5 0 1110 3.7a7 7 0 0010.5 10.8z"/></svg></button>
</header>

 <main class="content">
  <div class="ph">
   <div class="ph-t">
    <h1 id="phTitle"></h1>
    <p class="sub" id="phSub"></p>
   </div>
   <div class="acts" id="phActs"></div>
  </div>

  <!-- ══ DASHBOARD ══ -->
  <!-- ══ DASHBOARD ══ -->
  <section data-pg="dash">
   <div class="strip">
    <div class="cell">
     <div class="k"><i></i><span data-t="totalUsers"></span></div>
     <div class="v" id="sUsers">—</div>
     <div class="d"><span data-t="statHintUsers"></span></div>
    </div>
    <div class="cell">
     <div class="k"><i></i><span data-t="online"></span></div>
     <div class="v" id="sOnline" style="color:var(--acid)">—</div>
     <div class="d"><span data-t="statHintOnline"></span></div>
    </div>
    <div class="cell">
     <div class="k"><i></i><span data-t="devices"></span></div>
     <div class="v" id="sDev">—</div>
     <div class="d"><span data-t="statHintDev"></span></div>
    </div>
    <div class="cell">
     <div class="k"><i></i><span data-t="traffic"></span></div>
     <div class="v" id="sBytes">—</div>
     <div class="d"><span data-t="statHintBytes"></span></div>
    </div>
    <div class="cell">
     <div class="k"><i></i><span data-t="cleanIps"></span></div>
     <div class="v" id="sCip">—</div>
     <div class="d"><span data-t="statHintCip"></span></div>
    </div>
    <div class="cell">
     <div class="k"><i></i><span data-t="liveDevices"></span></div>
     <div class="v" id="sLive" style="color:var(--brand)">—</div>
     <div class="d"><span data-t="statHintLive"></span></div>
    </div>
   </div>

   <div class="g a" style="display:grid;grid-template-columns:1.6fr 1fr;gap:14px;margin-bottom:14px">
    <div class="card">
     <div class="card-head">
      <svg class="ic" viewBox="0 0 24 24" style="width:15px;height:15px;stroke:var(--acid);fill:none;stroke-width:1.8"
           width="15" height="15"><path d="M4 16l5-6 4 4 7-8"/></svg>
      <b data-t="chart24"></b>
      
      <div class="ms-auto" style="display:flex;gap:2px;padding:3px;border-radius:8px;
           background:var(--s2);border:1px solid var(--line2)">
       <span class="chip" style="border:0;background:transparent;color:var(--acid)">
         <span data-t="r24">۲۴ ساعت</span></span>
      </div>
     </div>
     <div style="padding:12px">
      <canvas id="chart" height="150"></canvas>
     </div>
    </div>

    <div class="card">
     <div class="card-head">
      <svg viewBox="0 0 24 24" style="width:15px;height:15px;stroke:var(--acid);fill:none;stroke-width:1.8">
        <path d="M4 6h16M4 12h10M4 18h6"/></svg>
      <b data-t="protoSplit"></b>
     </div>
     <div id="protoBox" style="padding:14px 15px;display:flex;flex-direction:column;gap:9px"></div>
    </div>
   </div>

   <div class="card">
    <div class="card-head">
     <svg viewBox="0 0 24 24" style="width:15px;height:15px;stroke:var(--acid);fill:none;stroke-width:1.8">
       <rect x="3" y="4.5" width="18" height="15" rx="3"/><path d="M7.4 10l2.4 2-2.4 2M12.6 14h4"/></svg>
     <b data-t="liveTitle"></b>
     <a class="chip ms-auto" onclick="go('live')" style="cursor:pointer">
       <span data-t="viewAll">همه</span>
       <svg viewBox="0 0 24 24" style="width:11px;height:11px;stroke:currentColor;fill:none;stroke-width:2.2">
         <path d="M15 6l-6 6 6 6"/></svg></a>
    </div>
    <div id="dashLive"><div class="lrow"><span class="dim" data-t="loadingLbl"></span></div></div>
   </div>
  </section>


  <!-- ══ USERS ══ -->
  <!-- ══ USERS ══ -->
  <section data-pg="users" class="hidden">
   <div class="card">
    <div class="card-head">
     <label class="fld" style="flex:1;max-width:280px">
      <input id="q" oninput="renderUsers()" class="inp" autocomplete="off">
     </label>
     <span id="uCount" class="chip ms-auto"></span>
    </div>
    <div id="rows"></div>
   </div>
  </section>

  <!-- ══ مودال ساخت کاربر (به‌جای فرم همیشه‌باز) ══ -->
  <div id="userModal" class="mwrap hidden" role="dialog" aria-modal="true" aria-labelledby="umTitle">
   <div class="sheet">
    <div class="sheet-head">
     <b id="umTitle" data-t="newUser"></b>
     <button class="x" onclick="closeUserForm()" aria-label="بستن">
      <svg viewBox="0 0 24 24" style="width:13px;height:13px;stroke:currentColor;fill:none;stroke-width:2.2;stroke-linecap:round">
        <path d="M6 6l12 12M18 6L6 18"/></svg>
     </button>
    </div>

    <div class="stabs" id="umTabs">
     <button class="on" data-pane="basic" data-t="tabBasic"></button>
     <button data-pane="limits" data-t="tabLimits"></button>
     <button data-pane="security" data-t="tabSecurity"></button>
    </div>

    <div class="sheet-body">

     <!-- ── پایه ── -->
     <div class="pane on" data-pane="basic">
      <div class="fld" style="margin-bottom:11px">
       <label data-t="name"></label>
       <input id="nName" class="inp" placeholder="ali_01" dir="ltr" autocomplete="off">
      </div>
      <div class="g2">
       <div class="fld">
        <label data-t="quota"></label>
        <input id="nQuota" type="number" step="0.5" value="30" class="inp">
       </div>
       <div class="fld">
        <label data-t="days"></label>
        <input id="nDays" type="number" value="30" class="inp">
       </div>
      </div>
      <div class="fld" style="margin-top:11px">
       <label data-t="transport"></label>
       <select id="nTr" class="inp">
        <option value="both"></option><option value="ws"></option><option value="xhttp"></option>
       </select>
      </div>
      <div class="notice" style="margin-top:13px">
       <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg>
       <span data-t="zeroInf"></span>
      </div>
     </div>

     <!-- ── محدودیت‌ها ── -->
     <div class="pane" data-pane="limits">
      <div class="g2">
       <div class="fld">
        <label data-t="devLimit"></label>
        <input id="nDev" type="number" value="1" class="inp">
       </div>
       <div class="fld">
        <label data-t="ipLimit"></label>
        <input id="nIp" type="number" value="0" class="inp">
       </div>
      </div>
      <div class="fld" style="margin-top:11px">
       <label data-t="resetCycle"></label>
       <select id="nReset" class="inp">
        <option value="0"></option><option value="1"></option><option value="3"></option>
        <option value="7"></option><option value="14"></option><option value="30"></option>
        <option value="60"></option><option value="90"></option><option value="-1"></option>
       </select>
      </div>
      <div class="fld hidden" id="nResetWrap" style="margin-top:11px">
       <label data-t="customDays"></label>
       <input id="nResetCustom" type="number" min="1" max="365" class="inp">
      </div>
      <p class="hint" data-t="zeroInfShort"></p>
      <p class="hint dev-device-hint" id="nDevHint" data-t="devLimitHint" style="margin-top:8px"></p>
     </div>

     <!-- ── امنیت ── -->
     <div class="pane" data-pane="security">
      <div class="fld" style="margin-bottom:11px">
       <label data-t="fpLbl"></label>
       <select id="nFp" class="inp"></select>
      </div>
      <div class="fld" style="margin-bottom:13px">
       <label data-t="alpnLbl"></label>
       <select id="nAlpn" class="inp"></select>
      </div>
      <div style="display:flex;flex-direction:column;gap:11px;padding:12px;
                  border-radius:10px;background:var(--s2);border:1px solid var(--line)">
       <label class="flex items-center gap-2" style="cursor:pointer">
        <input id="nObf" type="checkbox"><span data-t="obfLbl"></span></label>
       <label class="flex items-center gap-2" style="cursor:pointer">
        <input id="nEch" type="checkbox"><span data-t="echLbl"></span></label>
      </div>

      <details style="margin-top:13px">
       <summary class="text-xs dim" style="cursor:pointer;padding:6px 0" data-t="custLbl"></summary>
       <div style="margin-top:10px">
        <div class="fld">
         <label data-t="echValueLbl"></label>
         <input id="nEchVal" class="inp mono" style="font-size:11px"
                placeholder="cloudflare-ech.com+udp://1.1.1.1">
        </div>
        <div class="g2" style="margin-top:9px">
         <div class="fld">
          <label data-t="obfCsLbl"></label>
          <input id="nObfCs" class="inp mono" style="font-size:11px">
         </div>
         <div class="fld">
          <label data-t="obfFmLbl"></label>
          <textarea id="nObfFm" rows="3" spellcheck="false" class="inp mono" style="font-size:11px"></textarea>
         </div>
        </div>
        <p class="hint" style="color:var(--amber)" data-t="custHint"></p>
       </div>
      </details>
     </div>

    </div>

    <div class="sheet-foot">
     <button onclick="createUser()" id="btnAdd" class="btn"></button>
     <button class="btn btn-soft" onclick="closeUserForm()" data-t="cancel"></button>
     <p id="cErr" class="err"></p>
    </div>
   </div>
  </div>


  <!-- ══ CLEAN IP ══ -->
  <section data-pg="clean" class="hidden">
   <div class="card p-4">
    <b class="text-base" data-t="cleanTitle"></b>
    <p class="text-xs dim mt-1 mb-3" data-t="cleanHint"></p>
    <div class="g4">
     <input id="cAddr" class="inp" style="grid-column:span 2">
     <input id="cRem" class="inp">
     <select id="cCty" class="inp"></select>
    </div>
    <div class="flex flex-wrap gap-2 mt-3">
     <button onclick="addCip()" id="btnCipAdd" class="btn"></button>
    </div>
    <textarea id="cBulk" rows="4" class="inp mono mt-3"></textarea>
    <div class="g2 mt-2">
     <button onclick="bulkCip()" id="btnBulk" class="btn btn-soft"></button>
     <button onclick="clearCips()" id="btnClearAll" class="btn btn-danger"></button>
    </div>
    <p id="cipMsg" class="text-xs dim mt-2" style="margin-bottom:0"></p>
   </div>
   <div class="card p-4 mt-4"><div id="cipRows" class="g2"></div></div>
  </section>

  <!-- ══ SITE FILTER ══ -->
  <section data-pg="filter" class="hidden">
   <div class="card p-4">
    <b class="text-base" data-t="fltTitle"></b>
    <p class="text-xs dim mt-1 mb-3" data-t="fltHint"></p>
    <div class="soft" style="border-radius:12px;padding:12px">
     <label class="flex items-center gap-2 text-sm">
      <input id="fOn" type="checkbox" onchange="saveFilterMode()">
      <b data-t="fltEnable"></b></label>
     <p class="text-xs dim" style="margin:5px 0 0" data-t="fltEnableHint"></p>
    </div>
    <div class="soft mt-3" style="border-radius:12px;padding:12px">
     <label class="flex items-center gap-2 text-sm">
      <input id="fPorn" type="checkbox" onchange="saveFilterMode()">
      <b data-t="fltPorn"></b></label>
     <p class="text-xs dim" style="margin:5px 0 0"><span data-t="fltPornHint"></span>
      <span id="fPornN" class="mono"></span></p>
    </div>
    <p id="fMsg" class="text-xs mt-2" style="margin-bottom:0;color:var(--ok)"></p>
   </div>

   <div class="card p-4 mt-4">
    <b class="text-base" data-t="fltRules"></b>
    <div class="g2 mt-3">
     <input id="frPat" class="inp mono" placeholder="example.com">
     <select id="frKind" class="inp">
      <option value="domain" data-t="fltKindDomain"></option>
      <option value="keyword" data-t="fltKindKeyword"></option></select>
    </div>
    <button onclick="addFilterRule()" id="btnFrAdd" class="btn w-full mt-2"></button>
    <textarea id="frBulk" rows="5" spellcheck="false" class="inp mono mt-3"
      placeholder="example.com&#10;*.blocked-site.net&#10;porn-keyword"></textarea>
    <div class="g2 mt-2">
     <button onclick="bulkFilter()" id="btnFrBulk" class="btn btn-soft"></button>
     <button onclick="clearFilter()" id="btnFrClear" class="btn btn-danger"></button>
    </div>
    <p id="frMsg" class="text-xs dim mt-2" style="margin-bottom:0"></p>
   </div>

   <div class="card mt-4" style="overflow:hidden">
    <div class="card-head"><b class="text-base" data-t="fltList"></b>
     <span id="frCount" class="chip teal ms-auto"></span></div>
    <div id="frRows"></div>
   </div>
  </section>

  <!-- ══ PROXY ══ -->
  <section data-pg="proxy" class="hidden">
   <div class="card p-4">
    <b class="text-base" data-t="pxTitle"></b>
    <p class="text-xs dim mt-1 mb-3" data-t="pxHint"></p>
    <textarea id="pBulk" rows="3" spellcheck="false" class="inp mono"
      placeholder="socks5://1.1.1.1:5866"></textarea>
    <p class="text-xs dim mt-1" data-t="pxLineHint"></p>
    <button onclick="addBulk()" class="btn w-full mt-2" data-t="pxAddLines"></button>
    <details class="mt-3">
     <summary class="text-xs dim" style="cursor:pointer" data-t="pxAdvanced"></summary>
     <div class="g3 mt-3">
      <label class="fld"><span class="text-xs dim" data-t="pxKind"></span>
       <select id="pKind" class="inp"><option value="socks5">SOCKS5</option>
        <option value="socks4">SOCKS4</option><option value="http">HTTP</option></select></label>
      <label class="fld"><span class="text-xs dim" data-t="pxHost"></span>
       <input id="pHost" class="inp mono" placeholder="1.2.3.4"></label>
      <label class="fld"><span class="text-xs dim" data-t="pxPort"></span>
       <input id="pPort" type="number" class="inp mono" placeholder="1080"></label>
      <label class="fld"><span class="text-xs dim" data-t="pxUser"></span>
       <input id="pUser" class="inp mono"></label>
      <label class="fld"><span class="text-xs dim" data-t="pxPass"></span>
       <input id="pPass" type="password" class="inp mono"></label>
      <label class="fld"><span class="text-xs dim" data-t="remarkPh"></span>
       <input id="pRem" class="inp"></label>
     </div>
    </details>
    <div class="g2 mt-3">
     <button onclick="addProxy()" class="btn" data-t="pxAdd"></button>
     <button onclick="testAllProxies()" class="btn btn-soft" data-t="pxTestAll"></button>
    </div>
    <p id="pxMsg" class="text-xs dim mt-2" style="margin-bottom:0"></p>
   </div>

   <div class="card p-4 mt-4 space-y-3">
    <div class="flex items-center gap-3">
     <div class="flex-1">
      <b class="text-base" data-t="pxStrict"></b>
      <p class="text-xs dim" style="margin:0" data-t="pxStrictHint"></p>
     </div>
     <button id="pxStrictBtn" onclick="toggleStrict()" class="sw"></button>
    </div>
    <label class="fld"><span class="text-xs dim" data-t="pxFlagSrc"></span>
     <select id="pxFlagSel" onchange="saveFlagSource()" class="inp">
      <option value="proxy" data-t="pxFlagProxy"></option>
      <option value="entry" data-t="pxFlagEntry"></option></select></label>
   </div>

   <div class="card p-4 mt-4">
    <p class="text-xs dim" style="margin:0 0 12px" data-t="pxAutoNote"></p>
    <div id="pxRows" class="space-y-2"></div>
   </div>
  </section>

  <!-- ══ TELEGRAM WEB PROXY ══ -->
  <section data-pg="tgweb" class="hidden">
   <div class="card p-4">
    <div class="flex items-center gap-2">
     <b class="text-base flex-1" data-t="tgwNew"></b>
     <button onclick="openTgSettings()" id="btnTgSet" class="btn btn-soft"
             style="padding:7px 12px;font-size:12px"></button>
    </div>
    <p class="text-xs dim mt-1 mb-3" data-t="tgwHint"></p>
    <div class="seg" id="tgPlatSeg" style="margin:10px 0 4px">
     <button onclick="tgPickPlatform('render')" id="tgPlRender" class="on"></button>
     <button onclick="tgPickPlatform('railway')" id="tgPlRailway"></button>
    </div>
    <div class="g3 mt-3">
     <label class="fld"><span class="text-xs dim" data-t="tgwCarrier"></span>
      <select id="tgCarrier" class="inp">
       <option value="websocket">WebSocket</option>
       <option value="websocket-lanes">WebSocket (lanes)</option>
       <option value="https">HTTPS</option>
       <option value="https-lanes">HTTPS (lanes)</option>
      </select></label>
     <label class="fld hidden" id="tgRegionFld"><span class="text-xs dim" data-t="tgwRegion"></span>
      <select id="tgRegion" class="inp" dir="ltr"></select></label>
     <label class="fld"><span class="text-xs dim" data-t="tgwLabel"></span>
      <input id="tgLabel" class="inp"></label>
     <label class="fld"><span class="text-xs dim" data-t="tgwSecret"></span>
      <div class="flex gap-2">
       <input id="tgSecret" class="inp mono" style="font-size:11.5px" dir="ltr">
       <button onclick="genSecret(true)" id="btnTgGen" class="btn btn-soft"
               style="flex:0 0 auto;padding:8px 12px"></button>
      </div></label>
     <label class="fld"><span class="text-xs dim" data-t="quota"></span>
      <input id="tgQuota" type="number" step="0.5" value="0" class="inp"></label>
     <label class="fld"><span class="text-xs dim" data-t="days"></span>
      <input id="tgDays" type="number" value="0" class="inp"></label>
    </div>
    <div class="flex flex-wrap items-center gap-3 mt-3">
     <button onclick="createTgweb()" id="btnTgAdd" class="btn"></button>
     <span class="text-xs dim" data-t="tgwZeroInf"></span>
    </div>
    <p id="tgErr" class="text-sm mt-2" style="color:var(--bad);margin-bottom:0"></p>
   </div>

   <div class="card mt-4" style="overflow:hidden">
    <div class="card-head"><b class="text-base" data-t="tgwList"></b></div>
    <div id="tgRows"></div>
   </div>
  </section>

  <!-- ══ SETTINGS ══ -->
  <section data-pg="settings" class="hidden">
   <div class="card p-4">
    <b class="text-base" data-t="appearance"></b>
    <div class="g3 mt-3">
     <label class="fld"><span class="text-xs dim" data-t="theme"></span>
      <select id="thSel2" onchange="setTheme(this.value);syncSelects()" class="inp">
       <option value="light" data-t="thLight"></option>
       <option value="gray" data-t="thGray"></option></select></label>
     <label class="fld"><span class="text-xs dim" data-t="mainCountry"></span>
      <div class="flex gap-2">
       <select id="mcSel" class="inp flex-1"></select>
       <button onclick="saveMainCountry()" id="btnMc" class="btn"></button>
      </div>
      <span class="text-xs dim" data-t="flagsHint"></span></label>
    </div>
   </div>

   <div class="card p-4 mt-4 space-y-2">
    <b class="text-base" data-t="changePw"></b>
    <input id="pwCur" type="password" class="inp">
    <input id="pwNew" type="password" class="inp">
    <p class="text-xs dim" style="margin:0" data-t="pwRule"></p>
    <button onclick="doChangePw()" id="btnPw" class="btn w-full"></button>
    <p id="pwMsg" class="text-sm" style="margin:0"></p>
   </div>

   <div class="card p-4 mt-4 space-y-2">
    <b class="text-base" data-t="serverInfo"></b>
    <div id="srvBox" class="space-y-2 text-sm"></div>
    <p class="text-xs dim" style="margin:0" data-t="envNote"></p>
   </div>

   <!-- ══ DEVICE LIMIT GATE ══ -->
   <div class="card p-4 mt-4 space-y-3" id="devGateCard">
    <b class="text-base" data-t="devGateTitle"></b>
    <p class="text-xs dim" style="margin:0" data-t="devGateSub"></p>
    <label class="flex items-start gap-2 text-sm" style="cursor:pointer">
     <input type="checkbox" id="dgOn" style="margin-top:3px">
     <span data-t="devGateOn"></span></label>
    <label class="flex items-start gap-2 text-sm" style="cursor:pointer">
     <input type="checkbox" id="dgTraffic" style="margin-top:3px">
     <span data-t="devGateTraffic"></span></label>
    <p class="text-xs dim" style="margin:0" data-t="devGateTrafficHint"></p>
    <div>
     <p class="text-xs dim" style="margin:0 0 6px" data-t="devGateApps"></p>
     <div id="dgApps" class="flex flex-wrap gap-2 text-sm"></div>
    </div>
   </div>

   <!-- ══ BACKUP & RESTORE ══ -->
   <div class="card p-4 mt-4 space-y-3">
    <b class="text-base" data-t="backupTitle"></b>
    <p class="text-xs dim" style="margin:0" data-t="backupHint"></p>
    <div id="bkInfo" class="space-y-2 text-sm"></div>
    <div class="flex flex-wrap gap-2 text-sm">
     <label class="chip" style="cursor:pointer"><input type="checkbox" id="bkPw" checked> <span data-t="bkInclPw"></span></label>
     <label class="chip" style="cursor:pointer"><input type="checkbox" id="bkPxCreds" checked> <span data-t="bkInclProxyCreds"></span></label>
     <label class="chip" style="cursor:pointer"><input type="checkbox" id="bkTraffic"> <span data-t="bkInclTraffic"></span></label>
    </div>
    <p class="notice" data-t="bkSecretWarn"></p>
    <button onclick="doBackup()" id="btnBackup" class="btn w-full"></button>

    <div class="pt-3 space-y-2" style="border-top:1px solid var(--line)">
     <b class="text-base" data-t="restoreTitle"></b>
     <p class="text-xs dim" style="margin:0" data-t="restoreHint"></p>
     <input type="file" id="bkFile" accept=".ixpbak,application/json,.json"
       onchange="pickBackup()" class="hidden">
     <label for="bkFile" class="btn btn-soft w-full file-pick">
       <span data-t="pickFile"></span>
       <span id="bkFileName" class="text-xs dim"></span>
     </label>
     <div id="bkPreview" class="space-y-2 text-sm"></div>
     <div id="bkOpts" class="hidden space-y-2">
      <label class="fld"><span class="text-xs dim" data-t="restoreMode"></span>
       <select id="bkMode" class="inp"><option value="merge"></option><option value="replace"></option></select></label>
      <label class="flex items-center gap-2 text-sm"><input type="checkbox" id="bkRestorePw"> <span data-t="bkRestorePwLbl"></span></label>
      <button onclick="doRestore()" id="btnRestore" class="btn w-full"></button>
     </div>
     <p id="bkMsg" class="text-sm" style="margin:0"></p>
    </div>
   </div>

   <!-- ══ TELEGRAM BACKUP ══ -->
   <div class="card p-4 mt-4 space-y-3">
    <b class="text-base" data-t="tgTitle"></b>
    <p class="text-xs dim" style="margin:0" data-t="tgHint"></p>
    <div class="g2">
     <label class="fld"><span class="text-xs dim" data-t="tgTokenLbl"></span>
      <input id="tgToken" type="password" autocomplete="new-password" class="inp mono" style="font-size:11px"></label>
     <label class="fld"><span class="text-xs dim" data-t="tgChatLbl"></span>
      <input id="tgChat" class="inp mono" style="font-size:11px" placeholder="123456789"></label>
    </div>
    <label class="flex items-center gap-2 text-sm"><input type="checkbox" id="tgAuto"> <span data-t="tgAutoLbl"></span></label>
    <div class="g2">
     <button onclick="tgTest()" id="btnTgTest" class="btn btn-soft" style="font-size:12px"></button>
     <button onclick="tgBackupNow()" id="btnTgNow" class="btn" style="font-size:12px"></button>
    </div>
    <p id="tgMsg" class="text-sm" style="margin:0"></p>
   </div>
  </section>

  <!-- ══ EVENTS ══ -->
  <section data-pg="logs" class="hidden">
   <div class="card p-4">
    <b class="text-base" data-t="logs"></b>
    <div id="logRows" class="space-y-2 mt-3"></div>
   </div>
  </section>

  <!-- ══ LIVE CONNECTIONS ══ -->
  <section data-pg="live" class="hidden">
   <div class="card" style="overflow:hidden">
    <div class="card-head">
     <b class="text-base" data-t="liveTitle"></b>
     <span id="liveCount" class="text-xs dim"></span>
    </div>
    <div id="liveRows"></div>
    <div id="liveEmpty" class="p-4 text-sm dim" style="text-align:center" data-t="liveEmpty"></div>
   </div>
  </section>
 </main>
</div>

<div id="modal" class="hidden">
 <div class="modal-card">
  <div class="modal-head"><b id="mTitle"></b>
   <button onclick="closeModal()" class="icon-btn ms-auto">✕</button></div>
  <div id="mBody" class="space-y-3 text-sm"></div>
 </div>
</div>
<div class="toast" id="toast"></div>

<script>
const esc=(s)=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const ICO={
 cfg:'<svg class="ic" viewBox="0 0 24 24"><path d="M10 13.5a4 4 0 005.66 0l2.83-2.83a4 4 0 10-5.66-5.66L11.4 6.4"/><path d="M14 10.5a4 4 0 00-5.66 0L5.5 13.33a4 4 0 105.66 5.66l1.42-1.42"/></svg>',
 ips:'<svg class="ic" viewBox="0 0 24 24"><rect x="2.8" y="5" width="12.5" height="8.5" rx="1.8"/><path d="M6.4 17.4h5.3M9 13.5v3.9"/><rect x="16.4" y="9.5" width="4.8" height="9.5" rx="1.6"/></svg>',
 edit:'<svg class="ic" viewBox="0 0 24 24"><path d="M4 20h4L19 9l-4-4L4 16v4z"/><path d="M14 6l4 4"/></svg>',
 del:'<svg class="ic" viewBox="0 0 24 24"><path d="M5 7h14M9.5 7V5h5v2M7 7l1 13h8l1-13"/></svg>',
 pause:'<svg class="ic" viewBox="0 0 24 24" style="width:15px;height:15px"><path d="M9.5 5v14M14.5 5v14"/></svg>',
 play:'<svg class="ic" viewBox="0 0 24 24" style="width:15px;height:15px"><path d="M7.5 5.2l11 6.8-11 6.8z"/></svg>',
 x:'<svg class="ic" viewBox="0 0 24 24" style="width:15px;height:15px"><path d="M6 6l12 12M18 6L6 18"/></svg>',
 ping:'<svg class="ic" viewBox="0 0 24 24" style="width:15px;height:15px"><path d="M3 12h4l2.5-6 4 12 2.5-6h5"/></svg>',
 copy:'<svg class="ic" viewBox="0 0 24 24" style="width:15px;height:15px"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 012-2h9"/></svg>',
 key:'<svg class="ic" viewBox="0 0 24 24" style="width:14px;height:14px"><circle cx="8" cy="15" r="3.5"/><path d="M10.5 13L19 4.5M16 7.5l2 2M13.5 10l2 2"/></svg>',
 refresh:'<svg class="ic" viewBox="0 0 24 24" style="width:15px;height:15px"><path d="M20 11a8 8 0 10-2.3 5.7M20 5v6h-6"/></svg>',
 link:'<svg class="ic" viewBox="0 0 24 24" style="width:15px;height:15px"><path d="M10 13.5a4 4 0 005.7 0l2.8-2.8a4 4 0 10-5.7-5.7L11.4 6"/><path d="M14 10.5a4 4 0 00-5.7 0l-2.8 2.8a4 4 0 105.7 5.7l1.4-1.4"/></svg>',
 send:'<svg class="ic" viewBox="0 0 24 24" style="width:15px;height:15px"><path d="M21 4L3 11l7 3 3 7z"/><path d="M21 4L10 14"/></svg>',
 shield:'<svg class="ic" viewBox="0 0 24 24" style="width:15px;height:15px"><path d="M12 3.2l7 2.6v5.5c0 4.3-3 7.7-7 9.5-4-1.8-7-5.2-7-9.5V5.8l7-2.6z"/><path d="M8.9 12.2l2.2 2.2 4.1-4.4"/></svg>',
 route:'<svg class="ic" viewBox="0 0 24 24" style="width:15px;height:15px"><circle cx="6" cy="12" r="2.4"/><circle cx="18" cy="6" r="2.4"/><circle cx="18" cy="18" r="2.4"/><path d="M8.3 11.1l7.4-4.2M8.3 12.9l7.4 4.2"/></svg>',
 sliders:'<svg class="ic" viewBox="0 0 24 24" style="width:15px;height:15px"><path d="M4 7.5h9M17.5 7.5H20M4 16.5h2.5M11 16.5h9"/><circle cx="15" cy="7.5" r="2.3"/><circle cx="8.5" cy="16.5" r="2.3"/></svg>',
 terminal:'<svg class="ic" viewBox="0 0 24 24" style="width:15px;height:15px"><rect x="3" y="4.5" width="18" height="15" rx="3"/><path d="M7.4 10l2.4 2-2.4 2M12.6 14h4"/></svg>'
};

/* ─── shell: منوی همبرگری در همه‌ی عرض‌ها ─── */
const isDesktop=()=>window.matchMedia('(min-width:1024px)').matches;
let navOpen=localStorage.getItem('navOpen')==='1';
function applyNav(){
 if(!navOpen) navOpen=false;
 document.body.classList.toggle('nav-open',navOpen);
 if(typeof scrim!=='undefined'&&scrim) scrim.classList.toggle('hidden',!navOpen);
 const b=document.getElementById('btnBurger');
 if(b) b.setAttribute('aria-expanded',navOpen?'true':'false');
 document.body.style.overflow=navOpen?'hidden':'';
}
function toggleNav(force){
 navOpen = force===undefined ? !navOpen : !!force;
 try{localStorage.setItem('navOpen',navOpen?'1':'0')}catch(e){}
 applyNav();
 if(navOpen) setTimeout(()=>{const c=document.querySelector('#nav .side-collapse');if(c)c.focus()},60);
}
function closeDrawer(){ if(navOpen){navOpen=false;applyNav()} }
window.addEventListener('resize',applyNav);
document.addEventListener('keydown',e=>{
 if(e.key==='Escape'&&navOpen){closeDrawer();return}
 if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='b'){e.preventDefault();toggleNav()}
});
document.addEventListener('click',e=>{
 if(!navOpen)return;
 if(e.target.closest('#nav')||e.target.closest('#btnBurger'))return;
 if(e.target.closest('.sel'))return;
 closeDrawer();
});

/* ─── country flags + helpers ─── */
var CC=['DE','NL','FR','GB','FI','SE','PL','AT','CH','ES','IT','RO','TR','RU','AE','QA','OM',
        'AM','GE','IN','SG','JP','KR','HK','CA','US','BR','AU','DK','NO','BE','CZ','HU','LT',
        'LV','EE','IE','UA','KZ','IR'];
function flagOf(c){ /* بدون اموجی */ return ''; 

 /* پرچم اموجی روی خیلی از اندرویدها به‌صورت مربع خالی دیده می‌شود؛
    به‌جایش کد دوحرفی کشور را برمی‌گردانیم. */
 return '';
}
var CN={DE:['آلمان','Germany'],NL:['هلند','Netherlands'],FR:['فرانسه','France'],
 GB:['بریتانیا','United Kingdom'],FI:['فنلاند','Finland'],SE:['سوئد','Sweden'],
 PL:['لهستان','Poland'],AT:['اتریش','Austria'],CH:['سوئیس','Switzerland'],
 ES:['اسپانیا','Spain'],IT:['ایتالیا','Italy'],RO:['رومانی','Romania'],
 TR:['ترکیه','Turkey'],RU:['روسیه','Russia'],AE:['امارات','UAE'],QA:['قطر','Qatar'],
 OM:['عمان','Oman'],AM:['ارمنستان','Armenia'],GE:['گرجستان','Georgia'],
 IN:['هند','India'],SG:['سنگاپور','Singapore'],JP:['ژاپن','Japan'],KR:['کره جنوبی','South Korea'],
 HK:['هنگ‌کنگ','Hong Kong'],CA:['کانادا','Canada'],US:['آمریکا','United States'],
 BR:['برزیل','Brazil'],AU:['استرالیا','Australia'],DK:['دانمارک','Denmark'],
 NO:['نروژ','Norway'],BE:['بلژیک','Belgium'],CZ:['چک','Czechia'],HU:['مجارستان','Hungary'],
 LT:['لیتوانی','Lithuania'],LV:['لتونی','Latvia'],EE:['استونی','Estonia'],
 IE:['ایرلند','Ireland'],UA:['اوکراین','Ukraine'],KZ:['قزاقستان','Kazakhstan'],IR:['ایران','Iran']};
function cName(c){var r=CN[c];if(!r)return c;return (LANG==='fa'?r[0]:r[1])+' · '+c;}
function fillCountry(sel,cur){
 if(!sel)return;
 sel.innerHTML='<option value="">'+T('autoCountry')+'</option>'+
  CC.map(c=>'<option value="'+c+'" data-cc="'+c+'">'+cName(c)+'</option>').join('');
 sel.value=cur||'';
}
var MAIN_CC='';
var PROXIES=[],PX_SUB=[],PX_ACTIVE=0,PX_STRICT=true,PX_FLAG='proxy';

/* ─── routing ─── */
let PAGE=localStorage.getItem('page')||'dash';
function go(p){
 if(!document.querySelector('[data-pg="'+p+'"]')) p='dash';
 PAGE=p; localStorage.setItem('page',p);
 document.querySelectorAll('[data-pg]').forEach(s=>s.classList.toggle('hidden',s.dataset.pg!==p));
 document.querySelectorAll('.navi').forEach(n=>n.classList.toggle('on',n.dataset.page===p));
 crumb.textContent=T({dash:'navDash',users:'navUsers',clean:'navClean',filter:'navFilter',
   proxy:'navProxy',tgweb:'navTgweb',live:'navLive',settings:'navSettings',logs:'navLogs'}[p]);
 closeDrawer();
 try{paintPageHead(p)}catch(_){}
 if(p==='logs')loadLogs();
 if(p==='clean')loadCips();
 if(p==='filter')loadFilter();
 if(p==='tgweb'){loadTgSettings();loadTgweb();loadTgRegions();tgPickPlatform(tgPlatform)}
 if(p==='settings'){renderServer();loadBackupInfo();loadTelegram();loadDeviceGate()}
 if(p==='live')loadLive(); else stopLive();
}

/* ─── formatting helpers ─── */
const fmt=b=>{if(!b)return '0 B';const u=['B','KB','MB','GB','TB'];let i=0,n=b;
 while(n>=1024&&i<u.length-1){n/=1024;i++}return n.toFixed(i?1:0)+' '+u[i]};
const dt=t=>t?new Date(t*1000).toLocaleString(LANG==='fa'?'fa-IR-u-nu-latn':'en-GB',
  {year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}):T('never');
const statusTxt=s=>({disabled:T('statusDisabled'),expired:T('statusExpired'),
 quota:T('statusQuota')}[s]||s);
const trTxt=t=>({ws:T('trWs'),xhttp:T('trXhttp'),both:T('trBoth')}[t]||t);
const FP_OPTIONS=['unsafe','chrome','firefox','safari','ios','android','edge','ie','qq','random'];
const ALPN_OPTIONS=['','http/1.1','h2','h2,http/1.1','-'];
function fillSelect(sel,opts,blankLbl){
 if(!sel)return;
 sel.innerHTML='';
 const b=document.createElement('option');b.value='';b.textContent=blankLbl;sel.appendChild(b);
 opts.forEach(v=>{const o=document.createElement('option');o.value=v;o.textContent=v||'—';sel.appendChild(o)});
}
function fillAlpn(sel){
 fillSelect(sel,ALPN_OPTIONS,T('alpnDef'));
 if(sel){const o=[...sel.options].find(x=>x.value==='-');if(o)o.textContent=T('alpnNone')}
}
let users=[],cips=[],stats={},logItems=[],chart;

async function api(p,o={}){
 const r=await fetch(p,{headers:{'Content-Type':'application/json'},...o});
 if(r.status===401){location.href='/login';throw new Error('auth')}
 if(!r.ok){const j=await r.json().catch(()=>({}));throw new Error(j.detail||'error')}
 return r.status===204?null:r.json();
}
async function logout(){await fetch('/api/logout',{method:'POST'});location.href='/login'}

/* ── device gate (settings card) ── */
async function loadDeviceGate(){
 const on=document.getElementById('dgOn'), tr=document.getElementById('dgTraffic'),
       box=document.getElementById('dgApps');
 if(!on)return;
 try{
  const r=await api('/api/device-gate');
  on.checked=!!r.gate; tr.checked=!!r.traffic;
  if(box) box.innerHTML=(r.apps||[]).map(a=>`<span class="chip teal">${esc(a)}</span>`).join('');
 }catch(e){}
}
async function saveDeviceGate(){
 const on=document.getElementById('dgOn'), tr=document.getElementById('dgTraffic');
 try{ await api('/api/device-gate',{method:'POST',
   body:JSON.stringify({gate:on.checked,traffic:tr.checked})}); }
 catch(e){}
}
document.addEventListener('change',e=>{
 if(e.target&&(e.target.id==='dgOn'||e.target.id==='dgTraffic')) saveDeviceGate();
});

function syncSelects(){
 [thSel,thSel2].forEach(e=>{if(e)e.value=THEME});
 ['langSel','langSel2'].forEach(i=>{const e=document.getElementById(i);if(e)e.value='en'});
}
window.onTheme=()=>{syncSelects();if(chart)paintChart()};

function paintStatic(){
 document.querySelectorAll('[data-t]').forEach(e=>e.textContent=T(e.dataset.t));
 btnOut.textContent=T('logout'); btnAdd.textContent=T('add');
 btnTgAdd.textContent=T('add'); btnTgGen.textContent=T('tgwGen');
 btnTgSet.textContent=T('tgwSetBtn');
 tgPlRender.textContent=T('tgwPlRender');
 tgPlRailway.textContent=T('tgwPlRailway');
 fillTgRegions(tgPlatform);
 btnCipAdd.textContent=T('add'); btnBulk.textContent=T('bulkAdd');
 btnClearAll.textContent=T('clearAll'); btnPw.textContent=T('saveBtn');
 btnFrAdd.textContent=T('fltAdd'); btnFrBulk.textContent=T('fltBulk');
 btnFrClear.textContent=T('fltClear');
 btnBackup.textContent=T('btnBackupLbl'); btnRestore.textContent=T('btnRestoreLbl');
 btnTgTest.textContent=T('tgTestBtn'); btnTgNow.textContent=T('tgNowBtn');
 bkMode.options[0].textContent=T('bkMerge');
 bkMode.options[1].textContent=T('bkReplace');
 nName.placeholder=T('name'); nQuota.placeholder=T('quota');
 nDays.placeholder=T('days'); nDev.placeholder=T('devLimit'); nIp.placeholder=T('ipLimit');
 q.placeholder=T('search');
 ['resetOff','reset1','reset3','reset7','reset14','reset30','reset60','reset90','resetCustom']
  .forEach((k,i)=>{ if(nReset.options[i]) nReset.options[i].textContent=T(k); });
 nReset.addEventListener('change',()=>{ nResetWrap.classList.toggle('hidden',nReset.value!=='-1'); });
 const paintDevHint=(inp,hint)=>{
  if(!inp||!hint)return;
  const on=parseInt(inp.value||'0',10)>0;
  hint.classList.toggle('on',on);
 };
 const _nh=document.getElementById('nDevHint');
 if(_nh) _nh.classList.toggle('on',parseInt(nDev.value||'0',10)>0);
 nDev.addEventListener('input',()=>paintDevHint(nDev,document.getElementById('nDevHint')));
 nTr.options[0].textContent=T('trBoth');
 nTr.options[1].textContent=T('trWs');
 nTr.options[2].textContent=T('trXhttp');
 fillSelect(nFp,FP_OPTIONS,T('fpLbl'));
 fillAlpn(nAlpn);
 cAddr.placeholder=T('addrPh'); cRem.placeholder=T('remarkPh'); cBulk.placeholder=T('bulkPh');
 fillCountry(document.getElementById('cCty'),document.getElementById('cCty')?.value||'');
 fillCountry(document.getElementById('mcSel'),MAIN_CC);
 const _mb=document.getElementById('btnMc'); if(_mb)_mb.textContent=T('save');
 pwCur.placeholder=T('curPw'); pwNew.placeholder=T('newPw');
 applyNav();
 try{paintPageHead(PAGE)}catch(_){}
}
window.rerender=()=>{paintStatic();go(PAGE);renderUsers();renderCips();
 renderProto();renderServer();renderLogs();renderFilter()};

/* ─── charts / dashboard ─── */
function paintChart(){
 const cs=getComputedStyle(document.body);
 const c1=cs.getPropertyValue('--a1').trim()||'#008771';
 const grid=cs.getPropertyValue('--line').trim()||'#2c3950';
 const dim=cs.getPropertyValue('--dim').trim()||'#8fa3c0';
 const labels=(stats.series||[]).map(x=>new Date(x.h*1000).getHours()+':00');
 const data=(stats.series||[]).map(x=>(x.up+x.down)/1048576);
 if(!chart){
  chart=new Chart(document.getElementById('chart'),{type:'line',
   data:{labels,datasets:[{label:'MB',data,fill:true,tension:.4,borderColor:c1,
    backgroundColor:c1+'2e',pointRadius:0,borderWidth:2}]},
   options:{plugins:{legend:{display:false}},maintainAspectRatio:false,scales:{
    x:{grid:{color:grid},ticks:{color:dim,font:{size:10}}},
    y:{grid:{color:grid},ticks:{color:dim,font:{size:10}}}}}});
 }else{Object.assign(chart.data,{labels});
  chart.data.datasets[0].data=data;
  chart.data.datasets[0].borderColor=c1;
  chart.data.datasets[0].backgroundColor=c1+'2e';
  ['x','y'].forEach(k=>{const sc=chart.options&&chart.options.scales&&chart.options.scales[k];
   if(sc){sc.grid.color=grid;sc.ticks.color=dim}});
  chart.update()}
}
function renderProto(){
 const bp=stats.by_proto||{};
 const rows=[['ws',T('trWs'),'var(--a1)'],['xhttp',T('trXhttp'),'var(--a2)']];
 const max=Math.max(1,...rows.map(r=>bp[r[0]]||0));
 protoBox.innerHTML=rows.map(([k,lbl,col])=>{
  const v=bp[k]||0;
  return '<div class="prow">'
   +'<span class="lbl"><i style="background:'+col+'"></i>'+lbl+'</span>'
   +'<b>'+v+'</b>'
   +'<span class="bar"><i style="width:'+Math.round(v/max*100)+'%;background:'+col+'"></i></span>'
  +'</div>';
 }).join('');
}
function renderServer(){
 srvBox.innerHTML=[
  [T('wsPathLbl'),'/'+(stats.ws_path||'—')],
  [T('xhPathLbl'),'/'+(stats.xhttp_path||'—')],
  [T('xhModeLbl'),stats.xhttp_mode||'—'],
  [T('devWinLbl'),(stats.device_window||'—')+' '+T('seconds')],
  [T('ipWinLbl'),(stats.ip_window||'—')+' '+T('seconds')],
  [T('xSessions'),stats.xhttp_sessions??'—'],
  [T('relayLbl'),stats.relay_domain||T('relayNone')],
  [T('keepAliveLbl'),stats.keepalive?T('onLbl'):T('offLbl')],
 ].map(([k,v])=>`<div class="kv"><span class="dim">${k}</span><span class="ms-auto mono">${v}</span></div>`).join('')
 +(stats.xhttp_mode==='packet-up'
  ?`<p class="notice" style="margin-top:8px"><b style="color:var(--warn)">${T('trWarnTitle')}</b>
      <span class="dim">${T('xhModeHint')}</span></p>`
  :'');
}

async function loadStats(){
 stats=await api('/api/stats');
 sUsers.textContent=stats.users; sOnline.textContent=stats.online_users;
 sDev.textContent=stats.online_devices; sLive.textContent=stats.live_devices;
 sBytes.textContent=fmt(stats.total_bytes);
 sCip.textContent=stats.clean_ips;
 pill.textContent='/'+stats.ws_path+' · /'+stats.xhttp_path;
 paintChart(); renderProto();
 if(PAGE==='dash')loadDashLive();
 if(PAGE==='settings'){renderServer();loadBackupInfo();loadTelegram()}
}
async function loadUsers(){users=await api('/api/users');renderUsers()}
async function loadCips(){cips=await api('/api/clean-ips');renderCips()}
async function loadMainCountry(){
 try{const r=await api('/api/main-country');MAIN_CC=r.country||'';
      fillCountry(document.getElementById('mcSel'),MAIN_CC);}catch(e){}
}
async function saveMainCountry(){
 const sel=document.getElementById('mcSel');if(!sel)return;
 try{const r=await api('/api/main-country',{method:'POST',
      body:JSON.stringify({country:sel.value})});
  MAIN_CC=r.country||'';
  const b=document.getElementById('btnMc');
  if(b){const old=b.textContent;b.textContent=T('savedOk');setTimeout(()=>{b.textContent=old},1500)}
 }catch(e){alert(e.message)}
}
async function loadLogs(){logItems=await api('/api/logs');renderLogs()}

let liveTimer=null;
async function loadLive(){
 try{
  const d=await api('/api/live');
  const rows=d.connections||[];
  liveCount.textContent=rows.length?`(${rows.length})`:'';
  if(!rows.length){liveRows.innerHTML='';liveEmpty.style.display='';return}
  liveEmpty.style.display='none';
  const fmtDur=s=>{s=Math.max(0,Math.floor(s));const m=Math.floor(s/60),sec=s%60;
   return m?`${m}m ${sec}s`:`${sec}s`};
  liveRows.innerHTML=rows.map(c=>`<div class="lrow">
    <span class="chip blue">${esc((c.transport||'').toUpperCase())}</span>
    <div class="flex-1" style="min-width:120px">
      <b class="text-base">${esc(c.user||'—')}</b>
      <div class="text-xs dim mono truncate">${esc(c.ip||'')} · ${esc(c.route||'')}${c.mux?' · mux':''}</div>
    </div>
    <span class="text-xs mono dim">${fmtDur(c.connected_for)}</span>
   </div>`).join('');
 }catch(e){/* keep last render on transient error */}
 clearTimeout(liveTimer);
 liveTimer=setTimeout(loadLive,4000);
}
function stopLive(){clearTimeout(liveTimer);liveTimer=null}

/* ─── renderers ─── */

function durTxt(sec){
 sec=Math.max(0,Math.floor(sec||0));
 if(sec<60)return sec+'s';
 const m=Math.floor(sec/60);
 if(m<60)return m+'m '+(sec%60)+'s';
 return Math.floor(m/60)+'h '+(m%60)+'m';
}
async function loadDashLive(){
 const host=document.getElementById('dashLive');
 if(!host)return;
 try{
  const d=await api('/api/live');
  const rows=(d.connections||[]).slice(0,5);
  if(!rows.length){
   host.innerHTML='<div class="lrow"><span class="dim">'+T('noLive')+'</span></div>';
   return;
  }
  host.innerHTML=rows.map(c=>
   '<div class="lrow">'
    +'<span class="chip '+(c.transport==='xhttp'?'teal':'blue')+'">'
      +esc(String(c.transport||'').toUpperCase())+'</span>'
    +'<b>'+esc(c.user||'—')+'</b>'
    +'<span class="dim mono" style="min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'
      +esc(c.ip||'')+(c.route?' · '+esc(c.route):'')+'</span>'
    +'<span class="mono ms-auto" style="color:var(--tx3)">'+durTxt(c.connected_for)+'</span>'
   +'</div>').join('');
 }catch(_){}
}

function renderUsers(){
 const qi=document.getElementById('q');
 const t=((qi&&qi.value)||'').trim().toLowerCase();
 const list=t?users.filter(u=>u.name.toLowerCase().includes(t)):users;
 const cnt=document.getElementById('uCount');
 if(cnt)cnt.textContent=list.length+' / '+users.length;
 const host=document.getElementById('rows'); if(!host)return;
 const IC={
  phone:'<svg viewBox="0 0 24 24"><rect x="6.5" y="2.2" width="11" height="19.6" rx="2.8"/><path d="M10.6 18.9h2.8"/></svg>',
  globe:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9.2"/><path d="M2.8 12h18.4M12 2.8c2.6 2.6 3.9 5.8 3.9 9.2S14.6 18.6 12 21.2C9.4 18.6 8.1 15.4 8.1 12S9.4 5.4 12 2.8z"/></svg>',
  clock:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.8"/><path d="M12 7.2V12l3.2 2"/></svg>'
 };
 if(!list.length){
  host.innerHTML='<div class="empty"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M16.5 16.5L21 21"/></svg><span>'
   +(t?T('noResult'):T('noUsers'))+'</span></div>';
  return;
 }
 host.innerHTML=list.map(u=>{
  const pct=u.quota_bytes?Math.min(100,(u.used_bytes/u.quota_bytes)*100):0;
  const devL=u.device_limit||0, ipL=u.ip_limit||0;
  const devWarn=!!(devL&&u.devices_now>=devL);
  const ipWarn=!!(ipL&&u.ips_now>=ipL);
  const badge=u.active
   ?'<span class="chip green">'+T('active')+'</span>'
   :'<span class="chip red">'+statusTxt(u.status)+'</span>';
  const live=u.devices_live?'<span class="chip green dot">'+u.devices_live+'</span>':'';
  const used=fmt(u.used_bytes), total=u.quota_bytes?fmt(u.quota_bytes):'<i class="inf">&infin;</i>';
  return '<div class="ucard">'

   +'<div class="uc-top">'
     +'<span class="av">'+esc((u.name||'?').charAt(0).toUpperCase())+'</span>'
     +'<span class="nm">'+esc(u.name)+'</span>'
     +'<span class="uc-meta">'
       +badge
       +'<span class="chip teal uc-tsp">'+trTxt(u.transport)+'</span>'
       +live
     +'</span>'
   +'</div>'

   +'<div class="uc-tools">'
     +'<span class="uc-act">'
       +'<button class="icon-btn" title="'+T('config')+'" aria-label="'+T('config')+'" onclick="showConfig('+u.id+')">'+ICO.cfg+'</button>'
       +'<button class="icon-btn" title="'+T('ipsBtn')+'" aria-label="'+T('ipsBtn')+'" onclick="showIps('+u.id+')">'+ICO.ips+'</button>'
       +'<button class="icon-btn" title="'+T('edit')+'" aria-label="'+T('edit')+'" onclick="showEdit('+u.id+')">'+ICO.edit+'</button>'
     +'</span>'
   +'</div>'

   +'<div class="uc-bar'+(pct>=85?' hot':'')+'"><i style="width:'+pct.toFixed(1)+'%"></i></div>'

   +'<div class="uc-foot uc-num">'
     +'<bdi class="mono">'+used+' / '+total+'</bdi>'
     +'<bdi class="mono pct">'+pct.toFixed(0)+'%</bdi>'
   +'</div>'

   +'<div class="uc-foot uc-foot-1">'
     +'<span class="gf">'+IC.clock+'<span>'+T('expiry')+'</span> <bdi class="dt">'+dt(u.expire_at)+'</bdi></span>'
   +'</div>'

   +'<div class="uc-foot uc-foot-2">'
     +'<span class="gf'+(devWarn?' warn':'')+'">'+IC.phone+'<bdi class="mono">'
       +(devL?u.devices_now+' / '+devL:'<i class="inf">&infin;</i>')+'</bdi> <span>'+T('devSec')+'</span></span>'
     +'<span class="gf'+(ipWarn?' warn':'')+'">'+IC.globe+'<bdi class="mono">'
       +(ipL?u.ips_now+' / '+ipL:'<i class="inf">&infin;</i>')+'</bdi> <span>'+T('ipSec')+'</span></span>'
   +'</div>'

  +'</div>';
 }).join('');
}

function renderCips(){
 cipRows.innerHTML=cips.map(x=>`
  <div class="flex items-center gap-2 soft" style="border-radius:10px;padding:9px 12px">
   <span style="width:8px;height:8px;border-radius:50%;background:${x.enabled?'var(--ok)':'var(--dim)'}"></span>
   ${flagImg(x.flag)}
   <span class="mono text-sm truncate">${esc(x.address)}</span>
   ${x.remark?`<span class="text-xs dim truncate">${esc(x.remark)}</span>`:''}
   <div class="flex-1"></div>
   <button onclick="toggleCip(${x.id})" class="icon-btn">${x.enabled?ICO.pause:ICO.play}</button>
   <button onclick="delCip(${x.id})" class="icon-btn danger">${ICO.x}</button>
  </div>`).join('')||`<p class="text-xs dim" style="margin:0">${T('noCleanIps')}</p>`;
}

function renderLogs(){
 const box=document.getElementById('logRows');
 box.innerHTML=logItems.map(l=>`
  <div class="lrow">
   <span class="chip teal">${esc(l.event)}</span>
   <span class="mono dim">${esc(l.ip||'')}</span>
   <span class="dim flex-1 truncate">${esc(l.detail||'')}</span>
   <span class="ms-auto dim">${dt(l.ts)}</span></div>`).join('')
 ||`<p class="text-xs dim" style="margin:0">${T('noLogs')}</p>`;
}

/* ─── actions ─── */
const RESET_FIXED=[0,1,3,7,14,30,60,90];
function resolveReset(sel,custom){
 const v=parseInt(sel||'0',10);
 if(v!==-1)return Math.min(365,Math.max(0,v||0));
 const c=Math.round(parseFloat(custom||'0'));
 return Math.min(365,Math.max(0,c||0));
}
async function createUser(){
 cErr.textContent='';
 try{
  await api('/api/users',{method:'POST',body:JSON.stringify({
   name:nName.value.trim(),quota_gb:parseFloat(nQuota.value||0),
   expire_days:parseInt(nDays.value||0),reset_days:resolveReset(nReset.value,nResetCustom.value),device_limit:parseInt(nDev.value||0),
   ip_limit:parseInt(nIp.value||0),
   transport:nTr.value,obfuscate:nObf.checked,
   ech:nEch.checked,fp:nFp.value||'unsafe',alpn:nAlpn.value,
   ech_value:nEchVal.value.trim(),obf_cs:nObfCs.value.trim(),obf_fm:nObfFm.value.trim()})});
  nName.value='';loadUsers();loadStats();
  try{closeUserForm()}catch(_){}
 }catch(e){cErr.textContent=e.message}
}
async function addCip(){
 cipMsg.textContent='';
 try{await api('/api/clean-ips',{method:'POST',
  body:JSON.stringify({address:cAddr.value.trim(),remark:cRem.value.trim(),
                       country:(cCty&&cCty.value)||''})});
  cAddr.value='';cRem.value='';if(cCty)cCty.value='';loadCips();loadStats();
 }catch(e){cipMsg.textContent=e.message}
}
async function bulkCip(){
 cipMsg.textContent='';
 try{const r=await api('/api/clean-ips/bulk',{method:'POST',
  body:JSON.stringify({text:cBulk.value})});
  cipMsg.textContent=`${r.added} ${T('addedN')} · ${r.duplicates} ${T('dupN')} · ${r.invalid} ${T('invalidN')}`;
  cBulk.value='';loadCips();loadStats();
 }catch(e){cipMsg.textContent=e.message}
}
async function toggleCip(id){await api('/api/clean-ips/'+id,{method:'PATCH'});loadCips();loadStats()}
async function delCip(id){await api('/api/clean-ips/'+id,{method:'DELETE'});loadCips();loadStats()}
async function clearCips(){if(confirm(T('clearAll')+'?')){await api('/api/clean-ips',{method:'DELETE'});loadCips();loadStats()}}

/* ─── telegram web proxy ─── */
let tgwebs=[],tgPlatform='render',tgSettings=null,TGWREG=null,TGWSELF='';
function genSecret(setField){
 const b=new Uint8Array(16);crypto.getRandomValues(b);
 const s=[...b].map(x=>x.toString(16).padStart(2,'0')).join('');
 if(setField&&tgSecret)tgSecret.value=s;
 return s;
}
function tgPlName(p){return p==='render'?T('tgwPlRender'):p==='railway'?T('tgwPlRailway'):T('tgwPlExternal')}
function rgName(r){return (LANG==='fa'?r.fa:r.en)}
async function loadTgRegions(){
 if(TGWREG)return;
 try{TGWREG=await api('/api/tgweb/regions')}
 catch(e){TGWREG={render:[],railway:[],default:{}}}
 TGWSELF=TGWREG.self||'';
 if(TGWSELF){const seg=document.getElementById('tgPlatSeg');
  if(seg)seg.classList.add('hidden');}
 tgPickPlatform(TGWSELF||tgPlatform);
}
function fillTgRegions(p){
 if(!TGWREG||!tgRegion)return;
 const rows=TGWREG[p]||[];
 const cur=tgRegion.value;
 tgRegion.innerHTML=rows.map(r=>`<option value="${esc(r.id)}" data-cc="${esc(r.flag||'')}">${esc(rgName(r))}</option>`).join('');
 const def=(TGWREG.default||{})[p];
 if(def&&rows.some(r=>r.id===def))tgRegion.value=def;
 else if(cur&&rows.some(r=>r.id===cur))tgRegion.value=cur;
}
function tgPickPlatform(p){
 if(TGWSELF)p=TGWSELF;
 tgPlatform=p;
 [['tgPlRender','render'],['tgPlRailway','railway']]
  .forEach(([id,pp])=>{const el=document.getElementById(id);
   if(el)el.classList.toggle('on',pp===p)});
 if(tgRegionFld)tgRegionFld.classList.toggle('hidden',
  !(TGWREG&&(TGWREG[p]||[]).length));
 fillTgRegions(p);
 tgErr.textContent='';
 if(tgSettings&&!((p==='render'?tgSettings.render_token_set:tgSettings.railway_token_set)))
  tgErr.textContent=T('tgwTokenMissing');
}
async function loadTgSettings(){
 try{tgSettings=await api('/api/tgweb/settings')}catch(e){tgSettings=null}
}
async function loadTgweb(){
 try{tgwebs=await api('/api/tgweb')}catch(e){return}
 renderTgweb();
}
function dwChip(u){
 if(u.platform==='external')return '';
 const s=u.deploy_state||'';
 const cls=s==='live'?'green':s==='failed'?'red':s==='suspended'?'':'orange';
 const lbl=s==='live'?T('tgwLive'):s==='failed'?T('tgwFailed'):s==='suspended'?T('tgwSuspended'):T('tgwBuilding');
 return `<span class="chip ${cls}">${lbl}</span>`;
}
function tgPlatChip(u){
 if(u.platform==='external')return '';
 return `<span class="chip teal">${esc(tgPlName(u.platform))}</span>`;
}
function renderTgweb(){
 tgRows.innerHTML=tgwebs.map(u=>{
  const pct=u.quota_bytes?Math.min(100,u.used_bytes/u.quota_bytes*100):0;
  const plat=u.platform||'external';
  const building=plat!=='external'&&(!u.deploy_state||u.deploy_state==='building');
  const stBadge=!u.active?`<span class="chip red">${statusTxt(u.status)}</span>`
   :(plat==='external'?`<span class="chip green">${T('active')}</span>`:'');
  const srvChip=u.server?`<span class="chip mono">${esc(u.server)}</span>`
   :(plat!=='external'?`<span class="chip">${T('tgwNoServer')}</span>`:'');
  const rgChip=(plat!=='external'&&u.region)
   ?`<span class="chip">${esc(rgName(u.region))}</span>`:'';
  const syncBtn=(plat!=='external'&&(building||u.deploy_state==='failed'))
   ?`<button class="icon-btn" title="${T('tgwSync')}" onclick="tgSync(${u.id})">${ICO.refresh}</button>`:'';
  const linkBtn=u.link?`<button class="icon-btn" title="${T('tgwLink')}" onclick="tgLink(${u.id})">${ICO.copy}</button>`
   :`<span class="icon-btn" style="opacity:.35;cursor:default">${ICO.copy}</span>`;
  return `<div class="urow">
   <div class="u-av"><svg viewBox="0 0 24 24" style="width:15px;height:15px;stroke:currentColor;fill:none;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round"><path d="M21 3L3 10.5l6 2.4 2.4 6L21 3z"/><path d="M9 12.9L21 3"/></svg></div>
   <div class="u-main">
    <div class="flex items-center gap-2 flex-wrap">
     <b class="text-base">${esc(u.label||(u.server||tgPlName(plat)))}</b>${stBadge}${dwChip(u)}${tgPlatChip(u)}
     ${rgChip}
     ${srvChip}
    </div>
    ${u.quota_bytes?`<div class="progress mt-2${pct>=85?' hot':''}"><i style="width:${pct}%"></i></div>`:''}
    <div class="flex flex-wrap gap-3 text-xs dim mt-1">
     <span>${T('used')}: <bdi dir="ltr">${fmt(u.used_bytes)} / ${u.quota_bytes?fmt(u.quota_bytes):'&infin;'}</bdi></span>
     <span>${T('expiry')}: ${dt(u.expire_at)}</span>
     <span class="mono" dir="ltr">${esc(u.secret.slice(0,6))}…${esc(u.secret.slice(-4))}</span>
     ${building?`<span style="color:var(--warn)">${T('tgwBuildHint')}</span>`:''}
     ${u.error?`<span style="color:var(--bad)" dir="ltr">${esc(u.error)}</span>`:''}
    </div>
   </div>
   <div class="u-actions">
    ${linkBtn}
    ${syncBtn}
    <button class="icon-btn" title="${T('tgwRotate')}" onclick="tgRotate(${u.id})">${ICO.key}</button>
    <button class="icon-btn" title="${T('tgwEdit')}" onclick="tgEdit(${u.id})">${ICO.edit}</button>
    <button class="icon-btn" title="${u.enabled?T('offLbl'):T('onLbl')}" onclick="tgToggle(${u.id})">${u.enabled?ICO.pause:ICO.play}</button>
    <button class="icon-btn danger" title="${T('del')}" onclick="tgDel(${u.id})">${ICO.x}</button>
   </div></div>`}).join('')
  ||`<div class="p-4 text-sm dim" style="text-align:center">${T('tgwNone')}</div>`;
}
async function createTgweb(){
 tgErr.textContent='';
 const plat=tgPlatform;
 if(tgSettings&&!((plat==='render'?tgSettings.render_token_set:tgSettings.railway_token_set))){
  tgErr.textContent=T('tgwTokenMissing');return}
 try{
  await api('/api/tgweb',{method:'POST',body:JSON.stringify({
   platform:plat,carrier:tgCarrier.value,region:tgRegion.value,label:tgLabel.value.trim(),
   secret:tgSecret.value.trim().toLowerCase(),
   quota_gb:parseFloat(tgQuota.value||0),expire_days:parseInt(tgDays.value||0)})});
  tgLabel.value='';genSecret(true);tgQuota.value='0';tgDays.value='0';
  loadTgweb();
 }catch(e){tgErr.textContent=e.message}
}
function tgTokenField(id,hint,lbl){
 return `<label class="fld mt-3"><span class="text-xs dim">${esc(lbl)}</span>
  <input id="${id}" class="inp mono" style="font-size:11.5px" dir="ltr"
         placeholder="${esc(hint||'')}" autocomplete="off"></label>`;
}
function tgKeyList(plat){
 const s=tgSettings||{};
 const keys=(plat==='render'?s.render_keys:s.railway_keys)||[];
 if(!keys.length)return `<div class="text-xs dim mt-2">${T('tgwNoKeys')}</div>`;
 return `<div class="mt-2 flex flex-col gap-1.5">`+keys.map(k=>
  `<div class="flex items-center gap-2 text-sm border rounded p-2 ${k.active?'border-teal':''}">
    <span class="flex-1 min-w-0">
      <span class="flex items-center gap-2">
        <b class="truncate">${esc(k.name||('#'+k.id))}</b>
        ${k.active?`<span class="chip teal">${T('tgwActive')}</span>`:''}
      </span>
      <span class="text-xs dim mono">${esc(k.token_hint||'')}</span>
    </span>
    ${k.active?'':`<button class="btn btn-sm" onclick="tgSetKeyActive('${plat}',${k.id})">${T('tgwUse')}</button>`}
    <button class="icon-btn danger" title="${T('del')}" onclick="tgDelKey('${plat}',${k.id})">${ICO.x}</button>
   </div>`).join('')+`</div>`;
}
async function tgAddKey(plat){
 const inp=document.getElementById('tgsNewKey');if(!inp)return;
 const token=inp.value.trim();if(!token){toast(T('tgwKeyRequired'));return}
 try{
  await api('/api/tgweb/keys/'+plat,{method:'POST',body:JSON.stringify({token})});
  inp.value='';await loadTgSettings();
  const lk=document.getElementById('tgKeyListWrap');if(lk)lk.innerHTML=tgKeyList(plat);
  tgPickPlatform(tgPlatform);toast(T('tgwKeyAdded'));
 }catch(e){toast(e.message)}
}
async function tgSetKeyActive(plat,kid){
 try{
  await api('/api/tgweb/keys/'+plat+'/'+kid+'/active',{method:'POST'});
  await loadTgSettings();
  const lk=document.getElementById('tgKeyListWrap');if(lk)lk.innerHTML=tgKeyList(plat);
  toast(T('tgwSetSaved'));
 }catch(e){toast(e.message)}
}
async function tgDelKey(plat,kid){
 if(!confirm(T('tgwDelKeyQ')))return;
 try{
  await api('/api/tgweb/keys/'+plat+'/'+kid,{method:'DELETE'});
  await loadTgSettings();
  const lk=document.getElementById('tgKeyListWrap');if(lk)lk.innerHTML=tgKeyList(plat);
  tgPickPlatform(tgPlatform);toast(T('tgwKeyDeleted'));
 }catch(e){toast(e.message)}
}
async function openTgSettings(){
 await loadTgSettings();
 const s=tgSettings||{};
 const sub=TGWSELF?T('tgwSetSubSelf').replace('{p}',tgPlName(TGWSELF)):T('tgwSetSub');
 const plats=TGWSELF?[TGWSELF]:['render','railway'];
 function platSection(p){
  return `<div class="mt-3"><div class="flex items-center gap-2">
    <b>${esc(tgPlName(p))}</b>
    ${(p==='render'?s.render_token_set:s.railway_token_set)?`<span class="chip teal">${T('tgwActive')}</span>`:''}
   </div>
   <div id="tgKeyListWrap">${tgKeyList(p)}</div>
   <div class="fld mt-2 flex gap-2">
    <input id="tgsNewKey" class="inp mono" style="flex:1;font-size:11.5px" dir="ltr"
           placeholder="${T('tgwNewKey')}" autocomplete="off">
    <button class="btn" onclick="tgAddKey('${p}')">${T('tgwAddKey')}</button>
   </div>
  </div>`;
 }
 openModal(T('tgwSet'),`
  <p class="text-xs dim" style="margin:0">${sub}</p>
  ${plats.map(platSection).join('')}
  <button onclick="closeModal()" class="btn w-full mt-3">${T('close')}</button>`);
}
async function tgSync(id){
 try{await api('/api/tgweb/'+id+'/sync',{method:'GET'})}catch(e){}
 loadTgweb();
}
async function tgToggle(id){
 const u=tgwebs.find(x=>x.id===id);if(!u)return;
 if(u.platform!=='external'&&u.enabled&&!confirm(T('tgwPauseWarn')))return;
 try{
  await api('/api/tgweb/'+id,{method:'PATCH',body:JSON.stringify({enabled:!u.enabled})});
 }catch(e){toast(e.message)}
 loadTgweb();
}
async function tgRotate(id){
 const u=tgwebs.find(x=>x.id===id);if(!u)return;
 const warn=u.platform&&u.platform!=='external'
  ?T('tgwRotateWarnPl').replace('{p}',tgPlName(u.platform)):T('tgwRotateWarn');
 if(!confirm(warn))return;
 try{
  await api('/api/tgweb/'+id+'/rotate',{method:'POST'});
  loadTgweb();
 }catch(e){toast(e.message);loadTgweb()}
}
async function tgDel(id){
 const u=tgwebs.find(x=>x.id===id);if(!u)return;
 const warn=u.platform&&u.platform!=='external'
  ?T('tgwDelWarnPl').replace('{p}',tgPlName(u.platform)):T('tgwDelWarn');
 if(!confirm(warn))return;
 await api('/api/tgweb/'+id,{method:'DELETE'});loadTgweb();
}
async function tgLink(id){
 const u=tgwebs.find(x=>x.id===id);if(!u||!u.link)return;
 openModal(T('tgwLink'),`
  <label class="fld"><span class="text-xs dim">${esc(u.label||u.server)}</span>
   <div class="soft mono text-xs break-all" style="border-radius:10px;padding:10px">${esc(u.link)}</div></label>
  <button onclick="copy(this,'${u.link}')" class="btn w-full">${ICO.copy} ${T('tgwCopyLink')}</button>
  <div id="qr" style="display:grid;place-items:center;background:#fff;padding:12px;border-radius:12px"></div>
  <a href="${esc(u.link)}" target="_blank" rel="noopener" class="btn btn-soft w-full" style="text-align:center;text-decoration:none">${ICO.send} ${T('tgwOpen')}</a>`);
 new QRCode(document.getElementById('qr'),{text:u.link,width:180,height:180});
}
async function tgEdit(id){
 const u=tgwebs.find(x=>x.id===id);if(!u)return;
 if(!TGWREG)await loadTgRegions();
 const plat=u.platform||'external';
 const rgn=(plat!=='external'&&TGWREG&&TGWREG[plat])?TGWREG[plat]:[];
 openModal(T('tgwEdit'),`
  <label class="fld"><span class="text-xs dim">${T('tgwLabel')}</span>
   <input id="teLbl" class="inp" value="${esc(u.label)}"></label>
  ${plat==='external'
   ?`<label class="fld mt-2"><span class="text-xs dim">${T('tgwServer')}</span>
     <input id="teSrv" class="inp mono" style="font-size:11.5px" dir="ltr" value="${esc(u.server)}"></label>`
   :`<label class="fld mt-2"><span class="text-xs dim">${T('tgwServer')}</span>
     <div class="soft mono text-xs" style="border-radius:10px;padding:9px 11px" dir="ltr">${esc(u.server||'…')}</div></label>`}
  ${plat==='railway'&&rgn.length
   ?`<label class="fld mt-2"><span class="text-xs dim">${T('tgwRegion')}</span>
     <select id="teRgn" class="inp" dir="ltr">${(()=>{const curR=(u.region||{}).id||'';
      const ops=rgn.map(r=>`<option value="${esc(r.id)}"${curR===r.id?' selected':''}>${esc(rgName(r))}</option>`);
      if(curR&&!rgn.some(r=>r.id===curR))ops.unshift(`<option value="${esc(curR)}" selected data-cc="${esc(u.region.flag||'')}">${esc(rgName(u.region))}</option>`);
      if(!curR)ops.unshift(`<option value="" selected>${T('tgwRegionHostDefault')}</option>`);
      return ops.join('');})()}</select>
     <span class="text-xs dim">${T('tgwRegionHint')}</span></label>`
   :(plat==='render'&&u.region
    ?`<label class="fld mt-2"><span class="text-xs dim">${T('tgwRegion')}</span>
      <div class="soft text-xs" style="border-radius:10px;padding:9px 11px">${esc(rgName(u.region))} — ${T('tgwRegionLock')}</div></label>`
    :'')}
  <div class="g2 mt-2">
   <label class="fld"><span class="text-xs dim">${T('quota')}</span>
    <input id="teQ" type="number" step="0.5" class="inp" value="${u.quota_bytes?u.quota_bytes/1073741824:0}"></label>
   <label class="fld"><span class="text-xs dim">${T('days')}</span>
    <input id="teD" type="number" class="inp" value="${u.expire_at?Math.max(0,Math.round((u.expire_at-Date.now()/1000)/86400)):0}"></label>
  </div>
  <label class="fld mt-2"><span class="text-xs dim">${T('expiry')}</span>
   <div class="soft text-xs" style="border-radius:10px;padding:9px 11px">${dt(u.expire_at)}</div></label>
  <p class="text-xs dim mt-2" style="margin:0">${T('tgwZeroInf')}</p>
  <button onclick="saveTgweb(${id})" class="btn w-full mt-3">${T('saveBtn')}</button>`);
}
async function saveTgweb(id){
 const u=tgwebs.find(x=>x.id===id);if(!u)return;
 const body={label:teLbl.value.trim(),
  quota_gb:parseFloat(teQ.value||0),expire_days:parseInt(teD.value||0)};
 if((u.platform||'external')==='external')body.server=teSrv.value.trim();
 const teRgn=document.getElementById('teRgn');
 if(teRgn&&teRgn.value&&((u.region||{}).id||'')!==teRgn.value)body.region=teRgn.value;
 try{
  await api('/api/tgweb/'+id,{method:'PATCH',body:JSON.stringify(body)});
  closeModal();loadTgweb();
 }catch(e){toast(e.message)}
}
/* while any platform build is in flight, refresh the list every 5 s */
setInterval(()=>{
 const busy=(tgwebs||[]).some(u=>u.platform!=='external'
   &&(!u.deploy_state||u.deploy_state==='building'));
 if(busy&&!document.querySelector('[data-pg="tgweb"]').classList.contains('hidden'))
  loadTgweb();
},5000);

/* ─── site filter ─── */
let FILTER={enabled:false,block_porn:false,rules:[],porn_keywords:0};
async function loadFilter(){
 try{FILTER=await api('/api/filter');renderFilter()}catch(e){}
}
function renderFilter(){
 if(!window.fOn)return;
 fOn.checked=!!FILTER.enabled; fPorn.checked=!!FILTER.block_porn;
 fPornN.textContent=FILTER.porn_keywords?('('+FILTER.porn_keywords+')'):'';
 frCount.textContent=FILTER.rules.length;
 frRows.innerHTML=FILTER.rules.map(r=>`
  <div class="lrow">
   <span style="width:8px;height:8px;border-radius:50%;background:${r.enabled?'var(--ok)':'var(--dim)'}"></span>
   <span class="chip ${r.kind==='keyword'?'teal':''}" style="font-size:10px">${r.kind==='keyword'?T('fltKeyword'):T('fltDomain')}</span>
   <span class="mono text-sm truncate" style="flex:1">${esc(r.pattern)}</span>
   ${r.note?`<span class="text-xs dim truncate">${esc(r.note)}</span>`:''}
   <button onclick="toggleFilterRule(${r.id})" title="${T('active')}" class="icon-btn">${r.enabled?ICO.pause:ICO.play}</button>
   <button onclick="delFilterRule(${r.id})" class="icon-btn danger">${ICO.del}</button>
  </div>`).join('')||`<div class="p-4 text-sm dim" style="text-align:center">${T('fltNone')}</div>`;
}
async function saveFilterMode(){
 fMsg.textContent='';
 try{await api('/api/filter/mode',{method:'POST',
  body:JSON.stringify({enabled:fOn.checked,block_porn:fPorn.checked})});
  fMsg.style.color='var(--ok)';fMsg.textContent=T('savedOk');await loadFilter();
 }catch(e){fMsg.style.color='var(--bad)';fMsg.textContent=e.message}
}
async function addFilterRule(){
 frMsg.textContent='';
 const pat=frPat.value.trim(); if(!pat)return;
 try{await api('/api/filter/rules',{method:'POST',
  body:JSON.stringify({pattern:pat,kind:frKind.value})});
  frPat.value='';await loadFilter();
 }catch(e){frMsg.textContent=e.message}
}
async function bulkFilter(){
 frMsg.textContent='';
 try{const r=await api('/api/filter/rules',{method:'POST',
  body:JSON.stringify({bulk:frBulk.value,kind:frKind.value})});
  frMsg.textContent=(r.added||0)+' '+T('fltAdded');
  frBulk.value='';await loadFilter();
 }catch(e){frMsg.textContent=e.message}
}
async function toggleFilterRule(id){await api('/api/filter/rules/'+id,{method:'PATCH'});loadFilter()}
async function delFilterRule(id){await api('/api/filter/rules/'+id,{method:'DELETE'});loadFilter()}
async function clearFilter(){if(confirm(T('fltClearWarn'))){await api('/api/filter/rules',{method:'DELETE'});loadFilter()}}


async function loadProxies(){
 try{const r=await api('/api/proxies');
  PROXIES=r.proxies||[];PX_SUB=r.sub_ids||[];PX_ACTIVE=r.active_id||0;
  PX_STRICT=!!r.strict;PX_FLAG=r.flag_source||'proxy';
  renderProxies();
 }catch(e){if(pxMsg)pxMsg.textContent=e.message}
}
function renderProxies(){
 if(!window.pxRows)return;
 const sb=document.getElementById('pxStrictBtn');
 if(sb)sb.classList.toggle('on',PX_STRICT);
 const fs=document.getElementById('pxFlagSel');
 if(fs)fs.value=PX_FLAG;
 pxRows.innerHTML=PROXIES.map(x=>{
  const on=PX_SUB.indexOf(x.id)>-1;
  const dot=x.healthy?'var(--ok)':(x.checked_at?'var(--bad)':'var(--dim)');
  const state=x.healthy?T('pxHealthy'):(x.checked_at?T('pxDown'):T('pxUntested'));
  const geo=[x.country_name||'',x.city||''].filter(Boolean).join(' · ');
  return `<div class="prow ${on?'on':''}">
   <div class="prow-main">
    <div class="prow-head">
     <span style="width:8px;height:8px;flex:0 0 8px;border-radius:50%;background:${dot}"></span>
     ${flagImg(x.flag)}
     <span class="lbl">${esc(x.label)}</span>
     ${x.has_auth?ICO.key:''}
     ${on?`<span class="chip teal">${T('pxInSub')}</span>`:''}
    </div>
    <div class="prow-meta">
     <span>${state}</span>
     ${x.latency_ms?`<span>${T('pxLatency')}: ${x.latency_ms} ms</span>`:''}
     ${x.exit_ip?`<span class="mono">${T('pxExitIp')}: ${esc(x.exit_ip)}</span>`:''}
     ${geo?`<span>${esc(geo)}</span>`:''}
     ${x.isp?`<span>${esc(x.isp)}</span>`:''}
     ${x.remark?`<span>${esc(x.remark)}</span>`:''}
     ${x.last_error?`<span class="err">${esc(x.last_error)}</span>`:''}
    </div>
   </div>
   <div class="prow-act">
    <button onclick="testProxy(${x.id})" title="${T('pxTest')}" class="icon-btn">${ICO.ping}</button>
    <button onclick="toggleProxy(${x.id},${x.enabled?1:0})" title="${x.enabled?T('pxPause'):T('pxResume')}" class="icon-btn">${x.enabled?ICO.pause:ICO.play}</button>
    <button onclick="delProxy(${x.id})" title="${T('pxDel')}" class="icon-btn danger">${ICO.x}</button>
   </div>
  </div>`}).join('')||`<p class="text-xs dim" style="margin:0">${T('pxNone')}</p>`;
}
async function addProxy(){
 pxMsg.textContent=T('pxTesting');
 try{const r=await api('/api/proxies',{method:'POST',body:JSON.stringify({
   kind:pKind.value,host:pHost.value.trim(),port:parseInt(pPort.value||'0',10),
   username:pUser.value.trim(),password:pPass.value,remark:pRem.value.trim()})});
  pxMsg.textContent=r.ok?`${r.flag||''} ${r.country_name||''} · ${r.exit_ip||''} · ${r.latency_ms}ms`
                       :`${T('pxDown')}: ${r.error||''}`;
  pHost.value='';pPort.value='';pUser.value='';pPass.value='';pRem.value='';
  loadProxies();
 }catch(e){pxMsg.textContent=e.message}
}
async function addBulk(){
 const text=pBulk.value.trim();
 if(!text){pxMsg.textContent=T('pxLineHint');return}
 pxMsg.textContent=T('pxTesting');
 try{const r=await api('/api/proxies/bulk',{method:'POST',body:JSON.stringify({text:text})});
  const rows=r.results||[], good=rows.filter(x=>x.ok).length;
  pxMsg.innerHTML=rows.map(x=>x.ok
    ?`<span style="color:var(--ok)">${x.flag||''} ${esc(x.label)} · ${esc(x.country_name||'')} ${x.latency_ms||0}ms</span>`
    :`<span style="color:var(--bad)">${esc(x.label)}: ${esc(x.error||'')}</span>`).join('<br>')+
   `<br>${good}/${rows.length}`;
  if(good)pBulk.value='';
  loadProxies();
 }catch(e){pxMsg.textContent=e.message}
}
async function testProxy(id){
 pxMsg.textContent=T('pxTesting');
 try{const r=await api('/api/proxies/'+id+'/test',{method:'POST'});
  pxMsg.textContent=r.ok?`${r.flag||''} ${r.country_name||''} · ${r.exit_ip||''} · ${r.latency_ms}ms`
                       :`${T('pxDown')}: ${r.error||''}`;
  loadProxies();
 }catch(e){pxMsg.textContent=e.message}
}
async function testAllProxies(){
 pxMsg.textContent=T('pxTesting');
 try{await api('/api/proxies/test-all',{method:'POST'});pxMsg.textContent='';loadProxies();
 }catch(e){pxMsg.textContent=e.message}
}
async function toggleProxy(id,on){
 try{await api('/api/proxies/'+id,{method:'PATCH',body:JSON.stringify({enabled:!on})});loadProxies();
 }catch(e){pxMsg.textContent=e.message}
}
async function delProxy(id){
 if(!confirm(T('pxDelWarn')))return;
 try{await api('/api/proxies/'+id,{method:'DELETE'});loadProxies();
 }catch(e){pxMsg.textContent=e.message}
}
async function toggleStrict(){
 PX_STRICT=!PX_STRICT;renderProxies();
 try{await api('/api/proxies/mode',{method:'POST',body:JSON.stringify({strict:PX_STRICT})});
 }catch(e){pxMsg.textContent=e.message;loadProxies()}
}
async function saveFlagSource(){
 const v=document.getElementById('pxFlagSel').value;
 try{await api('/api/proxies/mode',{method:'POST',body:JSON.stringify({flag_source:v})});
  PX_FLAG=v;pxMsg.textContent=T('savedOk');
 }catch(e){pxMsg.textContent=e.message}
}

function openModal(t,h){mTitle.textContent=t;mBody.innerHTML=h;
 modal.classList.remove('hidden');modal.classList.add('flex')}
function closeModal(){modal.classList.add('hidden');modal.classList.remove('flex');
 clearInterval(ipTimer);ipTimer=null;ipUid=null}

async function showConfig(id){
 const c=await api('/api/users/'+id+'/config');
 const cfgs=c.configs.map(x=>`
  <div class="soft" style="border-radius:10px;padding:10px">
   <b class="text-sm">${esc(x.label)}</b>
   <p class="mono text-xs dim break-all" style="margin:5px 0">${esc(x.uri)}</p>
   <button onclick="copy(this,'${x.uri.replace(/'/g,"\\'")}')" class="btn btn-soft w-full" style="padding:6px;font-size:11px">${T('copy')}</button>
  </div>`).join('');
 openModal(T('config'),`
  <label class="fld"><span class="text-xs dim">${T('subLink')}</span>
   <div class="soft mono text-xs break-all" style="border-radius:10px;padding:10px">${esc(c.sub_link)}</div></label>
  <button onclick="copy(this,'${c.sub_link}')" class="btn w-full">${ICO.copy} ${T('copySub')}</button>
  <div id="qr" style="display:grid;place-items:center;background:#fff;padding:12px;border-radius:12px"></div>
  <label class="fld"><span class="text-xs dim">UUID</span>
   <div class="soft mono text-xs break-all" style="border-radius:10px;padding:10px">${esc(c.uuid)}</div></label>
  <p class="text-xs dim" style="margin:0">${T('singleCfg')} — ${trTxt(c.transport)}</p>${cfgs}`);
 new QRCode(document.getElementById('qr'),{text:c.sub_link,width:180,height:180});
}

let ipTimer=null, ipUid=null, ipHistory=false;

async function showIps(id){
 ipUid=id; ipHistory=false;
 await paintIps();
 clearInterval(ipTimer);
 ipTimer=setInterval(()=>{ if(!modal.classList.contains('hidden')&&ipUid) paintIps(true); },5000);
}

async function paintIps(quiet){
 let d;
 try{ d=await api('/api/users/'+ipUid+'/ips'+(ipHistory?'?history=1':'')); }
 catch(e){ if(!quiet) openModal(T('devTitle'),'<p class="text-sm" style="color:var(--bad)">'+esc(e.message)+'</p>'); return }

 const rows=d.rows.length ? d.rows.map(x=>`
  <div class="lrow">
   <span style="width:8px;height:8px;border-radius:50%;background:${x.online?'var(--ok)':(x.counted?'var(--info)':'var(--dim)')}"></span>
   <div style="min-width:0;flex:1">
    <div class="font-bold truncate">${esc(x.label||x.ip)}</div>
    <div class="text-xs dim mono truncate">${esc([x.client,x.client_version&&('v'+x.client_version),x.platform,x.ip,x.proto].filter(Boolean).join(' · '))}${x.hits?' · '+x.hits+'x':''}</div>
   </div>
   <span class="text-xs dim" title="${esc(x.ua||'')}">${dt(x.last_seen)}</span>
   <button class="icon-btn danger" title="${T('delDevice')}" onclick="delDevice(${ipUid},${x.id})">${ICO.del}</button>
  </div>`).join('')
  : `<p class="text-xs dim" style="margin:0">${ipHistory?T('noConn'):T('noneNow')}</p>`;

 const ipRows=d.ip_rows.length ? d.ip_rows.map(x=>`
  <div class="lrow">
   <span style="width:8px;height:8px;border-radius:50%;background:${x.online?'var(--ok)':(x.counted?'var(--info)':'var(--dim)')}"></span>
   <div style="min-width:0;flex:1">
    <div class="font-bold mono truncate">${esc(x.ip)}</div>
    <div class="text-xs dim mono truncate">${esc(x.proto||'ws')}${x.hits?' · '+x.hits+'x':''}</div>
   </div>
   <span class="text-xs dim">${dt(x.last_seen)}</span>
   <button class="icon-btn danger" title="${T('delIp')}" onclick="delIp(${ipUid},${x.id})">${ICO.del}</button>
  </div>`).join('')
  : `<p class="text-xs dim" style="margin:0">${ipHistory?T('noConn'):T('noneNow')}</p>`;

 const body=`
  <div class="soft" style="border-radius:12px;padding:16px;text-align:center">
   <p class="text-xs dim" style="margin:0">${T('liveNow')}</p>
   <p class="font-extrabold" style="font-size:34px;margin:4px 0 0;color:${d.live?'var(--ok)':'var(--dim)'}">${d.live}</p>
   <p class="text-xs dim" style="margin:0">${T('inLast').replace('%s',d.live_window)}</p>
  </div>
  <b class="text-base">${T('devSec')}</b>
  <div class="g2 text-sm">
   <div class="kv"><span class="dim">${T('countedFor')}</span>
    <span class="ms-auto font-bold" style="color:var(--info)"><bdi dir="ltr">${d.counted}${d.limit?' / '+d.limit:' / ∞'}</bdi></span></div>
   <div class="kv"><span class="dim">${T('totalSeen')}</span>
    <span class="ms-auto font-bold">${d.total_seen}</span></div>
  </div>
  <div class="space-y-2">${rows}</div>
  <b class="text-base">${T('ipSec')}</b>
  <div class="g2 text-sm">
   <div class="kv"><span class="dim">${T('ipCounted')}</span>
    <span class="ms-auto font-bold" style="color:var(--info)"><bdi dir="ltr">${d.ip_counted}${d.ip_limit?' / '+d.ip_limit:' / ∞'}</bdi></span></div>
   <div class="kv"><span class="dim">${T('ipsTotal')}</span>
    <span class="ms-auto font-bold">${d.ip_total_seen}</span></div>
  </div>
  <div class="space-y-2">${ipRows}</div>
  <button onclick="toggleIpHistory()" class="btn btn-soft w-full">
   ${ipHistory?T('showLive'):T('showHistory')}</button>
  <button onclick="clearIps(${ipUid})" class="btn btn-danger w-full">${T('clearIps')}</button>`;

 if(quiet){ const b=document.getElementById('mBody'); if(b) b.innerHTML=body; }
 else openModal(T('devTitle'),body);
}

function toggleIpHistory(){ ipHistory=!ipHistory; paintIps(); }

async function clearIps(id){await api('/api/users/'+id+'/clear-ips',{method:'POST'});closeModal();loadUsers();loadStats()}

async function delDevice(uid,did){
 if(!confirm(T('delDeviceWarn')))return;
 try{await api('/api/users/'+uid+'/devices/'+did,{method:'DELETE'});paintIps(true);loadUsers();loadStats();}
 catch(e){}
}

async function delIp(uid,iid){
 if(!confirm(T('delIpWarn')))return;
 try{await api('/api/users/'+uid+'/ips/'+iid,{method:'DELETE'});paintIps(true);loadUsers();loadStats();}
 catch(e){}
}

function showEdit(id){
 const u=users.find(x=>x.id===id);
 const days=u.expire_at?Math.max(0,Math.ceil((u.expire_at-Date.now()/1000)/86400)):0;
 const opt=v=>`<option value="${v}" ${u.transport===v?'selected':''}>${trTxt(v)}</option>`;
 openModal(T('editUser')+' · '+esc(u.name),`
  <label class="fld"><span class="text-xs dim">${T('quota')}</span>
   <input id="eQ" type="number" step="0.5" value="${(u.quota_bytes/1073741824).toFixed(2)}" class="inp"></label>
  <label class="fld"><span class="text-xs dim">${T('remainDays')}</span>
   <input id="eD" type="number" value="${days}" class="inp"></label>
  <label class="fld"><span class="text-xs dim">${T('resetCycle')}</span>
   <select id="eR" class="inp" onchange="eRCustomWrap.classList.toggle('hidden',this.value!=='-1')"><option value="0">${T('resetOff')}</option><option value="1">${T('reset1')}</option><option value="3">${T('reset3')}</option><option value="7">${T('reset7')}</option><option value="14">${T('reset14')}</option><option value="30">${T('reset30')}</option><option value="60">${T('reset60')}</option><option value="90">${T('reset90')}</option><option value="-1">${T('resetCustom')}</option></select></label>
  <label class="fld hidden" id="eRCustomWrap"><span class="text-xs dim">${T('customDays')}</span>
   <input id="eRCustom" type="number" min="1" max="365" class="inp"></label>
  <label class="fld"><span class="text-xs dim">${T('allowedDev')}</span>
   <input id="eV" type="number" value="${u.device_limit}" class="inp"
     oninput="document.getElementById('eDevHint').classList.toggle('on',parseInt(this.value||'0',10)>0)"></label>
  <p class="hint dev-device-hint${u.device_limit>0?' on':''}" id="eDevHint" style="margin:0 0 4px">${esc(T('devLimitHint'))}</p>
  <label class="fld"><span class="text-xs dim">${T('allowedIp')}</span>
   <input id="eIp" type="number" value="${u.ip_limit}" class="inp"></label>
  <label class="fld"><span class="text-xs dim">${T('transport')}</span>
   <select id="eT" class="inp">${opt('both')}${opt('ws')}${opt('xhttp')}</select></label>
  <label class="flex items-center gap-2"><input id="eObf" type="checkbox" ${u.obfuscate?'checked':''}> ${T('obfLbl')}</label>
  <label class="flex items-center gap-2"><input id="eEch" type="checkbox" ${u.ech?'checked':''}> ${T('echLbl')}</label>
  <div class="g2">
   <label class="fld"><span class="text-xs dim">${T('fpLbl')}</span>
    <select id="eFp" class="inp" style="font-size:12px"></select></label>
   <label class="fld"><span class="text-xs dim">${T('alpnLbl')}</span>
    <select id="eFpAlpn" class="inp" style="font-size:12px"></select></label>
  </div>
  <details>
   <summary class="text-xs dim" style="cursor:pointer">${T('custLbl')}</summary>
   <label class="fld mt-2"><span class="text-xs dim">${T('echValueLbl')}</span>
    <input id="eEchVal" class="inp mono" style="font-size:11px" value="${esc(u.ech_value||'')}" placeholder="${esc(T('optDefault'))}"></label>
   <div class="g2 mt-2">
    <label class="fld"><span class="text-xs dim">${T('obfCsLbl')}</span>
     <input id="eObfCs" class="inp mono" style="font-size:11px" value="${esc(u.obf_cs||'')}" placeholder="${esc(T('optDefault'))}"></label>
    <label class="fld"><span class="text-xs dim">${T('obfFmLbl')}</span>
     <textarea id="eObfFm" rows="3" spellcheck="false" class="inp mono" style="font-size:11px" placeholder="${esc(T('optDefault'))}">${esc(u.obf_fm||'')}</textarea></label>
   </div>
   <p class="text-xs mt-2" style="color:var(--warn,#e0a80d);margin:0">${T('custHint')}</p>
  </details>
  <label class="fld"><span class="text-xs dim">${T('customUuid')}</span>
   <input id="eU" value="${esc(u.uuid)}" class="inp mono" style="font-size:11px"></label>
  <label class="flex items-center gap-2"><input id="eE" type="checkbox" ${u.enabled?'checked':''}> ${T('active')}</label>
  <button onclick="saveEdit(${id})" class="btn w-full">${T('saveBtn')}</button>
  <div class="g2" style="grid-template-columns:repeat(3,1fr)">
   <button onclick="resetTraffic(${id})" class="btn btn-soft" style="font-size:11px;padding:7px">${T('resetTraffic')}</button>
   <button onclick="newUuid(${id})" class="btn btn-soft" style="font-size:11px;padding:7px">${T('newUuid')}</button>
   <button onclick="delUser(${id})" class="btn btn-danger" style="font-size:11px;padding:7px">${T('del')}</button>
  </div>
  <p id="eErr" class="text-sm" style="margin:0;color:var(--bad)"></p>`);
 fillSelect(eFp,FP_OPTIONS,T('fpLbl')); eFp.value=(FP_OPTIONS.indexOf(u.fp)>-1?u.fp:'unsafe');
 fillAlpn(eFpAlpn); eFpAlpn.value=(ALPN_OPTIONS.indexOf(u.alpn)>-1?u.alpn:'');
 const rd=parseInt(u.reset_days||0);
 if(RESET_FIXED.includes(rd)){ eR.value=String(rd); eRCustomWrap.classList.add('hidden'); }
 else{ eR.value='-1'; eRCustom.value=rd?(''+rd):''; eRCustomWrap.classList.remove('hidden'); }
}
async function saveEdit(id){
 try{
  const u=users.find(x=>x.id===id);
  const payload={quota_gb:parseFloat(eQ.value||0),expire_days:parseInt(eD.value||0),
   reset_days:resolveReset(eR.value,eRCustom.value),
   device_limit:parseInt(eV.value||0),ip_limit:parseInt(eIp.value||0),transport:eT.value,enabled:eE.checked,
   obfuscate:eObf.checked,ech:eEch.checked,
   fp:eFp.value||'unsafe',alpn:eFpAlpn.value,
   ech_value:eEchVal.value.trim(),obf_cs:eObfCs.value.trim(),obf_fm:eObfFm.value.trim()};
  if(eU.value.trim()&&eU.value.trim()!==u.uuid)payload.uuid=eU.value.trim();
  await api('/api/users/'+id,{method:'PATCH',body:JSON.stringify(payload)});
  closeModal();loadUsers();loadStats();
 }catch(e){document.getElementById('eErr').textContent=e.message}
}
async function resetTraffic(id){await api('/api/users/'+id+'/reset-traffic',{method:'POST'});closeModal();loadUsers()}
async function newUuid(id){if(confirm(T('uuidWarn'))){await api('/api/users/'+id+'/new-uuid',{method:'POST'});closeModal();loadUsers()}}
async function delUser(id){if(confirm(T('delWarn'))){await api('/api/users/'+id,{method:'DELETE'});closeModal();loadUsers();loadStats()}}

async function doChangePw(){
 pwMsg.textContent='';
 try{await api('/api/change-password',{method:'POST',
   body:JSON.stringify({current:pwCur.value,new:pwNew.value})});
  pwMsg.style.color='var(--ok)';pwMsg.textContent=T('pwChanged');
  pwCur.value='';pwNew.value='';
 }catch(e){pwMsg.style.color='var(--bad)';pwMsg.textContent=e.message}
}

/* ─── backup & restore ─── */
let BK=null;

const bkEsc=s=>(s==null?'':String(s)).replace(/[<>&"]/g,
 c=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c]));
const bkRow=(k,v)=>`<div class="kv"><span class="dim">${k}</span><span class="ms-auto mono">${v}</span></div>`;

async function loadBackupInfo(){
 try{
  const i=await api('/api/backup/info');
  bkInfo.innerHTML=bkRow(T('bkUsersN'),i.users)+bkRow(T('bkCipsN'),i.clean_ips)
   +bkRow(T('bkProxN'),i.proxies)+bkRow(T('bkTrafficN'),i.traffic_rows);
 }catch(e){bkInfo.innerHTML=''}
}

/* ─── telegram backup ─── */
async function loadTelegram(){
 try{
  const t=await api('/api/telegram');
  tgChat.value=t.chat_id||''; tgAuto.checked=!!t.auto;
  tgToken.placeholder=t.token_set?(t.token_from_env?T('tgFromEnv'):'••••••••'):T('tgNotSet');
 }catch(e){}
}
async function saveTelegram(){
 const body={chat_id:tgChat.value.trim(),auto:tgAuto.checked};
 if(tgToken.value.trim())body.bot_token=tgToken.value.trim();
 try{await api('/api/telegram',{method:'POST',body:JSON.stringify(body)});return true}
 catch(e){tgMsg.style.color='var(--bad)';tgMsg.textContent=e.message;return false}
}
async function tgTest(){
 tgMsg.textContent=''; tgMsg.style.color='';
 if(!await saveTelegram())return;
 tgMsg.textContent=T('tgWorking');
 try{const r=await api('/api/telegram/test',{method:'POST'});
  tgMsg.style.color=r.ok?'var(--ok)':'var(--bad)';
  tgMsg.textContent=r.ok?'✓ Telegram':(r.error||'failed');
 }catch(e){tgMsg.style.color='var(--bad)';tgMsg.textContent=e.message}
}
async function tgBackupNow(){
 tgMsg.textContent=''; tgMsg.style.color='';
 if(!await saveTelegram())return;
 tgMsg.textContent=T('tgWorking');
 try{const r=await api('/api/telegram/backup',{method:'POST'});
  tgMsg.style.color=r.ok?'var(--ok)':'var(--bad)';
  tgMsg.textContent=r.ok?('✓ '+T('tgSent')):(r.error||'failed');
 }catch(e){tgMsg.style.color='var(--bad)';tgMsg.textContent=e.message}
}

function doBackup(){
 const qs='password='+(bkPw.checked?1:0)+'&traffic='+(bkTraffic.checked?1:0)
  +'&proxy_creds='+(bkPxCreds.checked?1:0);
 const a=document.createElement('a');
 a.href='/api/backup?'+qs; a.rel='noopener';
 document.body.appendChild(a); a.click(); a.remove();
 bkMsg.style.color='var(--ok)'; bkMsg.textContent='✓';
 setTimeout(()=>{bkMsg.textContent=''},2000);
}

async function pickBackup(){
 const fi=document.getElementById('bkFile'), nm=document.getElementById('bkFileName');
 if(nm) nm.textContent=fi&&fi.files&&fi.files[0]?'· '+fi.files[0].name:'';
 BK=null; bkOpts.classList.add('hidden'); bkPreview.innerHTML='';
 bkMsg.style.color='var(--dim)'; bkMsg.textContent='';
 const f=bkFile.files&&bkFile.files[0];
 if(!f) return;
 bkMsg.textContent=T('bkReading');
 let parsed;
 try{ parsed=JSON.parse(await f.text()); }
 catch(e){ bkMsg.style.color='var(--bad)'; bkMsg.textContent=T('bkBadFile'); return }

 try{
  const p=await api('/api/restore/preview',{method:'POST',
    body:JSON.stringify({data:parsed})});
  BK=parsed;
  bkMsg.textContent='';
  let html=bkRow(T('bkFrom'),dt(p.created_at))+bkRow(T('bkUsersN'),p.users)
   +bkRow(T('bkCipsN'),p.clean_ips)+bkRow(T('bkProxN'),p.proxies);
  if(p.proxies_with_creds) html+=bkRow(T('bkProxCreds'),p.proxies_with_creds);
  if(p.traffic_rows) html+=bkRow(T('bkTrafficN'),p.traffic_rows);
  html+=bkRow(ICO.key,p.has_password?T('bkHasPw'):T('bkNoPw'));
  const diff=Object.entries(p.env_diff||{});
  if(diff.length){
   html+=`<p class="notice" style="margin-top:8px"><b style="color:var(--warn)">${T('bkEnvDiff')}</b><br>`
    +diff.map(([k,v])=>`<span class="mono">${bkEsc(k)}</span>: <span class="mono">${bkEsc(v.current||'—')}</span> → <span class="mono">${bkEsc(v.backup||'—')}</span>`).join('<br>')
    +`</p>`;
  }
  bkPreview.innerHTML=html;
  bkRestorePw.checked=false;
  bkRestorePw.parentElement.classList.toggle('hidden',!p.has_password);
  bkOpts.classList.remove('hidden');
 }catch(e){
  bkMsg.style.color='var(--bad)'; bkMsg.textContent=e.message||T('bkBadFile');
 }
}

async function doRestore(){
 if(!BK) return;
 const mode=bkMode.value;
 if(mode==='replace'&&!confirm(T('bkReplaceWarn'))) return;
 btnRestore.disabled=true;
 bkMsg.style.color='var(--dim)'; bkMsg.textContent='…';
 try{
  const r=await api('/api/restore',{method:'POST',body:JSON.stringify({
    data:BK,mode,restore_password:bkRestorePw.checked})});
  bkMsg.style.color='var(--ok)';
  bkMsg.textContent=`${T('bkDone')} — ${T('bkUsersN')}: +${r.users_added}/~${r.users_updated}`
   +` · ${T('bkCipsN')}: +${r.clean_ips_added}`
   +` · ${T('bkProxN')}: +${r.proxies_added}/~${r.proxies_updated}`
   +(r.users_skipped||r.proxies_skipped||r.clean_ips_skipped
     ?` · ${T('bkSkipped')}: ${r.users_skipped+r.proxies_skipped+r.clean_ips_skipped}`:'');
  BK=null; bkFile.value=''; bkOpts.classList.add('hidden'); bkPreview.innerHTML='';
  loadUsers(); loadCips(); loadStats(); loadBackupInfo(); loadTelegram();
  if(typeof loadProxies==='function') loadProxies();
  if(r.password_restored) alert(T('bkPwChanged'));
 }catch(e){ bkMsg.style.color='var(--bad)'; bkMsg.textContent=e.message }
 finally{ btnRestore.disabled=false }
}

function copy(btn,t){navigator.clipboard.writeText(t);
 const old=btn.innerHTML;btn.textContent=T('copied');setTimeout(()=>{btn.innerHTML=old},1200)}
let _tmr;
function toast(msg){const el=document.getElementById('toast');el.innerHTML=msg;el.classList.add('on');
 clearTimeout(_tmr);_tmr=setTimeout(()=>el.classList.remove('on'),2600)}

/* ══════════════════════════════════════════════════════════════════
   SELECT ENHANCER — همه‌ی <select>ها به منوی داخلی پنل تبدیل می‌شوند.
   خود select مخفی می‌ماند، پس تمام کدهای قبلی (.value / onchange) دست‌نخورده کار می‌کنند.
   ══════════════════════════════════════════════════════════════════ */
(function(){
 const MAPCE=new WeakMap();
 const escH=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

 let MUT=0;   /* گارد: نوشتن‌های خودمان نباید MutationObserver را بیدار کند */

 /* ── پرچم کشور به‌صورت SVG (سرور آن را از /flag/XX.svg می‌دهد) ── */
 function flagImg(cc,cls){
  var c=String(cc==null?'':cc).toUpperCase().replace(/[^A-Z]/g,'').slice(0,2);
  if(c.length!==2) return '';
  return '<img class="flag '+(cls||'')+'" src="/flag/'+c+'.svg" alt="'+c+'" title="'+c+'"'+
         ' width="18" height="13" loading="lazy" onerror="this.style.visibility=\'hidden\'">';
 }
 window.flagImg=flagImg;

 function build(sel){
  if(MAPCE.has(sel)){
   const a=MAPCE.get(sel);
   if(a.root.isConnected&&a.root.parentNode===sel.parentNode)return a;
   try{a.root.remove()}catch(_){}
   MAPCE.delete(sel);
  }
  const root=document.createElement('div'); root.className='sel';
  const btn=document.createElement('button');
  btn.type='button'; btn.className='sel-btn'; btn.setAttribute('aria-haspopup','listbox');
  btn.setAttribute('aria-expanded','false');
  btn.innerHTML='<span class="cur"></span><svg class="caret" viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg>';
  const menu=document.createElement('div');
  menu.className='sel-menu'; menu.setAttribute('role','listbox');
  root.appendChild(btn); root.appendChild(menu);
  root.dataset.forSel='1';
  MUT++; sel.parentNode.insertBefore(root, sel.nextSibling); MUT--;
  const api={sel,root,btn,menu,sig:null};
  MAPCE.set(sel,api);
  btn.addEventListener('click',e=>{e.stopPropagation();toggle(api)});
  root.addEventListener('keydown',e=>onKey(e,api));
  sync(sel);
  return api;
 }

 function txt(o){return (o.textContent||'').trim()||o.value||'—'}
 function ccOf(o){return (o&&o.dataset&&o.dataset.cc)||''}

 function sync(sel){
  const api=MAPCE.get(sel); if(!api)return;
  const opts=[...sel.options];
  const sig=opts.map(o=>o.value+'\u0001'+txt(o)+'\u0001'+ccOf(o)).join('\u0002')+'\u0003'+sel.value;
  if(api.sig===sig)return;
  api.sig=sig;
  const cur=opts.find(o=>o.value===sel.value)||opts[0];
  api.btn.querySelector('.cur').innerHTML=
   (cur?flagImg(ccOf(cur)):'')+
   '<span class="tx">'+escH(cur?txt(cur):'—')+'</span>';
  MUT++;
  if(!opts.length){api.menu.innerHTML='<div class="sempty">—</div>';MUT--;return}
  api.menu.innerHTML=opts.map(o=>{
   const on=String(o.value)===String(sel.value);
   return '<button type="button" class="sopt" role="option" data-v="'+escH(o.value)+'" '+
    'aria-selected="'+(on?'true':'false')+'"'+(o.disabled?' disabled':'')+'>'+
    flagImg(ccOf(o))+'<span class="tx">'+escH(txt(o))+'</span>'+
    '<svg class="tick" viewBox="0 0 24 24"><path d="M5 12.5l4.5 4.5L19 7"/></svg></button>';
  }).join('');
  MUT--;
  api.menu.querySelectorAll('.sopt').forEach(b=>{
   b.addEventListener('click',()=>{
    if(sel.value!==b.dataset.v){
     sel.value=b.dataset.v;
     sel.dispatchEvent(new Event('change',{bubbles:true}));
     sel.dispatchEvent(new Event('input',{bubbles:true}));
    }
    api.sig=null; sync(sel); close(api); api.btn.focus();
   });
  });
 }

 function markOpen(root,on){
  /* کارت‌هایی که overflow:hidden دارند منو را می‌بریدند */
  let el=root.parentElement, n=0;
  while(el&&el!==document.body&&n<6){
   if(el.classList&&(el.classList.contains('card')||el.classList.contains('sheet-body'))){
    el.classList.toggle('sel-open',on);
   }
   el=el.parentElement; n++;
  }
 }
 let OPENED_AT=0, OPEN_XY=[0,0], TOUCHED=false;
 function open(api){
  closeAll(api.root);
  markOpen(api.root,true);
  OPENED_AT=Date.now();
  OPEN_XY=[window.scrollX,window.scrollY];
  TOUCHED=false;
  const r=api.btn.getBoundingClientRect();
  api.root.classList.toggle('up',(window.innerHeight-r.bottom)<250&&r.top>260);
  api.root.classList.add('open');
  api.btn.setAttribute('aria-expanded','true');
  /* گزینهٔ فعلی را در دید می‌آوریم، ولی بدون اسکرول کردن صفحه
     (scrollIntoView باعث می‌شد صفحه جابه‌جا و منو فوراً بسته شود) */
  const selOpt=api.menu.querySelector('.sopt[aria-selected="true"]');
  if(selOpt) setTimeout(()=>{
   const m=api.menu;
   if(selOpt.offsetTop<m.scrollTop||selOpt.offsetTop+selOpt.offsetHeight>m.scrollTop+m.clientHeight)
    m.scrollTop=Math.max(0,selOpt.offsetTop-m.clientHeight/2+selOpt.offsetHeight/2);
  },0);
 }
 function close(api){api.root.classList.remove('open');
  api.btn.setAttribute('aria-expanded','false');markOpen(api.root,false)}
 function toggle(api){api.root.classList.contains('open')?close(api):open(api)}
 function closeAll(exceptRoot){
  document.querySelectorAll('.sel.open').forEach(r=>{
   if(exceptRoot&&r===exceptRoot)return;
   r.classList.remove('open');
   markOpen(r,false);
   const b=r.querySelector('.sel-btn'); if(b)b.setAttribute('aria-expanded','false');
  });
 }
 function hl(items,i){
  items.forEach(x=>x.classList.remove('hl'));
  if(items[i]){items[i].classList.add('hl');items[i].scrollIntoView({block:'nearest'})}
 }
 function onKey(e,api){
  const isOpen=api.root.classList.contains('open');
  if(e.key==='Escape'&&isOpen){e.preventDefault();close(api);api.btn.focus();return}
  if(e.key==='ArrowDown'&&!isOpen){e.preventDefault();open(api);return}
  if(!isOpen)return;
  const items=[...api.menu.querySelectorAll('.sopt')];
  let i=items.findIndex(x=>x.classList.contains('hl'));
  if(i<0)i=items.findIndex(x=>x.getAttribute('aria-selected')==='true');
  if(e.key==='ArrowDown'){e.preventDefault();hl(items,Math.min(items.length-1,i+1))}
  if(e.key==='ArrowUp'){e.preventDefault();hl(items,Math.max(0,i-1))}
  if(e.key==='Enter'||e.key===' '){e.preventDefault();const t=items[i]||items[0];if(t)t.click()}
  if(e.key==='Tab')close(api);
 }

 function prune(){
  /* آینه‌هایی که select‌شان از صفحه حذف شده باید بروند، وگرنه روی هم تلنبار می‌شوند */
  document.querySelectorAll('.sel[data-for-sel]').forEach(root=>{
   const prev=root.previousElementSibling;
   if(!prev||prev.tagName!=='SELECT'){try{root.remove()}catch(_){}}
  });
 }

 function scan(){
  if(MUT)return;
  prune();
  document.querySelectorAll('select').forEach(sel=>{
   if(sel.dataset.native==='1')return;      /* اگر خواستی بعضی‌ها نیتیو بمانند */
   if(!MAPCE.has(sel))build(sel); else sync(sel);
  });
 }

 document.addEventListener('click',()=>closeAll());
 document.addEventListener('keydown',e=>{if(e.key==='Escape')closeAll()});
 /* بستن با اسکرول — ولی نه اسکرولی که خودِ باز شدن منو ایجاد می‌کند */
 /* بستن با اسکرول — ولی نه با اسکرولی که خودِ باز شدن منو یا خودِ منو ایجاد می‌کند */
function scrolledByUser(){
  if(TOUCHED) return true;                      /* کاربر با انگشت کشیده */
  if(Date.now()-OPENED_AT<420) return false;    /* اسکرول خودکارِ لحظهٔ باز شدن */
  if(Math.abs(window.scrollX-OPEN_XY[0])>2||Math.abs(window.scrollY-OPEN_XY[1])>2) return true;
  return false;                                 /* اسکرول داخلی (مثلاً خود منو) */
}
window.addEventListener('scroll',(e)=>{
  const t=e.target;
  if(t&&t.nodeType===1&&t.closest&&t.closest('.sel'))return; /* خود منو */
  if(!scrolledByUser())return;
  closeAll();
},true);
/* روی موبایل، لمسی که واقعاً جابه‌جا شود منو را می‌بندد */
document.addEventListener('touchstart',()=>{TOUCHED=false},{passive:true,capture:true});
document.addEventListener('touchmove',(e)=>{
  const t=e.target;
  if(t&&t.nodeType===1&&t.closest&&t.closest('.sel-menu'))return;
  TOUCHED=true;
},{passive:true,capture:true});
document.addEventListener('wheel',(e)=>{
  const t=e.target;
  if(t&&t.nodeType===1&&t.closest&&t.closest('.sel-menu'))return;
  if(Date.now()-OPENED_AT>420) closeAll();
},{passive:true,capture:true});
 window.addEventListener('resize',()=>closeAll());
 /* هر بار پنل آپشن‌ها/متن‌ها را بازنویسی کرد، آینه به‌روز می‌شود */
 let mt=null;
 const mo=new MutationObserver(()=>{
  if(MUT)return;
  clearTimeout(mt);
  mt=setTimeout(()=>{try{scan()}catch(e){}},80);
 });
 function startObserver(){
  mo.observe(document.body,{childList:true,subtree:true,characterData:true});
 }
 window.enhanceSelects=scan;
 scan(); startObserver();
 setTimeout(scan,250); setTimeout(scan,1000); setTimeout(scan,2500);

 /* تگ زبان روی نوار بالا */
 function syncLangTag(){
  const el=document.getElementById('langTag');
  if(el) el.textContent=(document.documentElement.lang==='fa')?'EN':'FA';
 }
 new MutationObserver(syncLangTag).observe(document.documentElement,{attributes:true,attributeFilter:['lang']});
 syncLangTag();
})();

/* ══════════════════ v4 · سرصفحه، مودال کاربر، تب‌ها ══════════════════ */
const PH_MAP={
 dash:['navDash','phDash'],users:['navUsers','phUsers'],clean:['navClean','phClean'],
 filter:['navFilter','phFilter'],proxy:['navProxy','phProxy'],live:['navLive','phLive'],
 tgweb:['navTgweb','phTgweb'],settings:['navSettings','phSettings'],logs:['navLogs','phLogs']};
const PH_ICO={
 plus:'<svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>',
 refres:'<svg viewBox="0 0 24 24"><path d="M20 11.5a8 8 0 10-2.3 5.6M20 5v6.5h-6.5"/></svg>'};
function paintPageHead(p){
 const t=document.getElementById('phTitle'),s=document.getElementById('phSub'),
       a=document.getElementById('phActs');
 if(!t)return;
 const m=PH_MAP[p]||PH_MAP.dash;
 t.textContent=T(m[0]); s.textContent=T(m[1]||'');
 /* عنوان تکراری داخل کارت‌ها پنهان می‌شود تا صفحه دو بار تیتر نخورد */
 const sec=document.querySelector('[data-pg="'+p+'"]');
 if(sec)sec.querySelectorAll('.card-head b').forEach(b=>{
  const same=(b.dataset.t&&b.dataset.t===m[0])||b.textContent.trim()===t.textContent.trim();
  b.style.display=same?'none':'';
 });
 if(!a)return;
 if(p==='users'){
  a.innerHTML=`<button class="btn" onclick="openUserForm()">${PH_ICO.plus}<span>${T('newUser')}</span></button>`;
 }else if(p==='clean'||p==='filter'||p==='live'||p==='logs'){
  a.innerHTML=`<button class="btn btn-soft" onclick="refreshPage()">${PH_ICO.refres}<span>${T('refreshLbl')}</span></button>`;
 }else a.innerHTML='';
}
function refreshPage(){
 if(PAGE==='clean')loadCips(); else if(PAGE==='filter')loadFilter();
 else if(PAGE==='live')loadLive(); else if(PAGE==='logs')loadLogs(); else loadStats();
}

/* ── مودال ساخت کاربر ── */
function openUserForm(){
 const m=document.getElementById('userModal'); if(!m)return;
 const e=document.getElementById('cErr'); if(e)e.textContent='';
 m.classList.remove('hidden');
 document.body.classList.add('locked');
 switchTab('basic');
 try{enhanceSelects()}catch(_){}
 setTimeout(()=>{const n=document.getElementById('nName'); if(n&&!n.value)n.focus()},80);
}
function closeUserForm(){
 const m=document.getElementById('userModal'); if(!m)return;
 m.classList.add('hidden');
 document.body.classList.remove('locked');
}
function switchTab(p){
 document.querySelectorAll('#umTabs button').forEach(b=>b.classList.toggle('on',b.dataset.pane===p));
 document.querySelectorAll('#userModal .pane').forEach(x=>x.classList.toggle('on',x.dataset.pane===p));
 const body=document.querySelector('#userModal .sheet-body');
 if(body)body.scrollTop=0;
}
(function wireUserForm(){
 const m=document.getElementById('userModal'); if(!m)return;
 const tabs=document.getElementById('umTabs');
 if(tabs)tabs.addEventListener('click',ev=>{
  const b=ev.target.closest('button[data-pane]'); if(b)switchTab(b.dataset.pane);
 });
 m.addEventListener('click',ev=>{ if(ev.target===m)closeUserForm(); });
 document.addEventListener('keydown',ev=>{
  if(ev.key==='Escape'&&!m.classList.contains('hidden'))closeUserForm();
 });
 const nr=document.getElementById('nReset');
 if(nr)nr.addEventListener('change',()=>{
  const w=document.getElementById('nResetWrap');
  if(w)w.classList.toggle('hidden',nr.value!=='-1');
 });
})();

/* ─── boot ─── */
paintStatic(); syncSelects(); genSecret(true); tgPickPlatform('render');
go(PAGE);
loadStats();loadUsers();loadCips();loadMainCountry();loadProxies();
loadTgSettings();loadTgweb();loadTgRegions();
setInterval(()=>{loadStats();if(PAGE==='users')loadUsers()},15000);
</script></body></html>"""

LOGO_B64 = (
    "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"
)
LOGO_URI = "data:image/png;base64," + LOGO_B64
LOGO_PNG = base64.b64decode(LOGO_B64)

AUTH_HTML  = (AUTH_HTML.replace("__THEME__", THEME_CSS)
                        .replace("__I18N__", I18N_JS)
                        .replace("__LOGO__", LOGO_URI))
PANEL_HTML = (PANEL_HTML.replace("__THEME__", THEME_CSS)
                        .replace("__I18N__", I18N_JS)
                        .replace("__LOGO__", LOGO_URI))
_TEMPLATE  = _TEMPLATE.replace("__LOGO__", LOGO_URI)


@app.get("/favicon.ico")
async def favicon():
    return Response(LOGO_PNG, media_type="image/png",
                    headers={"cache-control": "public, max-age=604800"})
