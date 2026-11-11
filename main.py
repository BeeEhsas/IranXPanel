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
    ("v2rayng", "v2rayNG"), ("v2raytun", "v2rayTun"), ("v2rayn", "v2rayN"),
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


def device_key(ip: str, ua: str) -> str:
    """Opaque per-device identity: stable for one client+IP, distinct for others."""
    seed = f"{(ip or '').strip()}|{(ua or '').strip().lower()}"
    return hashlib.sha1(seed.encode()).hexdigest()[:16]


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
    dkey = device_key(ip, ua)
    if not device_allowed(row["id"], dkey, row["device_limit"]):
        return None, "device limit"
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
}

ISO2_RE = re.compile(r"(?:^|[\s\-_\[\(#|])([A-Za-z]{2})(?:$|[\s\-_\]\)#|])")


def flag_of(code: str) -> str:
    """ISO-3166 alpha-2 -> regional-indicator flag (e.g. DE -> German flag)."""
    c = re.sub(r"[^A-Za-z]", "", code or "")[:2].upper()
    if len(c) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(ch) - 65) for ch in c)


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
    return flag_of(get_setting("main_country") or "")


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
    server_flag = main_flag() or "\U0001f310"
    by_proxy_flag = (get_setting("flag_source") or "proxy") == "proxy"
    routes = [(server_flag, "", True, None)]
    for px in sub_proxies():
        try:
            pflag = flag_of(px["country"] or "") or flag_of(guess_country(px["remark"] or ""))
        except Exception:
            pflag = ""
        mark = (pflag or "\U0001f310") if by_proxy_flag else server_flag
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
         "flag": "\U0001f1e9\U0001f1ea"},
        {"id": "oregon", "fa": "اورگان، آمریکا", "en": "Oregon, USA",
         "flag": "\U0001f1fa\U0001f1f8"},
        {"id": "ohio", "fa": "اوهایو، آمریکا", "en": "Ohio, USA",
         "flag": "\U0001f1fa\U0001f1f8"},
        {"id": "virginia", "fa": "ویرجینیا، آمریکا", "en": "Virginia, USA",
         "flag": "\U0001f1fa\U0001f1f8"},
        {"id": "singapore", "fa": "سنگاپور", "en": "Singapore",
         "flag": "\U0001f1f8\U0001f1ec"},
    ],
    "railway": [
        {"id": "europe-west4-drams3a", "fa": "آمستردام، هلند",
         "en": "Amsterdam, Netherlands", "flag": "\U0001f1f3\U0001f1f1"},
        {"id": "us-west2", "fa": "کالیفرنیا، آمریکا", "en": "California, USA",
         "flag": "\U0001f1fa\U0001f1f8"},
        {"id": "us-east4-eqdc4a", "fa": "ویرجینیا، آمریکا", "en": "Virginia, USA",
         "flag": "\U0001f1fa\U0001f1f8"},
        {"id": "asia-southeast1-eqsg3a", "fa": "سنگاپور", "en": "Singapore",
         "flag": "\U0001f1f8\U0001f1ec"},
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
            used = await render_usage_bytes(get_setting("tgweb_render_token") or "",
                                            row["service_id"], since)
        else:
            token = get_setting("tgweb_railway_token") or ""
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
    return (get_setting("tgweb_render_token") or "",
            get_setting("tgweb_railway_token") or "")


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
            token = get_setting("tgweb_render_token") or ""
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
            token = get_setting("tgweb_railway_token") or ""
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
        token = get_setting("tgweb_render_token") or ""
        check = lambda: render_deploy_status(token, row["service_id"])
        hint = ("Render build failed — open the service's Events/Logs page in the "
                "Render dashboard (repo %s, branch %s)" % (repo, branch))
    else:
        try:
            coords = json.loads(row["coords"] or "{}")
        except Exception:
            coords = {}
        token = get_setting("tgweb_railway_token") or ""
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
            token = get_setting("tgweb_render_token") or ""
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
            token = get_setting("tgweb_railway_token") or ""
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
        token = get_setting("tgweb_render_token") or ""
        env = await render_get_env(token, row["service_id"])
        if "TGP_SECRET" not in env:
            raise PlatformError("service has no TGP_SECRET — not created by this panel?")
        env["TGP_SECRET"] = new
        await render_put_env(token, row["service_id"], env)
        await render_trigger_deploy(token, row["service_id"])
    elif platform == "railway":
        token = get_setting("tgweb_railway_token") or ""
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
        token = get_setting("tgweb_render_token") or ""
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
        token = get_setting("tgweb_railway_token") or ""
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
            token = get_setting("tgweb_render_token") or ""
            await render_delete_service(token, row["service_id"])
        elif platform == "railway":
            token = get_setting("tgweb_railway_token") or ""
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
    cols = "id,dkey,ip,ua,client,platform,proto,first_seen,last_seen,hits"
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
             "label": device_label(r["client"], r["platform"], r["ip"]),
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
    """Platform credentials — tokens are never returned, only a hint that one is set."""
    rt, rw = tgw_settings_tokens()
    return {
        "render_token_set": bool(rt),
        "render_token_hint": ("••••" + rt[-4:]) if rt else "",
        "railway_token_set": bool(rw),
        "railway_token_hint": ("••••" + rw[-4:]) if rw else "",
        "repo": tgw_repo_url(),
        "branch": tgw_branch(),
    }


@app.post("/api/tgweb/settings")
async def set_tgweb_settings(body: TgWebSettingsIn, _=Depends(require_admin)):
    if body.render_token:
        set_setting("tgweb_render_token", body.render_token.strip())
    if body.railway_token:
        set_setting("tgweb_railway_token", body.railway_token.strip())
    if body.repo is not None:
        set_setting("tgweb_repo", (body.repo or "").strip().rstrip("/")
                    or TGWEB_REPO)   # keep scheme + case: it is a repo URL, not a host
    if body.branch is not None:
        set_setting("tgweb_branch", body.branch.strip() or "main")
    audit("tgweb-settings", "", "platform tokens/repo updated")
    return await get_tgweb_settings()


@app.post("/api/tgweb")
async def add_tgweb(body: TgWebIn, _=Depends(require_admin)):
    platform = body.platform if body.platform in ("external", "render", "railway") \
        else "external"
    if platform == "external":
        server = tg_clean_server(body.server)
        if not server:
            raise HTTPException(400, "server is required (bare host, no https:// or port)")
    else:
        tok = get_setting("tgweb_render_token" if platform == "render"
                          else "tgweb_railway_token") or ""
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
                        get_setting("tgweb_railway_token") or "",
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
        token = get_setting("tgweb_railway_token") or ""
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
<html lang="fa" dir="rtl" data-theme="gray">
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
  font-family:'Inter','Vazirmatn',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,system-ui,sans-serif;
  font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased;
  background-image:radial-gradient(circle at 50% -18%,rgba(34,239,157,.07),transparent 58%);
}
html[lang="fa"] body{
  font-family:'Vazirmatn','Vazir','IRANSansX',Tahoma,'Segoe UI',system-ui,sans-serif;
  font-size:14px;line-height:1.85;
}
html[lang="fa"] b,html[lang="fa"] strong{font-weight:600}
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
      <button class="chip" id="langBtn" type="button"></button>
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
  fa:{brand:"IranX · اشتراک من", remainVol:"حجم باقی‌مانده", remainTime:"زمان باقی‌مانده",
    devices:"دستگاه مجاز", ipAddr:"آی‌پی مجاز", used:"مصرف‌شده", total:"کل", usage:"مصرف",
    copySub:"کپی لینک اشتراک", copyAll:"کپی همه کانفیگ‌ها", addTo:"افزودن به",
    configs:"کانفیگ‌ها", downloads:"دانلود برنامه‌ها", noConfigs:"کانفیگ فعالی وجود ندارد.",
    showQr:"نمایش QR", copyCfg:"کپی کانفیگ",
    scanHint:"با دوربین برنامه اسکن کنید تا اشتراک خودکار اضافه شود",
    footer:"لینک اشتراک شخصی شماست — آن را با کسی به اشتراک نگذارید",
    updEvery:(h)=>"به‌روزرسانی هر "+h+" ساعت", expires:"انقضا", noExpiry:"بدون انقضا",
    unlimited:"بی‌نهایت", support:"با پشتیبانی تماس بگیرید",
    statusActive:"فعال", statusExpired:"اشتراک منقضی شده", statusQuota:"حجم اشتراک تمام شده",
    statusDisabled:"اشتراک غیرفعال شده", statusInactive:"اشتراک فعال نیست",
    resetEveryN:(n)=>"ریست مصرف هر "+n+" روز", nextReset:"ریست بعدی",
    days:"روز", hours:"ساعت", left:"باقی‌مانده", cfgCount:(n)=>n+" کانفیگ فعال",
    copiedSub:"لینک اشتراک کپی شد", copiedAll:"همه کانفیگ‌ها کپی شد", copiedCfg:"کانفیگ کپی شد",
    noQr:"QR در دسترس نیست",
    importHint:"اگر برنامه باز نشد: لینک کپی شده — در برنامه گزینهٔ Add from clipboard را بزنید",
    allVersions:"همه نسخه‌ها", light:"روشن", dark:"خاکستری", subName:"اشتراک"},
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
let LANG="fa", THEME="gray", current=(D.osTabs&&D.osTabs[0]?D.osTabs[0][0]:"android");
try{ LANG=localStorage.getItem("iranx_lang")||LANG; THEME=localStorage.getItem("iranx_theme")||THEME; }catch(e){}
if(LANG!=="en") LANG="fa";
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
    <span class="nm">${esc(c.label)}</span>
    <span class="tchip">${esc((c.transport||"").toUpperCase())}</span>
    <button class="ico" data-qr="${i}" title="${esc(t("showQr"))}" aria-label="${esc(t("showQr"))}">${ICON_QR}</button>
    <button class="ico" data-copy="${i}" title="${esc(t("copyCfg"))}" aria-label="${esc(t("copyCfg"))}">${ICON_COPY}</button>
    <div class="cfgqr" data-box="${i}" hidden></div>
  </div>`).join("") : `<div class="card"><p class="hint" style="margin:0">${esc(t("noConfigs"))}</p></div>`;
}

function render(){
  const h = document.documentElement;
  h.lang = LANG; h.dir = LANG==="fa" ? "rtl" : "ltr"; h.dataset.theme = THEME;
  $("#bTitle").textContent = t("brand");
  $("#themeBtn").innerHTML = (THEME==="light" ? ICON_MOON : ICON_SUN) +
    "<span>"+(THEME==="light" ? t("dark") : t("light"))+"</span>";
  $("#langBtn").textContent = LANG==="fa" ? "EN" : "FA";
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
$("#langBtn").onclick = ()=>{ LANG = LANG==="fa" ? "en" : "fa";
  try{ localStorage.setItem("iranx_lang", LANG); }catch(e){} render(); };
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


@app.get("/sub/{token}")
async def subscription(token: str, request: Request):
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE sub_token=?", (token,)).fetchone()
        ips = c.execute("SELECT * FROM clean_ips WHERE enabled=1 ORDER BY id").fetchall()
    if not row:
        raise HTTPException(404, "not found")

    row = maybe_auto_reset(row)

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
  max-height:270px;overflow-y:auto;
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
  font-size:13px;font-weight:600;line-height:1.4;min-width:0;flex:0 1 auto;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:44vw;
}

/* ردیف ابزار: چیپ ترنسپورت کنار سه دکمه */
.uc-tools{display:flex;align-items:center;gap:8px;min-width:0}
/* RTL: چیپ ترنسپورت سمت راست، دکمه‌ها سمت چپ */
.uc-tsp{flex:0 0 auto;display:inline-flex}
.uc-tools .chip{flex:0 0 auto}
.uc-act{display:flex;gap:6px;align-items:center;flex:0 0 auto;
  margin-inline-start:auto}
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
  .uc-top .nm{max-width:40vw}
  .uc-foot{gap:3px 10px;font-size:10.5px}
  .uc-foot .dt{font-size:10.5px}
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
"""


I18N_JS = r"""
const I18N={
 fa:{dir:'rtl',
  unitBytes:'بایت',loadingLbl:'در حال بارگذاری…',noLive:'اتصال بازی نیست',
  phDash:'وضعیت لحظه‌ای سرور، کاربران و ترافیک',  phUsers:'ساخت، ویرایش و پیگیری حساب‌ها',  phClean:'آی‌پی‌هایی که در لینک ساب قرار می‌گیرند',  phFilter:'دامنه‌های مسدود و مجاز',  phProxy:'استخر پروکسی و انتخاب خودکار',  phLive:'اتصال‌های باز در همین لحظه',  phTgweb:'وب‌پروکسی تلگرام',  phSettings:'ظاهر، رمز عبور، پشتیبان‌گیری و سرور',  phLogs:'آخرین رخدادهای پنل',  refreshLbl:'به‌روزرسانی',  tabBasic:'پایه',  tabLimits:'محدودیت‌ها',  tabSecurity:'امنیت',  viewAll:'همه',  r24:'۲۴ ساعت',  cancel:'انصراف',  statHintUsers:'حساب ساخته‌شده',  statHintOnline:'الان متصل',  statHintDev:'دستگاه فعال',  statHintBytes:'از زمان راه‌اندازی',  statHintCip:'در لینک ساب',  statHintLive:'نشست زنده',  zeroInfShort:'صفر یعنی بی‌نهایت.',  moreLbl:'جزئیات',  noResult:'چیزی پیدا نشد',
  setupTitle:'تعیین رمز عبور',setupSub:'اولین ورود: یک رمز انتخاب کن.',
  loginTitle:'ورود به پنل',loginSub:'رمز عبور',
  password:'رمز عبور',confirm:'تکرار رمز عبور',enter:'ورود',save:'ذخیره و ورود',
  pwRule:'حداقل ۸ کاراکتر شامل حرف بزرگ، حرف کوچک و عدد',netErr:'خطای شبکه',
  navDash:'داشبورد',navUsers:'مدیریت کاربران',navClean:'آی‌پی تمیز',
  navProxy:'پروکسی',navLive:'اتصالات زنده',
  navSettings:'تنظیمات پنل',navLogs:'رخدادها',menu:'منو',
  totalUsers:'کل کاربران',online:'کاربران آنلاین',devices:'دستگاه‌های متصل',
  traffic:'مصرف کل',cleanIps:'آی‌پی تمیز',xSessions:'نشست‌های XHTTP',liveTitle:'اتصالات زنده',liveEmpty:'هیچ اتصالی فعال نیست',
  chart24:'مصرف ۲۴ ساعت اخیر',protoSplit:'تعداد اتصالات هر ترنسپورت',
  newUser:'ساخت کاربر جدید',users:'کاربران',
  name:'نام (انگلیسی)',quota:'حجم (GB)',days:'مدت (روز)',devLimit:'تعداد دستگاه',ipLimit:'تعداد آی‌پی',
  transport:'روش اتصال',trWs:'WS + TLS',trXhttp:'XHTTP + TLS',trBoth:'هر دو',
  add:'افزودن',zeroInf:'۰ = بی‌نهایت. هر دستگاه با IP و مشخصات کلاینتش شناخته می‌شود. سقف آی‌پی جداست و روی آدرس‌های تکراری حساب نمی‌شود.',
  search:'جستجو…',noUsers:'کاربری نیست',
  config:'کانفیگ',ipsBtn:'دستگاه‌ها و آی‌پی‌ها',edit:'ویرایش',
  used:'مصرف',expiry:'انقضا',never:'بی‌نهایت',
  subLink:'لینک اشتراک (Subscription)',copySub:'کپی لینک اشتراک',
  singleCfg:'کانفیگ‌های تکی',copy:'کپی',copied:'کپی شد ✓',
  devTitle:'دستگاه‌های متصل',noConn:'هنوز اتصالی ثبت نشده',
  clearIps:'پاک کردن دستگاه‌ها و آی‌پی‌ها',delDevice:'حذف دستگاه',delDeviceWarn:'این دستگاه از لیست حذف شود؟ (یک جای خالی آزاد می‌شود)',unknownClient:'ناشناس',devLimitLbl:'مجاز',onlineTag:'آنلاین',offlineTag:'آفلاین',
  devSec:'دستگاه‌ها',ipSec:'آی‌پی‌ها',ipCounted:'آی‌پی‌های شمرده‌شده',ipsTotal:'کل آی‌پی‌های دیده‌شده',delIp:'حذف آی‌پی',delIpWarn:'این آی‌پی از لیست حذف شود؟ (یک جای خالی آزاد می‌شود)',
  liveNow:'الان متصل',noneNow:'همین الان هیچ دستگاهی متصل نیست',
  countedFor:'حساب‌شده در سقف',totalSeen:'کل دستگاه‌های دیده‌شده',
  showHistory:'نمایش تاریخچه',showLive:'نمایش فقط متصل‌ها',
  inLast:'%s ثانیه پیش',refresh:'به‌روزرسانی',
  liveDevices:'دستگاه‌های فعال الان',
  editUser:'ویرایش',remainDays:'مدت باقی‌مانده (روز)',allowedDev:'تعداد دستگاه مجاز',allowedIp:'تعداد آی‌پی مجاز',
  active:'فعال',saveBtn:'ذخیره',resetTraffic:'ریست حجم',newUuid:'UUID جدید',
  customUuid:'UUID دستی',del:'حذف',
  obfLbl:'پنهان‌سازی (Fragment + Cipher)',
  echLbl:'ضد سانسور (ECH)',
  fpLbl:'فینگرپرینت TLS',alpnLbl:'ALPN',alpnDef:'پیش‌فرض این نوع کانفیگ',alpnNone:'بدون ALPN (حذف از لینک)',
  uuidWarn:'UUID عوض شود؟ کانفیگ‌های قبلی از کار می‌افتند.',delWarn:'این کاربر حذف شود؟',
  cleanTitle:'مدیریت Clean IP',
  cleanHint:'آی‌پی یا دامنه تمیز. در لینک اشتراک هر کاربر به عنوان کانفیگ اضافی اضافه می‌شود.',
  addrPh:'مثلا 1.2.3.4 یا cdn.example.com',remarkPh:'برچسب (اختیاری)',
  bulkPh:'چند مورد، هر خط یکی:\n1.2.3.4 # ایرانسل\n5.6.7.8 # همراه اول',
  bulkAdd:'افزودن انبوه',clearAll:'حذف همه',
  pxTitle:'پروکسی خروجی',
  pxHint:'وقتی پروکسی فعال است، ترافیک کاربران از آن خارج می‌شود و سایت‌ها IP پروکسی را می‌بینند.',
  pxKind:'نوع',pxHost:'هاست / ایپی',pxPort:'پورت',
  pxUser:'یوزرنیم (اختیاری)',pxPass:'پسورد (اختیاری)',
  pxAdd:'افزودن و تست',pxTestAll:'تست همه',
  pxInSub:'در ساب',
  pxAutoNote:'پروکسی‌های اضافه‌شده خودکار در ساب همه کاربران می‌آیند. کانفیگ مستقیم همیشه می‌ماند — تست ناموفق چیزی را حذف نمی‌کند.',
  pxLineHint:'هر خط یک پروکسی — مانند socks5://1.1.1.1:5866 یا http://user:pass@2.2.2.2:8080',
  pxAddLines:'افزودن لیست و تست',
  pxAdvanced:'ورود دستی فیلدها',
  pxDirect:'اتصال مستقیم (بدون پروکسی)',
  pxActive:'فعال',pxArm:'فعال کردن',pxTest:'تست سلامت',
  pxHealthy:'سالم',pxDown:'خراب',pxUntested:'تست نشده',
  pxExitIp:'آی‌پی خروجی',pxLatency:'تاخیر',
  pxNone:'هنوز پروکسی اضافه نشده است',
  pxStrict:'حالت سختگیرانه',
  pxStrictHint:'اگر پروکسی قطع شد، اتصال رد می‌شود تا آی‌پی اصلی سرور لو نرود',
  pxFlagSrc:'منبع پرچم نام کانفیگ',
  pxFlagProxy:'کشور پروکسی',pxFlagEntry:'کشور سرور ورودی',
  pxTesting:'در حال تست...',pxArmed:'پروکسی فعال شد',
  pxDelWarn:'این پروکسی حذف شود؟',
  addedN:'افزوده شد',dupN:'تکراری',invalidN:'نامعتبر',noCleanIps:'لیست خالی است',
  settings:'تنظیمات',appearance:'ظاهر',theme:'تم',language:'زبان',
  thDark:'تیره (مشکی و آبی)',thLight:'روشن (سفید و آبی)',thGray:'خاکستری',
  country:'کشور',autoCountry:'تشخیص خودکار',mainCountry:'کشور سرور اصلی',
  flagsHint:'پرچم کشور به ابتدای نام کانفیگ‌ها در لینک اشتراک اضافه می‌شود',
  savedOk:'ذخیره شد',save:'ذخیره',
  changePw:'تغییر رمز عبور',curPw:'رمز فعلی',newPw:'رمز جدید',pwChanged:'رمز تغییر کرد ✓',
  serverInfo:'اطلاعات سرور',wsPathLbl:'مسیر WebSocket',xhPathLbl:'مسیر XHTTP',
  xhModeLbl:'حالت XHTTP',
  xhModeHint:'packet-up برای هر تکه آپلود یک رکوئست می‌فرستد. اگر رله Cloudflare داری، stream-up را انتخاب کن تا هر اتصال فقط ۲ رکوئست شود.',
  trWarnTitle:'مصرف رکوئست XHTTP:',
  trWarn:'در XHTTP هر اتصال چند رکوئست می‌سازد. stream-up برای هر اتصال ۲ رکوئست؛ packet-up برای هر تکه آپلود یکی — که با رله Cloudflare سهمیه روزانه ورکر را زود تمام می‌کند. WS یک رکوئست برای کل اتصال است.',
  backupTitle:'پشتیبان‌گیری',
  backupHint:'همه‌ی کاربران با UUID و توکن، آی‌پی‌ها، پروکسی‌ها و تنظیمات در یک فایل .ixpbak ذخیره می‌شود.',
  bkInclPw:'رمز پنل هم ذخیره شود',
  bkInclProxyCreds:'یوزر و پسورد پروکسی‌ها هم ذخیره شود',
  bkInclTraffic:'تاریخچهٔ مصرف هم ذخیره شود (حجم فایل بیشتر می‌شود)',
  bkSecretWarn:'این فایل شامل رمز پنل و پسورد پروکسی‌هاست — مثل رمز عبور از آن مراقبت کنید.',
  btnBackupLbl:'دانلود فایل پشتیبان',
  restoreTitle:'بازگردانی',
  pickFile:'انتخاب فایل ixpbak',
  restoreHint:'فایل .ixpbak را انتخاب کن. اول محتوا نمایش داده می‌شود و تا تأیید نکنی چیزی نوشته نمی‌شود.',
  restoreMode:'نحوهٔ بازگردانی',
  bkMerge:'ادغام — موارد موجود به‌روز و بقیه اضافه می‌شوند',
  bkReplace:'جایگزینی کامل — کاربران، آی‌پی‌ها و پروکسی‌های فعلی حذف می‌شوند',
  bkRestorePwLbl:'رمز پنل هم از فایل بازگردانی شود',
  btnRestoreLbl:'بازگردانی کن',
  bkReading:'در حال خواندن فایل…',
  bkBadFile:'فایل قابل خواندن نیست یا پشتیبان این پنل نیست',
  bkFrom:'ساخته‌شده در',bkUsersN:'کاربر',bkCipsN:'آی‌پی تمیز',bkProxN:'پروکسی',
  bkTrafficN:'رکورد مصرف',
  bkHasPw:'شامل رمز پنل',bkNoPw:'بدون رمز پنل',
  bkProxCreds:'پروکسی با یوزر/پسورد',
  bkEnvDiff:'این متغیرها با پنل فعلی تفاوت دارند و باید دستی در Railway/Render ست شوند:',
  bkReplaceWarn:'همهٔ کاربران، آی‌پی‌های تمیز و پروکسی‌های فعلی حذف و با فایل جایگزین می‌شوند. مطمئنی؟',
  bkPwChanged:'رمز پنل از فایل بازگردانی شد — دفعهٔ بعد با رمز قدیمیِ همان فایل وارد شوید.',
  bkDone:'بازگردانی انجام شد',
  resetCycle:'ریست دوره‌ای مصرف',resetOff:'خاموش',reset1:'هر ۱ روز (روزانه)',reset3:'هر ۳ روز',
  reset7:'هر ۷ روز (هفتگی)',reset14:'هر ۱۴ روز (دو هفته)',reset30:'هر ۳۰ روز (ماهانه)',
  reset60:'هر ۶۰ روز (دو ماه)',reset90:'هر ۹۰ روز (سه ماه)',resetCustom:'دلخواه',customDays:'تعداد روز (۱ تا ۳۶۵)',
  tgTitle:'پشتیبان تلگرامی',
  tgHint:'فایل پشتیبان کامل به چت تلگرامت می‌رسد. توکن را از BotFather و Chat ID را از userinfobot بگیر. برای گروه، Chat ID با ‎-100 شروع می‌شود و ربات باید عضو گروه باشد.',
  tgTokenLbl:'Bot Token',tgChatLbl:'Chat ID',tgAutoLbl:'بکاپ خودکار روزانه',
  tgTestBtn:'پیام آزمایشی',tgNowBtn:'ارسال بکاپ حالا',
  tgWorking:'در حال اتصال به تلگرام…',tgSent:'به تلگرام ارسال شد ✓',
  tgFromEnv:'از متغیر محیطی تنظیم شده',tgNotSet:'تنظیم نشده',
  bkAdded:'اضافه‌شده',bkUpdated:'به‌روزشده',bkSkipped:'ردشده',
  relayLbl:'دامنه رله',keepAliveLbl:'جلوگیری از خواب',relayNone:'ندارد',
  onLbl:'فعال',offLbl:'خاموش',
  devWinLbl:'پنجره شمارش دستگاه',seconds:'ثانیه',
  ipWinLbl:'پنجره شمارش آی‌پی',
  envNote:'این مقادیر از متغیرهای محیطی خوانده می‌شوند و در Railway قابل تغییرند.',
  logout:'خروج',logs:'رخدادها',noLogs:'رخدادی نیست',
  navFilter:'فیلتر سایت',
  fltTitle:'فیلتر و سانسور محتوا',
  fltHint:'اتصال به سایت‌های فهرست‌شده بسته می‌شود. مقصد از همان هدر VLESS خوانده می‌شود، پس قبل از برقراری اتصال جلویش گرفته می‌شود.',
  fltEnable:'فیلتر فعال باشد',
  fltEnableHint:'وقتی خاموش باشد هیچ سایتی مسدود نمی‌شود.',
  fltPorn:'مسدودسازی خودکار محتوای بزرگسال',
  fltPornHint:'لیست آمادهٔ سایت‌ها و کلیدواژه‌های پورن.',
  fltRules:'قوانین مسدودسازی',
  fltKindDomain:'دامنه (و زیردامنه‌ها)',
  fltKindKeyword:'کلیدواژه (هرجای دامنه)',
  fltAdd:'افزودن قانون',
  fltBulk:'افزودن انبوه (هر خط یکی)',
  fltClear:'پاک کردن همهٔ قوانین',
  fltClearWarn:'همهٔ قوانین فیلتر حذف شوند؟',
  fltList:'قوانین فعلی',
  fltNone:'هنوز قانونی اضافه نشده',
  fltAdded:'قانون اضافه شد',
  fltDupe:'تکراری',
  fltDomain:'دامنه',fltKeyword:'کلیدواژه',
  fltOn:'فیلتر روشن است',fltOff:'فیلتر خاموش است',
  echValueLbl:'مقدار کاستوم ECH',obfCsLbl:'کاستوم cs (ماسک سیفر)',obfFmLbl:'کاستوم fm (مبهم‌ساز)',
  optDefault:'پیش‌فرض پنل',
  custLbl:'مقادیر کاستوم ECH و مبهم‌ساز (اختیاری)',
  custHint:'این مقادیر فقط وقتی اعمال می‌شوند که تیک مربوطه در بالا زده باشد: ECH با تیک «کانفیگ ECH»؛ cs و fm فقط روی لینک WS با تیک «لینک مبهم‌ساز». بعد از ذخیره، ساب را در کلاینت دوباره به‌روزرسانی کنید.',
  statusDisabled:'غیرفعال',statusExpired:'منقضی',statusQuota:'حجم تمام',
  navTgweb:'وب‌پروکسی تلگرام',
  tgwNew:'ساخت وب‌پروکسی جدید',
  tgwHint:'با استفاده از این قابلیت میتوانید یک پروکسی تلگرام با سکرت دلخواه بسازید؛ این قابلیت پروکسی تلگرام را با پروتکل وب پروکسی (WEB Proxy) روی حساب شما دیپلوی میکند و تحویل میدهد.',
  tgwPlatform:'میزبان پروکسی',
  tgwPlRender:'رندر',tgwPlRailway:'ریلوی',tgwPlExternal:'خارجی',
  tgwCarrier:'حامل ارتباط',
  tgwRegion:'ریجن میزبانی',
  tgwRegionHostDefault:'پیش‌فرض میزبان (بدون ریجن مشخص)',
  tgwRegionHint:'تغییر ریجن، سرویس را در ریجن جدید روی همان دامنه ری‌دپلوی می‌کند (چند دقیقه) و همهٔ لینک‌ها معتبر می‌مانند. ریجن واقعی سرویس بعد از هر همگام‌سازی از خود میزبان خوانده می‌شود.',
  tgwRegionLock:'ریجن سرویس‌های رندر بعد از ساخت قابل تغییر نیست',
  tgwTokenMissing:'توکن API این پلتفرم ذخیره نشده — اول از «تنظیمات پلتفرم» اضافه‌اش کن',
  tgwSetBtn:'تنظیمات پلتفرم',
  tgwSet:'پلتفرم میزبانی پروکسی',
  tgwSetSub:'برای اینکه پنل خودش پروکسی‌ها را بسازد، توکن API پلتفرم میزبان را اینجا ذخیره کن (Render: Account Settings → API Keys؛ Railway: Account Settings → Tokens). توکن فقط روی همین پنل ذخیره می‌شود. ریپو و برنچ به‌صورت پیش‌فرض (ریپوی خود پروژه، برنچ main) استفاده می‌شوند و پروکسی از پوشهٔ tproxy در همان ریپو ساخته می‌شود — پس اول پوشهٔ tproxy را در گیت‌هاب push کن.',
  tgwSetSubSelf:'این پنل روی {p} میزبانی می‌شود؛ پس برای ساخت وب پروکسی تلگرام به توکن {p} نیاز است آن را از حساب خود دریافت و در کادر زیر جای‌گذاری کنید.',
  tgwRenderToken:'توکن API رندر (rnd_…)',tgwRailwayToken:'توکن API ریلوی',
  tgwSetSaved:'ذخیره شد ✓',
  tgwBuildHint:'ساخت معمولاً ۲ تا ۴ دقیقه طول می‌کشد؛ اگر بیشتر شد، دکمهٔ ⟳ را بزن تا وضعیت از پلتفرم گرفته شود',
  tgwBuilding:'در حال ساخت',tgwLive:'آماده',tgwFailed:'خطا',tgwSuspended:'متوقف',
  tgwSync:'بررسی وضعیت ساخت',tgwNoServer:'بعد از استقرار، لینک همین‌جا ساخته می‌شود',
  tgwRotateWarnPl:'سکرت عوض شود؟ همهٔ لینک‌های قبلی از کار می‌افتند و سرویس روی {p} ری‌دپلوی می‌شود (چند دقیقه طول می‌کشد).',
  tgwDelWarnPl:'این پروکسی حذف شود؟ سرویس روی {p} هم از همان پلتفرم حذف می‌شود.',
  tgwPauseWarn:'پروکسی متوقف شود؟ سرویس به خواب می‌رود ولی نام میزبانش حفظ می‌شود و بعداً با روشن کردن، همهٔ لینک‌ها سر جایشان برمی‌گردند.',
  tgwServer:'سرور (دامنه)',tgwLabel:'برچسب (اختیاری)',tgwSecret:'سکرت (۳۲ کاراکتر hex)',
  tgwGen:'سکرت جدید',
  tgwZeroInf:'۰ = بی‌نهایت. حجم و مدت هر پروکسی همین‌جا ثبت می‌شود و وضعیتش (فعال / منقضی / اتمام حجم) در لیست پایین نمایش داده می‌شود.',
  tgwList:'وب‌پروکسی‌ها',tgwNone:'هنوز وب‌پروکسی‌ای ساخته نشده',
  tgwLink:'لینک عضویت تلگرام',tgwCopyLink:'کپی لینک',tgwOpen:'باز کردن در تلگرام',
  tgwRotate:'تعویض سکرت این پروکسی',
  tgwRotateWarn:'سکرت عوض شود؟ همهٔ لینک‌های قبلیِ همین پروکسی از کار می‌افتند و باید لینک جدید را در اختیار کاربر بگذاری.',
  tgwEdit:'ویرایش وب‌پروکسی',tgwDelWarn:'این وب‌پروکسی حذف شود؟',
 },
 en:{dir:'ltr',
  unitBytes:'bytes',loadingLbl:'Loading…',noLive:'No live connections',
  phDash:'Live server, user and traffic overview',  phUsers:'Create, edit and monitor accounts',  phClean:'IPs that go into the subscription link',  phFilter:'Blocked and allowed domains',  phProxy:'Proxy pool and auto selection',  phLive:'Connections open right now',  phTgweb:'Telegram web proxy',  phSettings:'Appearance, password, backup and server',  phLogs:'Latest panel events',  refreshLbl:'Refresh',  tabBasic:'Basics',  tabLimits:'Limits',  tabSecurity:'Security',  viewAll:'All',  r24:'24h',  cancel:'Cancel',  statHintUsers:'accounts',  statHintOnline:'online now',  statHintDev:'active devices',  statHintBytes:'since start',  statHintCip:'in subscription',  statHintLive:'live sessions',  zeroInfShort:'0 means unlimited.',  moreLbl:'Details',  noResult:'Nothing found',
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
let LANG=localStorage.getItem('lang')||'fa';
const THEMES=['gray','light'];
let THEME=localStorage.getItem('theme')||'gray';
if(!THEMES.includes(THEME)){THEME=(THEME==='light')?'light':'gray';localStorage.setItem('theme',THEME)}
const T=k=>I18N[LANG][k]||k;
function applyChrome(){
 document.documentElement.lang=LANG;
 document.documentElement.dir=I18N[LANG].dir;
 document.documentElement.dataset.theme=THEME;
}
function setLang(l){LANG=l;localStorage.setItem('lang',l);applyChrome();if(window.rerender)rerender()}
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
  <select id="langSel" class="hidden"><option value="fa">فارسی</option><option value="en">English</option></select>
  <select id="thSel" class="hidden"><option value="light"></option><option value="gray"></option></select>
  <button class="icon-btn" type="button" title="theme" id="btnTh"
    onclick="setTheme(THEMES[(THEMES.indexOf(THEME)+1)%THEMES.length])">
   <svg class="ic" viewBox="0 0 24 24"><path d="M20.5 14.5A8.5 8.5 0 1110 3.7a7 7 0 0010.5 10.8z"/></svg></button>
  <button class="icon-btn" type="button" title="language" id="btnLang"
    onclick="setLang(LANG==='fa'?'en':'fa')">
   <span class="mono" style="font-size:10px;font-weight:700" id="langTag">EN</span></button>
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
langSel.value=LANG; thSel.value=THEME;
function syncTags(){
 const lt=document.getElementById('langTag');
 if(lt) lt.textContent = (LANG==='fa') ? 'EN' : 'FA';
}
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
 langSel.value=LANG; thSel.value=THEME;
 syncTags();
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


PANEL_HTML = r"""<!DOCTYPE html><html lang="fa" dir="rtl" data-theme="dark"><head>
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
  <label class="fld"><span class="text-xs dim" data-t="language"></span>
   <select id="langSel" onchange="setLang(this.value)" class="inp">
    <option value="fa">فارسی</option><option value="en">English</option></select></label>
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
 <button class="icon-btn" onclick="setLang(LANG==='fa'?'en':'fa')"
         title="زبان" aria-label="تغییر زبان" style="width:34px;height:34px;flex:0 0 34px">
  <span class="mono" style="font-size:10.5px;font-weight:700" id="langTag">FA</span></button>
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
     <label class="fld"><span class="text-xs dim" data-t="language"></span>
      <select id="langSel2" onchange="setLang(this.value);syncSelects()" class="inp">
       <option value="fa">فارسی</option><option value="en">English</option></select></label>
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
    <p class="notice" style="margin:0" data-t="bkSecretWarn"></p>
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
  CC.map(c=>'<option value="'+c+'">'+cName(c)+'</option>').join('');
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
 if(p==='settings'){renderServer();loadBackupInfo();loadTelegram()}
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

function syncSelects(){
 [thSel,thSel2].forEach(e=>{if(e)e.value=THEME});
 [langSel,langSel2].forEach(e=>{if(e)e.value=LANG});
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
  const used=fmt(u.used_bytes), total=u.quota_bytes?fmt(u.quota_bytes):'∞';
  return '<div class="ucard">'

   +'<div class="uc-top">'
     +'<span class="av">'+esc((u.name||'?').charAt(0).toUpperCase())+'</span>'
     +'<span class="nm">'+esc(u.name)+'</span>'
     +badge+live
   +'</div>'

   +'<div class="uc-tools">'
     +'<span class="uc-tsp">'
     +'<span class="chip teal">'+trTxt(u.transport)+'</span>'
     +'</span>'
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

   +'<div class="uc-foot">'
     +'<span class="gf">'+IC.clock+'<span>'+T('expiry')+'</span> <bdi class="dt">'+dt(u.expire_at)+'</bdi></span>'
     +'<span class="gf'+(devWarn?' warn':'')+'">'+IC.phone+'<bdi class="mono">'
       +(devL?u.devices_now+' / '+devL:'∞')+'</bdi> <span>'+T('devSec')+'</span></span>'
     +'<span class="gf'+(ipWarn?' warn':'')+'">'+IC.globe+'<bdi class="mono">'
       +(ipL?u.ips_now+' / '+ipL:'∞')+'</bdi> <span>'+T('ipSec')+'</span></span>'
   +'</div>'

  +'</div>';
 }).join('');
}

function renderCips(){
 cipRows.innerHTML=cips.map(x=>`
  <div class="flex items-center gap-2 soft" style="border-radius:10px;padding:9px 12px">
   <span style="width:8px;height:8px;border-radius:50%;background:${x.enabled?'var(--ok)':'var(--dim)'}"></span>
   ${x.flag?`<span>${x.flag}</span>`:''}
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
 tgRegion.innerHTML=rows.map(r=>`<option value="${esc(r.id)}">${esc(rgName(r))}</option>`).join('');
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
async function openTgSettings(){
 await loadTgSettings();
 const s=tgSettings||{};
 const sub=TGWSELF?T('tgwSetSubSelf').replace('{p}',tgPlName(TGWSELF)):T('tgwSetSub');
 let fields='';
 if(TGWSELF==='railway')fields=tgTokenField('tgsRailway',s.railway_token_hint,T('tgwRailwayToken'));
 else if(TGWSELF==='render')fields=tgTokenField('tgsRender',s.render_token_hint,T('tgwRenderToken'));
 else fields=tgTokenField('tgsRender',s.render_token_hint,T('tgwRenderToken'))
     +tgTokenField('tgsRailway',s.railway_token_hint,T('tgwRailwayToken'));
 openModal(T('tgwSet'),`
  <p class="text-xs dim" style="margin:0">${sub}</p>
  ${fields}
  <button onclick="saveTgSettings()" class="btn w-full mt-3">${T('saveBtn')}</button>`);
}
async function saveTgSettings(){
 const body={};
 const rEl=document.getElementById('tgsRender'),wEl=document.getElementById('tgsRailway');
 if(rEl)body.render_token=rEl.value.trim();
 if(wEl)body.railway_token=wEl.value.trim();
 try{
  await api('/api/tgweb/settings',{method:'POST',body:JSON.stringify(body)});
  await loadTgSettings();tgPickPlatform(tgPlatform);
  closeModal();toast(T('tgwSetSaved'));
 }catch(e){toast(e.message)}
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
      if(curR&&!rgn.some(r=>r.id===curR))ops.unshift(`<option value="${esc(curR)}" selected>${esc(rgName(u.region))}</option>`);
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
   <div class="flex items-center gap-2 flex-wrap">
    <span style="width:8px;height:8px;border-radius:50%;background:${dot}"></span>
    <span>${x.flag||''}</span>
    <span class="mono text-sm break-all">${esc(x.label)}</span>
    ${x.has_auth?ICO.key:''}
    ${on?`<span class="chip teal">${T('pxInSub')}</span>`:''}
    <div class="flex-1"></div>
    <button onclick="testProxy(${x.id})" title="${T('pxTest')}" class="icon-btn">${ICO.ping}</button>
    <button onclick="toggleProxy(${x.id},${x.enabled?1:0})" class="icon-btn">${x.enabled?ICO.pause:ICO.play}</button>
    <button onclick="delProxy(${x.id})" class="icon-btn danger">${ICO.x}</button>
   </div>
   <div class="flex flex-wrap gap-3 text-xs dim mt-2">
    <span>${state}</span>
    ${x.latency_ms?`<span>${T('pxLatency')}: ${x.latency_ms} ms</span>`:''}
    ${x.exit_ip?`<span class="mono">${T('pxExitIp')}: ${esc(x.exit_ip)}</span>`:''}
    ${geo?`<span>${esc(geo)}</span>`:''}
    ${x.isp?`<span>${esc(x.isp)}</span>`:''}
    ${x.remark?`<span>${esc(x.remark)}</span>`:''}
    ${x.last_error?`<span style="color:var(--bad)">${esc(x.last_error)}</span>`:''}
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
    <div class="text-xs dim mono truncate">${esc(x.ip)} · ${esc(x.proto||'ws')}${x.hits?' · '+x.hits+'x':''}</div>
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
   <input id="eV" type="number" value="${u.device_limit}" class="inp"></label>
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

 function sync(sel){
  const api=MAPCE.get(sel); if(!api)return;
  const opts=[...sel.options];
  const sig=opts.map(o=>o.value+'\u0001'+txt(o)).join('\u0002')+'\u0003'+sel.value;
  if(api.sig===sig)return;
  api.sig=sig;
  const cur=opts.find(o=>o.value===sel.value)||opts[0];
  api.btn.querySelector('.cur').textContent=cur?txt(cur):'—';
  MUT++;
  if(!opts.length){api.menu.innerHTML='<div class="sempty">—</div>';MUT--;return}
  api.menu.innerHTML=opts.map(o=>{
   const on=String(o.value)===String(sel.value);
   return '<button type="button" class="sopt" role="option" data-v="'+escH(o.value)+'" '+
    'aria-selected="'+(on?'true':'false')+'"'+(o.disabled?' disabled':'')+'>'+
    '<span class="tx">'+escH(txt(o))+'</span>'+
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
 let OPENED_AT=0;
 function open(api){
  closeAll(api.root);
  markOpen(api.root,true);
  OPENED_AT=Date.now();
  const r=api.btn.getBoundingClientRect();
  api.root.classList.toggle('up',(window.innerHeight-r.bottom)<250&&r.top>260);
  api.root.classList.add('open');
  api.btn.setAttribute('aria-expanded','true');
  const selOpt=api.menu.querySelector('.sopt[aria-selected="true"]');
  if(selOpt) setTimeout(()=>selOpt.scrollIntoView({block:'center'}),0);
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
 window.addEventListener('scroll',()=>{
  if(Date.now()-OPENED_AT<420)return;
  closeAll();
 },true);
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
    "iVBORw0KGgoAAAANSUhEUgAAAGAAAABgCAIAAABt+uBvAAAzfUlEQVR42r19Z5hcxbF2VYdzJmzSrrJW2kUJ5UBQQBIig0w2"
    "tskCRDDRGBOM4fr6GowBG0wyWTbRYKJJIgqRJIFAIBGEUNYqa/PMTjihu+v7cSbvrGTf+zzfcJ5ldGKf6u7qqrfeqkHLjiIg"
    "IAQfIoKCD2X+A4Ci/aWfwoNYsocye7HcPbDgLMz+7emGhXcoPi1zHRY9sPRL/sL8uYCIe3wtUdTK3JsUCIqAABEQyzQdoPzO"
    "8jKAbjIrefvyF2C5m2CZW2KP/yySLCICERhjgPbY64hIJBCwzFtS9p8IwBA8A1oDmJKH76FRWRFQ8f7CFpW2jrLb/6cPs0Ih"
    "mwwZovKDiAgyI6ioVflZRQwgrRE0Vdo0ppbGV8OQCogKIDAsO9IgGFyYmQGMZcYvMkA0iIgIwIlxwGAnRy4AGQBDxpFJBkKg"
    "kChCXIZBhpmoYFYFWiFgIeAhJsMooihDwEPAwyhCxEMgQsht5BKYBOTZTsDcaMlPnKIeJIJYPL5u3bplyz7/7LNlHe0tACwU"
    "qdjDaBIEgNkuDuYVERED0ASuD0OrzNn7mOPrYXAFuAQxF3wCxII5iMAYAAAhMYTgGDBABMYBkACBCUQBTAAgcEEoEDggA5TI"
    "bM5sBlyAsLgVZnYlWjVo1aBdxawoiCjICpSVIKMooiArQGb/ihBwG5gFyPY4UPINRQSAcDhs2zYApFKpp5566p57/7r6+++E"
    "FRZcGKNL5i4BoGVHgysz0gEABuRokGAuHWGuGIW2BQt34ltb4etObHbAN1Aw/2jPGodoD3oDy+l4LNSFRCVaBKn7U7MnUQ8r"
    "QX6RQAAIhez+/ftPnXLAaaedOmfOHAC47bbbb7r5D+mUE4pEjNaljbTsimA4ZgYPR0j5NDCk79kfjhgELzSxe36AVR0IRMAQ"
    "WeYNskOYci0MVF9+cQCi7D4gQADCHpYy2uvCWO4QlVX/ZfqgWF8aQ2D8QJ+OGz/hpt///uSTT/rii+U/+9mpmzdvDkcqdLGM"
    "0LKjmdsQEUNwFQ0KmWdm0JAquPoL9uJmAERbUjC1qWg5/l8r1H/zWvw/KeHCdT7Xb9l1DBkReU4CgM4997zHHvt70+amww47"
    "fFNTk21HjNHFAgpEjADGUIjpf86AUXV4xif42XawwwAAhnKWEpXvUey2iP1Hb9ejwBGRISJjhTrFGENE3QwkLNeS3H3KPJAx"
    "hohuuuuQQw59543X1v2wdsYRR6ZSKcZETnNxJqzssgfk+uZ/JtJxDWzuEvxkG4QjoAmou0nX3YArb5D974SSaQ5jnHGltPbT"
    "WnmFmzEgpcUYZl8Dyw3rwkFTaB7m1zciIiI7FFm/7ocVX339yysvGxyNvPjmAinszDoOxIWwEAAYQNqHg/rqP++Pd6xmT6/B"
    "cBgVFSlNKH1iOZOoUFj/yymCiJwL301q5YbC4XHjxh988OzZhxw6bfpBo0aNqqyqTiQSia4OrTwhbUTMjiYsEFa3sVzoLhR3"
    "nzHGDkW+X/1dhdYXnz93ydLP127eaFm2MQYAUNrRjPHjKfPsLBpRww59B1OKGAMKFpKSbqGezWfcm5ahvY0vYowrpUg7Y8aO"
    "P+/cc0488YQRI0aUnLR79+533nn3scce//DDRQDcCoWzmrX8KMZSjV3aeIZojA6FQhv/9UzTuvVTLvuVlHZm0eJcAkdwFI2r"
    "of+eDHevZot3gG2hyZpcmdUT96Zki5RiD35Avnux3BTjXPhuqqIi8odbbvnb/PkHHzyrrq5uw4YNH3/88cL3Fy1btmzjxo1k"
    "zLBhwyZOnHjuuefsO2rU51983tHWIq0wkemhSVgqnG4tJAAhRCoZt5Q+64hZry/5YltLi5CSiEBaERGpkCDZVZNg65mssU6g"
    "LeyokBEuw1xGCrZwD1uk4G+44ORIt9PytxIyYoUq7HBlbgtFqgFg+IhRX3yxnIh833/44UcOOmhmOFJRJERhj58w8Y9/vLW9"
    "vZ2ItmzZOnPmwQBghSrLNSyzCSu3RQu+5zfLjiLKofVDzPOP33zyCQAQClcIKwLSjspQVIDFXjgG3ztBsFDmmjKiifQsnZIG"
    "lUiq9BIrVMFFuPsEGz58382bm4hoydKlBxxwYGb8i1BOlIEUsiePWLDgTSKKx+MHHTSzWEYlbSgRR7SsmLiMoAhtuunGxb+4"
    "GIBZdlRYYQFApAksDo1R+KoDjAJmg6biibSHOUV78tW7TcDAavechJDhg2bMOuCAA+rrB0spdu3a9e03K//whz82NAx54YWX"
    "5p4z10mn7HClMURktNYF8wWlXcEYW79+w7HHHffoI49ccMH5zz33zylTpjU3NzMuTRkvuGRhoeKFL9NmwdF1/G+3bJvSpxeX"
    "liaDAIIAwRBUCKi0oN0DyPu2CHs2fWgPOriMmwCAyLT2Seszzpx7+eWXT592YPcbf/DhR2eccbohZoUqlVJlpWyMNlpboYjR"
    "+sILL+zbt98JJxx3551/PuOM05mQULSodbfOsAfoIWPnN7e2V1VXhjhPaS0QRUaiDIGxnK+AZYxl/E+M3ABCAsTsGCNgyJXv"
    "VVVG/3zHXeeedw4Z+OjjxZ988snmzZu0No2NDbNnHzJsaOPcuecpbSzb1lr1DDshIGmtOePI+CWXXjZt2pRTT/3ZPffev+yz"
    "pZYd0UbvzVzHcp4jAKByPea6mJWhKHLnMKvsKecFUsFUwh7NvUKLFQEMkWcATA6KREADFAnbd95z349//JP3F37wp9v/+NFH"
    "HxntF1wr+vbr17y7WciQ7uY0lh2q2mjLjuzYvuXe++7/w82/v/CC85Z9thgZA2O6j3bcixLIQhqeh46bk674N9pBe7JsCu1H"
    "BHANgAbOaIAFg8JQJyEsAAETRjd1/PSocw+aNOvpRx6/4ffXJeJxYUWEDOWcAK118+5mIa2CBTuruXoeDMZoZOIfz/zztzfe"
    "MGfOMZFodTqdtiwbELQ2RCZzdeAsBVYd9GAQEQCAURodF7MaIoBckYJrsQSBKGzYHr1LhuAaAEMDbJhSB5NrqD6CUQEWB8YA"
    "yHBEv3GBv77ph9u+eu6tRDxu8wqFpngegZCy2Jyh7IAuVKslAiLOrc0b169YuXLatKljRo9avvxz1/GC+1mhsDGaqAeXEcqo"
    "c3I8TDo5GYq8PFnmZf4zX5khaEJX48AQHtOH9q+GGgsVkAH0GPlAYIgjMUJDLdTxATbDVQP41xX+P7bgVg8sAUB57J26j1Yq"
    "Nvm6G/HEhVC+WbXq+2nTpi5Y8Hp7e/uqVd8vfH/ha6+9vmP7Vi7CjDNjDOVwz7KeQPYQuR6knJwOYjk/FxnP6R/qyd4silUg"
    "csZdYhzVcTX+Nf29A7nvxvxdrV6s3Xc6PK/DVzEFKc0VEAjGLWZbOsJdovEV9N8j6dh+4GnQ1KPB8B9gRLBr165YLMYY7rvv"
    "yFNOOfnBB+5f8dWX1//mBsbId13GeA+XY5EuQSDXx7Sb6zEUdhSUgSrLfPVTeHEju/YjCoVAm73gNggIqDwHBgGcXV83dui+"
    "UL9vVUN9zcCaUJUlhIN+p+7a4bdtTO9a37F1u2qHdAK0AWYLkOgbA4YEwqft+Ox2SBqweUZSZRyXvUoOiUxNTY0lpe97VVVV"
    "48aOOfnkk88880zLEu++9/7ZZ5/d3NwirZAxpsDvoJIxKgAd5d0zdPhlNbW9v/mq05BEEPk2MYTyMaJyTVSgwO/7k1GHnP+j"
    "Hw2YPb3XhMa6esmY63jSElww4AAMgAEQxL3khuTWZc3fLdqxfMnulTvatgIRGFtqbg7sZWoFPrkdd3lg88y6VzRYSsXEOS8X"
    "y+KxWJyIAKittWXTxnWvv/7qAw/c/5e77j7qyMNfeunl448/rqsrwbgwhrC7EVfQMaQMeio3ojgTFmiCEKOLJ8KqDnxvMwhR"
    "bOWVU8oV2HDMiP2HTPRf3/XZCx8seOP1FatWyKhdP6whrd2Em/JBK6M1GUCIiNCASO8Deo/56T5HzBt+3KzBB/mJ9M7k7qTT"
    "QTGH10XZxCramsYWFyQvi5rlpMMY891kCTwUbGR8MoqMknZESFtIe+uWTc8//8LIUWOOOfqIXrV9Xn/1ZS6sPDqBpQsaAmhj"
    "jolUTRXWn9pbHCCOiMKOgDJQZZuvz4bn1+I1CyEUzk6xns3AWmkrkWxvL5IaF2eeedZtt97af0D/VDIlLckYY5mIIxkiAJJc"
    "dm79Uilh+g9/+Yc3n/zutU83LgPto4zyV5vpyzhYrNg6zetDzpnnJH7y09MOPPAAx3EYYwFOH6zhRGTbsr298+6771bKAIIQ"
    "0nVSNTXV77773vgJ4+ccM+fDD963QlGtTRZjLPI2OICr1V29B/0iWl239YdOIolYYAcxCUz8W2gxArV6KXJFKMoAgQAZMsaM"
    "MU89+finS5e8/PK/xo8f66RdFrxWxgY1jInWXd+s37Cwpvf+7QvfOXvi8WccOfH9dcue2LL8jfUfqhNqeI3gi2KaEYgAVs+u"
    "zERCSjcdP/6Ek154/tk9NO2MM+d6blpYYWOMUr4dinR2tN10880vv/Ti2XPP+fCD9zOWUDdsKAgxACBpg77OHRPZ8Ccgk8Q4"
    "/XuqESWXiAGap43WngLK2MTr16879PDDP3jttfHTpvgAwhAYDYwhgOs6m1e/MXDIEd+881Ovdcv61R/X1tSNHH7008dct3DV"
    "+Pu+eHHRjI067MpFLqSNsYKljQCAC+Gmu8aOm/DE44+lHddx3ODROU2gje5d2+uSSy9/9pmnpF2RQ921UlyEFr638JPFn02b"
    "flDffoOam3dJaRuinLdYCqcTYAaDz0VWMSsg5EF4pntAu1BejHHfdQFyXgKrreszqL5+SEND//4DK6trd7S1/fb6/7m3lz34"
    "vHPNCSdyJozyGfK1Xy/Y+P3HzO6X7NiCMmK6PhzR6C5ftvz7NU/POvJ3P7rglI+bvr918AOLer0Pb7XJVomSaUYMUPlubV3v"
    "5557rqq6OpFISimJgIgCy1gp3aeu1933/PXhh+63QpWFbkoAKjvprqWfLpk374KGhiHNu7chhgotrpK12RgClX9ZkUNsES1C"
    "RuWX2AKtgMx3E336DTjwgAPGj5+w336TR40aXdenr1J6x67mNWvWfvPNNx3bt37RtPH8j9a88MoravpBFb++zj7xRACIVtT3"
    "rYLVi65nEObaTB6lGwfDZyu/J9Zvc9PS9mRy5rAZbw574qXxb907Zv6y5xbBtwn0LS4EkX7qyafGjhnVGUsIzo3JdSL6vl9X"
    "W71gwdvXXH2VtIKITRl+xaZNmx3Xq6yqLpVKIexAGdsctEHIuRpZh5IxC1AWWGxl5hpn3HOTJ5xw0lNPPl5VXa2U2bBx45df"
    "frls2RcrVq5cu3ZNa0urVg4ACJQL7eh/a/+OT5c2n3RS5Igjor/9bePBBzeMefvD56/s+OZe4mARbN0qDptqr4v3RT7IaExp"
    "T/vqxH2PPHjg1HemfvzM2/9c/vbS+Kqdd/zprh/96OhYPCGEIKIcmKKUqqqq/G7V93PPmRvEu8mYsualUiqRTLquU0pjyUaE"
    "iICQgthfoYTz3jxjFiKnbISsu/GKiMr36nr3feqpJ5uami76+ZwNm5pampvB5PwpwYQQVhQRiMgy5q/IZwp5PNDuhQvTCxfK"
    "U366+6QR9cOTfRvuS7R7u2Pbli969KDxCWl9kUwe32dApW1FUn6sLdnpet6s/gfuf8aEFTNWeV7iwh+fnUimOeeFoVxjTMi2"
    "47HOU089vb2t1bKjOh/ww6IQLECkomr37pZdu3YDZINFlFvsEYgQc8QfAGNY0RRDQEALLcOkKgoCUEmgShlv4qRJVVWVV19z"
    "7WeffopgcQAuKpCBMYoICZGCBT2LMFwObKT2hgiRIKNfesF6CfyDDxxx8yWhOfunzdautkVO7TR31wdjxh5S16eX76UIEAiV"
    "UrFUor09Nry2YdZB+6UcF/K0pUyQHBEtS/zstPO/X/WNCFf6vuIILOstmazm1VoLGRrS0PDDmh+2b9vKuG0MFehmLMJ1AAwR"
    "mLx7yHKuYgRDNkoqJSyVGopSCCJyfY9zLsf0Mo9NUQMtv59QH8zSM2rB94Fl3G4DIABakF3Ipau1IDBShoQV+fiLLbMPWDl6"
    "6MdnTh07+oqDTn/IapySSqwXVkS5rvY833V93/c9JQQfN25EynMNGcSiNVlrXV0V/fVvblzw+ivVocqQ79sAisAD44H2wSAA"
    "B+IMtXL2GTaytq7fxx9+4KS7uBDFU6OAU0dZGKwA2BC5sHMELQW8C6CcnVYUZkNEIYTWmtVaMKoaIwI6XVibxA7FOIfCMDFQ"
    "CGA54aVE843ytPYAUAgisn/YVP8DOO/97st971Mj/cpLQk46KWrrlOcDS2ilHa9j3OiRFRUR1/URkQgIMgu7r1RdbfXf/v7E"
    "X+64PWJHK5XqC2ww8CHIaojtBPMx02uNDwBMU8gOT5s5e+u2rYsWvovMKqDtAGHx62WBo0KXK28oRtFyUVJ57yIvKUQ0xrhp"
    "FxHZ55046wOjDAHA+UsBQANC2im80gcEwFeQWcDuIWMAXCIkMpwbJNW23Vq6vWopbHz2EBq6Dx8/EUeONIPqO4GNPvLIvn3q"
    "XDdr8mSHulKqV031J4uXXnH5ZUKGPKJtCNuAVoCqAZhI7DIWeRBCy8B7mnt/9xO9h+9bU1P7+isvtbfuElaECtgyhfZPEUZE"
    "lAvECsgiZlEQKeR7YtQRAEBLSytjbObMGUsWf+R6SQAubcu2ZSjSO2yHw+GwbYekZUlpccGNAc/3Pc9Lxrueb23uSMVvV16F"
    "1mlE5FwbYzgnRE1auU569equ1asdgJ0A4y+4cOhF89JpB5FRQTcbYyKR8PYdO84666y040grbIzOdXIHwIdMfwixq7T3F1E9"
    "A+0LrPD5be3/evWlnRvXcxkupKhmCDpUGl4MRmrpCEKACpAx5LmB1p1rqo0RVuTbb1a+8cabt916y/nnn4eAdjgshYWMGQLf"
    "V6lUuiMWb2trb21t27l71/bt23fvbt65c0c67fTi/D3CDaHIM+PHRT9flvZ9BNBCKEQFQgkiACZkykk3HnrYUQ8+6Ho+AFJW"
    "RwRIN2PIEOaec+6Wpk1WqDIAJHOt5AAc0AC/h3mXkNqH2P7AH4/rKW1rgXMspRrml3oCwh4wp6zzRRBBaQPfqx9mAE8/48wz"
    "zjh92LBh8XisszPW1tYei8Vi8XhHR0cikUinUo7jKq2V8skYRE5gOOecy8pwZGOq64Z+/d9cunTzvfd2vPOO09GhAHwAH0AB"
    "dCll1w/+0dNPA4DRGpAFy1YgI61Vr5qqK6+65sNF79nhKqX87orSABJQBVEUQCA4SJNATBb256QsAF0alsrMDCxlrGERRzEY"
    "L2ESVl5AWA6vBSJgTCS6OhcseHPc2LHhSLiiorK6uqq+vj4SjYZCYTsUEUJoIt/Xnu+7jtPeEYt1dcVina0tLS0tLVZr86LX"
    "X71lxoybnn02sW1bctmyjsWL279bldq2NdXRYQkx+5lnowMHuIkUcl4oHaVUr5qqJ59+5t6777Tsim4hs/yMcMCcBeGBwF0g"
    "CaiAusgU0W0wy3krRPFLwMAsDp5X0mEUVp4PST1wdrjvJq6//oZbb73FVzoej6cdJ5lMxeNd7R0d8Vi8ta29rbWtpbW1pbW1"
    "s6Ojs7MzFoslk8lUKuU4ad/3jdaWXXHz9ddNGzvmR8cdG6qv73fKKQbAczw3FmOc23W1XspBzjN0UgJEUEpXVkZXfv3t5Zde"
    "yoVtqCxAixLAAT2RxB+xQiMaJI7sfeP8AEoAp+4RCMwCZ5hnPlOx1ha5rxEUdgb9KB8/YMh8L93QOOzWW2957vkXLr3k4rSr"
    "3LRrjCoYvGVXwID0iwHFkXPOuHXBzy/5/LOlA/r3c32NjCFjobo6IFJZxRywfhDJGGNZMpVMzZ17TldX3LIrdMZ2LwJoBYAD"
    "ehzxN7CmCtBBE0KWJPNLSgAgK2xiVqmVMHmoHPYtcmHQSpAh2BOjFhkC6cbGRgB46KFH2tvbBQ+DxbgnkdlQyTFpMvYVFrFP"
    "M7M9m9JgtJEytHPH1nnnX/juu29pQDIEROT7hoIVlbJQRuYL52zuORd8+82KnGIuVAQc0AA5oI8C62lW3YcwxSgC3AH4CXV+"
    "R8pCrrsvzVg8cnoIu7JcL1ShFUYB5SyDwu9aayIKRUKIyKb0puWH0YQaqg+rzw/Vh/fWrqfBaK21NsZoYwI6YWDG5Ki6qLRv"
    "h6vee+/t//rt7ywpAi4XZbMdsmdTVk5ERE6xeZWzWASAB0aTuRGib2GvOoA0owjxraCP0m1vk2sh19RTzIR65AvlQN6c01+J"
    "VhStnlNNcvFok5mEiNjusw87WFyzhBYv7WJNDhOcIWOMscz/gtmD2Q/L8+GIAGDgwIEl8aTceMtZvESgNT3xxOP7jhrrOUnO"
    "AlsEBaAGcEFPBr4Qqv8AFR4YhiwM7FVIT9Otn4BvA9dAgD2wAqkw0l6QaVBwpsiN1EqwIij3xLPEvFuvlTHGuGta4PJdmb3X"
    "f54LeJSTMsuATsgQUViWm45feNEll17y87TjMcb2TFl0XbeqqurJJ5887LBDXceVTHhkFFAtwTUQ+SWrCCP4YELImkD/jhJP"
    "GAeQWcBU0SsUzY2CSHKAa5cEXKnU1agCK1IIUZf1wphct259Mpm6/vpfb9u6xdcEHDhwRBSWCIZLlrcPROArRURKa8/zlfI9"
    "z3NdV/leMt4xcdJ+d991h+f5Qa4HUUG2RGnIB4UQ8XjXlAP3u+fOuy74+fnKYiGAuWT9GiNDiRMZYDwNdKdJ3EGpNiCJHDJa"
    "GfcYf8xZ0Jgzn7MsJixidyBANchIGS5DYVYUCSvUvHvHJZdeNn/+I6tWfet4igxpbXylPN93XC+VSqdS6UQyGYvFW9s6Ojo6"
    "Y7HO1rb2zs7OtrbWlubmWGd7S/POisrKJ594IhKJpNIuZyxASHJTyxhirCAxBQC0lohtXal5F8377rtvd9933w3h/uN8ACLg"
    "2GXMkyZ5N6Q3gA4Gjt4bx7h7YA0LrJ/CC0Xu7StJhoH3GAkLsBKlpF3x1JOPP//8CyNGjNRaKa21UkpppZRSvtJaK23IaKW1"
    "1gRgtDKUWa4BQEjhOcn5f3tswoRxqZTDOSeiQI8joiFjWZaUvKsrhQG5SGtAoGiUJBNbtjkPPXrXR1+C6A0ugWDbjHpKp/+G"
    "7gbQABhoHF3KRi5VQFgQw4CyOgmKplig4qkCRbjIWS3TA8hQK6+ud7/LL79s0qTJOaNdG9LG+L7yPD+VdpKpZDKZSibT8a6u"
    "RDLZFe9qa2uLxTpjsc7tm1ZfeNEl5887N5V2s9LJDBPf96urKt55d+G777xz551/jnfEybKwMmI0iZVf86ef48+9wnau80Ej"
    "67siBH9zO19iupU0ALeAE5D692n9ZWke5TIrRdayxigIG/m/kfRA/3j66aOPPuKVV1+PxeIajOd4nus6vu+k007aTaXTiUQy"
    "mUolk+lkKplOp1OpVDKRcJx0e8vuiZP2u+svd3i+QsyBv0RAAX66c/vOyy++ZP2m9X0aG391xWWp5hbxxgLrqef4m+8jtQMI"
    "M2ikc+TBeNaZTcn4wz/9MRALManJ6J5IY916OhcvpFzAq9BhLcnqIwBpR5kIRSt77U7G5z/1JADY4cqyBFVpVwDg6DETiOiX"
    "v7z6P8wrEYA8HI5+8813RJRKOWnHS6e9VMpJJtJdsa5ELOErPePoOUEq4GQruuOcS/1B49IABsCpaUiefEb7/Cd2rd+8w1Hb"
    "4klt6PZb/wwAdobZWsLJjfS0ZSiuMlpACY5yGREyEpJREPZNoX4UHT5AhkHYUoZyWpksYKLIki5LUqSKiggRrVm7lnNuV1er"
    "cVH8Jg4e0aQK+CEJSZ3PHSoYvZxzJxW/776/jh8/NpV2ODLSmowhZGRJI0MWwDXX/rr9nbf+YNf+WLHRxOGJR9y6Bjx9Xudh"
    "B+tZM3RDAzCGyZSMxQCx1XV/de01S5cte/WVF+1QpdKqB5iYeuZYYhlGfrfkC1Hg1yPDnkYm5jwHpTQihqIhrbUaX+W9MYUd"
    "8yk0xem16XjRCnx5K4Qs0KbQzxFCOqn4eeddcP7556YTKS4lWTIHd+K2HWLxZ/yd96984tm7RT9QsIr0XcJ7lRgM7f3C4w8j"
    "FyaRFF0JAEDOQUpAQEOpdOqBB+7/5puVmzdtFlbIGL3XpKMCYDuXv4R5+CNPqWTFy3z2WlbIJuqGLmE2rYGIfMcTQojv43D6"
    "V/BDF7pgzlmBX3WCZREgMMwic8Q5d9OJ8fsfeN/fH/UAsCICALh1Gy5fQR9+Ap8s5avXM6W+UV3fisjvILkE1cYgLY1J+GLZ"
    "lXPPeeqpJzuVz60iIxYF8z2/X7++8+f/7eijjwIyBVktPXNxKbDM8ync2WRAzAz6DC/XlMGkESCTltVDSkrQ6s5YHBHr64co"
    "pVRLO7yRJXgsiHVHR4ALBTwUDj3xx1ujy75wvlzJvv4WVv9AO3drxszg+vTsmZU3//cVf5//8GuvAHdBG0DkwAQgGYOhimef"
    "e2bS/vtfd+2v2tpjMkieyAKBUorOzthhhx78+5tuvvE319nh7rzqssxcLJMvXlQugKDAdxMFOBoVE5OwO11SWOGNG9e9/sZb"
    "9//1nvpBA5pbWjSQ73qe57vKd9KOk3Ydx0mlUulUyiRTMtYVbd5xw+HHTv7gk0Ssg2p60fhx+qQT9D6NZuAAz7brbPH0S688"
    "/OrLgtvcACA3QASogjcxJO3IDTdcP2H8+KOPObKjIy5Eka0vhOiMJa6/7pqlS5YseONVK1SplerWwdgDzE5YnB2NVEzGKxYQ"
    "FqRTYRFRvjg7DJGfd+65d9zx5/PmnR9IzRjjK+V6ftpxE4lkR2e8pbW1pbmledfud954bb+jDp/z2KOdvoKwnfFLFTHXhbTT"
    "C3HjmrW/vuB8DhwBFZjiVK8gOsiMgXnz5i1duqT/gAGO43LO8wcRAMj1/IceenD69K+3b98mpG2MybNjex5KWHCLPLBIOUoJ"
    "FbNcsVBvlbXRg+lrGBdt7Z3nnXeOsMKcc6DARUdELOQkMcaSyUT9kCE33XFb0vfJcTGVzoA8iAHpgklx0WWXtne2l6A8JQ6g"
    "tEI7d24759zz3n3nbUTwfR+xaAFJJpL9+vV98MEHjz9ujtECGaMi75S6CR3yCQWFEbG8JslfJApjioV5qdl7YwmjnIiElIxZ"
    "Simd48kX35UhEphe1VXvvvnGwH59ASAaDnV/+V9ff8PSxR9l4fcekxu01na46uOPFl173XX33nNXT6cdd+wxd91939VX/5Jh"
    "iHqoEoDlkytKMDMsoOcV6KA90m2LjGkiozUyxrKjHQFIa52TOkPm+86Qhn3eWPDWs889LzLwey60S0KKnTt2PvTww8KKaKX2"
    "mvqhtZJW9L5773McZ/DgIYEyFsUeZwBTVVfXxWKdjIkA1mEZxIuy1RByrAyC4hol+ZTO4tC7KBMlKsORLSM9pbTyUnkRcpsx"
    "HljwmjTj1soVX61c8cUeXpvLcFFRgD14TwSAJKzQo488tBebXYSy0gEG6IPJ8/SDZgLL5FEWhg8LiEIlsWVRdtjsrSgKauUO"
    "rh/y5z/dGrhUxuhrr71+x/btXNq59AhhhThneyDqa6UJyiwcPbuYZIcrg68hwBNABkkGBogTfISqGQh0oKKBA3ig9ycxApgC"
    "IIIQ4G6kRaBYEd+uO++4aGyIIrMH98xsx3zerVGjR4869dSfBQdc173iiqsIkPOAH53Jbg+sxQCWBiBEDFLVjdHGBHsYZ5wA"
    "CnlzAWSbU0DB92AKZ0OIJgl0EPFLKAIYCATeI/cYlgwYcxzAAzOTxDtQFQkGCWMK6AiKFVR/KPpTZBwViE3kVdTek7ipUI5D"
    "hgxWSnuua9n2ihUr2lpbuLTddDz/niKsvK7MI5nFOdfa5GclsxCRtKvAAICwogBEhgDRdxPFN0kGUS9kTPspAJBWFAguhdRo"
    "FLNJpMAgwJEs9BtQt1A6jDxNehzwV7AqTJAkbSFLgDmGYp+jlsBNgetUiFYjlYkBlZ9ie+S4YjZldLgQXPkoBN/ctAVAc86u"
    "uPzqfn37EsCmTZsfe+yxeRdcNGfOMQMHDfzVr679dOniisqaww6bc/hhh44ZM6aurpZzEY/HV61a9dprb7z55gLkUkrL95yj"
    "jzn2kENmB0jcX+66+5DZx5x22qkjR4wQgm/a1PTcc8/985/PWlbYIJ9nEl9QVTWiQfLA/I7CH4K/xHgNKF7D6jrCFJgQMh/g"
    "Jyb2OWobuCpUxjntFHDigEqXOsQM3BGpqOnq6nru+RcCuEP0nI/LZcQKVQLAiy++RETpVIqIbrr5FgDoP2Cw53pBrObrr79+"
    "++13KPuZvP9UIaxPP/2Uevi89NLLFZXVQZ2Ml17+V27/e+8t7H7yPffcB8hCVgSEfQqPEu/v8P6u6E9i4Pei72hmrRB9SQxK"
    "8X4e76/kgON5BIQVKk3wjQaJvEJmkphtGQFp/4/dh0KNg2QYpC2FzbDHudRjLS5jNDIZRBAD923jxo0AMHDgAGTo+77v+WPH"
    "jj366KOCe3R0dPzww+r+gwZPmzYtuFc6nW5tbU0lUwCglfY878c/Pvn222/z3CSiGNC/n1LKcRzf94844vBCg8j3faXUL35x"
    "+axZBzteKizkS+D9FRwbkAAU0L7AP+V1k0C4oDkyiexs6nodfRu4n1ckCN2rMGCe7wu5ejiIjArMw26QSXeMDhFB+aq6uqa+"
    "fhAACC4AYNOmTYFWEkIwRCFFoFl37d61cuXKJUuWpJPxUSOHx2KxBx544Kijjxk+Yt+hw0eM3Hff39zwX4YMZ1xrffqpP6uq"
    "rg2FI40NDUIIKYSUMplMPvLII1dd9avHH38iKFkRDKKjjzoyYMYJZNdQ8ivybUINpIGqDHlgBKCF7OcUf5YcG7jCMpmUpTYQ"
    "YvdEMAHd8Mge0lIL6jiRP2BA/951vYmIC55KpbZu3RZopWx0iBHRDTfeOH/+/Pa2DiEtaUW+/npl/eCGRFdMynBt79qqyqqu"
    "rsRtt95y4gnHT5s2lYypqKysrKoSnPfp25eIkLFEIjFnzo8WL/4keLTneRdddKHnaillRWVlruUuwtmQWERVvYFpgEDLaICr"
    "TfwRcizkfgHxMpfcECCsiN0ILFSKSRezPopRgO45SYgMgBobG7jgvu9LKXft2tXc3AIAI0eMAABtjGTstttu+9PttwNy5NwQ"
    "GT9lWX0uu/TS448/rr6+PhqNMsbSqfTu5t0DBgwwxjDG3FSqvbX1oBkHCSFc17Vt+7HHHl+8+BM7HGWInpv+8quvcl7Nzp07"
    "C/t6G5hOpD7ZOBECuEBvkguIJldfo+DdEKGI2EHdc3S7Cyh/IvbgZ+QrAwwbNixQClLKpqYtia4YABsxYjgASCk9z3t0/t84"
    "58glECnfmz370JdffrG2trbwvuFwuLauFrJG0K6dO9PpxNixY3L9+NHHHzHGjNYGQGs9bOg+uQasX78xYEIQQAjgDajcF4QL"
    "JpgEBqAC8AVWPd10+gisMAhPBTkZkMc4sNCSLjAaRVESR2ltghI+cF60w4cNy73Ghg0bAExFVW1jY0MAP2/bum3Hjh3aEEdj"
    "jK6p6fXss8/U1ta6rmtJ+Y9nnvnXv/7V0dnJGRszZuzdd/0luM+mzU0AMG7s2OAmRLRx4yZjDGZLHYwaNRoAArL9+vXrAYCM"
    "MWSeoegskA4aBmgBAyIfyQWaCPJ2jPwCkhYxjfkoRmGxs0BMpdAIFdpBmONSUzmoqRTEDF5maEFnrlm7FgAGDuifmyxNW5qc"
    "dIoLizGmlXfY4YcPGNDfcZxQKPTqq6+effbZudtFIlFkTHmeEGLNmjUAMHr0aACQQra1tzU1NQU+kjaGcxH0ihCitbV169Zt"
    "DLhn1IMQPRnCaTQIaCG7g5KzwToQpAvGBXMFRhaRegV8C3gxhYkCiBZ7KrqRJaMxyBJsiUrQ1bJ1pUBrw7jd2NAQ+AQAsG7d"
    "egBobGy0bdv3/ZzIWFA7EaBfv74mm0JRVVVdWVkZBCFnzpx1//1/JaLgPt+tWgUA++zTGDy2qampo70duQAAMqp3n771g+uD"
    "mzQ1NcU72oxgN5vwxRRKgwGAELDHTfpaSlwBCY9M0HoN8ChWDCamgAoT9XIERaLu6cTFOojyiGthjabuVVEpl65RW1fXr1+/"
    "AHPwfb+paQsANAwZrJTyPJ9zvnr16oxPYwgAvvpqBWNMSul73qGHHvLll1+uWbO2rq52+vTpwdpERFrr1atX1/Sqq6ut8zyP"
    "MbZ+wwYiI7gVvM2QIYMjkUg6nZZSrl+7Vhn1C9nrvyjURYYBRYG/Ce752GUDXwb+7yF1C0WTYBRAHbL5WHE0xRlyzHI68n5G"
    "dzYvllYEwCxO3R1KKo00MYZA/rCh+/Tt11cIYVkWEe3cuQsADjjwACFEZWWFEGLz5qbgsdoYLkPLPvv03nvv45xLywKAESNG"
    "HHfcsdOnT1+3bt327Tssy7Jtm3O+Zu26yZMnh8Ihy7KEEFuamjLQAWMAsN9++wkhwuGwEOLrDRtOB7iHKoGoEjCK8kvwT4Mu"
    "QK4RJfLb0fkQvCjwoEbkUWT9iSKaDMulq3RbnksNxuxEE4VYPfVYdSvPpkMmEonEHXfe6ftKCrFr9+729nZkYvHiJfFYzFeK"
    "c758+ZfIBGWIiYxL+8orr1y06INTfnLK0KH7IOKO7ds//mTxU089ffzxx40fP56IUqlUS3NLfFD9nX+5y3VdKcWLL76MjGe6"
    "mokNGzbdccednucJKT/612uzUP7JxDVohkgEDzCvC1AC0wAcwZA5H1IXg1ImyCxADVAFrAuIBetWsIBhkAFVvFQXTzmUdjTQ"
    "rDu3Ny1evOSkk060w5UZbKG8N4/a9wvSDYHLMAAGfnY+Y1PIgDpntJaW7XtuNmczyEY1gUMPxiu8j/bdgkwsJu1woKEZMuU7"
    "BYckWBKMBmPAKBAWAArEwjinAsgQPfLEC1ZS560kN5wDuKRv4VU3sGh/f/duNJJQZHOtnba29oAQZwop1qXKCABIWJaU0XwJ"
    "Fq2JSEaqAhsSEX3fN8YQgRCysqamrXVXvwFDurriqUQXgBEypPw0oBBCKI9CkbDruFJKbTQTVmNDQ3VNzXfffksAvpsEQC7D"
    "2gS1iLkdjiCik+oCT9nCjlRUVtfU7Ni+nRgjBJ7JmAQAsgFYhvadeQuvsHwk9ogLDkGRAuoCE+AfDIg4ZwD622+/HT16VKSi"
    "Wnl+ATJL3YtmGK3Tyc50MhZsnpPw3aSTigc7U4lO33WzdDtz7rnnHnvcCaefdqrrpMaMHTN+wmREmDJ1+qhRo4xWQ4cPc1Lp"
    "wUMGc8GN8vv26TNv3ryJEyZccsklpL2p02aMGz+JjKqIVkybPuPAKVN933dSyYmT9h87bqKrnEkHHnDwYYd62mWcK8/x3ISf"
    "2ZKum0y7ibSbSGe/7KV4NIAGAoADUa4hlQIKsDeRqUAN8N57C0855cf7TZ60ZPHHjEmtqbh4UD5sEg6Hp049mDGWpSHl0wCJ"
    "QAi+Zs3arVu3WHbYScW2bN36m9/cOGvm9OpedTfc+F93/+XOUDg8ZcoBEyZOvvaaa+fMmfP1yq8mT97voYceJFL19fXIsLm5"
    "ubaulgu5336Tpk+f8currjr44Nnjxo62LLszFmtsGHLUUUdEIhW33HJLTU1NU1NTgOoPH7Hv0GFDla+KSyZmIB7f85d9/rnv"
    "+4is2FzO57EooH1QjCR+m0kGM04F4XijDaJY8NbbxnEuOOM0IsIy6bxYoOGJM8Y5E4JxzjjngjPBOeeMMeQZUivzPWfEyNHD"
    "hu6zePEnDY3DGhsaln22bPnyz884/TTLCgFAKpVcuWLF1Vdf/eKLL2qlAWDo0KFKaeU7d991xxlnnBmJRH2lXMcdPnzo/Pl/"
    "37Fjh5NOjRo1ynG8pUuXtLe3jRw5YseOnQCMyDCGnCHnKDgTggnBBGecM86Y4IwxLMcfy9vODIDIzMUQIjxPDiAGBAyQdlTa"
    "0VC4EgCemz/fb93d2DgMkVt2RQ+V7yLIQ3sDZ4W0K5CJadNn9R84pH7wPmPHTe4/cPCYsRO4sCZM2v+00886/IhjAOCkk396"
    "yWW/AAA7XMW4nDT5wJravkF0YvSYCaedftZhhx+NTE6dNjNa2Wva9JmWHa2t63f23PP2238qAJsxc3Y4WsO4LWQEYM91pYGJ"
    "UGntQBkU+wtLGeYyVCNDbaEhS+wBIG0pw0KGuAihtCMAyBnz3PS+I0euWvTWGy+/csLlV9p2VBMVV+kqwu0DxwMBqZQNEqSt"
    "EiBqLw0Bc5YMIAfSXFradzJ1q4U9derUFStW+p4LyABQ+w5yKaU0xigvs2xxGdF+mnHbaJcLW2sN5AMwYYWUl2IilKksliXY"
    "QlGF+Eyd5oDE1p0TFHhoHMAl9SCvuZhVzFYtH4NvZyjEwLmwgii1tKydO7djyrnonNPiO3Yv/vZrS9o9WUbFEChkeZg5bnxG"
    "wQtpMcYY54xLxhnjEoCEsIS0GZcAuGXzBmPyxX65sBiiIRN8D04jIiEtABTCIgDOuZB2ULBXSLtQ3ZRtTEGrCsrxYV46AsAl"
    "fTqEb+W9HqXEX03KQm6yiiwjoIxm4fLD5V9OHdD3shOP3rJl+/L16xgTgjGiHvkSewb4iagcNzkvRyEsQOzBD8qfRobyFN3g"
    "QBG61RM7secUjOB9AxyO9Algv8h6LSf3dBMjLAo9ZwWECASIjMi8tvTzgwf1v/zwmZhyP9y4Wfk+40IEqQRZRYd58JawoERr"
    "waGSf2J2Z+H3TD7xXrYs4anbbff80O5HKfjLIUNW9YEMmV9g5AnWazXqY01HO4LIhX8wGNSZetLBtcS5SDnui59/tW8kfPHM"
    "A4/r03tTLLY+FtdKaUMmawUXbGQADeQOocGCnQQG0RAY7HZhsJOyJ2e+BzvJIJaen7lt9ikEBQ/q3hIs19TMaZpIgzFAM0A8"
    "waov4VUfkHMCde5EsgBN8fTIViTP4dVAjKGvlNbmyikTb91/fBjZ1xuantnQ9El7Z1PKSWmdh0Oo2JKgnurt9xCCzDG6C4gR"
    "BSB4MXkl+0sMBegylf5mS55QB0Xwc8GcCSPWA5sB4lSwp6FtwPwOkrdRSgEWSicHOudKtudY/0GdBgQg13EHVlX8fHjjvAF9"
    "67kET0HK0WmPlAFDoAmUAUVgshnopqBmAWUBgsxOU/JLLDmmIFFZagDlUrmwpDZeEdmJ8oIuYZwGN8nq7RzVLsMJMdQC6glK"
    "PwDOJtACGEMwZfFmaUfLJm0CEWcsrRT4vm1ZEysiU6LRkVLWAEJQBswAGiKdT6PGLPqUg+DySctUOp6KtT0VUTDyUCiCgaDq"
    "SIbikfu1hVwfFKXoZvPdTaG4TSEmHyezDtRyUitAJYEA0EbUpSAPlRdQUV0KhKDkBwP0jNFaA5m9haO7g/2ZTKPyzOKy7jD9"
    "X38NYS+Ny1a2Z0Gtm9KBU7ooo7Si5X9eqEhqVIJsU7l0oDIr/h5sAPz/+Ts+ZfAtDdls1IIR0b1ZomxuR8mczxZTKZEJlXDM"
    "S6pPY7G6KP2NB+qR8k177C3o4Te3qAeeffGhwh+/oEziIxZEPLo97v8BAnIizB4NaTgAAAAASUVORK5CYII="
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
