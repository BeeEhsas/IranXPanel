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
DB_PATH        = os.getenv("DB_PATH", "/tmp/panel.db")
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


_TEMPLATE = r"""<!doctype html>
<html lang="fa" dir="rtl" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<meta name="color-scheme" content="dark light">
<title>__TITLE__ &middot; Subscription</title>
__FONTS__
<style>
/* Sanaei (3x-ui) visual language: deep navy surfaces + teal-green accent */
:root,[data-theme="dark"]{
  --bg:#0a1222;--surface:#151f31;--surface2:#1b2740;--line:#2c3950;--line2:#222d42;
  --tx:#e7edf7;--tx2:rgba(231,237,247,.52);--a1:#008771;--a2:#3ad3ba;
  --ok:#3ad3ba;--warn:#ffa031;--bad:#e04141;--info:#529fff;
  --ring:rgba(0,135,113,.5);--chip:rgba(255,255,255,.05);--chip-line:rgba(255,255,255,.09);
  --shadow:0 10px 30px rgba(0,0,0,.4);
  --glow:radial-gradient(1100px 480px at 50% -140px,rgba(0,135,113,.18),transparent 70%)}
[data-theme="light"]{
  --bg:#f0f2f5;--surface:#ffffff;--surface2:#f7f9fc;--line:#e6e9ef;--line2:#eef1f5;
  --tx:#1f2937;--tx2:#7a8694;--a1:#008771;--a2:#009980;
  --ok:#199270;--warn:#f37b24;--bad:#cf3c3c;--info:#0e49b5;
  --ring:rgba(0,135,113,.3);--chip:#f3f5f8;--chip-line:#e6e9ef;
  --shadow:0 8px 24px rgba(16,24,40,.08);
  --glow:radial-gradient(1100px 480px at 50% -140px,rgba(0,135,113,.10),transparent 70%)}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--tx);min-height:100vh;padding:20px 16px 46px;
  font:16px/1.55 Vazirmatn,"Vazirmatn Variable",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Tahoma,sans-serif}
body::before{content:"";position:fixed;inset:0;background:var(--glow);pointer-events:none}
.wrap{position:relative;max-width:960px;margin:0 auto}
/* ── top bar ── */
.top{display:flex;align-items:center;gap:10px;margin-bottom:18px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:9px;font-weight:700}
.dot{width:9px;height:9px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 4px rgba(58,211,186,.16)}
.dot.off{background:var(--bad);box-shadow:0 0 0 4px rgba(224,65,65,.16)}
.spacer{flex:1}
.tag{font-size:11px;font-weight:700;padding:5px 11px;border-radius:99px;background:var(--chip);
  border:1px solid var(--chip-line);color:var(--tx2)}
.chip{border:1px solid var(--line);background:var(--surface);color:var(--tx);border-radius:99px;
  min-height:38px;padding:0 13px;font:inherit;font-size:13px;font-weight:600;cursor:pointer;
  display:inline-flex;align-items:center;gap:7px}
.chip:hover{border-color:var(--a1)}
.chip:focus-visible,.btn:focus-visible,.tab:focus-visible,.ico:focus-visible{outline:2px solid var(--ring);outline-offset:2px}
.chip svg{width:16px;height:16px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
/* ── cards ── */
.card{background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:20px;
  box-shadow:var(--shadow)}
.hero{display:grid;grid-template-columns:1.5fr .9fr;gap:14px;align-items:stretch}
@media(max-width:820px){.hero{grid-template-columns:1fr}}
h1{margin:0;font-size:22px;letter-spacing:-.2px;word-break:break-word}
.expline{display:flex;align-items:center;gap:7px;margin:7px 0 16px;color:var(--tx2);font-size:13px}
.expline svg{width:15px;height:15px;flex:none;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.schip{font-size:12px;font-weight:700;padding:5px 12px;border-radius:99px;white-space:nowrap;
  border:1px solid transparent;flex:none}
.schip.ok{color:var(--ok);background:rgba(58,211,186,.10);border-color:rgba(58,211,186,.35)}
.schip.warn{color:var(--warn);background:rgba(255,160,49,.10);border-color:rgba(255,160,49,.35)}
.schip.bad{color:var(--bad);background:rgba(224,65,65,.10);border-color:rgba(224,65,65,.35)}
[data-theme="light"] .schip.ok{background:rgba(25,146,112,.08);border-color:rgba(25,146,112,.3)}
[data-theme="light"] .schip.warn{background:rgba(243,123,36,.08);border-color:rgba(243,123,36,.3)}
[data-theme="light"] .schip.bad{background:rgba(207,60,60,.07);border-color:rgba(207,60,60,.3)}
/* ── stats ── */
.stats{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px}
.stat{background:var(--surface2);border:1px solid var(--line2);border-radius:12px;padding:11px 13px;
  display:flex;align-items:center;gap:10px;min-width:0}
.stat svg{width:19px;height:19px;flex:none;stroke:var(--a2);fill:none;stroke-width:1.8;
  stroke-linecap:round;stroke-linejoin:round}
.stat div{min-width:0}
.stat b{display:block;font-size:15.5px;font-weight:700;letter-spacing:-.2px;white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis}
.stat span{color:var(--tx2);font-size:11.5px}
/* ── usage donut ── */
.donutrow{display:flex;align-items:center;gap:18px;margin-bottom:4px;flex-wrap:wrap}
.donutbox{position:relative;width:132px;height:132px;flex:none}
.donut{width:132px;height:132px;transform:rotate(-90deg)}
.donut .bgc{fill:none;stroke:var(--surface2);stroke-width:11}
.donut .fgc{fill:none;stroke:url(#dg);stroke-width:11;stroke-linecap:round;transition:stroke-dashoffset .7s}
.donut .fgc.hot{stroke:var(--bad)}
.dg1{stop-color:var(--a1)}.dg2{stop-color:var(--a2)}
.dcenter{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:1px}
.dcenter b{font-size:23px;font-weight:800;letter-spacing:-.4px}
.dcenter span{color:var(--tx2);font-size:11px}
.donutside{flex:1 1 200px;min-width:180px}
.bar{height:9px;border-radius:99px;background:var(--surface2);overflow:hidden;border:1px solid var(--line2)}
.bar>i{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--a1),var(--a2));transition:width .7s}
.bar.hot>i{background:var(--bad)}
.meta{display:flex;justify-content:space-between;color:var(--tx2);font-size:12.5px;margin-top:8px}
.rchip{display:inline-flex;align-items:center;gap:7px;margin-top:11px;padding:6px 12px;border-radius:99px;
  background:var(--chip);border:1px solid var(--chip-line);color:var(--tx2);font-size:12px;font-weight:600}
.rchip svg{width:14px;height:14px;stroke:var(--a2);fill:none;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round}
/* ── buttons ── */
.row{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px}
.btn{border:1px solid transparent;border-radius:11px;background:linear-gradient(135deg,var(--a1),var(--a2));
  color:#fff;font:inherit;font-size:14px;font-weight:700;min-height:44px;padding:0 16px;cursor:pointer;
  display:inline-flex;align-items:center;justify-content:center;gap:8px;text-decoration:none}
.btn:hover{filter:brightness(1.07)}
.btn.alt{background:var(--surface2);color:var(--tx);border-color:var(--line)}
.btn.alt:hover{border-color:var(--a1);filter:none}
.btn:active{transform:translateY(1px)}
.btn img{width:19px;height:19px;border-radius:5px;object-fit:cover}
/* ── QR ── */
.qrbox{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;text-align:center}
.qrsvg{width:186px;height:186px;background:#fff;border-radius:12px;padding:8px;display:block;
  border:1px solid var(--line)}
.hint{margin:0;color:var(--tx2);font-size:12.5px;line-height:1.7}
/* ── sections ── */
h2{font-size:16.5px;margin:30px 0 12px;display:flex;align-items:center;gap:8px}
h2::before{content:"";width:4px;height:17px;border-radius:99px;background:linear-gradient(180deg,var(--a1),var(--a2))}
.cfg{display:flex;align-items:center;gap:10px;padding:11px 14px;border:1px solid var(--line);
  border-radius:12px;background:var(--surface);margin-bottom:8px;flex-wrap:wrap;box-shadow:var(--shadow)}
.cfg .nm{flex:1 1 120px;min-width:0;font-size:13.5px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
@media(max-width:430px){.cfg .nm{flex:1 1 100%}}
.ico{width:42px;height:42px;border-radius:10px;border:1px solid var(--line);background:var(--surface2);
  color:var(--tx);cursor:pointer;display:grid;place-items:center}
.ico:hover{border-color:var(--a1);color:var(--a2)}
.ico svg{width:18px;height:18px;display:block;margin:auto;stroke:currentColor;fill:none;stroke-width:1.7;
  stroke-linecap:round;stroke-linejoin:round}
.cfgqr{width:100%;display:flex;justify-content:center;padding:14px 0 4px}
.cfgqr[hidden]{display:none}
.tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.tab{border:1px solid var(--line);background:var(--surface);color:var(--tx2);border-radius:99px;
  min-height:40px;padding:0 16px;font:inherit;font-size:13.5px;cursor:pointer}
.tab:hover{border-color:var(--a1)}
.tab[aria-selected=true]{background:linear-gradient(135deg,var(--a1),var(--a2));border-color:transparent;
  color:#fff;font-weight:700}
.apps{display:grid;grid-template-columns:repeat(auto-fill,minmax(244px,1fr));gap:12px}
.app{border:1px solid var(--line);border-radius:14px;background:var(--surface);padding:16px;box-shadow:var(--shadow)}
.app .head{display:flex;align-items:center;gap:11px;margin-bottom:12px}
.logo,.mark{width:44px;height:44px;border-radius:11px;display:block;flex:none}
.logo{object-fit:contain;background:var(--surface2);padding:3px;border:1px solid var(--line2)}
.mark{display:grid;place-items:center;color:#fff;font-weight:800;font-size:16px}
.app .nm{font-weight:700;font-size:15px}
.app .rp{color:var(--tx2);font-size:11.5px;word-break:break-all}
.add{width:100%;margin-bottom:9px;min-height:40px;font-size:13.5px}
.dl{display:flex;flex-direction:column;gap:6px}
.dl a{display:flex;align-items:center;justify-content:space-between;gap:8px;min-height:40px;padding:0 12px;
  border:1px solid var(--line);border-radius:10px;color:var(--tx);text-decoration:none;font-size:13.5px;
  background:var(--surface2)}
.dl a:hover{border-color:var(--a1)}
.dl a .sz{color:var(--tx2);font-size:11.5px}
/* ── banner / footer / toast ── */
.banner{display:flex;gap:10px;align-items:center;border:1px solid var(--bad);color:var(--bad);
  border-radius:12px;padding:12px 14px;font-size:13.5px;margin-bottom:16px;background:rgba(224,65,65,.07)}
[data-theme="light"] .banner{background:rgba(207,60,60,.05)}
.banner svg{width:19px;height:19px;flex:none;stroke:currentColor;fill:none;stroke-width:1.9;
  stroke-linecap:round;stroke-linejoin:round}
footer{margin-top:34px;text-align:center;color:var(--tx2);font-size:12px;line-height:1.8}
.toast{position:fixed;inset-inline:0;bottom:22px;margin:auto;width:max-content;max-width:90vw;
  background:linear-gradient(135deg,var(--a1),var(--a2));color:#fff;font-weight:700;font-size:14px;
  padding:11px 18px;border-radius:99px;opacity:0;transform:translateY(8px);transition:.2s;
  pointer-events:none;text-align:center;box-shadow:var(--shadow);z-index:9}
.toast.on{opacity:1;transform:none}
@media(prefers-reduced-motion:reduce){*{transition:none!important}}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div class="brand"><span class="dot" id="dot"></span><span id="bTitle">IranX</span></div>
    <span class="spacer"></span>
    <span class="tag" id="trTag">&mdash;</span>
    <button class="chip" id="themeBtn" type="button"></button>
    <button class="chip" id="langBtn" type="button"></button>
  </div>

  <div id="banner"></div>

  <section class="hero">
    <div class="card">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <h1 id="uname">&mdash;</h1><span class="spacer"></span><span class="schip ok" id="schip">&mdash;</span>
      </div>
      <p class="expline">
        <svg viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="16" rx="2.5"/><path d="M8 3v4M16 3v4M3 10h18"/></svg>
        <span id="expLine">&mdash;</span>
      </p>
      <div class="stats">
        <div class="stat">
          <svg viewBox="0 0 24 24"><path d="M12 3c-4 4.5-6.5 7.8-6.5 11a6.5 6.5 0 0013 0c0-3.2-2.5-6.5-6.5-11z"/></svg>
          <div><b id="sRemain">&mdash;</b><span id="lRemain"></span></div>
        </div>
        <div class="stat">
          <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/></svg>
          <div><b id="sDays">&mdash;</b><span id="lDays"></span></div>
        </div>
        <div class="stat">
          <svg viewBox="0 0 24 24"><rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18.5h2"/></svg>
          <div><b id="sDev">&mdash;</b><span id="lDev"></span></div>
        </div>
        <div class="stat">
          <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3.5 9h17M3.5 15h17M12 3a15 15 0 010 18M12 3a15 15 0 000 18"/></svg>
          <div><b id="sIp">&mdash;</b><span id="lIp"></span></div>
        </div>
      </div>
      <div class="donutrow">
        <div class="donutbox">
          <svg class="donut" viewBox="0 0 120 120" aria-hidden="true">
            <defs>
              <linearGradient id="dg" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0" class="dg1"/><stop offset="1" class="dg2"/>
              </linearGradient>
            </defs>
            <circle class="bgc" cx="60" cy="60" r="52"/>
            <circle class="fgc" id="dfg" cx="60" cy="60" r="52" stroke-dasharray="326.726" stroke-dashoffset="326.726"/>
          </svg>
          <div class="dcenter"><b id="dPct">0%</b><span id="dLbl"></span></div>
        </div>
        <div class="donutside">
          <div class="bar" id="bar"><i style="width:0%"></i></div>
          <div class="meta"><span id="mUsed">&mdash;</span><span id="mQuota">&mdash;</span></div>
          <div class="rchip" id="resetChip" hidden>
            <svg viewBox="0 0 24 24"><path d="M20 11a8 8 0 10.4 4M20 4v7h-7"/></svg>
            <span id="resetTxt"></span>
          </div>
        </div>
      </div>
      <div class="row">
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
  </section>

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
    copySub:"کپی لینک اشتراک", copyAll:"کپی همه کانفیگ‌ها", addTo:"افزودن به", configs:"کانفیگ‌ها",
    downloads:"دانلود برنامه‌ها", noConfigs:"کانفیگ فعالی وجود ندارد.", showQr:"نمایش QR",
    copyCfg:"کپی کانفیگ", scanHint:"با دوربین برنامه اسکن کنید<br>تا اشتراک خودکار اضافه شود",
    footer:"لینک اشتراک شخصی شماست — آن را با کسی به اشتراک نگذارید",
    updEvery:(h)=>"به‌روزرسانی هر "+h+" ساعت", expires:"انقضا", noExpiry:"بدون انقضا",
    unlimited:"بی‌نهایت", support:"با پشتیبانی تماس بگیرید",
    statusActive:"فعال", statusExpired:"اشتراک منقضی شده", statusQuota:"حجم اشتراک تمام شده",
    statusDisabled:"اشتراک غیرفعال شده", statusInactive:"اشتراک فعال نیست",
    resetEveryN:(n)=>"ریست مصرف هر "+n+" روز", nextReset:"ریست بعدی",
    days:"روز", hours:"ساعت", left:"باقی‌مانده", cfgCount:(n)=>n+" کانفیگ فعال",
    copiedSub:"لینک اشتراک کپی شد ✓", copiedAll:"همه کانفیگ‌ها کپی شد ✓",
    copiedCfg:"کانفیگ کپی شد ✓", noQr:"QR در دسترس نیست",
    importHint:"اگر برنامه باز نشد: لینک کپی شده — در برنامه گزینهٔ Add from clipboard را بزنید",
    allVersions:"همه نسخه‌ها", theme:"تم", light:"روشن", dark:"تیره", subName:"اشتراک"},
  en:{brand:"IranX · My subscription", remainVol:"Remaining data", remainTime:"Remaining time",
    devices:"Devices", ipAddr:"Allowed IPs", used:"Used", total:"Total", usage:"Used",
    copySub:"Copy subscription link", copyAll:"Copy all configs", addTo:"Add to", configs:"Configs",
    downloads:"Download apps", noConfigs:"No active config.", showQr:"Show QR", copyCfg:"Copy config",
    scanHint:"Scan with your client app<br>to add the subscription",
    footer:"This is your personal subscription link — do not share it",
    updEvery:(h)=>"Updates every "+h+"h", expires:"Expires", noExpiry:"No expiry",
    unlimited:"Unlimited", support:"please contact support",
    statusActive:"Active", statusExpired:"Subscription expired", statusQuota:"Out of data",
    statusDisabled:"Subscription disabled", statusInactive:"Subscription inactive",
    resetEveryN:(n)=>"Usage resets every "+n+" days", nextReset:"Next reset",
    days:"days", hours:"hours", left:"left", cfgCount:(n)=>n+" active configs",
    copiedSub:"Subscription link copied ✓", copiedAll:"All configs copied ✓",
    copiedCfg:"Config copied ✓", noQr:"QR unavailable",
    importHint:"If the app did not open: the link is copied — use “Add from clipboard” inside the app",
    allVersions:"All versions", theme:"Theme", light:"Light", dark:"Dark", subName:"Subscription"}
};
let LANG = "fa", THEME = "dark", current = D.osTabs[0][0];
try{ LANG = localStorage.getItem("iranx_lang") || LANG; THEME = localStorage.getItem("iranx_theme") || THEME; }catch(e){}
if(LANG!=="en") LANG="fa"; if(THEME!=="light") THEME="dark";
const t = (k)=>T[LANG][k];
const num = (n)=>Number(n).toLocaleString(LANG==="fa"?"fa-IR":"en-US");
const ICON_SUN = '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="4.2"/><path d="M12 2.5v2.6M12 18.9v2.6M2.5 12h2.6M18.9 12h2.6M5 5l1.8 1.8M17.2 17.2L19 19M19 5l-1.8 1.8M6.8 17.2L5 19"/></svg>';
const ICON_MOON = '<svg viewBox="0 0 24 24"><path d="M20.5 14.5A8.5 8.5 0 1110 3.7a7 7 0 0010.5 10.8z"/></svg>';
const ICON_WARN = '<svg viewBox="0 0 24 24"><path d="M12 3.5L2.5 20h19L12 3.5z"/><path d="M12 10v4.5M12 17.6v.2"/></svg>';
const ICON_QR = '<svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><path d="M14 14h3v3h-3zM20 14v3M14 20h6"/></svg>';
const ICON_COPY = '<svg viewBox="0 0 24 24"><rect x="9" y="9" width="11" height="11" rx="2.5"/><path d="M15 5.5A2.5 2.5 0 0012.5 3H6.5A2.5 2.5 0 004 5.5v6A2.5 2.5 0 006.5 14"/></svg>';

/* ── toast + clipboard ── */
let tmr;
function toast(msg){ const el=$("#toast"); el.innerHTML=msg; el.classList.add("on"); clearTimeout(tmr); tmr=setTimeout(()=>el.classList.remove("on"),2600); }
async function copy(text,msg){
  try{ await navigator.clipboard.writeText(text); }
  catch(e){ const ta=document.createElement("textarea"); ta.value=text; ta.style.position="fixed"; ta.style.opacity="0";
    document.body.appendChild(ta); ta.select(); try{document.execCommand("copy");}catch(_){} ta.remove(); }
  if(msg) toast(msg);
}

/* ── one-tap import into clients ── */
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

/* ── status helpers ── */
function statusInfo(){
  if(D.active) return {cls:"ok", key:"statusActive"};
  const m = {expired:["bad","statusExpired"], quota:["warn","statusQuota"], disabled:["bad","statusDisabled"]};
  const f = m[D.status] || ["bad","statusInactive"];
  return {cls:f[0], key:f[1]};
}
function fmtDate(ts){
  return new Date(ts*1000).toLocaleDateString(LANG==="fa"?"fa-IR":"en-GB");
}
const CIRC = 2*Math.PI*52;
function paintUsage(){
  const p = D.quota ? D.pct : 0;
  $("#dfg").style.strokeDashoffset = (CIRC*(1-p/100)).toFixed(1);
  $("#dfg").classList.toggle("hot", !!(D.quota && D.pct>=85));
  $("#dPct").textContent = D.quota ? num(D.pct)+"%" : "∞";
  $("#dLbl").textContent = t("usage");
  $("#bar").firstElementChild.style.width = (D.quota ? D.pct : 0) + "%";
  $("#bar").classList.toggle("hot", D.pct >= 85 && !!D.quota);
}

/* ── render ── */
function paintApps(){
  $("#tabs").innerHTML = D.osTabs.map(([id,faName,en])=>
    `<button class="tab" role="tab" data-os="${id}" aria-selected="${id===current}">${esc(LANG==="fa"?faName:en)}</button>`).join("");
  $("#apps").innerHTML = D.clients.filter(a=>a.os===current).map(a=>{
    const mark = `<span class="mark" style="background:${esc(a.accent)}">${esc(a.name[0])}</span>`;
    const logo = a.logo
      ? `<img class="logo" src="${esc(a.logo)}" alt="${esc(a.name)}" loading="lazy" onerror="this.replaceWith(Object.assign(document.createElement('span'),{className:'mark',style:'background:${esc(a.accent)}',textContent:'${esc(a.name[0])}'}))">`
      : mark;
    const add = a.scheme
      ? `<button class="btn add" data-add="${esc(a.scheme)}">${esc(t("addTo"))} ${esc(a.name)}</button>` : "";
    const dl = a.builds.map(b=>{
      const label = b.label==="@ALL@" ? t("allVersions") : b.label;
      return `<a href="${esc(b.url)}" target="_blank" rel="noopener"><span>${esc(label)}</span><span class="sz">${esc(b.note||"")}</span></a>`;
    }).join("");
    return `<div class="app"><div class="head">${logo}<div><div class="nm">${esc(a.name)}</div>`+
           `<div class="rp">${esc(a.repo)}</div></div></div>${add}<div class="dl">${dl}</div></div>`;
  }).join("");
}

function paintConfigs(){
  $("#cfgs").innerHTML = D.configs.length ? D.configs.map((c,i)=>`
  <div class="cfg">
    <span class="nm">${esc(c.label)}</span>
    <button class="ico" data-qr="${i}" title="${esc(t("showQr"))}" aria-label="${esc(t("showQr"))}">${ICON_QR}</button>
    <button class="ico" data-copy="${i}" title="${esc(t("copyCfg"))}" aria-label="${esc(t("copyCfg"))}">${ICON_COPY}</button>
    <div class="cfgqr" data-box="${i}" hidden></div>
  </div>`).join("") : `<div class="card"><p class="hint" style="margin:0">${esc(t("noConfigs"))}</p></div>`;
}

function render(){
  const h = document.documentElement;
  h.lang = LANG; h.dir = LANG==="fa" ? "rtl" : "ltr"; h.dataset.theme = THEME;
  $("#bTitle").textContent = t("brand");
  $("#themeBtn").innerHTML = (THEME==="dark" ? ICON_SUN : ICON_MOON) +
    "<span>"+(THEME==="dark" ? t("light") : t("dark"))+"</span>";
  $("#langBtn").textContent = LANG==="fa" ? "EN" : "فا";
  $("#trTag").textContent = D.transport === "BOTH" ? "WS + XHTTP" : D.transport;
  $("#uname").textContent = D.name || t("subName");
  $("#lRemain").textContent = t("remainVol");
  $("#lDays").textContent = t("remainTime");
  $("#lDev").textContent = t("devices");
  $("#lIp").textContent = t("ipAddr");
  $("#sRemain").textContent = D.quota ? D.remainText : t("unlimited");
  $("#sDays").textContent = D.expireAt
    ? (D.remainDays > 0 ? num(D.remainDays)+" "+t("days") : num(D.remainHours)+" "+t("hours"))
    : t("unlimited");
  $("#sDev").textContent = D.deviceLimit ? num(D.devicesNow)+" / "+num(D.deviceLimit) : t("unlimited");
  $("#sIp").textContent = D.ipLimit ? num(D.ipsNow)+" / "+num(D.ipLimit) : t("unlimited");
  $("#mUsed").textContent = t("used")+": "+D.usedText;
  $("#mQuota").textContent = t("total")+": "+D.quotaText;
  paintUsage();
  $("#expLine").textContent = D.expireAt
    ? t("expires")+": "+fmtDate(D.expireAt) + (D.active ? "  ("+num(D.remainDays)+" "+t("days")+" "+t("left")+")" : "")
    : t("noExpiry");
  const st = statusInfo();
  $("#schip").className = "schip "+st.cls;
  $("#schip").textContent = t(st.key);
  $("#dot").classList.toggle("off", !D.active);
  $("#banner").innerHTML = D.active ? "" :
    `<div class="banner">${ICON_WARN}<span>${esc(t(st.key))} — ${esc(t("support"))}.</span></div>`;
  if(D.resetDays > 0){
    $("#resetChip").hidden = false;
    $("#resetTxt").textContent = t("resetEveryN")(num(D.resetDays)) +
      (D.nextResetAt ? " · "+t("nextReset")+": "+fmtDate(D.nextResetAt) : "");
  }else{
    $("#resetChip").hidden = true;
  }
  $("#copySub").textContent = t("copySub");
  $("#copyAll").textContent = t("copyAll");
  $("#impHid").textContent = t("addTo")+" Hiddify";
  $("#impV2").textContent  = t("addTo")+" v2rayNG";
  $("#qrHint").innerHTML = t("scanHint");
  $("#hCfg").textContent = t("configs");
  $("#hApps").textContent = t("downloads");
  $("#fNote").textContent = t("footer");
  $("#upd").textContent = t("updEvery")(num(D.updateInterval)) + " · " + t("cfgCount")(num(D.configs.length));
  $("#qrMain").innerHTML = QRS[0] || `<p class="hint">${esc(t("noQr"))}</p>`;
  paintConfigs();
  paintApps();
}

/* ── events ── */
$("#copySub").onclick = ()=>copy(D.subLink, t("copiedSub"));
$("#copyAll").onclick = ()=>copy(D.allConfigs, t("copiedAll"));
$("#impHid").onclick = ()=>addSub("hiddify");
$("#impV2").onclick = ()=>addSub("v2rayng");
$("#themeBtn").onclick = ()=>{ THEME = THEME==="dark" ? "light" : "dark";
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
$("#tabs").addEventListener("click",(e)=>{ const b=e.target.closest("[data-os]"); if(!b) return; current=b.dataset.os; paintApps(); });
$("#apps").addEventListener("click",(e)=>{ const b=e.target.closest("[data-add]"); if(!b) return; addSub(b.dataset.add); });

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
    return HTMLResponse(AUTH_HTML.replace("{{TITLE}}", PANEL_TITLE).replace("{{MODE}}", "setup"))


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    if not password_is_set():
        return RedirectResponse("/setup")
    return HTMLResponse(AUTH_HTML.replace("{{TITLE}}", PANEL_TITLE).replace("{{MODE}}", "login"))


@app.get("/panel", response_class=HTMLResponse)
async def panel_page(session: Optional[str] = Cookie(default=None)):
    if not password_is_set():
        return RedirectResponse("/setup")
    if not valid_session(session):
        return RedirectResponse("/login")
    return HTMLResponse(PANEL_HTML.replace("{{TITLE}}", PANEL_TITLE))


@app.get("/healthz")
async def healthz():
    return {"ok": True}


# ════════════════════════════ FRONTEND ════════════════════════════

THEME_CSS = r"""
/* ── IranX Panel UI — visual language modelled on the 3x-ui (Sanaei) panel ──
   teal-green accent, deep navy surfaces, collapsible rail sidebar.        */
html,body{overflow-x:hidden;max-width:100%}
:root,[data-theme="dark"]{
  --bg:#0a1222; --surface:#151f31; --surface2:#1b2740; --card:#151f31;
  --line:#2c3950; --line2:#222d42;
  --txt:#e7edf7; --dim:rgba(231,237,247,.52);
  --a1:#008771; --a2:#3ad3ba; --ok:#3ad3ba; --bad:#e04141; --warn:#ffa031; --info:#529fff;
  --btn:#008771; --btn-tx:#ffffff; --btn-line:#008771; --ring:rgba(0,135,113,.5);
  --chip:rgba(255,255,255,.05); --chip-line:rgba(255,255,255,.09);
  --shadow:0 10px 30px rgba(0,0,0,.4)}
[data-theme="light"]{
  --bg:#f0f2f5; --surface:#ffffff; --surface2:#f7f9fc; --card:#ffffff;
  --line:#e6e9ef; --line2:#eef1f5;
  --txt:#1f2937; --dim:#7a8694;
  --a1:#008771; --a2:#009980; --ok:#199270; --bad:#cf3c3c; --warn:#f37b24; --info:#0e49b5;
  --btn:#008771; --btn-tx:#ffffff; --btn-line:#008771; --ring:rgba(0,135,113,.3);
  --chip:#f3f5f8; --chip-line:#e6e9ef;
  --shadow:0 8px 24px rgba(16,24,40,.08)}
[data-theme="gray"]{
  --bg:#1a1d22; --surface:#22262c; --surface2:#282d34; --card:#22262c;
  --line:#343a43; --line2:#2b3037;
  --txt:#e8ebef; --dim:#98a1ad;
  --a1:#008771; --a2:#3ad3ba; --ok:#4ade80; --bad:#f87171; --warn:#fbbf24; --info:#60a5fa;
  --btn:#008771; --btn-tx:#ffffff; --btn-line:#008771; --ring:rgba(0,135,113,.5);
  --chip:rgba(255,255,255,.06); --chip-line:rgba(255,255,255,.1);
  --shadow:0 10px 30px rgba(0,0,0,.4)}

*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);
  font-family:Vazirmatn,system-ui,-apple-system,"Segoe UI",Roboto,Tahoma,sans-serif}
a{color:var(--a2)}
::placeholder{color:var(--dim)}
input[type=checkbox]{accent-color:var(--a1);width:15px;height:15px;cursor:pointer}
::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--line);border-radius:9px}
::-webkit-scrollbar-thumb:hover{background:var(--dim)}

/* ── tiny utility set (no external framework needed) ── */
.flex{display:flex}.items-center{align-items:center}.items-start{align-items:flex-start}
.flex-wrap{flex-wrap:wrap}.flex-1{flex:1 1 auto;min-width:0}.ms-auto{margin-inline-start:auto}
.grid{display:grid;gap:12px;grid-template-columns:1fr}
@media(min-width:620px){.g2,.g3,.g4{display:grid;gap:12px;grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(min-width:1000px){
  .g3{grid-template-columns:repeat(3,minmax(0,1fr))}
  .g4{grid-template-columns:repeat(4,minmax(0,1fr))}}
.gap-1{gap:4px}.gap-2{gap:8px}.gap-3{gap:12px}
.mt-1{margin-top:4px}.mt-2{margin-top:8px}.mt-3{margin-top:12px}.mt-4{margin-top:16px}
.mb-2{margin-bottom:8px}.mb-3{margin-bottom:12px}.pt-3{padding-top:12px}
.p-3{padding:12px}.p-4{padding:16px}.py-2{padding-block:8px}
.text-xs{font-size:11px}.text-sm{font-size:12.5px}.text-base{font-size:14px}
.font-bold{font-weight:700}.font-extrabold{font-weight:800}
.dim{color:var(--dim)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;direction:ltr}
.w-full{width:100%}.break-all{word-break:break-all}.truncate{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hidden{display:none!important}
.space-y-2>*+*{margin-top:8px}.space-y-3>*+*{margin-top:12px}
.fld{display:flex;flex-direction:column;gap:5px}

/* ── sidebar ── */
#nav{position:fixed;inset-block:0;inset-inline-start:0;width:244px;z-index:60;
  display:flex;flex-direction:column;background:var(--surface);
  border-inline-end:1px solid var(--line);
  transition:width .2s ease,transform .2s ease}
.side-brand{display:flex;align-items:center;gap:10px;height:58px;padding:0 14px;flex:none;
  border-bottom:1px solid var(--line);overflow:hidden}
.side-brand .brand-logo{width:36px;height:36px;flex:none;border-radius:10px;display:grid;
  place-items:center;background:linear-gradient(135deg,var(--a1),var(--a2));color:#fff}
.brand-text{min-width:0;line-height:1.15}
.brand-text b{display:block;font-size:14px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.brand-text span{font-size:11px;color:var(--dim)}
.side-collapse{margin-inline-start:auto;flex:none}
.side-nav{flex:1 1 auto;overflow-y:auto;padding:10px 8px;display:flex;flex-direction:column;gap:2px}
.navi{display:flex;align-items:center;gap:11px;padding:9px 11px;border-radius:9px;
  color:var(--dim);font-size:13.5px;font-weight:500;cursor:pointer;white-space:nowrap;
  position:relative;transition:background .15s,color .15s}
.navi:hover{background:var(--chip);color:var(--txt)}
.navi.on{background:color-mix(in srgb,var(--a1) 18%,transparent);color:var(--a2);font-weight:700}
.navi.on:before{content:"";position:absolute;inset-inline-start:0;top:9px;bottom:9px;width:3px;
  border-radius:3px;background:var(--a2)}
.side-foot{flex:none;padding:10px;border-top:1px solid var(--line);display:flex;
  flex-direction:column;gap:8px}
.side-foot .row2{display:flex;gap:8px}

/* collapsed rail (desktop) */
body.nav-mini #nav{width:66px}
body.nav-mini .brand-text,body.nav-mini .navi span,body.nav-mini .side-foot .row2,body.nav-mini #btnOut{display:none}
body.nav-mini .navi{justify-content:center;padding:11px 0}
body.nav-mini .side-collapse{display:none}

#scrim{position:fixed;inset:0;z-index:55;background:rgba(0,0,0,.55);backdrop-filter:blur(2px)}

/* ── app shell ── */
#app{margin-inline-start:244px;min-height:100vh;display:flex;flex-direction:column;
  transition:margin-inline-start .2s ease}
body.nav-mini #app{margin-inline-start:66px}
.appbar{position:sticky;top:0;z-index:40;flex:none;height:58px;display:flex;align-items:center;
  gap:12px;padding:0 16px;border-bottom:1px solid var(--line);
  background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(10px)}
.appbar .ttl{min-width:0;line-height:1.2}
.appbar h1{margin:0;font-size:14.5px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.appbar .crumb{font-size:11px;color:var(--dim)}
.path-pill{font-size:10.5px;color:var(--dim);background:var(--chip);border:1px solid var(--chip-line);
  border-radius:999px;padding:4px 10px;white-space:nowrap;max-width:44vw;overflow:hidden;text-overflow:ellipsis}
.content{flex:1 1 auto;width:100%;max-width:1240px;margin:0 auto;padding:16px}

/* ── surfaces ── */
.card{background:var(--card);border:1px solid var(--line);border-radius:12px}
.card-head{display:flex;align-items:center;gap:10px;padding:12px 14px;border-bottom:1px solid var(--line2)}
.soft{background:var(--chip);border:1px solid var(--chip-line)}
.sheet{background:var(--surface)}
.kv{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:9px;background:var(--chip)}
.notice{font-size:11.5px;line-height:1.75;border-radius:9px;padding:10px 12px;
  background:color-mix(in srgb,var(--warn) 12%,transparent);
  border:1px solid color-mix(in srgb,var(--warn) 38%,transparent)}
.notice.ok{background:color-mix(in srgb,var(--ok) 12%,transparent);
  border-color:color-mix(in srgb,var(--ok) 38%,transparent)}

/* ── stat cards ── */
.stat{display:flex;align-items:center;gap:12px;padding:14px;border-radius:12px;
  background:var(--card);border:1px solid var(--line);transition:border-color .15s,transform .15s}
.stat:hover{border-color:color-mix(in srgb,var(--a1) 60%,var(--line));transform:translateY(-1px)}
.stat .ico{width:40px;height:40px;flex:none;border-radius:11px;display:grid;place-items:center}
.stat b{display:block;font-size:20px;font-weight:800;line-height:1.2}
.stat span{font-size:11.5px;color:var(--dim)}

/* ── buttons ── */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;cursor:pointer;
  border:1px solid var(--btn-line);background:var(--btn);color:var(--btn-tx);
  border-radius:9px;padding:9px 15px;font:inherit;font-size:13px;font-weight:600;
  white-space:nowrap;transition:filter .15s,background .15s}
.btn:hover{filter:brightness(1.12)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn-soft{background:var(--chip);color:var(--txt);border-color:var(--chip-line)}
.btn-soft:hover{background:color-mix(in srgb,var(--txt) 12%,transparent);filter:none}
.btn-danger{background:color-mix(in srgb,var(--bad) 14%,transparent);color:var(--bad);border-color:transparent}
.btn-danger:hover{background:color-mix(in srgb,var(--bad) 24%,transparent);filter:none}
.icon-btn{width:34px;height:34px;flex:none;border-radius:9px;display:grid;place-items:center;
  background:transparent;border:1px solid transparent;color:var(--dim);cursor:pointer;
  transition:background .15s,color .15s}
.icon-btn:hover{background:var(--chip);color:var(--txt)}
.icon-btn.danger:hover{color:var(--bad);background:color-mix(in srgb,var(--bad) 14%,transparent)}
.grad{background:linear-gradient(135deg,var(--a1),var(--a2));color:#fff}

/* ── form fields ── */
.inp{width:100%;background:var(--surface2);border:1px solid var(--line);color:var(--txt);
  border-radius:9px;padding:9px 12px;font:inherit;font-size:13px;
  transition:border-color .15s,box-shadow .15s}
.inp:focus{outline:none;border-color:var(--a1);box-shadow:0 0 0 3px var(--ring)}
textarea.inp{resize:vertical;min-height:76px}

/* ── chips / badges ── */
.chip{display:inline-flex;align-items:center;gap:5px;font-size:10.5px;font-weight:700;
  padding:3px 9px;border-radius:999px;background:var(--chip);border:1px solid var(--chip-line);
  color:var(--dim);white-space:nowrap}
.chip.green{background:color-mix(in srgb,var(--ok) 15%,transparent);border-color:transparent;color:var(--ok)}
.chip.red{background:color-mix(in srgb,var(--bad) 15%,transparent);border-color:transparent;color:var(--bad)}
.chip.blue{background:color-mix(in srgb,var(--info) 15%,transparent);border-color:transparent;color:var(--info)}
.chip.orange{background:color-mix(in srgb,var(--warn) 16%,transparent);border-color:transparent;color:var(--warn)}
.chip.teal{background:color-mix(in srgb,var(--a2) 15%,transparent);border-color:transparent;color:var(--a2)}

/* ── switch ── */
.sw{width:42px;height:24px;flex:none;border-radius:999px;background:var(--line);position:relative;
  border:none;cursor:pointer;transition:background .18s;padding:0}
.sw:after{content:"";position:absolute;top:3px;inset-inline-start:3px;width:18px;height:18px;
  border-radius:50%;background:#fff;transition:inset-inline-start .18s}
.sw.on{background:var(--a1)}
.sw.on:after{inset-inline-start:21px}

/* ── progress ── */
.progress{height:6px;border-radius:6px;background:var(--chip);overflow:hidden}
.progress>i{display:block;height:100%;border-radius:6px;background:linear-gradient(90deg,var(--a1),var(--a2))}
.progress.hot>i{background:var(--bad)}

/* ── user row ── */
.urow{display:flex;align-items:center;gap:12px;padding:12px 14px;flex-wrap:wrap;
  border-bottom:1px solid var(--line2)}
.urow:last-child{border-bottom:0}
.urow:hover{background:var(--chip)}
.u-av{width:38px;height:38px;flex:none;border-radius:11px;display:grid;place-items:center;
  font-weight:800;font-size:15px;background:color-mix(in srgb,var(--a1) 18%,transparent);color:var(--a2)}
.u-main{flex:1 1 220px;min-width:0}
.u-dev{font-size:12px;font-weight:700;flex:none}
.u-actions{display:flex;gap:6px;align-items:center;flex:none}

/* ── list rows ── */
.prow{border-radius:10px;padding:10px 12px;background:var(--chip);border:1px solid var(--chip-line)}
.prow.on{border-color:var(--a1);box-shadow:0 0 0 2px var(--ring)}
.lrow{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:9px;
  background:var(--chip);font-size:11.5px;flex-wrap:wrap}

/* ── modal ── */
#modal{position:fixed;inset:0;z-index:80;align-items:center;justify-content:center;
  background:rgba(0,0,0,.62);padding:14px}
.modal-card{width:100%;max-width:460px;max-height:86vh;overflow-y:auto;
  background:var(--surface);border:1px solid var(--line);border-radius:14px;
  padding:18px;box-shadow:var(--shadow)}
.modal-head{display:flex;align-items:center;margin-bottom:14px}
.modal-head b{font-size:14px}

.ic{width:18px;height:18px;flex:none;stroke:currentColor;fill:none;stroke-width:1.7;
  stroke-linecap:round;stroke-linejoin:round}
.ic-lg{width:22px;height:22px}

@media(max-width:1023px){
  #nav{transform:translateX(-100%);width:244px}
  [dir="rtl"] #nav{transform:translateX(100%)}
  body.nav-open #nav{transform:none}
  #app{margin-inline-start:0!important}
  .path-pill{display:none}
}
@media(prefers-reduced-motion:reduce){*{transition:none!important}}
"""

I18N_JS = r"""
const I18N={
 fa:{dir:'rtl',
  setupTitle:'تعیین رمز عبور',setupSub:'اولین ورود — یک رمز برای پنل انتخاب کنید',
  loginTitle:'ورود به پنل',loginSub:'رمز عبور خود را وارد کنید',
  password:'رمز عبور',confirm:'تکرار رمز عبور',enter:'ورود',save:'ذخیره و ورود',
  pwRule:'حداقل ۸ کاراکتر شامل حرف بزرگ، حرف کوچک و عدد',netErr:'خطای شبکه',
  navDash:'داشبورد',navUsers:'مدیریت کاربران',navClean:'Clean IP',
  navProxy:'پروکسی',navLive:'اتصالات زنده',
  navSettings:'تنظیمات پنل',navLogs:'رخدادها',menu:'منو',
  totalUsers:'کل کاربران',online:'کاربران آنلاین',devices:'دستگاه‌های متصل',
  traffic:'مصرف کل',cleanIps:'آی‌پی تمیز',xSessions:'سشن‌های XHTTP',liveTitle:'اتصالات زنده',liveEmpty:'هیچ اتصالی فعال نیست',
  chart24:'مصرف ۲۴ ساعت اخیر',protoSplit:'تقسیم بر اساس ترنسپورت',
  newUser:'ساخت کاربر جدید',users:'کاربران',
  name:'نام (انگلیسی)',quota:'حجم (GB)',days:'مدت (روز)',devLimit:'تعداد دستگاه',ipLimit:'تعداد آی‌پی',
  transport:'ترنسپورت',trWs:'🔌 WS + TLS',trXhttp:'🚀 XHTTP + TLS',trBoth:'🔀 هر دو',
  add:'افزودن',zeroInf:'۰ = بی‌نهایت. «تعداد دستگاه» هر دستگاه را از روی IP و User-Agent کلاینت شناسایی و ثبت می‌کند و فقط همان دستگاه‌ها اجازه اتصال دارند؛ «تعداد آی‌پی» جداست و روی آدرس‌های متمایز اعمال می‌شود.',
  search:'جستجو…',noUsers:'کاربری نیست',
  config:'کانفیگ',ipsBtn:'دستگاه‌ها و آی‌پی‌ها',edit:'ویرایش',
  used:'مصرف',expiry:'انقضا',never:'بی‌نهایت',
  subLink:'لینک اشتراک (Subscription)',copySub:'کپی لینک اشتراک',
  singleCfg:'کانفیگ‌های تکی',copy:'کپی',copied:'کپی شد ✓',
  devTitle:'دستگاه‌های متصل',noConn:'هنوز اتصالی ثبت نشده',
  clearIps:'پاک کردن دستگاه‌ها و آی‌پی‌ها',delDevice:'حذف دستگاه',delDeviceWarn:'این دستگاه از لیست حذف شود؟ (یک جای خالی آزاد می‌شود)',unknownClient:'ناشناس',devLimitLbl:'مجاز',onlineTag:'آنلاین',offlineTag:'آفلاین',
  devSec:'دستگاه‌ها',ipSec:'آی‌پی‌ها',ipCounted:'آی‌پی‌های شمرده‌شده',ipsTotal:'کل آی‌پی‌های دیده‌شده',delIp:'حذف آی‌پی',delIpWarn:'این آی‌پی از لیست حذف شود؟ (یک جای خالی آزاد می‌شود)',
  liveNow:'الان متصل',noneNow:'همین الان هیچ دستگاهی متصل نیست',
  countedFor:'شمرده‌شده برای محدودیت',totalSeen:'کل دستگاه‌های دیده‌شده',
  showHistory:'نمایش تاریخچه',showLive:'نمایش فقط متصل‌ها',
  inLast:'در %s ثانیه اخیر',refresh:'به‌روزرسانی',
  liveDevices:'دستگاه‌های فعال الان',
  editUser:'ویرایش',remainDays:'مدت باقی‌مانده (روز)',allowedDev:'تعداد دستگاه مجاز',allowedIp:'تعداد آی‌پی مجاز',
  active:'فعال',saveBtn:'ذخیره',resetTraffic:'ریست حجم',newUuid:'UUID جدید',
  customUuid:'UUID دستی',del:'حذف',
  obfLbl:'مبهم‌ساز (Fragment + Cipher mask)',
  echLbl:'آنتی سانسور (Ech)',
  fpLbl:'فینگرپرینت TLS',alpnLbl:'ALPN',alpnDef:'پیش‌فرض این نوع کانفیگ',alpnNone:'بدون ALPN (حذف از لینک)',
  uuidWarn:'UUID عوض شود؟ کانفیگ‌های قبلی از کار می‌افتند.',delWarn:'این کاربر حذف شود؟',
  cleanTitle:'مدیریت Clean IP',
  cleanHint:'آی‌پی یا دامنه تمیز. در لینک اشتراک هر کاربر به عنوان کانفیگ اضافی اضافه می‌شود.',
  addrPh:'مثلا 1.2.3.4 یا cdn.example.com',remarkPh:'برچسب (اختیاری)',
  bulkPh:'چند مورد، هر خط یکی:\n1.2.3.4 # ایرانسل\n5.6.7.8 # همراه اول',
  bulkAdd:'افزودن انبوه',clearAll:'حذف همه',
  pxTitle:'پروکسی خروجی',
  pxHint:'با فعال کردن یک پروکسی، تمام ترافیک کاربران از همان مسیر خارج می‌شود و سایت‌ها ایپی پروکسی را می‌بینند.',
  pxKind:'نوع',pxHost:'هاست / ایپی',pxPort:'پورت',
  pxUser:'یوزرنیم (اختیاری)',pxPass:'پسورد (اختیاری)',
  pxAdd:'افزودن و تست',pxTestAll:'تست همه',
  pxInSub:'در ساب',
  pxAutoNote:'هر پروکسی که اضافه شود خودبه‌خود در ساب همه کاربران می‌آید — همه با هم، بدون دکمه. کانفیگ بدون پروکسی همیشه سر جایش هست؛ قطعی یا ناموفق بودن تست، پروکسی را از ساب حذف نمی‌کند و فقط با غیرفعال کردن یا حذف از پنل بیرون می‌رود.',
  pxLineHint:'هر خط یک پروکسی — مانند socks5://1.1.1.1:5866 یا http://user:pass@2.2.2.2:8080',
  pxAddLines:'افزودن لیست و تست',
  pxAdvanced:'ورود دستی فیلدها',
  pxDirect:'اتصال مستقیم (بدون پروکسی)',
  pxActive:'فعال',pxArm:'فعال کردن',pxTest:'تست سلامت',
  pxHealthy:'سالم',pxDown:'خراب',pxUntested:'تست نشده',
  pxExitIp:'ایپی خروجی',pxLatency:'تاخیر',
  pxNone:'هنوز پروکسی اضافه نشده است',
  pxStrict:'حالت سختگیرانه',
  pxStrictHint:'اگر پروکسی قطع شد، اتصال رد می‌شود تا ایپی اصلی سرور لو نرود',
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
  xhModeHint:'حالت روی packet-up است و برای هر تکه آپلود یک رکوئست جدا می‌فرستد. اگر رله '
        +'کلادفلر دارید، XHTTP_MODE را به stream-up تغییر دهید تا هر اتصال فقط ۲ رکوئست شود. '
        +'کانفیگ‌های قبلی همچنان کار می‌کنند، ولی کاربران باید لینک اشتراک را یک بار به‌روز کنند.',
  trWarnTitle:'⚠️ مصرف رکوئست XHTTP:',
  trWarn:'مصرف این ترنسپورت به حالت (mode) بستگی دارد. در stream-up — که پیش‌فرض این پنل '
        +'است — هر اتصال ۲ رکوئست می‌شود (یک GET برای دانلود و یک POST بلندمدت برای آپلود). '
        +'در packet-up هر تکه از آپلود یک POST جداگانه است و یک کاربر فعال دقیقه‌ای صدها '
        +'رکوئست می‌سازد که سهمیه روزانه ورکر کلادفلر (۱۰۰٬۰۰۰) را زود پر می‌کند. WS از همه '
        +'کم‌مصرف‌تر است: هر اتصال فقط ۱ رکوئست، هر چقدر هم طول بکشد.',
  backupTitle:'📦 پشتیبان‌گیری',
  backupHint:'یک فایل با پسوند .ixpbak که همهٔ کاربران (با UUID و توکن اشتراکشان)، '
        +'آی‌پی‌های تمیز، پروکسی‌ها، رمز پنل و تنظیمات را نگه می‌دارد. همین فایل را در پنل '
        +'جدید وارد کنید تا همه چیز برگردد — کانفیگ‌های دست کاربران هم کار می‌کنند چون '
        +'UUID و توکن‌ها عوض نمی‌شوند.',
  bkInclPw:'رمز پنل هم ذخیره شود',
  bkInclProxyCreds:'یوزر و پسورد پروکسی‌ها هم ذخیره شود',
  bkInclTraffic:'تاریخچهٔ مصرف هم ذخیره شود (حجم فایل بیشتر می‌شود)',
  bkSecretWarn:'⚠️ این فایل شامل رمز پنل و پسورد پروکسی‌هاست — مثل رمز عبور از آن مراقبت کنید.',
  btnBackupLbl:'⬇️ دانلود فایل پشتیبان',
  restoreTitle:'♻️ بازگردانی',
  restoreHint:'فایل .ixpbak را انتخاب کنید. اول محتوایش نمایش داده می‌شود و تا تأیید '
        +'نکنید هیچ چیزی در دیتابیس نوشته نمی‌شود.',
  restoreMode:'نحوهٔ بازگردانی',
  bkMerge:'ادغام — موارد موجود به‌روز و بقیه اضافه می‌شوند',
  bkReplace:'جایگزینی کامل — کاربران، آی‌پی‌ها و پروکسی‌های فعلی حذف می‌شوند',
  bkRestorePwLbl:'رمز پنل هم از فایل بازگردانی شود',
  btnRestoreLbl:'♻️ بازگردانی کن',
  bkReading:'در حال خواندن فایل…',
  bkBadFile:'فایل قابل خواندن نیست یا پشتیبان این پنل نیست',
  bkFrom:'ساخته‌شده در',bkUsersN:'کاربر',bkCipsN:'آی‌پی تمیز',bkProxN:'پروکسی',
  bkTrafficN:'رکورد مصرف',
  bkHasPw:'شامل رمز پنل',bkNoPw:'بدون رمز پنل',
  bkProxCreds:'پروکسی با یوزر/پسورد',
  bkEnvDiff:'⚠️ این متغیرها با پنل فعلی تفاوت دارند و باید دستی در Railway/Render ست شوند:',
  bkReplaceWarn:'همهٔ کاربران، آی‌پی‌های تمیز و پروکسی‌های فعلی حذف و با فایل جایگزین می‌شوند. مطمئنی؟',
  bkPwChanged:'رمز پنل از فایل بازگردانی شد — دفعهٔ بعد با رمز قدیمیِ همان فایل وارد شوید.',
  bkDone:'بازگردانی انجام شد',
  resetCycle:'ریست دوره‌ای مصرف',resetOff:'خاموش',reset1:'هر ۱ روز (روزانه)',reset3:'هر ۳ روز',
  reset7:'هر ۷ روز (هفتگی)',reset14:'هر ۱۴ روز (دو هفته)',reset30:'هر ۳۰ روز (ماهانه)',
  reset60:'هر ۶۰ روز (دو ماه)',reset90:'هر ۹۰ روز (سه ماه)',resetCustom:'دلخواه',customDays:'تعداد روز (۱ تا ۳۶۵)',
  tgTitle:'🤖 بکاپ تلگرامی',
  tgHint:'از پنل یک فایل پشتیبان کامل به چت تلگرام شما می‌رسد — روی Railway/Render که دیتابیس با ری‌دپلوی پاک می‌شود، این فایل نسخهٔ پشتیبان شماست. توکن را از @BotFather بگیرید و آی‌دی چت را از @userinfobot. برای گروه، آی‌دی را با -100 شروع کنید و ربات را عضو گروه کنید.',
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
  fltHint:'اتصال کاربران به سایت‌های فیلترشده رد می‌شود. مقصد از همان هدر VLESS خوانده می‌شود، پس پیش از برقراری اتصال جلوی آن گرفته می‌شود.',
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
  custHint:'⚠️ این مقادیر فقط وقتی اعمال می‌شوند که تیک مربوطه در بالا زده باشد: ECH با تیک «کانفیگ ECH»؛ cs و fm فقط روی لینک WS با تیک «لینک مبهم‌ساز». بعد از ذخیره، ساب را در کلاینت دوباره به‌روزرسانی کنید.',
  statusDisabled:'غیرفعال',statusExpired:'منقضی',statusQuota:'حجم تمام',
 },
 en:{dir:'ltr',
  setupTitle:'Set a password',setupSub:'First run — choose your panel password',
  loginTitle:'Sign in',loginSub:'Enter your password',
  password:'Password',confirm:'Confirm password',enter:'Sign in',save:'Save & enter',
  pwRule:'At least 8 chars with upper case, lower case and a digit',netErr:'Network error',
  navDash:'Dashboard',navUsers:'Users',navClean:'Clean IP',
  navProxy:'Proxy',navLive:'Live connections',
  navSettings:'Panel settings',navLogs:'Events',menu:'Menu',
  totalUsers:'Total users',online:'Online users',devices:'Connected devices',
  traffic:'Total traffic',cleanIps:'Clean IPs',xSessions:'XHTTP sessions',liveTitle:'Live connections',liveEmpty:'No active connections',
  chart24:'Last 24 hours',protoSplit:'Split by transport',
  newUser:'Create user',users:'Users',
  name:'Name',quota:'Quota (GB)',days:'Days',devLimit:'Devices',ipLimit:'IPs',
  transport:'Transport',trWs:'🔌 WS + TLS',trXhttp:'🚀 XHTTP + TLS',trBoth:'🔀 Both',
  add:'Add',zeroInf:'0 = unlimited. "Devices" identifies and registers every device from its IP and client User-Agent and only lets those devices connect; "IPs" is separate and counts distinct source addresses.',
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
  pxHint:'Arm a proxy and every user connection leaves through it, so target sites see the proxy IP.',
  pxKind:'Type',pxHost:'Host / IP',pxPort:'Port',
  pxUser:'Username (optional)',pxPass:'Password (optional)',
  pxAdd:'Add & test',pxTestAll:'Test all',
  pxInSub:'in subscriptions',
  pxAutoNote:'Every proxy you add joins all subscriptions automatically — all of them at once, no button. The no-proxy config is always there, and a failed health check or a dropped connection never removes a proxy: only disabling or deleting it in the panel does.',
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
  xhModeHint:'The mode is packet-up, which spends one request per upload chunk. Behind a '
        +'Cloudflare relay, set XHTTP_MODE=stream-up to get 2 requests per connection instead. '
        +'Existing configs keep working, but users need to refresh their subscription once.',
  trWarnTitle:'⚠️ XHTTP request cost:',
  trWarn:'Cost depends on the mode. stream-up — this panel\'s default — is 2 requests per '
        +'connection (a GET downlink plus one long-lived POST uplink). packet-up sends every '
        +'upload chunk as its own POST, so one active client can be hundreds of requests a '
        +'minute and will drain a Cloudflare Worker\'s daily quota (100k). WS is cheapest of '
        +'all: 1 request per connection no matter how long it stays open.',
  backupTitle:'📦 Backup',
  backupHint:'A single .ixpbak file holding every user (with their UUID and subscription '
        +'token), your clean IPs, your proxies, the panel password and its settings. Import '
        +'it into a fresh panel and everything comes back — configs already handed out keep '
        +'working, because UUIDs and tokens are preserved.',
  bkInclPw:'include the panel password',
  bkInclProxyCreds:'include proxy usernames and passwords',
  bkInclTraffic:'include traffic history (larger file)',
  bkSecretWarn:'⚠️ This file contains the panel password and your proxy credentials — treat it like a password.',
  btnBackupLbl:'⬇️ Download backup',
  restoreTitle:'♻️ Restore',
  restoreHint:'Pick a .ixpbak file. Its contents are shown first and nothing is written '
        +'to the database until you confirm.',
  restoreMode:'Restore mode',
  bkMerge:'Merge — update matching entries, add the rest',
  bkReplace:'Replace — wipe current users, clean IPs and proxies first',
  bkRestorePwLbl:'also restore the panel password from the file',
  btnRestoreLbl:'♻️ Restore now',
  bkReading:'Reading file…',
  bkBadFile:'File cannot be read, or is not a backup from this panel',
  bkFrom:'Created',bkUsersN:'users',bkCipsN:'clean IPs',bkProxN:'proxies',
  bkTrafficN:'traffic rows',
  bkHasPw:'includes the panel password',bkNoPw:'no panel password',
  bkProxCreds:'proxies with credentials',
  bkEnvDiff:'⚠️ These variables differ from this panel and must be set by hand in Railway/Render:',
  bkReplaceWarn:'All current users, clean IPs and proxies will be deleted and replaced by the file. Continue?',
  bkPwChanged:'The panel password was restored from the file — sign in with that file\'s password next time.',
  bkDone:'Restore complete',
  resetCycle:'Usage reset cycle',resetOff:'Off',reset1:'Daily (1 day)',reset3:'Every 3 days',
  reset7:'Weekly (7 days)',reset14:'Every 14 days (2 weeks)',reset30:'Monthly (30 days)',
  reset60:'Every 60 days (2 months)',reset90:'Every 90 days (3 months)',resetCustom:'Custom',customDays:'Days (1–365)',
  tgTitle:'🤖 Telegram backup',
  tgHint:'A full panel backup lands in your Telegram chat — on Railway/Render the database dies with a redeploy, so this file is your off-site copy. Get the token from @BotFather and the chat ID from @userinfobot. For a group chat, start the ID with -100 and add the bot to the group.',
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
  fltHint:'Connections to filtered sites are refused. The destination is read from the VLESS header, so it is blocked before the connection is even made.',
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
  custHint:'⚠️ These only apply when the matching toggle above is on: ECH needs the "ECH config" checkbox; cs and fm only ride the WS link with the "obfuscated link" checkbox. After saving, refresh the subscription in your client.',
  statusDisabled:'disabled',statusExpired:'expired',statusQuota:'quota used',
 }
};
let LANG=localStorage.getItem('lang')||'fa';
const THEMES=['dark','light','gray'];
let THEME=localStorage.getItem('theme')||'dark';
if(!THEMES.includes(THEME)){THEME='light'===THEME?'light':'dark';localStorage.setItem('theme',THEME)}
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
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>__THEME__
body{min-height:100vh;display:grid;place-items:center;padding:18px;position:relative}
.bg-glow{position:fixed;inset:0;pointer-events:none;
  background:
   radial-gradient(58% 55% at 50% -8%,color-mix(in srgb,var(--a1) 34%,transparent),transparent 70%),
   radial-gradient(40% 40% at 92% 100%,color-mix(in srgb,var(--a2) 16%,transparent),transparent 72%)}
.auth{position:relative;width:100%;max-width:392px;background:var(--surface);
  border:1px solid var(--line);border-radius:16px;padding:30px 26px;box-shadow:var(--shadow)}
.auth .top{display:flex;gap:8px;justify-content:flex-end;margin-bottom:18px}
.auth select{width:auto}
.auth .logo{width:56px;height:56px;margin:0 auto 14px;border-radius:16px;display:grid;
  place-items:center;background:linear-gradient(135deg,var(--a1),var(--a2));color:#fff;
  box-shadow:0 10px 26px color-mix(in srgb,var(--a1) 45%,transparent)}
.auth h1{margin:0;text-align:center;font-size:19px;font-weight:800}
.auth .sub{margin:5px 0 22px;text-align:center;font-size:12px;color:var(--dim)}
.auth .go{width:100%;margin-top:6px;padding:11px}
</style></head><body>
<script>__I18N__</script>
<div class="bg-glow"></div>
<div class="auth">
 <div class="top">
  <select onchange="setLang(this.value)" id="langSel" class="inp" style="width:auto;font-size:12px;padding:5px 9px">
   <option value="fa">🇮🇷 فارسی</option><option value="en">🇬🇧 English</option></select>
  <select onchange="setTheme(this.value)" id="thSel" class="inp" style="width:auto;font-size:12px;padding:5px 9px">
   <option value="dark">Dark</option><option value="light">Light</option><option value="gray">Gray</option></select>
 </div>
 <div class="logo">
  <svg class="ic ic-lg" viewBox="0 0 24 24" style="stroke:#fff">
   <path d="M12 2.7l7.5 3.4v5.3c0 4.4-3.1 8.2-7.5 9.9-4.4-1.7-7.5-5.5-7.5-9.9V6.1L12 2.7z"/>
   <path d="M12.6 8.2L9.4 13h2.6l-.6 3.4L14.6 11H12l.6-2.8z" style="fill:#fff;stroke-width:1"/></svg>
 </div>
 <h1 id="h1"></h1>
 <p id="sub" class="sub"></p>
 <div class="space-y-2">
  <input id="p1" type="password" class="inp" autocomplete="current-password">
  <input id="p2" type="password" class="inp hidden" autocomplete="new-password">
  <p id="rule" class="text-xs dim hidden" style="margin:0"></p>
  <button id="go" class="btn go"></button>
  <p id="err" class="text-sm" style="text-align:center;color:var(--bad);min-height:18px;margin:0"></p>
 </div>
</div>
<script>
const MODE="{{MODE}}";
langSel.value=LANG; thSel.value=THEME;
function paint(){
 h1.textContent  = MODE==='setup'?T('setupTitle'):T('loginTitle');
 sub.textContent = MODE==='setup'?T('setupSub'):T('loginSub');
 p1.placeholder  = T('password'); p2.placeholder = T('confirm');
 go.textContent  = MODE==='setup'?T('save'):T('enter');
 rule.textContent= T('pwRule');
 if(MODE==='setup'){p2.classList.remove('hidden');rule.classList.remove('hidden')}
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


PANEL_HTML = r"""<!DOCTYPE html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>__THEME__</style>
</head><body>
<script>__I18N__</script>

<!-- ══════════ SIDEBAR ══════════ -->
<aside id="nav">
 <div class="side-brand">
  <div class="brand-logo">
   <svg class="ic ic-lg" viewBox="0 0 24 24" style="stroke:#fff">
    <path d="M12 2.7l7.5 3.4v5.3c0 4.4-3.1 8.2-7.5 9.9-4.4-1.7-7.5-5.5-7.5-9.9V6.1L12 2.7z"/>
    <path d="M12.6 8.2L9.4 13h2.6l-.6 3.4L14.6 11H12l.6-2.8z" style="fill:#fff;stroke-width:1"/></svg>
  </div>
  <div class="brand-text"><b>{{TITLE}}</b><span>admin</span></div>
  <button class="icon-btn side-collapse" onclick="toggleNav()" aria-label="collapse">
   <svg class="ic" viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h16"/></svg></button>
 </div>
 <nav class="side-nav">
  <div class="navi" data-page="dash" onclick="go('dash')">
   <svg class="ic" viewBox="0 0 24 24"><path d="M4 13h6V4H4v9zM14 20h6v-9h-6v9zM4 20h6v-4H4v4zM14 8h6V4h-6v4z"/></svg>
   <span data-t="navDash"></span></div>
  <div class="navi" data-page="users" onclick="go('users')">
   <svg class="ic" viewBox="0 0 24 24"><circle cx="9" cy="8" r="3.2"/>
    <path d="M3.5 19.5c0-3 2.5-4.8 5.5-4.8s5.5 1.8 5.5 4.8"/>
    <path d="M16.5 5.6a3 3 0 010 5.6M18 14.9c2 .6 3.4 2.2 3.4 4.6"/></svg>
   <span data-t="navUsers"></span></div>
  <div class="navi" data-page="clean" onclick="go('clean')">
   <svg class="ic" viewBox="0 0 24 24"><path d="M12 3.2c3.6 3.2 5.6 6 5.6 9a5.6 5.6 0 11-11.2 0c0-3 2-5.8 5.6-9z"/>
    <path d="M9.4 14.6a2.8 2.8 0 002.6 2.6"/></svg><span data-t="navClean"></span></div>
  <div class="navi" data-page="filter" onclick="go('filter')">
   <svg class="ic" viewBox="0 0 24 24"><path d="M3.5 5h17l-6.5 7.5V20l-4-2.2v-5.3z"/></svg>
   <span data-t="navFilter"></span></div>
  <div class="navi" data-page="proxy" onclick="go('proxy')">
   <svg class="ic" viewBox="0 0 24 24"><path d="M4 7h6.5a3 3 0 013 3v4a3 3 0 003 3H20"/>
    <path d="M17 4l3 3-3 3M17 14l3 3-3 3"/><circle cx="4" cy="7" r="1.6"/></svg>
   <span data-t="navProxy"></span></div>
  <div class="navi" data-page="live" onclick="go('live')">
   <svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/>
    <path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1"/></svg>
   <span data-t="navLive"></span></div>
  <div class="navi" data-page="settings" onclick="go('settings')">
   <svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/>
    <path d="M19.4 14.5a1.7 1.7 0 00.35 1.87l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.7 1.7 0 00-1.87-.35 1.7 1.7 0 00-1.03 1.56V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1.1-1.55 1.7 1.7 0 00-1.87.35l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.7 1.7 0 00.35-1.87 1.7 1.7 0 00-1.56-1.03H3a2 2 0 110-4h.1a1.7 1.7 0 001.55-1.1 1.7 1.7 0 00-.35-1.87l-.06-.06a2 2 0 112.83-2.83l.06.06a1.7 1.7 0 001.87.35H9a1.7 1.7 0 001-1.56V3a2 2 0 114 0v.1a1.7 1.7 0 001.03 1.56 1.7 1.7 0 001.87-.35l.06-.06a2 2 0 112.83 2.83l-.06.06a1.7 1.7 0 00-.35 1.87V9a1.7 1.7 0 001.56 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1.05z"/></svg>
   <span data-t="navSettings"></span></div>
  <div class="navi" data-page="logs" onclick="go('logs')">
   <svg class="ic" viewBox="0 0 24 24"><path d="M5 4.5h11l3 3V19a1 1 0 01-1 1H5a1 1 0 01-1-1V5.5a1 1 0 011-1z"/>
    <path d="M15.5 4.5V8H19M7.5 12h9M7.5 15.5h6"/></svg><span data-t="navLogs"></span></div>
 </nav>
 <div class="side-foot">
  <div class="row2">
   <select id="thSel" onchange="setTheme(this.value)" class="inp" style="font-size:11.5px;padding:6px 8px">
    <option value="dark" data-t="thDark"></option><option value="light" data-t="thLight"></option>
    <option value="gray" data-t="thGray"></option></select>
   <select id="langSel" onchange="setLang(this.value)" class="inp" style="font-size:11.5px;padding:6px 8px">
    <option value="fa">فا</option><option value="en">EN</option></select>
  </div>
  <button onclick="logout()" id="btnOut" class="btn btn-danger"></button>
 </div>
</aside>

<div id="scrim" class="hidden" onclick="closeDrawer()"></div>

<!-- ══════════ APP ══════════ -->
<div id="app">
 <header class="appbar">
  <button class="icon-btn" onclick="toggleNav()" aria-label="menu">
   <svg class="ic" viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h16"/></svg></button>
  <div class="ttl">
   <h1>{{TITLE}}</h1>
   <span id="crumb" class="crumb"></span>
  </div>
  <div class="flex-1"></div>
  <span id="pill" class="path-pill mono"></span>
 </header>

 <main class="content">

  <!-- ══ DASHBOARD ══ -->
  <section data-pg="dash">
   <div class="g4">
    <div class="stat">
     <div class="ico" style="background:color-mix(in srgb,var(--info) 16%,transparent);color:var(--info)">
      <svg class="ic ic-lg" viewBox="0 0 24 24"><circle cx="9" cy="8" r="3.2"/><path d="M3.5 19.5c0-3 2.5-4.8 5.5-4.8s5.5 1.8 5.5 4.8"/><path d="M16.5 5.6a3 3 0 010 5.6M18 14.9c2 .6 3.4 2.2 3.4 4.6"/></svg></div>
     <div><b id="sUsers">—</b><span data-t="totalUsers"></span></div></div>
    <div class="stat">
     <div class="ico" style="background:color-mix(in srgb,var(--ok) 16%,transparent);color:var(--ok)">
      <svg class="ic ic-lg" viewBox="0 0 24 24"><path d="M3 12h4l2.5-6 4 12 2.5-6h5"/></svg></div>
     <div><b id="sOnline" style="color:var(--ok)">—</b><span data-t="online"></span></div></div>
    <div class="stat">
     <div class="ico" style="background:color-mix(in srgb,var(--a2) 16%,transparent);color:var(--a2)">
      <svg class="ic ic-lg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/></svg></div>
     <div><b id="sLive" style="color:var(--ok)">—</b><span data-t="liveDevices"></span></div></div>
    <div class="stat">
     <div class="ico" style="background:color-mix(in srgb,var(--info) 16%,transparent);color:var(--info)">
      <svg class="ic ic-lg" viewBox="0 0 24 24"><rect x="7" y="3" width="10" height="18" rx="2"/><path d="M11 18h2"/></svg></div>
     <div><b id="sDev" style="color:var(--info)">—</b><span data-t="devices"></span></div></div>
    <div class="stat">
     <div class="ico" style="background:color-mix(in srgb,var(--a1) 20%,transparent);color:var(--a2)">
      <svg class="ic ic-lg" viewBox="0 0 24 24"><path d="M4 16l5-6 4 4 7-8"/><path d="M4 20h16"/></svg></div>
     <div><b id="sBytes" style="color:var(--a2)">—</b><span data-t="traffic"></span></div></div>
    <div class="stat">
     <div class="ico" style="background:color-mix(in srgb,var(--a1) 20%,transparent);color:var(--a2)">
      <svg class="ic ic-lg" viewBox="0 0 24 24"><path d="M12 3.2c3.6 3.2 5.6 6 5.6 9a5.6 5.6 0 11-11.2 0c0-3 2-5.8 5.6-9z"/></svg></div>
     <div><b id="sCip" style="color:var(--a1)">—</b><span data-t="cleanIps"></span></div></div>
    <div class="stat">
     <div class="ico" style="background:color-mix(in srgb,var(--warn) 16%,transparent);color:var(--warn)">
      <svg class="ic ic-lg" viewBox="0 0 24 24"><path d="M13 3L5 14h5l-1 7 8-11h-5z"/></svg></div>
     <div><b id="sXs">—</b><span data-t="xSessions"></span></div></div>
   </div>

   <div class="card p-4 mt-4">
    <b class="text-base" data-t="chart24"></b>
    <div class="mt-3"><canvas id="chart" height="88"></canvas></div>
   </div>

   <div class="card p-4 mt-4">
    <b class="text-base" data-t="protoSplit"></b>
    <div id="protoBox" class="flex flex-wrap gap-2 mt-3 text-sm"></div>
   </div>
  </section>

  <!-- ══ USERS ══ -->
  <section data-pg="users" class="hidden">
   <div class="card p-4">
    <b class="text-base" data-t="newUser"></b>
    <div class="g3 mt-3">
     <label class="fld"><span class="text-xs dim" data-t="name"></span><input id="nName" class="inp"></label>
     <label class="fld"><span class="text-xs dim" data-t="quota"></span><input id="nQuota" type="number" step="0.5" value="30" class="inp"></label>
     <label class="fld"><span class="text-xs dim" data-t="days"></span><input id="nDays" type="number" value="30" class="inp"></label>
     <label class="fld"><span class="text-xs dim" data-t="resetCycle"></span>
      <select id="nReset" class="inp"><option value="0"></option><option value="1"></option><option value="3"></option><option value="7"></option><option value="14"></option><option value="30"></option><option value="60"></option><option value="90"></option><option value="-1"></option></select></label>
     <label class="fld hidden" id="nResetWrap"><span class="text-xs dim" data-t="customDays"></span>
      <input id="nResetCustom" type="number" min="1" max="365" class="inp"></label>
     <label class="fld"><span class="text-xs dim" data-t="devLimit"></span><input id="nDev" type="number" value="1" class="inp"></label>
     <label class="fld"><span class="text-xs dim" data-t="ipLimit"></span><input id="nIp" type="number" value="0" class="inp"></label>
     <label class="fld"><span class="text-xs dim" data-t="transport"></span>
      <select id="nTr" class="inp"><option value="both"></option><option value="ws"></option><option value="xhttp"></option></select></label>
    </div>
    <div class="flex flex-wrap items-center gap-3 mt-3 text-sm">
     <label class="flex items-center gap-2"><input id="nObf" type="checkbox"><span data-t="obfLbl"></span></label>
     <label class="flex items-center gap-2"><input id="nEch" type="checkbox"><span data-t="echLbl"></span></label>
     <label class="flex items-center gap-2"><span class="dim" data-t="fpLbl"></span>
      <select id="nFp" class="inp" style="width:auto;padding:6px 9px;font-size:12px"></select></label>
     <label class="flex items-center gap-2"><span class="dim" data-t="alpnLbl"></span>
      <select id="nAlpn" class="inp" style="width:auto;padding:6px 9px;font-size:12px"></select></label>
    </div>
    <details class="mt-3">
     <summary class="text-xs dim" style="cursor:pointer" data-t="custLbl"></summary>
     <div class="mt-3">
      <label class="fld"><span class="text-xs dim" data-t="echValueLbl"></span>
       <input id="nEchVal" class="inp mono" style="font-size:11px" placeholder="cloudflare-ech.com+udp://1.1.1.1"></label>
      <div class="g2 mt-2">
       <label class="fld"><span class="text-xs dim" data-t="obfCsLbl"></span>
        <input id="nObfCs" class="inp mono" style="font-size:11px"></label>
       <label class="fld"><span class="text-xs dim" data-t="obfFmLbl"></span>
        <textarea id="nObfFm" rows="3" spellcheck="false" class="inp mono" style="font-size:11px"></textarea></label>
      </div>
      <p class="text-xs mt-2" style="color:var(--warn,#e0a80d);margin:0" data-t="custHint"></p>
     </div>
    </details>
    <div class="flex flex-wrap items-center gap-3 mt-3">
     <button onclick="createUser()" id="btnAdd" class="btn"></button>
     <span class="text-xs dim" data-t="zeroInf"></span>
    </div>
    <p id="cErr" class="text-sm mt-2" style="color:var(--bad);margin-bottom:0"></p>
   </div>

   <div class="card mt-4" style="overflow:hidden">
    <div class="card-head">
     <b class="text-base" data-t="users"></b>
     <input id="q" oninput="renderUsers()" class="inp ms-auto" style="width:190px;padding:7px 11px">
    </div>
    <div id="rows"></div>
   </div>
  </section>

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

  <!-- ══ SETTINGS ══ -->
  <section data-pg="settings" class="hidden">
   <div class="card p-4">
    <b class="text-base" data-t="appearance"></b>
    <div class="g3 mt-3">
     <label class="fld"><span class="text-xs dim" data-t="theme"></span>
      <select id="thSel2" onchange="setTheme(this.value);syncSelects()" class="inp">
       <option value="dark" data-t="thDark"></option><option value="light" data-t="thLight"></option>
       <option value="gray" data-t="thGray"></option></select></label>
     <label class="fld"><span class="text-xs dim" data-t="language"></span>
      <select id="langSel2" onchange="setLang(this.value);syncSelects()" class="inp">
       <option value="fa">🇮🇷 فارسی</option><option value="en">🇬🇧 English</option></select></label>
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
       onchange="pickBackup()" class="inp" style="font-size:12px">
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

<script>
const esc=(s)=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const ICO={
 cfg:'<svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3.5 12h17"/><path d="M12 3c2.5 2.4 3.8 5.4 3.8 9s-1.3 6.6-3.8 9c-2.5-2.4-3.8-5.4-3.8-9S9.5 5.4 12 3z"/></svg>',
 ips:'<svg class="ic" viewBox="0 0 24 24"><rect x="3" y="4.5" width="18" height="12" rx="2"/><path d="M8 20h8M12 16.5V20"/></svg>',
 edit:'<svg class="ic" viewBox="0 0 24 24"><path d="M4 20h4L19 9l-4-4L4 16v4z"/><path d="M14 6l4 4"/></svg>',
 del:'<svg class="ic" viewBox="0 0 24 24"><path d="M5 7h14M9.5 7V5h5v2M7 7l1 13h8l1-13"/></svg>',
 pause:'<svg class="ic" viewBox="0 0 24 24" style="width:15px;height:15px"><path d="M9.5 5v14M14.5 5v14"/></svg>',
 play:'<svg class="ic" viewBox="0 0 24 24" style="width:15px;height:15px"><path d="M7.5 5.2l11 6.8-11 6.8z"/></svg>',
 x:'<svg class="ic" viewBox="0 0 24 24" style="width:15px;height:15px"><path d="M6 6l12 12M18 6L6 18"/></svg>',
 ping:'<svg class="ic" viewBox="0 0 24 24" style="width:15px;height:15px"><path d="M3 12h4l2.5-6 4 12 2.5-6h5"/></svg>',
 copy:'<svg class="ic" viewBox="0 0 24 24" style="width:15px;height:15px"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 012-2h9"/></svg>',
 key:'<svg class="ic" viewBox="0 0 24 24" style="width:14px;height:14px"><circle cx="8" cy="15" r="3.5"/><path d="M10.5 13L19 4.5M16 7.5l2 2M13.5 10l2 2"/></svg>'
};

/* ─── responsive shell: rail on desktop, drawer on mobile ─── */
const isDesktop=()=>window.matchMedia('(min-width:1024px)').matches;
let navMini=localStorage.getItem('navMini')==='1';
let navOpen=false;
function applyNav(){
 document.body.classList.toggle('nav-mini',isDesktop()&&navMini);
 document.body.classList.toggle('nav-open',!isDesktop()&&navOpen);
 scrim.classList.toggle('hidden',isDesktop()||!navOpen);
}
function toggleNav(force){
 if(isDesktop()){
  navMini = force===undefined ? !navMini : !!force;
  localStorage.setItem('navMini',navMini?'1':'0');
 }else{
  navOpen = force===undefined ? !navOpen : !!force;
 }
 applyNav();
}
function closeDrawer(){ if(!isDesktop()){navOpen=false;applyNav()} }
window.addEventListener('resize',applyNav);

/* ─── country flags + helpers ─── */
var CC=['DE','NL','FR','GB','FI','SE','PL','AT','CH','ES','IT','RO','TR','RU','AE','QA','OM',
        'AM','GE','IN','SG','JP','KR','HK','CA','US','BR','AU','DK','NO','BE','CZ','HU','LT',
        'LV','EE','IE','UA','KZ','IR'];
function flagOf(c){
 return String(c||'').toUpperCase().replace(/[^A-Z]/g,'').slice(0,2)
   .replace(/./g,ch=>String.fromCodePoint(0x1F1E6+ch.charCodeAt(0)-65));
}
function fillCountry(sel,cur){
 if(!sel)return;
 sel.innerHTML='<option value="">'+T('autoCountry')+'</option>'+
  CC.map(c=>'<option value="'+c+'">'+flagOf(c)+' '+c+'</option>').join('');
 sel.value=cur||'';
}
var MAIN_CC='';
var PROXIES=[],PX_SUB=[],PX_ACTIVE=0,PX_STRICT=true,PX_FLAG='proxy';

/* ─── routing ─── */
let PAGE=localStorage.getItem('page')||'dash';
function go(p){
 PAGE=p; localStorage.setItem('page',p);
 document.querySelectorAll('[data-pg]').forEach(s=>s.classList.toggle('hidden',s.dataset.pg!==p));
 document.querySelectorAll('.navi').forEach(n=>n.classList.toggle('on',n.dataset.page===p));
 crumb.textContent=T({dash:'navDash',users:'navUsers',clean:'navClean',filter:'navFilter',
   proxy:'navProxy',live:'navLive',settings:'navSettings',logs:'navLogs'}[p]);
 closeDrawer();
 if(p==='logs')loadLogs();
 if(p==='clean')loadCips();
 if(p==='filter')loadFilter();
 if(p==='settings'){renderServer();loadBackupInfo();loadTelegram()}
 if(p==='live')loadLive(); else stopLive();
}

/* ─── formatting helpers ─── */
const fmt=b=>{if(!b)return '0 B';const u=['B','KB','MB','GB','TB'];let i=0,n=b;
 while(n>=1024&&i<u.length-1){n/=1024;i++}return n.toFixed(i?1:0)+' '+u[i]};
const dt=t=>t?new Date(t*1000).toLocaleString(LANG==='fa'?'fa-IR':'en-GB'):T('never');
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
 const pairs=[['ws',T('trWs'),'var(--a1)'],['xhttp',T('trXhttp'),'var(--a2)']];
 protoBox.innerHTML=pairs.map(([k,lbl,col])=>`
  <div class="chip" style="font-size:12px;padding:7px 12px">
   <span style="width:8px;height:8px;border-radius:50%;background:${col}"></span>
   <span class="dim">${lbl}</span><b>${bp[k]||0}</b></div>`).join('');
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
 sCip.textContent=stats.clean_ips; sXs.textContent=stats.xhttp_sessions;
 pill.textContent='/'+stats.ws_path+' · /'+stats.xhttp_path;
 paintChart(); renderProto();
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
function renderUsers(){
 const term=(q.value||'').toLowerCase();
 rows.innerHTML=users.filter(u=>u.name.toLowerCase().includes(term)).map(u=>{
  const pct=u.quota_bytes?Math.min(100,u.used_bytes/u.quota_bytes*100):0;
  const badge=u.active
   ?`<span class="chip green">${T('active')}</span>`
   :`<span class="chip red">${statusTxt(u.status)}</span>`;
  const dev=u.device_limit?`${u.devices_now}/${u.device_limit}`:'∞';
  const liveTag=u.devices_live?`<span class="chip green">● ${u.devices_live}</span>`:'';
  const devWarn=u.device_limit&&u.devices_now>=u.device_limit;
  const ipN=u.ip_limit?`${u.ips_now}/${u.ip_limit}`:'∞';
  const ipWarn=u.ip_limit&&u.ips_now>=u.ip_limit;
  const ipTag=u.ips_live?`<span class="chip green">● ${u.ips_live}</span>`:'';
  return `<div class="urow">
   <div class="u-av">${esc((u.name||'?').slice(0,1).toUpperCase())}</div>
   <div class="u-main">
    <div class="flex items-center gap-2 flex-wrap">
     <b class="text-base">${esc(u.name)}</b>${badge}
     <span class="chip teal">${trTxt(u.transport)}</span>${liveTag}${ipTag}
    </div>
    <div class="progress mt-2${pct>=85?' hot':''}"><i style="width:${pct}%"></i></div>
    <div class="flex flex-wrap gap-3 text-xs dim mt-1">
     <span>${T('used')}: ${fmt(u.used_bytes)} / ${u.quota_bytes?fmt(u.quota_bytes):'♾️'}</span>
     <span>${T('expiry')}: ${dt(u.expire_at)}</span>
    </div>
   </div>
   <div class="u-dev">
    <div style="color:${devWarn?'var(--bad)':'var(--info)'}">📱 ${dev}</div>
    <div style="color:${ipWarn?'var(--bad)':'var(--info)'}">🌐 ${ipN}</div>
   </div>
   <div class="u-actions">
    <button class="icon-btn" title="${T('config')}" onclick="showConfig(${u.id})">${ICO.cfg}</button>
    <button class="icon-btn" title="${T('ipsBtn')}" onclick="showIps(${u.id})">${ICO.ips}</button>
    <button class="icon-btn" title="${T('edit')}" onclick="showEdit(${u.id})">${ICO.edit}</button>
   </div></div>`}).join('')
  ||`<div class="p-4 text-sm dim" style="text-align:center">${T('noUsers')}</div>`;
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
    <span>${x.flag||'🌐'}</span>
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
    <span class="ms-auto font-bold" style="color:var(--info)">${d.counted}${d.limit?' / '+d.limit:' / ∞'}</span></div>
   <div class="kv"><span class="dim">${T('totalSeen')}</span>
    <span class="ms-auto font-bold">${d.total_seen}</span></div>
  </div>
  <div class="space-y-2">${rows}</div>
  <b class="text-base">${T('ipSec')}</b>
  <div class="g2 text-sm">
   <div class="kv"><span class="dim">${T('ipCounted')}</span>
    <span class="ms-auto font-bold" style="color:var(--info)">${d.ip_counted}${d.ip_limit?' / '+d.ip_limit:' / ∞'}</span></div>
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
  html+=bkRow('🔐',p.has_password?T('bkHasPw'):T('bkNoPw'));
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

/* ─── boot ─── */
paintStatic(); syncSelects();
go(PAGE);
loadStats();loadUsers();loadCips();loadMainCountry();loadProxies();
setInterval(()=>{loadStats();if(PAGE==='users')loadUsers()},15000);
</script></body></html>"""

AUTH_HTML  = AUTH_HTML.replace("__THEME__", THEME_CSS).replace("__I18N__", I18N_JS)
PANEL_HTML = PANEL_HTML.replace("__THEME__", THEME_CSS).replace("__I18N__", I18N_JS)
