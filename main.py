"""
IranX Panel v3  —  VLESS over WebSocket+TLS  and  VLESS over XHTTP+TLS
----------------------------------------------------------------------
Single-file FastAPI panel.  Deploy on Railway / Render / any ASGI host.

The hosting platform terminates TLS, so clients speak:
    wss://<domain>/<WS_PATH>                    →  type=ws
    https://<domain>/<XHTTP_PATH>/<session>     →  type=xhttp  (packet-up mode)

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
import sqlite3
import ipaddress
from urllib.parse import quote
from contextlib import asynccontextmanager
from typing import Optional, Callable, Awaitable

import jwt
from fastapi import (FastAPI, Request, WebSocket, HTTPException, Depends,
                     Cookie, Body)
from fastapi.responses import (HTMLResponse, JSONResponse, PlainTextResponse,
                               RedirectResponse, StreamingResponse, Response)
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
LIVE_WINDOW    = int(os.getenv("LIVE_WINDOW", "60"))      # shown as "connected right now"
SESSION_IDLE   = int(os.getenv("SESSION_IDLE", "90"))     # xhttp session reaper

# Self-ping, for hosts that idle a service out (Render's free plan does after ~15 min).
# Read the caveats in the README before switching this on.
KEEPALIVE       = os.getenv("KEEPALIVE", "").strip().lower() in ("1", "true", "yes", "on")
KEEPALIVE_MINS  = max(1, int(os.getenv("KEEPALIVE_MINUTES", "10")))

JWT_ALG, JWT_TTL, GB = "HS256", 60 * 60 * 12, 1024 ** 3
TRANSPORTS = ("ws", "xhttp", "both")

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
    transport    TEXT    DEFAULT 'both',
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
CREATE INDEX IF NOT EXISTS idx_traf_user ON traffic_log(user_id, ts);
"""


def now() -> int:
    return int(time.time())


def migrate():
    """Add columns that older databases may be missing."""
    wanted = {"users": [("transport", "TEXT DEFAULT 'both'")],
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


def active_devices(uid: int, window: Optional[int] = None) -> int:
    """Distinct IPs seen inside a window. Defaults to the enforcement window."""
    w = DEVICE_WINDOW if window is None else window
    with db() as c:
        r = c.execute("SELECT COUNT(*) n FROM user_ips WHERE user_id=? AND last_seen>?",
                      (uid, now() - w)).fetchone()
    return r["n"] if r else 0


def live_devices(uid: int) -> int:
    return active_devices(uid, LIVE_WINDOW)


def touch_ip(uid: int, ip: str, proto: str):
    with db() as c:
        c.execute("""INSERT INTO user_ips(user_id,ip,proto,first_seen,last_seen,hits)
                     VALUES(?,?,?,?,?,1)
                     ON CONFLICT(user_id,ip) DO UPDATE
                     SET last_seen=excluded.last_seen, proto=excluded.proto, hits=hits+1""",
                  (uid, ip, proto, now(), now()))


def ip_allowed(uid: int, ip: str, limit: int) -> bool:
    if limit <= 0:
        return True
    with db() as c:
        known = c.execute("SELECT 1 FROM user_ips WHERE user_id=? AND ip=? AND last_seen>?",
                          (uid, ip, now() - DEVICE_WINDOW)).fetchone()
    return bool(known) or active_devices(uid) < limit


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
    """Every enabled proxy that passed its health check, fastest first.

    These are exactly the proxies a subscription lists, so a working proxy joins
    the user's config list on its own and a failing one drops out — no arming step.
    """
    with db() as c:
        return c.execute("""SELECT * FROM proxies WHERE enabled=1 AND healthy=1
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


async def dial_target(host: str, port: int, direct: bool = False,
                      pid: int | None = None):
    """The single outbound path for user traffic.

    The inbound path decides the exit: "-d" leaves from the host's own IP, "-p<id>"
    leaves through that one proxy, and the plain path follows the fastest healthy
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
    return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=12)


def mark_proxy_down(pid: int, err: str):
    with db() as c:
        c.execute("UPDATE proxies SET healthy=0, last_error=?, checked_at=? WHERE id=?",
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


def lookup_user(uid_str: str):
    with db() as c:
        return c.execute("SELECT * FROM users WHERE uuid=?", (uid_str,)).fetchone()


def authorize(uid_str: str, ip: str, proto: str):
    """Returns (row, None) on success or (None, reason)."""
    row = lookup_user(uid_str)
    if not row:
        return None, "unknown uuid"
    ok, reason = user_status(row)
    if not ok:
        return None, reason
    if not transport_allowed(row, proto):
        return None, f"{proto} not allowed"
    if not ip_allowed(row["id"], ip, row["device_limit"]):
        return None, "device limit"
    touch_ip(row["id"], ip, proto)
    return row, None


async def relay_session(stream: ByteStream,
                        send: Callable[[bytes], Awaitable[None]],
                        ip: str, proto: str, direct: bool = False,
                        pid: int | None = None) -> None:
    """Shared VLESS handling: authenticate, dial the target, pump both ways."""
    parsed = await parse_vless(stream)
    if not parsed:
        raise ValueError("bad vless header")
    uid_str, cmd, host, port = parsed

    row, reason = authorize(uid_str, ip, proto)
    if not row:
        audit("reject", ip, f"{proto}: {reason}")
        raise PermissionError(reason)

    if cmd != 1:
        raise ValueError("only TCP supported")
    if blocked(host) or port == 0:
        raise PermissionError("blocked destination")

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


# ══════════════════════════ XHTTP (packet-up) ══════════════════════════
#
#  Downlink :  GET  /<XHTTP_PATH>/<session>          → streamed response body
#  Uplink   :  POST /<XHTTP_PATH>/<session>/<seq>    → one ordered chunk
#
#  Chunks may arrive out of order, so each session keeps a reorder buffer.

class XSession:
    def __init__(self, sid: str, ip: str):
        self.sid = sid
        self.ip = ip
        self.stream = ByteStream()
        self.out: asyncio.Queue = asyncio.Queue()
        self.next_seq = 0
        self.hold: dict[int, bytes] = {}
        self.touched = time.time()
        self.worker: Optional[asyncio.Task] = None
        self.closed = False

    def touch(self):
        self.touched = time.time()

    async def send(self, data: bytes):
        await self.out.put(data)

    def push(self, seq: int, data: bytes):
        """Insert an uplink chunk, forwarding everything now contiguous."""
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


def get_session(sid: str, ip: str, direct: bool = False,
                pid: int | None = None) -> XSession:
    s = SESSIONS.get(sid)
    if s is None or s.closed:
        s = XSession(sid, ip)
        s.direct = direct
        s.pid = pid
        SESSIONS[sid] = s
        s.worker = asyncio.create_task(run_session(s))
    s.touch()
    return s


async def run_session(s: XSession):
    try:
        await relay_session(s.stream, s.send, s.ip, "xhttp",
                            getattr(s, "direct", False),
                            getattr(s, "pid", None))
    except Exception:
        pass
    finally:
        s.close()
        SESSIONS.pop(s.sid, None)


async def reaper():
    while True:
        await asyncio.sleep(20)
        cutoff = time.time() - SESSION_IDLE
        for sid, s in list(SESSIONS.items()):
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
    ]
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(title=PANEL_TITLE, docs_url=None, redoc_url=None, lifespan=lifespan)


# ── XHTTP downlink ──
@app.get("/" + XHTTP_PATH + "/{session}")
async def xhttp_down(session: str, request: Request):
    if not SID_RE.match(session):
        raise HTTPException(404)
    ip = client_ip(request)
    s = get_session(session, ip)

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
            s.close()

    return StreamingResponse(gen(), headers=NOBUF_HEADERS)


# ── XHTTP uplink ──
@app.post("/" + XHTTP_PATH + "/{session}/{seq}")
async def xhttp_up(session: str, seq: str, request: Request):
    if not SID_RE.match(session) or not seq.isdigit():
        raise HTTPException(404)
    ip = client_ip(request)
    s = get_session(session, ip)
    body = await request.body()
    if body:
        s.push(int(seq), body)
    return Response(status_code=200, headers=NOBUF_HEADERS)


# ── XHTTP, no-proxy variant ──
#  Same protocol on "<XHTTP_PATH>-d"; session keys are namespaced so a direct and a
#  proxied session can never collide.

@app.get("/" + XHTTP_PATH + "-d/{session}")
async def xhttp_down_direct(session: str, request: Request):
    if not SID_RE.match(session):
        raise HTTPException(404)
    s = get_session("d." + session, client_ip(request), True)

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
            s.close()

    return StreamingResponse(gen(), headers=NOBUF_HEADERS)


@app.post("/" + XHTTP_PATH + "-d/{session}/{seq}")
async def xhttp_up_direct(session: str, seq: str, request: Request):
    if not SID_RE.match(session) or not seq.isdigit():
        raise HTTPException(404)
    s = get_session("d." + session, client_ip(request), True)
    body = await request.body()
    if body:
        s.push(int(seq), body)
    return Response(status_code=200, headers=NOBUF_HEADERS)


# ── XHTTP, per-proxy variants ──
#  "<XHTTP_PATH>-p<id>" always leaves through proxy <id>. Session keys are namespaced
#  per route, so the same client id on two routes never shares a session.

@app.get("/" + XHTTP_PATH + "-p{pid}/{session}")
async def xhttp_down_proxy(pid: int, session: str, request: Request):
    if not SID_RE.match(session) or pid <= 0:
        raise HTTPException(404)
    s = get_session("p%d.%s" % (pid, session), client_ip(request), False, pid)

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
            s.close()

    return StreamingResponse(gen(), headers=NOBUF_HEADERS)


@app.post("/" + XHTTP_PATH + "-p{pid}/{session}/{seq}")
async def xhttp_up_proxy(pid: int, session: str, seq: str, request: Request):
    if not SID_RE.match(session) or not seq.isdigit() or pid <= 0:
        raise HTTPException(404)
    s = get_session("p%d.%s" % (pid, session), client_ip(request), False, pid)
    body = await request.body()
    if body:
        s.push(int(seq), body)
    return Response(status_code=200, headers=NOBUF_HEADERS)


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
    await websocket.accept()
    stream = WSStream(websocket)

    async def send(data: bytes):
        await websocket.send_bytes(data)

    try:
        await relay_session(stream, send, ip, "ws", direct, pid)
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
    return (f"vless://{row['uuid']}@{address}:443"
            f"?encryption=none&security=tls&sni={host}&fp=chrome&alpn=http%2F1.1"
            f"&type=ws&host={host}&path=%2F{path}"
            f"#{quote(label)}")


def xhttp_uri(row, address: str, host: str, label: str, direct: bool = False,
              pid: int | None = None) -> str:
    path = XHTTP_PATH + ("-d" if direct else ("-p%d" % pid if pid else ""))
    return (f"vless://{row['uuid']}@{address}:443"
            f"?encryption=none&security=tls&sni={host}&fp=chrome"
            f"&type=xhttp&host={host}&path=%2F{path}&mode=packet-up"
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


def build_configs(row, host: str, clean_ips) -> list[dict]:
    t = (row["transport"] or "both").lower()
    kinds = []
    if t in ("ws", "both"):
        kinds.append(("WS", ws_uri))
    if t in ("xhttp", "both"):
        kinds.append(("XHTTP", xhttp_uri))

    # Every route sits in the same subscription, side by side: first the host's own
    # exit (Render / Railway) flagged with the server country, then one route per
    # healthy proxy flagged with that proxy's exit country. A proxy shows up here as
    # soon as its health check passes — there is nothing to arm.
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
                title = f"{mark} {row['name']}{suffix}"
                out.append({"label": f"{mark} {row['name']}{suffix} \u00b7 Default",
                            "transport": tag,
                            "uri": fn(row, host, host, title, direct, pid)})
            for cip in clean_ips:
                note = cip["remark"] or cip["address"]
                cmark = (cip_flag(cip) or mark) if direct else mark
                out.append({"label": f"{cmark} {note}{suffix}",
                            "transport": tag,
                            "uri": fn(row, cip["address"], host,
                                      f"{cmark} {row['name']} \u00b7 {note}{suffix}",
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
    return [info_uri(info_label(row), host)]


def row_out(r) -> dict:
    d = dict(r)
    d["devices_now"] = active_devices(r["id"])
    d["devices_live"] = live_devices(r["id"])
    ok, reason = user_status(r)
    d["active"], d["status"] = ok, reason
    return d


# ────────────────────────────── MODELS ──────────────────────────────

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
    device_limit: int = 1
    transport: str = "both"
    note: str = ""
    enabled: bool = True


class UserPatch(BaseModel):
    name: Optional[str] = None
    quota_gb: Optional[float] = None
    expire_days: Optional[int] = None
    device_limit: Optional[int] = None
    transport: Optional[str] = None
    note: Optional[str] = None
    enabled: Optional[bool] = None
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
    try:
        with db() as c:
            cur = c.execute(
                """INSERT INTO users(name,uuid,sub_token,note,enabled,quota_bytes,
                                     used_bytes,expire_at,device_limit,transport,created_at)
                   VALUES(?,?,?,?,?,?,0,?,?,?,?)""",
                (name, str(uuid.uuid4()), secrets.token_urlsafe(16), body.note,
                 1 if body.enabled else 0, int(body.quota_gb * GB), expire,
                 max(0, body.device_limit), tr, now()))
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
        if body.device_limit is not None:
            sets.append("device_limit=?"); vals.append(max(0, body.device_limit))
        if body.transport is not None:
            tr = body.transport.lower()
            if tr not in TRANSPORTS:
                raise HTTPException(400, "transport must be ws, xhttp or both")
            sets.append("transport=?"); vals.append(tr)
        if body.note is not None:
            sets.append("note=?"); vals.append(body.note)
        if body.enabled is not None:
            sets.append("enabled=?"); vals.append(1 if body.enabled else 0)
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
        c.execute("UPDATE users SET used_bytes=0 WHERE id=?", (uid,))
    return {"ok": True}


@app.post("/api/users/{uid}/new-uuid")
async def rotate_uuid(uid: int, _=Depends(require_admin)):
    new = str(uuid.uuid4())
    with db() as c:
        c.execute("UPDATE users SET uuid=? WHERE id=?", (new, uid))
        c.execute("DELETE FROM user_ips WHERE user_id=?", (uid,))
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
    return {"ok": True}


@app.get("/api/users/{uid}/ips")
async def user_ips(uid: int, history: int = 0, _=Depends(require_admin)):
    """Live view by default: only IPs still connected. history=1 returns everything."""
    live_cut = now() - LIVE_WINDOW
    count_cut = now() - DEVICE_WINDOW
    with db() as c:
        if history:
            rows = c.execute("""SELECT ip,proto,first_seen,last_seen,hits FROM user_ips
                                WHERE user_id=? ORDER BY last_seen DESC LIMIT 200""",
                             (uid,)).fetchall()
        else:
            rows = c.execute("""SELECT ip,proto,first_seen,last_seen,hits FROM user_ips
                                WHERE user_id=? AND last_seen>?
                                ORDER BY last_seen DESC""", (uid, live_cut)).fetchall()
        total = c.execute("SELECT COUNT(*) n FROM user_ips WHERE user_id=?",
                          (uid,)).fetchone()["n"]
    return {
        "live": live_devices(uid),
        "counted": active_devices(uid),
        "total_seen": total,
        "live_window": LIVE_WINDOW,
        "device_window": DEVICE_WINDOW,
        "history": bool(history),
        "rows": [
            {**dict(r), "online": r["last_seen"] > live_cut,
             "counted": r["last_seen"] > count_cut}
            for r in rows
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


# ─────────────────────────────── STATS ──────────────────────────────

@app.get("/api/stats")
async def stats(_=Depends(require_admin)):
    with db() as c:
        tot = c.execute("SELECT COUNT(*) n, COALESCE(SUM(used_bytes),0) b FROM users").fetchone()
        act = c.execute("SELECT COUNT(*) n FROM users WHERE enabled=1").fetchone()
        onl = c.execute("SELECT COUNT(DISTINCT user_id) n FROM user_ips WHERE last_seen>?",
                        (now() - DEVICE_WINDOW,)).fetchone()
        dev = c.execute("SELECT COUNT(*) n FROM user_ips WHERE last_seen>?",
                        (now() - DEVICE_WINDOW,)).fetchone()
        liv = c.execute("SELECT COUNT(*) n FROM user_ips WHERE last_seen>?",
                        (now() - LIVE_WINDOW,)).fetchone()
        lu = c.execute("SELECT COUNT(DISTINCT user_id) n FROM user_ips WHERE last_seen>?",
                       (now() - LIVE_WINDOW,)).fetchone()
        cip = c.execute("SELECT COUNT(*) n FROM clean_ips WHERE enabled=1").fetchone()
        byp = c.execute("SELECT proto, COUNT(*) n FROM user_ips WHERE last_seen>? "
                        "GROUP BY proto", (now() - DEVICE_WINDOW,)).fetchall()
        series = c.execute("""SELECT ts/3600*3600 h, SUM(up) up, SUM(down) down
                              FROM traffic_log WHERE ts>? GROUP BY h ORDER BY h""",
                           (now() - 86400,)).fetchall()
    return {"users": tot["n"], "active_users": act["n"], "online_users": onl["n"],
            "live_users": lu["n"], "online_devices": dev["n"], "live_devices": liv["n"],
            "total_bytes": tot["b"], "clean_ips": cip["n"],
            "by_proto": {r["proto"]: r["n"] for r in byp},
            "xhttp_sessions": len(SESSIONS),
            "series": [dict(r) for r in series],
            "ws_path": WS_PATH, "xhttp_path": XHTTP_PATH,
            "device_window": DEVICE_WINDOW, "live_window": LIVE_WINDOW,
            "keepalive": KEEPALIVE, "keepalive_mins": KEEPALIVE_MINS,
            "relay_domain": RELAY_DOMAIN}


@app.get("/api/logs")
async def logs(_=Depends(require_admin)):
    with db() as c:
        rows = c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 80").fetchall()
    return [dict(r) for r in rows]


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

Features: Vazirmatn Persian webfont, dark (black/white) + light (white/blue)
themes, and a Persian/English language switch. No new Python dependencies
(QR codes come from `subpage_qr.py`).
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
    panel_url: str = "",
    update_interval: int = 12,
) -> str:
    """Return the full HTML page for one subscription token."""
    now = int(time.time())
    quota_bytes = int(quota_bytes or 0)
    used_bytes = int(used_bytes or 0)
    expire_at = int(expire_at or 0)

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
        "updateInterval": int(update_interval or 12),
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
:root{--bg:#000;--surface:#0b0b0c;--raised:#16161a;--line:rgba(255,255,255,.14);
--tx:#fff;--tx2:rgba(255,255,255,.62);--accent:#fff;--accent-tx:#000;
--ok:#4ade80;--warn:#fbbf24;--bad:#f87171;--ring:rgba(255,255,255,.22)}
html[data-theme=light]{--bg:#f4f8ff;--surface:#fff;--raised:#eaf1fd;--line:#d5e2f6;
--tx:#0b1c38;--tx2:#516b8f;--accent:#1d4ed8;--accent-tx:#fff;
--ok:#15803d;--warn:#b45309;--bad:#b91c1c;--ring:rgba(29,78,216,.25)}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--tx);min-height:100vh;padding:22px 16px 48px;
font:16px/1.55 Vazirmatn,"Vazirmatn Variable",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Noto Sans Arabic",Tahoma,sans-serif}
.wrap{max-width:960px;margin:0 auto}
.top{display:flex;align-items:center;gap:10px;margin-bottom:22px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:9px;font-weight:650}
.dot{width:9px;height:9px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 4px rgba(74,222,128,.16)}
.dot.off{background:var(--bad);box-shadow:0 0 0 4px rgba(248,113,113,.16)}
.spacer{flex:1}
.chip{border:1px solid var(--line);background:var(--surface);color:var(--tx);border-radius:99px;
min-height:38px;padding:0 13px;font:inherit;font-size:13px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:6px}
.chip:hover{background:var(--raised)}
.chip:focus-visible{outline:2px solid var(--ring);outline-offset:2px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:20px}
.hero{display:grid;grid-template-columns:1.4fr .6fr;gap:16px;align-items:stretch}
@media(max-width:780px){.hero{grid-template-columns:1fr}}
h1{margin:0 0 2px;font-size:23px;letter-spacing:-.2px}
.sub{margin:0 0 18px;color:var(--tx2);font-size:13.5px}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:16px}
@media(max-width:520px){.stats{grid-template-columns:1fr 1fr}}
.stat{background:var(--raised);border-radius:12px;padding:12px 14px}
.stat b{display:block;font-size:19px;font-weight:650;letter-spacing:-.2px}
.stat span{color:var(--tx2);font-size:12.5px}
.bar{height:9px;border-radius:99px;background:var(--raised);overflow:hidden}
.bar>i{display:block;height:100%;border-radius:99px;background:var(--accent)}
.bar.hot>i{background:var(--bad)}
.meta{display:flex;justify-content:space-between;color:var(--tx2);font-size:12.5px;margin-top:8px}
.qrbox{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;text-align:center}
.qrsvg{width:186px;height:186px;background:#fff;border-radius:10px;padding:7px;display:block}
.qrsvg.sm{width:158px;height:158px}
.hint{margin:0;color:var(--tx2);font-size:12.5px}
.row{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px}
.btn{border:0;border-radius:10px;background:var(--accent);color:var(--accent-tx);font:inherit;font-size:14px;font-weight:600;
min-height:44px;padding:0 16px;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:8px;text-decoration:none}
.btn.alt{background:var(--raised);color:var(--tx);border:1px solid var(--line)}
.btn:active{transform:translateY(1px)}
.btn:focus-visible{outline:2px solid var(--ring);outline-offset:2px}
.btn img{width:19px;height:19px;border-radius:5px;object-fit:cover}
h2{font-size:17px;margin:32px 0 12px}
.cfg{display:flex;align-items:center;gap:10px;padding:11px 14px;border:1px solid var(--line);
border-radius:12px;background:var(--surface);margin-bottom:8px;flex-wrap:wrap}
.cfg .nm{flex:1 1 120px;min-width:0;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
@media(max-width:430px){.cfg .nm{flex:1 1 100%}}
.tag{font-size:11px;font-weight:700;padding:4px 9px;border-radius:99px;background:var(--raised);color:var(--tx2)}
.tag.x{color:var(--warn)}
.ico{width:44px;height:44px;border-radius:10px;border:1px solid var(--line);background:transparent;color:var(--tx);cursor:pointer;font-size:14px}
.ico:hover{background:var(--raised)}
.cfgqr{width:100%;display:flex;justify-content:center;padding:14px 0 4px}
.cfgqr[hidden]{display:none}
.ico svg{width:18px;height:18px;display:block;margin:auto;stroke:currentColor;fill:none;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.tab{border:1px solid var(--line);background:transparent;color:var(--tx2);border-radius:99px;
min-height:40px;padding:0 16px;font:inherit;font-size:13.5px;cursor:pointer}
.tab[aria-selected=true]{background:var(--accent);border-color:transparent;color:var(--accent-tx);font-weight:600}
.apps{display:grid;grid-template-columns:repeat(auto-fill,minmax(244px,1fr));gap:12px}
.app{border:1px solid var(--line);border-radius:12px;background:var(--surface);padding:16px}
.app .head{display:flex;align-items:center;gap:11px;margin-bottom:12px}
.logo,.mark{width:44px;height:44px;border-radius:11px;display:block;flex:none}
.logo{object-fit:contain;background:var(--raised);padding:3px}
.mark{display:grid;place-items:center;color:#fff;font-weight:800;font-size:16px}
.app .nm{font-weight:650;font-size:15px}
.app .rp{color:var(--tx2);font-size:11.5px;word-break:break-all}
.add{width:100%;margin-bottom:9px;min-height:40px;font-size:13.5px}
.dl{display:flex;flex-direction:column;gap:6px}
.dl a{display:flex;align-items:center;justify-content:space-between;gap:8px;min-height:40px;padding:0 12px;
border:1px solid var(--line);border-radius:10px;color:var(--tx);text-decoration:none;font-size:13.5px}
.dl a:hover{background:var(--raised)}
.dl a .sz{color:var(--tx2);font-size:11.5px}
.banner{display:flex;gap:10px;align-items:center;border:1px solid var(--bad);
color:var(--bad);border-radius:12px;padding:12px 14px;font-size:13.5px;margin-bottom:16px}
footer{margin-top:36px;text-align:center;color:var(--tx2);font-size:12px}
.toast{position:fixed;inset-inline:0;bottom:22px;margin:auto;width:max-content;max-width:90vw;background:var(--tx);
color:var(--bg);font-weight:650;font-size:14px;padding:11px 18px;border-radius:99px;opacity:0;transform:translateY(8px);
transition:.2s;pointer-events:none;text-align:center}
.toast.on{opacity:1;transform:none}
@media(prefers-reduced-motion:reduce){*{transition:none!important}}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div class="brand"><span class="dot" id="dot"></span><span id="bTitle">IranX</span></div>
    <span class="spacer"></span>
    <span class="tag" id="trTag">—</span>
    <button class="chip" id="themeBtn" type="button"></button>
    <button class="chip" id="langBtn" type="button"></button>
  </div>

  <div id="banner"></div>

  <section class="hero">
    <div class="card">
      <h1 id="uname">—</h1>
      <p class="sub" id="usub">—</p>
      <div class="stats">
        <div class="stat"><b id="sRemain">—</b><span id="lRemain"></span></div>
        <div class="stat"><b id="sDays">—</b><span id="lDays"></span></div>
        <div class="stat"><b id="sDev">—</b><span id="lDev"></span></div>
      </div>
      <div class="bar" id="bar"><i style="width:0%"></i></div>
      <div class="meta"><span id="mUsed">—</span><span id="mQuota">—</span></div>
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

  <footer><span id="fNote"></span> · <span id="upd"></span></footer>
</div>
<div class="toast" id="toast"></div>
<script>
const D = __DATA__, QRS = __QRS__;
const $ = (s)=>document.querySelector(s);
const esc = (s)=>String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

/* ── i18n ── */
const T = {
  fa:{brand:"IranX · اشتراک من", remainVol:"حجم باقی‌مانده", remainTime:"زمان باقی‌مانده",
    devices:"دستگاه مجاز", used:"مصرف‌شده", total:"کل", copySub:"کپی لینک اشتراک",
    copyAll:"کپی همه کانفیگ‌ها", addTo:"افزودن به", configs:"کانفیگ‌ها", downloads:"دانلود برنامه‌ها",
    noConfigs:"کانفیگ فعالی وجود ندارد.", showQr:"نمایش QR", copyCfg:"کپی کانفیگ",
    scanHint:"با دوربین برنامه اسکن کنید<br>تا اشتراک خودکار اضافه شود",
    footer:"لینک اشتراک شخصی شماست — آن را با کسی به اشتراک نگذارید",
    updEvery:(h)=>"به‌روزرسانی هر "+h+" ساعت", expires:"انقضا", noExpiry:"بدون انقضا",
    unlimited:"بی‌نهایت", inactive:"این اشتراک فعال نیست", support:"با پشتیبانی تماس بگیرید",
    days:"روز", hours:"ساعت", cfgCount:(n)=>n+" کانفیگ فعال", copiedSub:"لینک اشتراک کپی شد ✓",
    copiedAll:"همه کانفیگ‌ها کپی شد ✓", copiedCfg:"کانفیگ کپی شد ✓", noQr:"QR در دسترس نیست",
    importHint:"اگر برنامه باز نشد: لینک کپی شده — در برنامه گزینهٔ Add from clipboard را بزنید",
    allVersions:"همه نسخه‌ها", theme:"تم", light:"روشن", dark:"تیره", subName:"اشتراک"},
  en:{brand:"IranX · My subscription", remainVol:"Remaining data", remainTime:"Remaining time",
    devices:"Devices", used:"Used", total:"Total", copySub:"Copy subscription link",
    copyAll:"Copy all configs", addTo:"Add to", configs:"Configs", downloads:"Download apps",
    noConfigs:"No active config.", showQr:"Show QR", copyCfg:"Copy config",
    scanHint:"Scan with your client app<br>to add the subscription",
    footer:"This is your personal subscription link — do not share it",
    updEvery:(h)=>"Updates every "+h+"h", expires:"Expires", noExpiry:"No expiry",
    unlimited:"Unlimited", inactive:"This subscription is not active", support:"please contact support",
    days:"days", hours:"hours", cfgCount:(n)=>n+" active configs", copiedSub:"Subscription link copied ✓",
    copiedAll:"All configs copied ✓", copiedCfg:"Config copied ✓", noQr:"QR unavailable",
    importHint:"If the app did not open: the link is copied — use “Add from clipboard” inside the app",
    allVersions:"All versions", theme:"Theme", light:"Light", dark:"Dark", subName:"Subscription"}
};
let LANG = "fa", THEME = "dark", current = D.osTabs[0][0];
try{ LANG = localStorage.getItem("iranx_lang") || LANG; THEME = localStorage.getItem("iranx_theme") || THEME; }catch(e){}
if(LANG!=="en") LANG="fa"; if(THEME!=="light") THEME="dark";
const t = (k)=>T[LANG][k];
const num = (n)=>Number(n).toLocaleString(LANG==="fa"?"fa-IR":"en-US");

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
  const s = D.subLink, e = encodeURIComponent(s), n = encodeURIComponent(D.name || "IranX");
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
  await copy(D.subLink, "");
  const url = deepLink(kind);
  if(!url){ toast(t("copiedSub")); return; }
  const a = document.createElement("a");
  a.href = url; a.rel = "noopener"; a.style.display = "none";
  document.body.appendChild(a);
  try{ a.click(); }catch(e){ try{ location.href = url; }catch(_){} }
  a.remove();
  setTimeout(()=>toast(t("importHint")), 1200);
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
    <span class="tag ${c.transport==="XHTTP"?"x":""}">${esc(c.transport)}</span>
    <button class="ico" data-qr="${i}" title="${esc(t("showQr"))}" aria-label="${esc(t("showQr"))}">${ICON_QR}</button>
    <button class="ico" data-copy="${i}" title="${esc(t("copyCfg"))}" aria-label="${esc(t("copyCfg"))}">${ICON_COPY}</button>
    <div class="cfgqr" data-box="${i}" hidden></div>
  </div>`).join("") : `<div class="card"><p class="hint" style="margin:0">${esc(t("noConfigs"))}</p></div>`;
}

function render(){
  const h = document.documentElement;
  h.lang = LANG; h.dir = LANG==="fa" ? "rtl" : "ltr"; h.dataset.theme = THEME;
  $("#bTitle").textContent = t("brand");
  $("#themeBtn").textContent = (THEME==="dark" ? "☀️ " : "🌙 ") + (THEME==="dark" ? t("light") : t("dark"));
  $("#langBtn").textContent = LANG==="fa" ? "🌐 English" : "🌐 فارسی";
  $("#uname").textContent = D.name || t("subName");
  $("#trTag").textContent = D.transport === "BOTH" ? "WS + XHTTP" : D.transport;
  $("#lRemain").textContent = t("remainVol");
  $("#lDays").textContent = t("remainTime");
  $("#lDev").textContent = t("devices");
  $("#sRemain").textContent = D.quota ? D.remainText : t("unlimited");
  $("#sDays").textContent = D.expireAt
    ? (D.remainDays > 0 ? num(D.remainDays)+" "+t("days") : num(D.remainHours)+" "+t("hours"))
    : t("unlimited");
  $("#sDev").textContent = D.deviceLimit ? num(D.devicesNow)+" / "+num(D.deviceLimit) : t("unlimited");
  $("#mUsed").textContent = t("used")+": "+D.usedText;
  $("#mQuota").textContent = t("total")+": "+D.quotaText;
  $("#bar").firstElementChild.style.width = (D.quota ? D.pct : 0) + "%";
  $("#bar").classList.toggle("hot", D.pct >= 85 && !!D.quota);
  const exp = D.expireAt ? new Date(D.expireAt*1000).toLocaleDateString(LANG==="fa"?"fa-IR":"en-GB") : t("noExpiry");
  $("#usub").textContent = t("expires")+": "+exp+" · "+t("cfgCount")(num(D.configs.length));
  $("#copySub").textContent = t("copySub");
  $("#copyAll").textContent = t("copyAll");
  $("#impHid").textContent = t("addTo")+" Hiddify";
  $("#impV2").textContent  = t("addTo")+" v2rayNG";
  $("#qrHint").innerHTML = t("scanHint");
  $("#hCfg").textContent = t("configs");
  $("#hApps").textContent = t("downloads");
  $("#fNote").textContent = t("footer");
  $("#upd").textContent = t("updEvery")(num(D.updateInterval));
  $("#qrMain").innerHTML = QRS[0] || `<p class="hint">${esc(t("noQr"))}</p>`;
  $("#dot").classList.toggle("off", !D.active);
  $("#banner").innerHTML = D.active ? "" :
    `<div class="banner">⚠️ ${esc(t("inactive"))}${D.status?" ("+esc(D.status)+")":""} — ${esc(t("support"))}.</div>`;
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

    d = base_domain(request)
    lines = build_info_lines(row, d)
    if user_status(row)[0]:
        lines += [c["uri"] for c in build_configs(row, d, ips)]

    # browser? serve the subscription page, clients keep the base64 payload
    ua = (request.headers.get("user-agent") or "").lower()
    accept = request.headers.get("accept") or ""
    force_page = request.query_params.get("page") in ("1", "true")
    force_raw = request.query_params.get("raw") in ("1", "true")
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
            panel_url=("https" + "://") + origin_domain(request) + "/",
        ))

    body = base64.b64encode("\n".join(lines).encode()).decode()
    headers = {
        "profile-title": "base64:" + base64.b64encode(f"⚡ {row['name']}".encode()).decode(),
        "profile-update-interval": "12",
        "profile-web-page-url": f"https://{origin_domain(request)}/",
        "subscription-userinfo":
            f"upload=0; download={row['used_bytes']}; "
            f"total={row['quota_bytes']}; expire={row['expire_at']}",
        "content-type": "text/plain; charset=utf-8",
    }
    return PlainTextResponse(body, headers=headers)


# ────────────────────────────── PAGES ──────────────────────────────

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
html,body{overflow-x:hidden;max-width:100%}
/* three themes only: black+blue, white+blue, grey. Buttons are black on white text. */
:root,[data-theme="dark"]{--bg:#000000;--panel:#07090f;--card:#0b0f17;--line:#1b2537;
      --txt:#f2f6fc;--dim:#8fa3c0;--a1:#1d4ed8;--a2:#3b82f6;--ok:#34d399;--bad:#fb7185;--info:#38bdf8;
      --btn:#000000;--btn-tx:#ffffff;--btn-line:#2f4570;--ring:#1d4ed855}
[data-theme="light"]{--bg:#f3f7ff;--panel:#ffffff;--card:#ffffff;--line:#d3e0f5;
      --txt:#0b1c38;--dim:#5b7a9c;--a1:#1d4ed8;--a2:#3b82f6;--ok:#15803d;--bad:#b91c1c;--info:#0369a1;
      --btn:#0b0f17;--btn-tx:#ffffff;--btn-line:#0b0f17;--ring:#1d4ed833}
[data-theme="gray"]{--bg:#1a1d21;--panel:#22262b;--card:#282d33;--line:#3a424c;
      --txt:#eef1f5;--dim:#a7b0bc;--a1:#3f6fd1;--a2:#5b8ae6;--ok:#4ade80;--bad:#f87171;--info:#60a5fa;
      --btn:#0d0f12;--btn-tx:#ffffff;--btn-line:#0d0f12;--ring:#3f6fd155}
body{background:var(--bg);color:var(--txt)}
.card{background:var(--card);border:1px solid var(--line)}
.grad{background-image:linear-gradient(to right,var(--a1),var(--a2))}
/* every action button: solid black, white text */
button.grad,a.grad.btn,.btn-solid{background-image:none;background:var(--btn);color:var(--btn-tx);
  border:1px solid var(--btn-line)}
button.grad:hover,.btn-solid:hover{filter:brightness(1.25)}
button.grad:focus-visible,.btn-solid:focus-visible{outline:2px solid var(--ring);outline-offset:2px}
.ic{width:18px;height:18px;flex:none;stroke:currentColor;fill:none;stroke-width:1.7;
    stroke-linecap:round;stroke-linejoin:round}
.ic-lg{width:22px;height:22px}
.icbox{display:grid;place-items:center}
.dim{color:var(--dim)}
.inp{background:color-mix(in srgb,var(--bg) 65%,#8881);border:1px solid var(--line);color:var(--txt)}
.inp:focus{border-color:var(--a1);outline:none}
.soft{background:color-mix(in srgb,var(--txt) 8%,transparent)}
.sw{width:44px;height:24px;background:var(--line);position:relative;transition:.18s;flex:none}
.sw:after{content:"";position:absolute;top:3px;inset-inline-start:3px;width:18px;height:18px;
  border-radius:50%;background:var(--txt);transition:.18s}
.sw.on{background:var(--a1)}
.sw.on:after{inset-inline-start:23px;background:#fff}
.navi{display:flex;align-items:center;gap:.6rem;padding:.7rem .9rem;border-radius:.85rem;
      font-size:.85rem;cursor:pointer;transition:.15s}
.navi:hover{background:color-mix(in srgb,var(--txt) 7%,transparent)}
.navi.on{background:var(--btn);color:var(--btn-tx);font-weight:700;border:1px solid var(--btn-line)}
.navi.on .ic{stroke:var(--btn-tx)}
.sheet{background:var(--panel)}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-thumb{background:var(--line);border-radius:8px}
.mono{font-family:ui-monospace,Menlo,monospace;direction:ltr}
"""

I18N_JS = r"""
const I18N={
 fa:{dir:'rtl',
  setupTitle:'تعیین رمز عبور',setupSub:'اولین ورود — یک رمز برای پنل انتخاب کنید',
  loginTitle:'ورود به پنل',loginSub:'رمز عبور خود را وارد کنید',
  password:'رمز عبور',confirm:'تکرار رمز عبور',enter:'ورود',save:'ذخیره و ورود',
  pwRule:'حداقل ۸ کاراکتر شامل حرف بزرگ، حرف کوچک و عدد',netErr:'خطای شبکه',
  navDash:'داشبورد',navUsers:'مدیریت کاربران',navClean:'Clean IP',
  navProxy:'پروکسی',
  navSettings:'تنظیمات پنل',navLogs:'رخدادها',menu:'منو',
  totalUsers:'کل کاربران',online:'کاربران آنلاین',devices:'دستگاه‌های متصل',
  traffic:'مصرف کل',cleanIps:'آی‌پی تمیز',xSessions:'سشن‌های XHTTP',
  chart24:'مصرف ۲۴ ساعت اخیر',protoSplit:'تقسیم بر اساس ترنسپورت',
  newUser:'ساخت کاربر جدید',users:'کاربران',
  name:'نام (انگلیسی)',quota:'حجم (GB)',days:'مدت (روز)',devLimit:'تعداد دستگاه',
  transport:'ترنسپورت',trWs:'🔌 WS + TLS',trXhttp:'🚀 XHTTP + TLS',trBoth:'🔀 هر دو',
  add:'افزودن',zeroInf:'۰ = بی‌نهایت. «تعداد دستگاه» بر اساس IP یکتای فعال محاسبه می‌شود.',
  search:'جستجو…',noUsers:'کاربری نیست',
  config:'کانفیگ',ipsBtn:'IP ها',edit:'ویرایش',
  used:'مصرف',expiry:'انقضا',never:'بی‌نهایت',
  subLink:'لینک اشتراک (Subscription)',copySub:'کپی لینک اشتراک',
  singleCfg:'کانفیگ‌های تکی',copy:'کپی',copied:'کپی شد ✓',
  devTitle:'دستگاه‌های متصل',noConn:'هنوز اتصالی ثبت نشده',
  clearIps:'پاک کردن لیست IP',
  liveNow:'الان متصل',noneNow:'همین الان هیچ دستگاهی متصل نیست',
  countedFor:'شمرده‌شده برای محدودیت',totalSeen:'کل IP های دیده‌شده',
  showHistory:'نمایش تاریخچه',showLive:'نمایش فقط متصل‌ها',
  inLast:'در %s ثانیه اخیر',refresh:'به‌روزرسانی',
  liveDevices:'دستگاه‌های فعال الان',
  editUser:'ویرایش',remainDays:'مدت باقی‌مانده (روز)',allowedDev:'تعداد دستگاه مجاز',
  active:'فعال',saveBtn:'ذخیره',resetTraffic:'ریست حجم',newUuid:'UUID جدید',
  customUuid:'UUID دستی',del:'حذف',
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
  pxAutoNote:'هر پروکسی که تستش سالم باشد خودبه‌خود در ساب همه کاربران می‌آید — همه با هم، بدون دکمه. کانفیگ بدون پروکسی همیشه سر جایش هست؛ پروکسی خراب خودبه‌خود حذف می‌شود.',
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
  relayLbl:'دامنه رله',keepAliveLbl:'جلوگیری از خواب',relayNone:'ندارد',
  onLbl:'فعال',offLbl:'خاموش',
  devWinLbl:'پنجره شمارش دستگاه',seconds:'ثانیه',
  envNote:'این مقادیر از متغیرهای محیطی خوانده می‌شوند و در Railway قابل تغییرند.',
  logout:'خروج',logs:'رخدادها',noLogs:'رخدادی نیست',
  statusDisabled:'غیرفعال',statusExpired:'منقضی',statusQuota:'حجم تمام',
 },
 en:{dir:'ltr',
  setupTitle:'Set a password',setupSub:'First run — choose your panel password',
  loginTitle:'Sign in',loginSub:'Enter your password',
  password:'Password',confirm:'Confirm password',enter:'Sign in',save:'Save & enter',
  pwRule:'At least 8 chars with upper case, lower case and a digit',netErr:'Network error',
  navDash:'Dashboard',navUsers:'Users',navClean:'Clean IP',
  navProxy:'Proxy',
  navSettings:'Panel settings',navLogs:'Events',menu:'Menu',
  totalUsers:'Total users',online:'Online users',devices:'Connected devices',
  traffic:'Total traffic',cleanIps:'Clean IPs',xSessions:'XHTTP sessions',
  chart24:'Last 24 hours',protoSplit:'Split by transport',
  newUser:'Create user',users:'Users',
  name:'Name',quota:'Quota (GB)',days:'Days',devLimit:'Devices',
  transport:'Transport',trWs:'🔌 WS + TLS',trXhttp:'🚀 XHTTP + TLS',trBoth:'🔀 Both',
  add:'Add',zeroInf:'0 = unlimited. Device count is based on distinct active IPs.',
  search:'Search…',noUsers:'No users yet',
  config:'Config',ipsBtn:'IPs',edit:'Edit',
  used:'Used',expiry:'Expires',never:'Never',
  subLink:'Subscription link',copySub:'Copy subscription link',
  singleCfg:'Individual configs',copy:'Copy',copied:'Copied ✓',
  devTitle:'Connected devices',noConn:'No connections recorded yet',
  clearIps:'Clear IP list',
  liveNow:'Connected now',noneNow:'No device connected right now',
  countedFor:'Counted toward the limit',totalSeen:'Total IPs ever seen',
  showHistory:'Show history',showLive:'Show only connected',
  inLast:'in the last %ss',refresh:'Refresh',
  liveDevices:'Devices live now',
  editUser:'Edit',remainDays:'Days remaining',allowedDev:'Allowed devices',
  active:'Enabled',saveBtn:'Save',resetTraffic:'Reset traffic',newUuid:'New UUID',
  customUuid:'Custom UUID',del:'Delete',
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
  pxAutoNote:'Every proxy that passes its health check joins all subscriptions automatically — all of them at once, no button. The no-proxy config is always there, and a failing proxy drops out on its own.',
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
  relayLbl:'Relay domain',keepAliveLbl:'Keep-alive',relayNone:'none',
  onLbl:'on',offLbl:'off',
  devWinLbl:'Device counting window',seconds:'seconds',
  envNote:'These come from environment variables and can be changed in Railway.',
  logout:'Sign out',logs:'Events',noLogs:'No events yet',
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
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;800&display=swap" rel="stylesheet">
<style>body{font-family:Vazirmatn,system-ui,sans-serif}__THEME__
.glow{background:radial-gradient(60% 55% at 50% 0%,color-mix(in srgb,var(--a1) 40%,transparent),transparent 70%)}
</style></head><body class="min-h-screen flex items-center justify-center p-4">
<script>__I18N__</script>
<div class="glow fixed inset-0 pointer-events-none"></div>
<div class="relative w-full max-w-sm card rounded-3xl p-8 shadow-2xl backdrop-blur">
 <div class="flex justify-between mb-4">
  <select onchange="setLang(this.value)" id="langSel" class="inp rounded-lg px-2 py-1 text-xs">
   <option value="fa">🇮🇷 فارسی</option><option value="en">🇬🇧 English</option></select>
  <select onchange="setTheme(this.value)" id="thSel" class="inp rounded-lg px-2 py-1 text-xs">
   <option value="dark">Dark</option><option value="light">Light</option>
   <option value="gray">Gray</option></select>
 </div>
 <div class="mb-6 text-center">
  <div class="mx-auto mb-3 h-14 w-14 rounded-2xl grad grid place-items-center">
   <svg viewBox="0 0 24 24" style="width:30px;height:30px;stroke:#fff;fill:none;stroke-width:1.6;stroke-linejoin:round">
    <path d="M12 2.7l7.5 3.4v5.3c0 4.4-3.1 8.2-7.5 9.9-4.4-1.7-7.5-5.5-7.5-9.9V6.1L12 2.7z"/>
    <path d="M12.6 8.2L9.4 13h2.6l-.6 3.4L14.6 11H12l.6-2.8z" style="fill:#fff;stroke-width:1"/></svg></div>
  <h1 id="h1" class="text-xl font-extrabold"></h1>
  <p id="sub" class="text-xs dim mt-1"></p>
 </div>
 <div class="space-y-3">
  <input id="p1" type="password" class="w-full inp rounded-xl px-4 py-3">
  <input id="p2" type="password" class="w-full inp rounded-xl px-4 py-3 hidden">
  <p id="rule" class="text-[11px] dim hidden"></p>
  <button id="go" class="w-full grad rounded-xl py-3 font-bold text-white hover:opacity-90"></button>
  <p id="err" class="text-center text-xs min-h-4" style="color:var(--bad)"></p>
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
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;800&display=swap" rel="stylesheet">
<style>body{font-family:Vazirmatn,system-ui,sans-serif}__THEME__</style>
</head><body class="min-h-screen">
<script>__I18N__</script>

<!-- ─── top bar ─── -->
<header class="sticky top-0 z-30 backdrop-blur border-b"
        style="border-color:var(--line);background:color-mix(in srgb,var(--bg) 88%,transparent)">
 <div class="max-w-6xl mx-auto px-3 py-3 flex items-center gap-2">
  <button onclick="toggleNav()" aria-label="menu"
          class="h-9 w-9 rounded-xl soft grid place-items-center">
   <svg class="ic" viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h16"/></svg></button>
  <div class="h-9 w-9 rounded-xl grad grid place-items-center text-white">
   <svg class="ic" viewBox="0 0 24 24" style="stroke:#fff">
    <path d="M12 2.7l7.5 3.4v5.3c0 4.4-3.1 8.2-7.5 9.9-4.4-1.7-7.5-5.5-7.5-9.9V6.1L12 2.7z"/>
    <path d="M12.6 8.2L9.4 13h2.6l-.6 3.4L14.6 11H12l.6-2.8z" style="fill:#fff;stroke-width:1"/></svg></div>
  <h1 class="font-extrabold text-sm sm:text-base">{{TITLE}}</h1>
  <span id="crumb" class="text-[11px] dim px-2 py-1 rounded-lg soft hidden sm:inline"></span>
  <div class="flex-1"></div>
  <span id="pill" class="mono text-[10px] dim"></span>
 </div>
</header>

<!-- ─── drawer ─── -->
<div id="scrim" onclick="toggleNav()" class="fixed inset-0 z-40 bg-black/60 hidden"></div>
<aside id="nav" class="fixed top-0 z-50 h-full w-72 sheet p-4 space-y-1 shadow-2xl
        transition-transform duration-200 overflow-y-auto"
       style="border-inline-end:1px solid var(--line)">
 <div class="flex items-center gap-2 mb-4">
  <div class="h-10 w-10 rounded-xl grad grid place-items-center">
   <svg class="ic ic-lg" viewBox="0 0 24 24" style="stroke:#fff">
    <path d="M12 2.7l7.5 3.4v5.3c0 4.4-3.1 8.2-7.5 9.9-4.4-1.7-7.5-5.5-7.5-9.9V6.1L12 2.7z"/>
    <path d="M12.6 8.2L9.4 13h2.6l-.6 3.4L14.6 11H12l.6-2.8z" style="fill:#fff;stroke-width:1"/></svg></div>
  <div><p class="font-extrabold text-sm">{{TITLE}}</p>
       <p class="text-[10px] dim">admin</p></div>
  <button onclick="toggleNav()" aria-label="close" class="ms-auto dim icbox h-8 w-8">
   <svg class="ic" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></svg></button>
 </div>

 <div class="navi" data-page="dash" onclick="go('dash')">
  <svg class="ic" viewBox="0 0 24 24"><path d="M4 19V11M9.5 19V5M15 19v-6M20.5 19V8"/>
   <path d="M3 21h18"/></svg><span data-t="navDash"></span></div>
 <div class="navi" data-page="users" onclick="go('users')">
  <svg class="ic" viewBox="0 0 24 24"><circle cx="9" cy="8" r="3.2"/>
   <path d="M3.5 19.5c0-3 2.5-4.8 5.5-4.8s5.5 1.8 5.5 4.8"/>
   <path d="M16.5 5.6a3 3 0 010 5.6M18 14.9c2 .6 3.4 2.2 3.4 4.6"/></svg><span data-t="navUsers"></span></div>
 <div class="navi" data-page="clean" onclick="go('clean')">
  <svg class="ic" viewBox="0 0 24 24"><path d="M12 3.2c3.6 3.2 5.6 6 5.6 9a5.6 5.6 0 11-11.2 0c0-3 2-5.8 5.6-9z"/>
   <path d="M9.4 14.6a2.8 2.8 0 002.6 2.6"/></svg><span data-t="navClean"></span></div>
 <div class="navi" data-page="proxy" onclick="go('proxy')">
  <svg class="ic" viewBox="0 0 24 24"><path d="M4 7h6.5a3 3 0 013 3v4a3 3 0 003 3H20"/>
   <path d="M17 4l3 3-3 3M17 14l3 3-3 3"/><circle cx="4" cy="7" r="1.6"/></svg>
  <span data-t="navProxy"></span></div>
 <div class="navi" data-page="settings" onclick="go('settings')">
  <svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/>
   <path d="M19.4 14.5a1.7 1.7 0 00.35 1.87l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.7 1.7 0 00-1.87-.35 1.7 1.7 0 00-1.03 1.56V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1.1-1.55 1.7 1.7 0 00-1.87.35l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.7 1.7 0 00.35-1.87 1.7 1.7 0 00-1.56-1.03H3a2 2 0 110-4h.1a1.7 1.7 0 001.55-1.1 1.7 1.7 0 00-.35-1.87l-.06-.06a2 2 0 112.83-2.83l.06.06a1.7 1.7 0 001.87.35H9a1.7 1.7 0 001-1.56V3a2 2 0 114 0v.1a1.7 1.7 0 001.03 1.56 1.7 1.7 0 001.87-.35l.06-.06a2 2 0 112.83 2.83l-.06.06a1.7 1.7 0 00-.35 1.87V9a1.7 1.7 0 001.56 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1.05z"/></svg><span data-t="navSettings"></span></div>
 <div class="navi" data-page="logs" onclick="go('logs')">
  <svg class="ic" viewBox="0 0 24 24"><path d="M5 4.5h11l3 3V19a1 1 0 01-1 1H5a1 1 0 01-1-1V5.5a1 1 0 011-1z"/>
   <path d="M15.5 4.5V8H19M7.5 12h9M7.5 15.5h6"/></svg><span data-t="navLogs"></span></div>

 <div class="pt-3 mt-3 border-t space-y-2" style="border-color:var(--line)">
  <div class="flex gap-2">
   <select id="thSel" onchange="setTheme(this.value)" class="inp rounded-lg px-2 py-1.5 text-xs flex-1">
    <option value="dark" data-t="thDark"></option><option value="light" data-t="thLight"></option>
    <option value="gray" data-t="thGray"></option></select>
   <select id="langSel" onchange="setLang(this.value)" class="inp rounded-lg px-2 py-1.5 text-xs">
    <option value="fa">فا</option><option value="en">EN</option></select>
  </div>
  <button onclick="logout()" id="btnOut"
    class="w-full rounded-xl py-2 text-xs font-bold"
    style="background:color-mix(in srgb,var(--bad) 16%,transparent);color:var(--bad)"></button>
 </div>
</aside>

<main class="max-w-6xl mx-auto p-4">

 <!-- ══ DASHBOARD ══ -->
 <section data-pg="dash" class="space-y-4">
  <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="totalUsers"></p><p id="sUsers" class="text-2xl font-extrabold mt-1">—</p></div>
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="online"></p><p id="sOnline" class="text-2xl font-extrabold mt-1" style="color:var(--ok)">—</p></div>
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="liveDevices"></p><p id="sLive" class="text-2xl font-extrabold mt-1" style="color:var(--ok)">—</p></div>
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="devices"></p><p id="sDev" class="text-2xl font-extrabold mt-1" style="color:var(--info)">—</p></div>
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="traffic"></p><p id="sBytes" class="text-2xl font-extrabold mt-1" style="color:var(--a2)">—</p></div>
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="cleanIps"></p><p id="sCip" class="text-2xl font-extrabold mt-1" style="color:var(--a1)">—</p></div>
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="xSessions"></p><p id="sXs" class="text-2xl font-extrabold mt-1">—</p></div>
  </div>
  <div class="card rounded-2xl p-4">
   <p class="text-sm font-bold mb-3" data-t="chart24"></p>
   <canvas id="chart" height="90"></canvas>
  </div>
  <div class="card rounded-2xl p-4">
   <p class="text-sm font-bold mb-3" data-t="protoSplit"></p>
   <div id="protoBox" class="flex gap-3 flex-wrap text-xs"></div>
  </div>
 </section>

 <!-- ══ USERS ══ -->
 <section data-pg="users" class="space-y-4 hidden">
  <div class="card rounded-2xl p-4">
   <p class="text-sm font-bold mb-3" data-t="newUser"></p>
   <div class="grid sm:grid-cols-3 lg:grid-cols-5 gap-2">
    <input id="nName" class="inp rounded-xl px-3 py-2 text-sm">
    <input id="nQuota" type="number" step="0.5" value="30" class="inp rounded-xl px-3 py-2 text-sm">
    <input id="nDays" type="number" value="30" class="inp rounded-xl px-3 py-2 text-sm">
    <input id="nDev" type="number" value="1" class="inp rounded-xl px-3 py-2 text-sm">
    <select id="nTr" class="inp rounded-xl px-3 py-2 text-sm">
     <option value="both"></option><option value="ws"></option><option value="xhttp"></option></select>
   </div>
   <button onclick="createUser()" id="btnAdd" class="grad rounded-xl px-4 py-2 mt-2 text-sm font-bold text-white w-full sm:w-auto"></button>
   <p class="text-[11px] dim mt-2" data-t="zeroInf"></p>
   <p id="cErr" class="text-xs mt-1" style="color:var(--bad)"></p>
  </div>
  <div class="card rounded-2xl overflow-hidden">
   <div class="px-4 py-3 flex items-center gap-2 border-b" style="border-color:var(--line)">
    <p class="text-sm font-bold" data-t="users"></p>
    <input id="q" oninput="renderUsers()" class="ms-auto inp rounded-xl px-3 py-1.5 text-xs w-40">
   </div>
   <div id="rows"></div>
  </div>
 </section>

 <!-- ══ CLEAN IP ══ -->
 <section data-pg="clean" class="space-y-4 hidden">
  <div class="card rounded-2xl p-4">
   <p class="text-sm font-bold" data-t="cleanTitle"></p>
   <p class="text-[11px] dim mt-1 mb-3" data-t="cleanHint"></p>
   <div class="grid sm:grid-cols-4 gap-2">
    <input id="cAddr" class="inp rounded-xl px-3 py-2 text-sm">
    <input id="cRem" class="inp rounded-xl px-3 py-2 text-sm">
    <select id="cCty" class="inp rounded-xl px-3 py-2 text-sm"></select>
    <button onclick="addCip()" id="btnCipAdd" class="grad rounded-xl px-4 py-2 text-sm font-bold"></button>
   </div>
   <textarea id="cBulk" rows="4" class="inp rounded-xl px-3 py-2 text-sm w-full mt-2 mono"></textarea>
   <div class="grid grid-cols-2 gap-2 mt-2">
    <button onclick="bulkCip()" id="btnBulk" class="rounded-xl soft py-2 text-xs font-bold"></button>
    <button onclick="clearCips()" id="btnClearAll" class="rounded-xl py-2 text-xs font-bold"
      style="background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)"></button>
   </div>
   <p id="cipMsg" class="text-xs dim mt-2"></p>
  </div>
  <div class="card rounded-2xl p-4"><div id="cipRows" class="grid sm:grid-cols-2 gap-2"></div></div>
 </section>

 <!-- ══ PROXY ══ -->
 <section data-pg="proxy" class="space-y-4 hidden">
  <div class="card rounded-2xl p-4">
   <p class="text-sm font-bold" data-t="pxTitle"></p>
   <p class="text-[11px] dim mt-1 mb-3" data-t="pxHint"></p>
   <textarea id="pBulk" rows="3" spellcheck="false"
     class="w-full inp rounded-xl px-3 py-2 text-sm mono"
     placeholder="socks5://1.1.1.1:5866"></textarea>
   <p class="text-[10px] dim mt-1" data-t="pxLineHint"></p>
   <button onclick="addBulk()" class="w-full grad rounded-xl px-4 py-2 text-sm font-bold mt-2"
     data-t="pxAddLines"></button>
   <details class="mt-3">
   <summary class="text-[11px] dim cursor-pointer" data-t="pxAdvanced"></summary>
   <div class="grid sm:grid-cols-3 gap-2 mt-2">
    <div><label class="text-[11px] dim" data-t="pxKind"></label>
     <select id="pKind" class="w-full inp rounded-xl px-3 py-2 text-sm mt-1">
      <option value="socks5">SOCKS5</option><option value="socks4">SOCKS4</option>
      <option value="http">HTTP</option></select></div>
    <div><label class="text-[11px] dim" data-t="pxHost"></label>
     <input id="pHost" class="w-full inp rounded-xl px-3 py-2 text-sm mt-1 mono" placeholder="1.2.3.4"></div>
    <div><label class="text-[11px] dim" data-t="pxPort"></label>
     <input id="pPort" type="number" class="w-full inp rounded-xl px-3 py-2 text-sm mt-1 mono" placeholder="1080"></div>
    <div><label class="text-[11px] dim" data-t="pxUser"></label>
     <input id="pUser" class="w-full inp rounded-xl px-3 py-2 text-sm mt-1 mono"></div>
    <div><label class="text-[11px] dim" data-t="pxPass"></label>
     <input id="pPass" type="password" class="w-full inp rounded-xl px-3 py-2 text-sm mt-1 mono"></div>
    <div><label class="text-[11px] dim" data-t="remarkPh"></label>
     <input id="pRem" class="w-full inp rounded-xl px-3 py-2 text-sm mt-1"></div>
   </div>
   </details>
   <div class="grid grid-cols-2 gap-2 mt-3">
    <button onclick="addProxy()" class="grad rounded-xl px-4 py-2 text-sm font-bold" data-t="pxAdd"></button>
    <button onclick="testAllProxies()" class="rounded-xl soft py-2 text-xs font-bold" data-t="pxTestAll"></button>
   </div>
   <p id="pxMsg" class="text-xs dim mt-2"></p>
  </div>

  <div class="card rounded-2xl p-4 space-y-3">
   <div class="flex items-center gap-3">
    <div class="flex-1">
     <p class="text-sm font-bold" data-t="pxStrict"></p>
     <p class="text-[10px] dim" data-t="pxStrictHint"></p>
    </div>
    <button id="pxStrictBtn" onclick="toggleStrict()" class="sw rounded-full"></button>
   </div>
   <div>
    <label class="text-xs dim" data-t="pxFlagSrc"></label>
    <select id="pxFlagSel" onchange="saveFlagSource()" class="w-full inp rounded-xl px-3 py-2 text-sm mt-1">
     <option value="proxy" data-t="pxFlagProxy"></option>
     <option value="entry" data-t="pxFlagEntry"></option></select>
   </div>
  </div>

  <div class="card rounded-2xl p-4 space-y-2">
   <p class="text-[11px] dim" data-t="pxAutoNote"></p>
   <div id="pxRows" class="space-y-2"></div>
  </div>
 </section>

 <!-- ══ SETTINGS ══ -->
 <section data-pg="settings" class="space-y-4 hidden">
  <div class="card rounded-2xl p-4 space-y-3">
   <p class="text-sm font-bold" data-t="appearance"></p>
   <div class="grid sm:grid-cols-2 gap-2">
    <div><label class="text-xs dim" data-t="theme"></label>
     <select id="thSel2" onchange="setTheme(this.value);syncSelects()" class="w-full inp rounded-xl px-3 py-2 text-sm mt-1">
      <option value="dark" data-t="thDark"></option><option value="light" data-t="thLight"></option>
      <option value="gray" data-t="thGray"></option></select></div>
    <div><label class="text-xs dim" data-t="mainCountry"></label>
     <div class="flex gap-2 mt-1">
      <select id="mcSel" class="flex-1 inp rounded-xl px-3 py-2 text-sm"></select>
      <button onclick="saveMainCountry()" id="btnMc" class="grad rounded-xl px-3 py-2 text-xs font-bold"></button>
     </div>
     <p class="text-[10px] dim mt-1" data-t="flagsHint"></p></div>
    <div><label class="text-xs dim" data-t="language"></label>
     <select id="langSel2" onchange="setLang(this.value);syncSelects()" class="w-full inp rounded-xl px-3 py-2 text-sm mt-1">
      <option value="fa">🇮🇷 فارسی</option><option value="en">🇬🇧 English</option></select></div>
   </div>
  </div>
  <div class="card rounded-2xl p-4 space-y-2">
   <p class="text-sm font-bold" data-t="changePw"></p>
   <input id="pwCur" type="password" class="w-full inp rounded-xl px-3 py-2 text-sm">
   <input id="pwNew" type="password" class="w-full inp rounded-xl px-3 py-2 text-sm">
   <p class="text-[11px] dim" data-t="pwRule"></p>
   <button onclick="doChangePw()" id="btnPw" class="grad rounded-xl py-2 px-4 font-bold text-sm text-white"></button>
   <p id="pwMsg" class="text-xs"></p>
  </div>
  <div class="card rounded-2xl p-4 space-y-2">
   <p class="text-sm font-bold" data-t="serverInfo"></p>
   <div id="srvBox" class="space-y-1 text-xs"></div>
   <p class="text-[11px] dim pt-1" data-t="envNote"></p>
  </div>
 </section>

 <!-- ══ LOGS ══ -->
 <section data-pg="logs" class="hidden">
  <div class="card rounded-2xl p-4">
   <p class="text-sm font-bold mb-3" data-t="logs"></p>
   <div id="logRows" class="space-y-1"></div>
  </div>
 </section>
</main>

<div id="modal" class="fixed inset-0 z-[60] hidden items-center justify-center bg-black/70 p-4">
 <div class="card rounded-2xl w-full max-w-md p-5 max-h-[85vh] overflow-y-auto sheet">
  <div class="flex items-center mb-3"><p id="mTitle" class="font-bold"></p>
   <button onclick="closeModal()" class="ms-auto dim hover:opacity-70">✕</button></div>
  <div id="mBody" class="space-y-3 text-sm"></div>
 </div>
</div>

<script>
/* ─── drawer position depends on writing direction ─── */
function placeNav(open){
 const rtl=I18N[LANG].dir==='rtl';
 nav.style.left = rtl?'auto':'0';
 nav.style.right= rtl?'0':'auto';
 nav.style.transform = open?'translateX(0)':(rtl?'translateX(100%)':'translateX(-100%)');
 /* A drawer that is only pushed aside still takes up layout width, so any sideways
    scroll (long proxy rows caused exactly that) dragged it back into view. Pulling it
    out of the layout keeps it hidden until it is actually asked for. */
 nav.style.visibility    = open?'visible':'hidden';
 nav.style.pointerEvents = open?'auto':'none';
}
let navOpen=false;
function toggleNav(force){
 navOpen = force===undefined?!navOpen:force;
 placeNav(navOpen);
 scrim.classList.toggle('hidden',!navOpen);
}
placeNav(false);

/* ─── country flags + inline icons ───
   `var` and function declarations on purpose: paintStatic() runs during boot, before
   this point in the script, and `const` would throw a temporal-dead-zone error that
   aborts the whole panel script. */
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
var SVG_PAUSE='<svg class="ic" style="width:14px;height:14px" viewBox="0 0 24 24">'+
  '<path d="M9.5 5v14M14.5 5v14"/></svg>';
var SVG_PLAY='<svg class="ic" style="width:14px;height:14px" viewBox="0 0 24 24">'+
  '<path d="M7.5 5.2l11 6.8-11 6.8z"/></svg>';
var SVG_X='<svg class="ic" style="width:14px;height:14px" viewBox="0 0 24 24">'+
  '<path d="M6 6l12 12M18 6L6 18"/></svg>';
var MAIN_CC='';
var SVG_PING='<svg class="ic" style="width:14px;height:14px" viewBox="0 0 24 24">'+
  '<path d="M3 12h4l2.5-6 4 12 2.5-6h5"/></svg>';
var SVG_ARM='<svg class="ic" style="width:14px;height:14px" viewBox="0 0 24 24">'+
  '<path d="M13 3L5 14h5l-1 7 8-11h-5z"/></svg>';
var PROXIES=[],PX_SUB=[],PX_ACTIVE=0,PX_STRICT=true,PX_FLAG='proxy';

/* ─── routing ─── */
let PAGE=localStorage.getItem('page')||'dash';
function go(p){
 PAGE=p; localStorage.setItem('page',p);
 document.querySelectorAll('[data-pg]').forEach(s=>s.classList.toggle('hidden',s.dataset.pg!==p));
 document.querySelectorAll('.navi').forEach(n=>n.classList.toggle('on',n.dataset.page===p));
 crumb.textContent=T({dash:'navDash',users:'navUsers',clean:'navClean',
   proxy:'navProxy',settings:'navSettings',logs:'navLogs'}[p]);
 toggleNav(false);
 if(p==='logs')loadLogs();
 if(p==='clean')loadCips();
 if(p==='settings')renderServer();
}

/* ─── helpers ─── */
const fmt=b=>{if(!b)return '0 B';const u=['B','KB','MB','GB','TB'];let i=0,n=b;
 while(n>=1024&&i<u.length-1){n/=1024;i++}return n.toFixed(i?1:0)+' '+u[i]};
const dt=t=>t?new Date(t*1000).toLocaleString(LANG==='fa'?'fa-IR':'en-GB'):T('never');
const statusTxt=s=>({disabled:T('statusDisabled'),expired:T('statusExpired'),
 quota:T('statusQuota')}[s]||s);
const trTxt=t=>({ws:T('trWs'),xhttp:T('trXhttp'),both:T('trBoth')}[t]||t);
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
 nName.placeholder=T('name'); nQuota.placeholder=T('quota');
 nDays.placeholder=T('days'); nDev.placeholder=T('devLimit');
 q.placeholder=T('search');
 nTr.options[0].textContent=T('trBoth');
 nTr.options[1].textContent=T('trWs');
 nTr.options[2].textContent=T('trXhttp');
 cAddr.placeholder=T('addrPh'); cRem.placeholder=T('remarkPh'); cBulk.placeholder=T('bulkPh');
 fillCountry(document.getElementById('cCty'),document.getElementById('cCty')?.value||'');
 fillCountry(document.getElementById('mcSel'),MAIN_CC);
 const _mb=document.getElementById('btnMc'); if(_mb)_mb.textContent=T('save');
 pwCur.placeholder=T('curPw'); pwNew.placeholder=T('newPw');
 placeNav(navOpen);
}
window.rerender=()=>{paintStatic();go(PAGE);renderUsers();renderCips();
 renderProto();renderServer();renderLogs()};
paintStatic(); syncSelects();

/* ─── data ─── */
function paintChart(){
 const c1=getComputedStyle(document.body).getPropertyValue('--a1').trim()||'#818cf8';
 const labels=(stats.series||[]).map(x=>new Date(x.h*1000).getHours()+':00');
 const data=(stats.series||[]).map(x=>(x.up+x.down)/1048576);
 if(!chart){
  chart=new Chart(document.getElementById('chart'),{type:'line',
   data:{labels,datasets:[{label:'MB',data,fill:true,tension:.4,borderColor:c1,
    backgroundColor:c1+'33',pointRadius:0,borderWidth:2}]},
   options:{plugins:{legend:{display:false}},scales:{
    x:{grid:{color:'#8882'},ticks:{color:'#94a3b8',font:{size:10}}},
    y:{grid:{color:'#8882'},ticks:{color:'#94a3b8',font:{size:10}}}}}});
 }else{Object.assign(chart.data,{labels});
  chart.data.datasets[0].data=data;
  chart.data.datasets[0].borderColor=c1;
  chart.data.datasets[0].backgroundColor=c1+'33';chart.update()}
}
function renderProto(){
 const bp=stats.by_proto||{};
 const pairs=[['ws',T('trWs'),'var(--a1)'],['xhttp',T('trXhttp'),'var(--a2)']];
 protoBox.innerHTML=pairs.map(([k,lbl,col])=>`
  <div class="rounded-xl soft px-3 py-2 flex items-center gap-2">
   <span class="h-2 w-2 rounded-full" style="background:${col}"></span>
   <span>${lbl}</span><span class="font-bold">${bp[k]||0}</span></div>`).join('');
}
function renderServer(){
 srvBox.innerHTML=[
  [T('wsPathLbl'),'/'+(stats.ws_path||'—')],
  [T('xhPathLbl'),'/'+(stats.xhttp_path||'—')],
  [T('devWinLbl'),(stats.device_window||'—')+' '+T('seconds')],
  [T('xSessions'),stats.xhttp_sessions??'—'],
  [T('relayLbl'),stats.relay_domain||T('relayNone')],
  [T('keepAliveLbl'),stats.keepalive?T('onLbl'):T('offLbl')],
 ].map(([k,v])=>`<div class="flex items-center gap-2 rounded-xl soft px-3 py-2">
   <span class="dim">${k}</span><span class="ms-auto mono">${v}</span></div>`).join('');
}

async function loadStats(){
 stats=await api('/api/stats');
 sUsers.textContent=stats.users; sOnline.textContent=stats.online_users;
 sDev.textContent=stats.online_devices; sLive.textContent=stats.live_devices;
 sBytes.textContent=fmt(stats.total_bytes);
 sCip.textContent=stats.clean_ips; sXs.textContent=stats.xhttp_sessions;
 pill.textContent='/'+stats.ws_path+' · /'+stats.xhttp_path;
 paintChart(); renderProto();
 if(PAGE==='settings')renderServer();
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

function renderUsers(){
 const term=(q.value||'').toLowerCase();
 rows.innerHTML=users.filter(u=>u.name.toLowerCase().includes(term)).map(u=>{
  const pct=u.quota_bytes?Math.min(100,u.used_bytes/u.quota_bytes*100):0;
  const badge=u.active
   ?`<span class="text-[10px] px-2 py-0.5 rounded-full" style="background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)">${T('active')}</span>`
   :`<span class="text-[10px] px-2 py-0.5 rounded-full" style="background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)">${statusTxt(u.status)}</span>`;
  const dev=u.device_limit?`${u.devices_now}/${u.device_limit}`:`${u.devices_now}/♾️`;
  const liveTag=u.devices_live?`<span class="text-[10px] px-1.5 py-0.5 rounded-full" style="background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)">● ${u.devices_live}</span>`:'';
  const devCol=u.device_limit&&u.devices_now>=u.device_limit?'var(--bad)':'var(--info)';
  return `<div class="p-4 border-b" style="border-color:var(--line)">
   <div class="flex items-center gap-2 flex-wrap">
    <p class="font-bold">${u.name}</p>${badge}
    <span class="text-[10px] px-2 py-0.5 rounded-full soft">${trTxt(u.transport)}</span>
    <span class="text-[11px]" style="color:${devCol}">📱 ${dev}</span>${liveTag}
    <div class="flex-1"></div>
    <button onclick="showConfig(${u.id})" class="text-[11px] px-2 py-1 rounded-lg" style="background:color-mix(in srgb,var(--a1) 22%,transparent)">${T('config')}</button>
    <button onclick="showIps(${u.id})" class="text-[11px] px-2 py-1 rounded-lg" style="background:color-mix(in srgb,var(--info) 20%,transparent)">${T('ipsBtn')}</button>
    <button onclick="showEdit(${u.id})" class="text-[11px] px-2 py-1 rounded-lg soft">${T('edit')}</button>
   </div>
   <div class="mt-2 h-1.5 rounded-full overflow-hidden soft">
    <div class="h-full grad" style="width:${pct}%"></div></div>
   <div class="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[11px] dim">
    <span>${T('used')}: ${fmt(u.used_bytes)} / ${u.quota_bytes?fmt(u.quota_bytes):'♾️'}</span>
    <span>${T('expiry')}: ${dt(u.expire_at)}</span>
   </div></div>`}).join('')||`<p class="p-6 text-center text-sm dim">${T('noUsers')}</p>`;
}

function renderCips(){
 cipRows.innerHTML=cips.map(x=>`
  <div class="flex items-center gap-2 rounded-xl soft px-3 py-2">
   <span class="h-2 w-2 rounded-full" style="background:${x.enabled?'var(--ok)':'var(--dim)'}"></span>
   ${x.flag?`<span class="text-sm">${x.flag}</span>`:''}
   <span class="mono text-[11px]">${x.address}</span>
   ${x.remark?`<span class="text-[10px] dim">${x.remark}</span>`:''}
   <div class="flex-1"></div>
   <button onclick="toggleCip(${x.id})" class="icbox px-2 py-1 rounded-lg soft">${x.enabled?SVG_PAUSE:SVG_PLAY}</button>
   <button onclick="delCip(${x.id})" class="icbox px-2 py-1 rounded-lg" style="color:var(--bad)">${SVG_X}</button>
  </div>`).join('')||`<p class="text-xs dim">${T('noCleanIps')}</p>`;
}

function renderLogs(){
 const box=document.getElementById('logRows');
 box.innerHTML=logItems.map(l=>`
  <div class="flex items-center gap-2 rounded-xl soft px-3 py-2 text-[11px]">
   <span class="font-bold">${l.event}</span>
   <span class="mono dim">${l.ip||''}</span>
   <span class="dim">${l.detail||''}</span>
   <span class="ms-auto dim">${dt(l.ts)}</span></div>`).join('')
  ||`<p class="text-xs dim">${T('noLogs')}</p>`;
}

/* ─── actions ─── */
async function createUser(){
 cErr.textContent='';
 try{
  await api('/api/users',{method:'POST',body:JSON.stringify({
   name:nName.value.trim(),quota_gb:parseFloat(nQuota.value||0),
   expire_days:parseInt(nDays.value||0),device_limit:parseInt(nDev.value||0),
   transport:nTr.value})});
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
  // A healthy, enabled proxy is already in every subscription — nothing to press.
  const on=PX_SUB.indexOf(x.id)>-1;
  const dot=x.healthy?'var(--ok)':(x.checked_at?'var(--bad)':'var(--dim)');
  const state=x.healthy?T('pxHealthy'):(x.checked_at?T('pxDown'):T('pxUntested'));
  const geo=[x.country_name||'',x.city||''].filter(Boolean).join(' \u00b7 ');
  return `<div class="rounded-xl soft px-3 py-2 ${on?'ring-2':''}" style="${on?'outline:2px solid var(--a1)':''}">
   <div class="flex items-center gap-2 flex-wrap">
    <span class="h-2 w-2 rounded-full" style="background:${dot}"></span>
    <span class="text-base">${x.flag||'\u{1F310}'}</span>
    <span class="mono text-[11px] min-w-0 break-all">${x.label}</span>
    ${x.has_auth?'<span class="text-[10px] dim">\u{1F511}</span>':''}
    ${on?`<span class="text-[10px] font-bold" style="color:var(--a2)">${T('pxInSub')}</span>`:''}
    <div class="flex-1"></div>
    <button onclick="testProxy(${x.id})" title="${T('pxTest')}" class="icbox px-2 py-1 rounded-lg soft">${SVG_PING}</button>
    <button onclick="toggleProxy(${x.id},${x.enabled?1:0})" class="icbox px-2 py-1 rounded-lg soft">${x.enabled?SVG_PAUSE:SVG_PLAY}</button>
    <button onclick="delProxy(${x.id})" class="icbox px-2 py-1 rounded-lg" style="color:var(--bad)">${SVG_X}</button>
   </div>
   <div class="flex flex-wrap gap-x-3 gap-y-1 mt-1 text-[10px] dim">
    <span>${state}</span>
    ${x.latency_ms?`<span>${T('pxLatency')}: ${x.latency_ms} ms</span>`:''}
    ${x.exit_ip?`<span class="mono">${T('pxExitIp')}: ${x.exit_ip}</span>`:''}
    ${geo?`<span>${geo}</span>`:''}
    ${x.isp?`<span>${x.isp}</span>`:''}
    ${x.remark?`<span>${x.remark}</span>`:''}
    ${x.last_error?`<span style="color:var(--bad)">${x.last_error}</span>`:''}
   </div>
  </div>`}).join('')||`<p class="text-xs dim">${T('pxNone')}</p>`;
}
async function addProxy(){
 pxMsg.textContent=T('pxTesting');
 try{const r=await api('/api/proxies',{method:'POST',body:JSON.stringify({
   kind:pKind.value,host:pHost.value.trim(),port:parseInt(pPort.value||'0',10),
   username:pUser.value.trim(),password:pPass.value,remark:pRem.value.trim()})});
  pxMsg.textContent=r.ok?`${r.flag||''} ${r.country_name||''} \u00b7 ${r.exit_ip||''} \u00b7 ${r.latency_ms}ms`
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
    ?`<span style="color:var(--ok)">${x.flag||''} ${x.label} · ${x.country_name||''} ${x.latency_ms||0}ms</span>`
    :`<span style="color:var(--bad)">${x.label}: ${x.error||''}</span>`).join('<br>')+
   `<br>${good}/${rows.length}`;
  if(good)pBulk.value='';
  loadProxies();
 }catch(e){pxMsg.textContent=e.message}
}
async function testProxy(id){
 pxMsg.textContent=T('pxTesting');
 try{const r=await api('/api/proxies/'+id+'/test',{method:'POST'});
  pxMsg.textContent=r.ok?`${r.flag||''} ${r.country_name||''} \u00b7 ${r.exit_ip||''} \u00b7 ${r.latency_ms}ms`
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
  <div class="rounded-xl soft p-2">
   <p class="text-[11px] font-bold mb-1">${x.label}</p>
   <p class="mono text-[9px] break-all dim">${x.uri}</p>
   <button onclick="copy(this,'${x.uri.replace(/'/g,"\\'")}')" class="mt-1 w-full rounded-lg soft py-1 text-[10px]">${T('copy')}</button>
  </div>`).join('');
 openModal(T('config'),`
  <p class="text-xs dim">${T('subLink')}</p>
  <div class="rounded-xl soft p-2 mono text-[10px] break-all">${c.sub_link}</div>
  <button onclick="copy(this,'${c.sub_link}')" class="w-full grad rounded-xl py-2 text-xs font-bold text-white">${T('copySub')}</button>
  <div id="qr" class="grid place-items-center bg-white p-3 rounded-xl"></div>
  <p class="text-xs dim pt-2">UUID</p>
  <div class="rounded-xl soft p-2 mono text-[10px] break-all">${c.uuid}</div>
  <p class="text-xs dim pt-2">${T('singleCfg')} — ${trTxt(c.transport)}</p>${cfgs}`);
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
 catch(e){ if(!quiet) openModal(T('devTitle'),'<p class="text-xs" style="color:var(--bad)">'+e.message+'</p>'); return }

 const rows=d.rows.length ? d.rows.map(x=>`
  <div class="flex items-center gap-2 rounded-xl soft px-3 py-2">
   <span class="h-2 w-2 rounded-full" style="background:${x.online?'var(--ok)':(x.counted?'var(--info)':'var(--dim)')}"></span>
   <span class="mono text-[11px]">${x.ip}</span>
   <span class="text-[9px] px-1.5 py-0.5 rounded soft">${x.proto||'ws'}</span>
   <span class="ms-auto text-[10px] dim">${dt(x.last_seen)}</span>
  </div>`).join('')
  : `<p class="text-xs dim py-2">${ipHistory?T('noConn'):T('noneNow')}</p>`;

 const body=`
  <div class="rounded-2xl p-4 text-center soft">
   <p class="text-[11px] dim">${T('liveNow')}</p>
   <p class="text-4xl font-extrabold mt-1" style="color:${d.live?'var(--ok)':'var(--dim)'}">${d.live}</p>
   <p class="text-[10px] dim mt-1">${T('inLast').replace('%s',d.live_window)}</p>
  </div>
  <div class="grid grid-cols-2 gap-2 text-[11px]">
   <div class="rounded-xl soft px-3 py-2"><span class="dim">${T('countedFor')}</span>
    <span class="float-end font-bold" style="color:var(--info)">${d.counted}</span></div>
   <div class="rounded-xl soft px-3 py-2"><span class="dim">${T('totalSeen')}</span>
    <span class="float-end font-bold">${d.total_seen}</span></div>
  </div>
  <div class="space-y-1">${rows}</div>
  <button onclick="toggleIpHistory()" class="w-full rounded-xl soft py-2 text-xs">
   ${ipHistory?T('showLive'):T('showHistory')}</button>
  <button onclick="clearIps(${ipUid})" class="w-full rounded-xl py-2 text-xs"
   style="background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)">${T('clearIps')}</button>`;

 if(quiet){ const b=document.getElementById('mBody'); if(b) b.innerHTML=body; }
 else openModal(T('devTitle'),body);
}

function toggleIpHistory(){ ipHistory=!ipHistory; paintIps(); }

async function clearIps(id){await api('/api/users/'+id+'/clear-ips',{method:'POST'});closeModal();loadUsers();loadStats()}

function showEdit(id){
 const u=users.find(x=>x.id===id);
 const days=u.expire_at?Math.max(0,Math.ceil((u.expire_at-Date.now()/1000)/86400)):0;
 const opt=v=>`<option value="${v}" ${u.transport===v?'selected':''}>${trTxt(v)}</option>`;
 openModal(T('editUser')+' · '+u.name,`
  <label class="block text-xs dim">${T('quota')}</label>
  <input id="eQ" type="number" step="0.5" value="${(u.quota_bytes/1073741824).toFixed(2)}" class="w-full inp rounded-xl px-3 py-2">
  <label class="block text-xs dim">${T('remainDays')}</label>
  <input id="eD" type="number" value="${days}" class="w-full inp rounded-xl px-3 py-2">
  <label class="block text-xs dim">${T('allowedDev')}</label>
  <input id="eV" type="number" value="${u.device_limit}" class="w-full inp rounded-xl px-3 py-2">
  <label class="block text-xs dim">${T('transport')}</label>
  <select id="eT" class="w-full inp rounded-xl px-3 py-2">${opt('both')}${opt('ws')}${opt('xhttp')}</select>
  <label class="block text-xs dim">${T('customUuid')}</label>
  <input id="eU" value="${u.uuid}" class="w-full inp rounded-xl px-3 py-2 mono text-[11px]">
  <label class="flex items-center gap-2 text-xs"><input id="eE" type="checkbox" ${u.enabled?'checked':''}> ${T('active')}</label>
  <button onclick="saveEdit(${id})" class="w-full grad rounded-xl py-2 font-bold text-sm text-white">${T('saveBtn')}</button>
  <div class="grid grid-cols-3 gap-2 pt-2">
   <button onclick="resetTraffic(${id})" class="rounded-xl soft py-2 text-[11px]">${T('resetTraffic')}</button>
   <button onclick="newUuid(${id})" class="rounded-xl soft py-2 text-[11px]">${T('newUuid')}</button>
   <button onclick="delUser(${id})" class="rounded-xl py-2 text-[11px]" style="background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)">${T('del')}</button>
  </div>
  <p id="eErr" class="text-xs" style="color:var(--bad)"></p>`);
}
async function saveEdit(id){
 try{
  const u=users.find(x=>x.id===id);
  const payload={quota_gb:parseFloat(eQ.value||0),expire_days:parseInt(eD.value||0),
   device_limit:parseInt(eV.value||0),transport:eT.value,enabled:eE.checked};
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

function copy(btn,t){navigator.clipboard.writeText(t);
 const old=btn.textContent;btn.textContent=T('copied');setTimeout(()=>btn.textContent=old,1200)}

go(PAGE);
loadStats();loadUsers();loadCips();loadMainCountry();loadProxies();
setInterval(()=>{loadStats();if(PAGE==='users')loadUsers()},15000);
</script></body></html>"""

AUTH_HTML  = AUTH_HTML.replace("__THEME__", THEME_CSS).replace("__I18N__", I18N_JS)
PANEL_HTML = PANEL_HTML.replace("__THEME__", THEME_CSS).replace("__I18N__", I18N_JS)
