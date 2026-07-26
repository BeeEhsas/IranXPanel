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
    enabled  INTEGER DEFAULT 1,
    added_at INTEGER NOT NULL
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
              "user_ips": [("proto", "TEXT DEFAULT 'ws'")]}
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
                        ip: str, proto: str) -> None:
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

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=12)

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


def get_session(sid: str, ip: str) -> XSession:
    s = SESSIONS.get(sid)
    if s is None or s.closed:
        s = XSession(sid, ip)
        SESSIONS[sid] = s
        s.worker = asyncio.create_task(run_session(s))
    s.touch()
    return s


async def run_session(s: XSession):
    try:
        await relay_session(s.stream, s.send, s.ip, "xhttp")
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


# ── WebSocket inbound (catch-all, validated inside) ──
@app.websocket("/{path:path}")
async def vless_ws(websocket: WebSocket, path: str):
    if path.strip("/") != WS_PATH:
        await websocket.close(code=1008)
        return
    ip = client_ip(websocket)
    await websocket.accept()
    stream = WSStream(websocket)

    async def send(data: bytes):
        await websocket.send_bytes(data)

    try:
        await relay_session(stream, send, ip, "ws")
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


def ws_uri(row, address: str, host: str, label: str) -> str:
    return (f"vless://{row['uuid']}@{address}:443"
            f"?encryption=none&security=tls&sni={host}&fp=chrome&alpn=http%2F1.1"
            f"&type=ws&host={host}&path=%2F{WS_PATH}"
            f"#{quote(label)}")


def xhttp_uri(row, address: str, host: str, label: str) -> str:
    return (f"vless://{row['uuid']}@{address}:443"
            f"?encryption=none&security=tls&sni={host}&fp=chrome"
            f"&type=xhttp&host={host}&path=%2F{XHTTP_PATH}&mode=packet-up"
            f"#{quote(label)}")


def build_configs(row, host: str, clean_ips) -> list[dict]:
    t = (row["transport"] or "both").lower()
    kinds = []
    if t in ("ws", "both"):
        kinds.append(("WS", ws_uri))
    if t in ("xhttp", "both"):
        kinds.append(("XHTTP", xhttp_uri))

    out = []
    for tag, fn in kinds:
        out.append({"label": f"🌐 {row['name']} · {tag} · Default",
                    "transport": tag,
                    "uri": fn(row, host, host, f"🌐 {row['name']} · {tag}")})
        for cip in clean_ips:
            note = cip["remark"] or cip["address"]
            out.append({"label": f"⚡ {note} · {tag}",
                        "transport": tag,
                        "uri": fn(row, cip["address"], host,
                                  f"⚡ {row['name']} · {note} · {tag}")})
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


class CleanIpBulkIn(BaseModel):
    text: str


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
    return [dict(r) for r in rows]


@app.post("/api/clean-ips")
async def add_clean_ip(body: CleanIpIn, _=Depends(require_admin)):
    addr = body.address.strip()
    if not valid_address(addr):
        raise HTTPException(400, "invalid IP or domain")
    try:
        with db() as c:
            c.execute("INSERT INTO clean_ips(address,remark,enabled,added_at) "
                      "VALUES(?,?,1,?)", (addr, body.remark.strip()[:40], now()))
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
                c.execute("INSERT INTO clean_ips(address,remark,enabled,added_at) "
                          "VALUES(?,?,1,?)", (addr, remark, now()))
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


# ────────────────────────────── STATS ──────────────────────────────

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
            "keepalive": KEEPALIVE, "keepalive_mins": KEEPALIVE_MINS}


@app.get("/api/logs")
async def logs(_=Depends(require_admin)):
    with db() as c:
        rows = c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 80").fetchall()
    return [dict(r) for r in rows]


# ────────────────────────────── SUBSCRIPTION ──────────────────────────────

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

    body = base64.b64encode("\n".join(lines).encode()).decode()
    headers = {
        "profile-title": "base64:" + base64.b64encode(f"⚡ {row['name']}".encode()).decode(),
        "profile-update-interval": "12",
        "profile-web-page-url": f"https://{d}/",
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
:root{--bg:#020617;--panel:#0b1220;--card:#ffffff0d;--line:#ffffff17;--txt:#e2e8f0;
      --dim:#94a3b8;--a1:#6366f1;--a2:#d946ef;--ok:#34d399;--bad:#fb7185;--info:#38bdf8}
[data-theme="ocean"]{--bg:#04121f;--panel:#07203a;--a1:#0ea5e9;--a2:#22d3ee}
[data-theme="forest"]{--bg:#04160f;--panel:#062718;--a1:#10b981;--a2:#84cc16}
[data-theme="sunset"]{--bg:#1a0710;--panel:#2b0c1a;--a1:#f97316;--a2:#ec4899}
[data-theme="violet"]{--bg:#0e0524;--panel:#190a3a;--a1:#8b5cf6;--a2:#c026d3}
[data-theme="light"]{--bg:#f1f5f9;--panel:#ffffff;--card:#ffffff;--line:#0f172a17;
                     --txt:#0f172a;--dim:#64748b;--a1:#4f46e5;--a2:#c026d3}
body{background:var(--bg);color:var(--txt)}
.card{background:var(--card);border:1px solid var(--line)}
.grad{background-image:linear-gradient(to right,var(--a1),var(--a2))}
.dim{color:var(--dim)}
.inp{background:color-mix(in srgb,var(--bg) 65%,#8881);border:1px solid var(--line);color:var(--txt)}
.inp:focus{border-color:var(--a1);outline:none}
.soft{background:color-mix(in srgb,var(--txt) 8%,transparent)}
.navi{display:flex;align-items:center;gap:.6rem;padding:.7rem .9rem;border-radius:.85rem;
      font-size:.85rem;cursor:pointer;transition:.15s}
.navi:hover{background:color-mix(in srgb,var(--txt) 7%,transparent)}
.navi.on{background-image:linear-gradient(to right,var(--a1),var(--a2));color:#fff;font-weight:700}
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
  addedN:'افزوده شد',dupN:'تکراری',invalidN:'نامعتبر',noCleanIps:'لیست خالی است',
  settings:'تنظیمات',appearance:'ظاهر',theme:'تم',language:'زبان',
  changePw:'تغییر رمز عبور',curPw:'رمز فعلی',newPw:'رمز جدید',pwChanged:'رمز تغییر کرد ✓',
  serverInfo:'اطلاعات سرور',wsPathLbl:'مسیر WebSocket',xhPathLbl:'مسیر XHTTP',
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
  addedN:'added',dupN:'duplicates',invalidN:'invalid',noCleanIps:'List is empty',
  settings:'Settings',appearance:'Appearance',theme:'Theme',language:'Language',
  changePw:'Change password',curPw:'Current password',newPw:'New password',
  pwChanged:'Password changed ✓',
  serverInfo:'Server info',wsPathLbl:'WebSocket path',xhPathLbl:'XHTTP path',
  devWinLbl:'Device counting window',seconds:'seconds',
  envNote:'These come from environment variables and can be changed in Railway.',
  logout:'Sign out',logs:'Events',noLogs:'No events yet',
  statusDisabled:'disabled',statusExpired:'expired',statusQuota:'quota used',
 }
};
let LANG=localStorage.getItem('lang')||'fa';
let THEME=localStorage.getItem('theme')||'default';
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
   <option value="default">🌌 Midnight</option><option value="ocean">🌊 Ocean</option>
   <option value="forest">🌿 Forest</option><option value="sunset">🌅 Sunset</option>
   <option value="violet">🔮 Violet</option><option value="light">☀️ Light</option></select>
 </div>
 <div class="mb-6 text-center">
  <div class="mx-auto mb-3 h-14 w-14 rounded-2xl grad grid place-items-center text-2xl">⚡</div>
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
          class="h-9 w-9 rounded-xl soft grid place-items-center text-lg">☰</button>
  <div class="h-9 w-9 rounded-xl grad grid place-items-center">⚡</div>
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
  <div class="h-10 w-10 rounded-xl grad grid place-items-center text-lg">⚡</div>
  <div><p class="font-extrabold text-sm">{{TITLE}}</p>
       <p class="text-[10px] dim">admin</p></div>
  <button onclick="toggleNav()" class="ms-auto dim text-lg">✕</button>
 </div>

 <div class="navi" data-page="dash"     onclick="go('dash')"><span>📊</span><span data-t="navDash"></span></div>
 <div class="navi" data-page="users"    onclick="go('users')"><span>👥</span><span data-t="navUsers"></span></div>
 <div class="navi" data-page="clean"    onclick="go('clean')"><span>🧊</span><span data-t="navClean"></span></div>
 <div class="navi" data-page="settings" onclick="go('settings')"><span>⚙️</span><span data-t="navSettings"></span></div>
 <div class="navi" data-page="logs"     onclick="go('logs')"><span>📜</span><span data-t="navLogs"></span></div>

 <div class="pt-3 mt-3 border-t space-y-2" style="border-color:var(--line)">
  <div class="flex gap-2">
   <select id="thSel" onchange="setTheme(this.value)" class="inp rounded-lg px-2 py-1.5 text-xs flex-1">
    <option value="default">🌌 Midnight</option><option value="ocean">🌊 Ocean</option>
    <option value="forest">🌿 Forest</option><option value="sunset">🌅 Sunset</option>
    <option value="violet">🔮 Violet</option><option value="light">☀️ Light</option></select>
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
   <div class="grid sm:grid-cols-3 gap-2">
    <input id="cAddr" class="inp rounded-xl px-3 py-2 text-sm">
    <input id="cRem" class="inp rounded-xl px-3 py-2 text-sm">
    <button onclick="addCip()" id="btnCipAdd" class="grad rounded-xl px-4 py-2 text-sm font-bold text-white"></button>
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

 <!-- ══ SETTINGS ══ -->
 <section data-pg="settings" class="space-y-4 hidden">
  <div class="card rounded-2xl p-4 space-y-3">
   <p class="text-sm font-bold" data-t="appearance"></p>
   <div class="grid sm:grid-cols-2 gap-2">
    <div><label class="text-xs dim" data-t="theme"></label>
     <select id="thSel2" onchange="setTheme(this.value);syncSelects()" class="w-full inp rounded-xl px-3 py-2 text-sm mt-1">
      <option value="default">🌌 Midnight</option><option value="ocean">🌊 Ocean</option>
      <option value="forest">🌿 Forest</option><option value="sunset">🌅 Sunset</option>
      <option value="violet">🔮 Violet</option><option value="light">☀️ Light</option></select></div>
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
}
let navOpen=false;
function toggleNav(force){
 navOpen = force===undefined?!navOpen:force;
 placeNav(navOpen);
 scrim.classList.toggle('hidden',!navOpen);
}
placeNav(false);

/* ─── routing ─── */
let PAGE=localStorage.getItem('page')||'dash';
function go(p){
 PAGE=p; localStorage.setItem('page',p);
 document.querySelectorAll('[data-pg]').forEach(s=>s.classList.toggle('hidden',s.dataset.pg!==p));
 document.querySelectorAll('.navi').forEach(n=>n.classList.toggle('on',n.dataset.page===p));
 crumb.textContent=T({dash:'navDash',users:'navUsers',clean:'navClean',
   settings:'navSettings',logs:'navLogs'}[p]);
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
   <span class="mono text-[11px]">${x.address}</span>
   ${x.remark?`<span class="text-[10px] dim">${x.remark}</span>`:''}
   <div class="flex-1"></div>
   <button onclick="toggleCip(${x.id})" class="text-[10px] px-2 py-0.5 rounded-lg soft">${x.enabled?'⏸':'▶️'}</button>
   <button onclick="delCip(${x.id})" class="text-[10px] px-2 py-0.5 rounded-lg" style="color:var(--bad)">✕</button>
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
  body:JSON.stringify({address:cAddr.value.trim(),remark:cRem.value.trim()})});
  cAddr.value='';cRem.value='';loadCips();loadStats();
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
loadStats();loadUsers();loadCips();
setInterval(()=>{loadStats();if(PAGE==='users')loadUsers()},15000);
</script></body></html>"""

AUTH_HTML  = AUTH_HTML.replace("__THEME__", THEME_CSS).replace("__I18N__", I18N_JS)
PANEL_HTML = PANEL_HTML.replace("__THEME__", THEME_CSS).replace("__I18N__", I18N_JS)
