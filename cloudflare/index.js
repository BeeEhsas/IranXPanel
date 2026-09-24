var __freeze = Object.freeze;
var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __template = (cooked, raw) => __freeze(__defProp(cooked, "raw", { value: __freeze(raw || cooked.slice()) }));

// src/auth.js
var enc = new TextEncoder();
var dec = new TextDecoder();
var randomHex = /* @__PURE__ */ __name((n) => {
  const b = crypto.getRandomValues(new Uint8Array(n));
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}, "randomHex");
async function hashPassword(password, iterations = 21e4) {
  const salt = randomHex(16);
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations }, key, 256);
  const hash = [...new Uint8Array(bits)].map((x) => x.toString(16).padStart(2, "0")).join("");
  return { algorithm: "PBKDF2-SHA256", iterations, salt, hash };
}
__name(hashPassword, "hashPassword");
async function verifyPassword(password, stored) {
  try {
    if (!stored?.salt || !stored?.hash) return false;
    const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(stored.salt), iterations: Number(stored.iterations) || 21e4 }, key, 256);
    const actual = [...new Uint8Array(bits)].map((x) => x.toString(16).padStart(2, "0")).join("");
    let diff = actual.length ^ stored.hash.length;
    for (let i = 0; i < actual.length; i++) diff |= actual.charCodeAt(i) ^ (stored.hash.charCodeAt(i) || 0);
    return diff === 0;
  } catch {
    return false;
  }
}
__name(verifyPassword, "verifyPassword");
var b64url = /* @__PURE__ */ __name((b) => Buffer.from(b).toString("base64url"), "b64url");
var unb64url = /* @__PURE__ */ __name((s) => Buffer.from(s, "base64url").toString("utf8"), "unb64url");
async function makeSession(secret, ttlSeconds = 43200, now2 = Math.floor(Date.now() / 1e3)) {
  const payload = b64url(JSON.stringify({ sub: "admin", iat: now2, exp: now2 + ttlSeconds }));
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(payload)));
  return `${payload}.${Buffer.from(sig).toString("base64url")}`;
}
__name(makeSession, "makeSession");
async function verifySession(token, secret, now2 = Math.floor(Date.now() / 1e3)) {
  try {
    const [payload, signature] = String(token || "").split(".");
    if (!payload || !signature) return false;
    const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const ok = await crypto.subtle.verify("HMAC", key, Buffer.from(signature, "base64url"), enc.encode(payload));
    if (!ok) return false;
    const data = JSON.parse(unb64url(payload));
    return data.sub === "admin" && Number(data.exp) > now2;
  } catch {
    return false;
  }
}
__name(verifySession, "verifySession");
function readCookie(request, name) {
  const value = String(request.headers.get("cookie") || "").split(";").map((x) => x.trim()).find((x) => x.startsWith(`${name}=`));
  return value ? decodeURIComponent(value.slice(name.length + 1)) : "";
}
__name(readCookie, "readCookie");

// src/model.js
var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
var nonNegative = /* @__PURE__ */ __name((v) => Math.max(0, Number.isFinite(Number(v)) ? Number(v) : 0), "nonNegative");
var isValidName = /* @__PURE__ */ __name((name) => /^[A-Za-z0-9_.-]{2,32}$/.test(String(name || "")), "isValidName");
var isValidAddress = /* @__PURE__ */ __name((value) => {
  const s = String(value || "");
  if (s.length > 253) return false;
  if (s.includes(":")) return /^[0-9A-Fa-f:.]+$/.test(s) && s.includes("::") === false;
  return /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(s);
}, "isValidAddress");
var passwordPolicy = /* @__PURE__ */ __name((p) => /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/.test(String(p || "")), "passwordPolicy");
var userStatus = /* @__PURE__ */ __name((u, now2 = Date.now() / 1e3) => {
  if (!u?.enabled) return [false, "disabled"];
  if (u.expire_at && u.expire_at < now2) return [false, "expired"];
  if (u.quota_bytes && u.used_bytes >= u.quota_bytes) return [false, "quota exceeded"];
  return [true, "active"];
}, "userStatus");
function publicUser(u) {
  if (!u) return null;
  const { password_hash, ...safe } = u;
  const [active, status] = userStatus(u);
  return { ...safe, active, status };
}
__name(publicUser, "publicUser");
function vlessLink({ user, host, type, path, ip, label }) {
  const address = ip || host;
  const q = new URLSearchParams({ encryption: "none", security: "tls", sni: host, type, host, path });
  return `vless://${user.uuid}@${address}:443?${q}#${encodeURIComponent(label || `IranX ${user.name} ${type.toUpperCase()}`)}`;
}
__name(vlessLink, "vlessLink");
function countryFlag(code) {
  const c = String(code || "").replace(/[^A-Za-z]/g, "").slice(0, 2).toUpperCase();
  return c.length === 2 ? [...c].map((x) => String.fromCodePoint(127397 + x.charCodeAt(0) - 65)).join("") : "\u{1F310}";
}
__name(countryFlag, "countryFlag");
async function buildSubscription({ user, host, cleanIps = [], proxies = [], wsPath = "ws", xhttpPath = "xh" }) {
  const [ok] = userStatus(user);
  if (!ok) return "";
  const info = `\u{1F4CA} ${user.name} | ${(user.used_bytes / 1073741824).toFixed(2)}GB used`;
  const links = [];
  if (["ws", "both"].includes(user.transport)) {
    links.push(vlessLink({ user, host, type: "ws", path: `/${wsPath}-d`, label: `\u{1F310} ${user.name} \xB7 Direct` }));
    for (const row of cleanIps.filter((x) => x.enabled)) links.push(vlessLink({ user, host, type: "ws", path: `/${wsPath}-d`, ip: row.address, label: `${countryFlag(row.country)} ${row.remark || row.address} \xB7 Direct` }));
    for (const px of proxies.filter((x) => x.enabled)) {
      const spot = px.city || px.country_name || px.remark || px.host;
      const label = `${countryFlag(px.country)} ${spot}${spot ? " \xB7 " : ""}${user.name}`;
      links.push(vlessLink({ user, host, type: "ws", path: `/${wsPath}-p${px.id}`, label }));
    }
  }
  if (["xhttp", "both"].includes(user.transport)) {
    const session = crypto.randomUUID().replaceAll("-", "").slice(0, 16);
    links.push(vlessLink({ user, host, type: "xhttp", path: `/${xhttpPath}/${session}`, label: `\u{1F310} ${user.name} \xB7 XHTTP Direct` }));
    for (const px of proxies.filter((x) => x.enabled)) {
      const sid = crypto.randomUUID().replaceAll("-", "").slice(0, 16), spot = px.city || px.country_name || px.remark || px.host;
      links.push(vlessLink({ user, host, type: "xhttp", path: `/${xhttpPath}-p${px.id}/${sid}`, label: `${countryFlag(px.country)} ${spot} \xB7 XHTTP` }));
    }
  }
  return [info, ...links].join("\n");
}
__name(buildSubscription, "buildSubscription");

// src/vless-worker.js
import { connect } from "cloudflare:sockets";

// src/vless-core.js
function buildVlessRequest(input) {
  const b = Buffer.from(input);
  if (b.length < 18 || b[0] !== 0) throw new Error("invalid VLESS header");
  const uuid = `${b.subarray(1, 5).toString("hex")}-${b.subarray(5, 7).toString("hex")}-${b.subarray(7, 9).toString("hex")}-${b.subarray(9, 11).toString("hex")}-${b.subarray(11, 17).toString("hex")}`;
  let pos = 17;
  b[pos];
  pos += b[pos] + 1;
  if (b.length < pos + 4) throw new Error("truncated VLESS header");
  const command = b[pos], port = b[pos + 1] << 8 | b[pos + 2], type = b[pos + 3];
  pos += 4;
  let host = "";
  if (type === 1) {
    if (b.length < pos + 4) throw new Error("truncated address");
    host = b.subarray(pos, pos + 4).join(".");
    pos += 4;
  } else if (type === 2) {
    const n = b[pos++];
    if (n < 1 || b.length < pos + n) throw new Error("truncated address");
    host = b.subarray(pos, pos + n).toString("utf8");
    pos += n;
  } else if (type === 3) {
    if (b.length < pos + 16) throw new Error("truncated address");
    const h = [...b.subarray(pos, pos + 16)].map((x) => x.toString(16).padStart(2, "0"));
    host = `${h.slice(0, 4).join(":")}:${h.slice(4, 8).join(":")}:${h.slice(8, 12).join(":")}:${h.slice(12).join(":")}`;
    pos += 16;
  } else throw new Error("unsupported address type");
  if (!host || host.length > 253 || port < 1 || port > 65535) throw new Error("invalid destination");
  return { uuid, command, host, port, payload: b.subarray(pos) };
}
__name(buildVlessRequest, "buildVlessRequest");
var isBlockedHost = /* @__PURE__ */ __name((host) => {
  const h = String(host || "").toLowerCase().replace(/\.$/, "");
  if (!h || h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal") || h === "::" || h === "::1" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80:")) return true;
  const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const a = m.slice(1).map(Number);
  return a[0] === 127 || a[0] === 10 || a[0] === 0 || a.some(Number.isNaN) || a.some((x) => x < 0 || x > 255) || a[0] === 169 && a[1] === 254 || a[0] === 172 && a[1] >= 16 && a[1] <= 31 || a[0] === 192 && a[1] === 168 || a[0] === 100 && a[1] >= 64 && a[1] <= 127 || a[0] >= 224;
}, "isBlockedHost");

// src/proxy.js
var encoder = new TextEncoder();
var decoder = new TextDecoder();
var sleep = /* @__PURE__ */ __name((ms) => new Promise((resolve) => setTimeout(resolve, ms)), "sleep");
async function waitOpened(socket) {
  for (let i = 0; i < 80; i++) {
    if (socket.opened) return;
    if (!socket.started) await sleep(25);
    else await socket.opened;
  }
  throw new Error("proxy connection timeout");
}
__name(waitOpened, "waitOpened");
var SocketReader = class {
  static {
    __name(this, "SocketReader");
  }
  constructor(reader) {
    this.reader = reader;
    this.buffer = Buffer.alloc(0);
  }
  async fill() {
    const { done, value } = await this.reader.read();
    if (done) throw new Error("proxy closed during handshake");
    this.buffer = Buffer.concat([this.buffer, Buffer.from(value)]);
  }
  async exact(size) {
    while (this.buffer.length < size) await this.fill();
    const out = this.buffer.subarray(0, size);
    this.buffer = this.buffer.subarray(size);
    return out;
  }
  async line(max = 16384) {
    let end;
    while ((end = this.buffer.indexOf("\r\n")) < 0) {
      if (this.buffer.length > max) throw new Error("proxy response header too large");
      await this.fill();
    }
    const out = this.buffer.subarray(0, end).toString("latin1");
    this.buffer = this.buffer.subarray(end + 2);
    return out;
  }
  async read() {
    if (this.buffer.length) {
      const out = this.buffer;
      this.buffer = Buffer.alloc(0);
      return { done: false, value: out };
    }
    return this.reader.read();
  }
};
function isIPv4(host) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(String(host)) && String(host).split(".").every((x) => Number(x) >= 0 && Number(x) <= 255);
}
__name(isIPv4, "isIPv4");
function isIPv6(host) {
  return /^[0-9a-f]*:[0-9a-f:.]+$/i.test(String(host)) && String(host).includes(":");
}
__name(isIPv6, "isIPv6");
function addressBytes(host) {
  if (isIPv4(host)) return { type: 1, bytes: Buffer.from(host.split(".").map(Number)) };
  if (isIPv6(host)) {
    const raw2 = Buffer.from(host.replaceAll("%", ""), "utf8");
    const parts = host.split(":").map((x) => parseInt(x || "0", 16));
    if (parts.length !== 8) throw new Error("invalid IPv6 destination");
    return { type: 4, bytes: Buffer.from(parts.flatMap((x) => [x >> 8, x & 255])) };
  }
  if (!host || !/^[A-Za-z0-9_.-]+$/.test(host)) throw new Error("invalid destination hostname");
  const raw = encoder.encode(host);
  if (raw.length > 255) throw new Error("invalid destination hostname");
  return { type: 3, bytes: Buffer.concat([Buffer.from([raw.length]), raw]) };
}
__name(addressBytes, "addressBytes");
function buildSocks5Greeting(px) {
  return Buffer.from(px.username ? [5, 2, 0, 2] : [5, 1, 0]);
}
__name(buildSocks5Greeting, "buildSocks5Greeting");
function buildSocks5Auth(px) {
  const u = encoder.encode(px.username), p = encoder.encode(px.password || "");
  if (!u.length || u.length > 255 || p.length > 255) throw new Error("invalid SOCKS5 credentials");
  return Buffer.concat([Buffer.from([1, u.length]), u, Buffer.from([p.length]), p]);
}
__name(buildSocks5Auth, "buildSocks5Auth");
function buildSocks5Connect(host, port) {
  const { type, bytes } = addressBytes(host);
  return Buffer.concat([Buffer.from([5, 1, 0]), Buffer.from([port >> 8, port & 255]), Buffer.from([type]), bytes]);
}
__name(buildSocks5Connect, "buildSocks5Connect");
function buildSocks4Connect(host, port) {
  if (!isIPv4(host)) throw new Error("SOCKS4 requires an IPv4 destination");
  const ipv4 = Buffer.from(host.split(".").map(Number));
  return Buffer.concat([Buffer.from([4, 1, port >> 8, port & 255]), ipv4, Buffer.from([0])]);
}
__name(buildSocks4Connect, "buildSocks4Connect");
function buildHttpConnect(px, host, port) {
  const authority = `${host}:${port}`;
  const auth = px.username ? `Proxy-Authorization: Basic ${btoa(`${px.username}:${px.password || ""}`)}\r
` : "";
  return Buffer.from(`CONNECT ${authority} HTTP/1.1\r
Host: ${authority}\r
${auth}Proxy-Connection: Keep-Alive\r
\r
`);
}
__name(buildHttpConnect, "buildHttpConnect");
async function openThroughProxy(px, host, port, connect2) {
  const socket = connect2({ hostname: px.host, port: px.port }, { secureTransport: "off", allowHalfOpen: true });
  const writer = socket.writable.getWriter();
  const stream = new SocketReader(socket.readable.getReader());
  try {
    if (px.kind === "socks5") {
      await writer.write(buildSocks5Greeting(px));
      const greeting = await stream.exact(2);
      if (greeting[0] !== 5) throw new Error("invalid SOCKS5 greeting");
      if (greeting[1] === 2) {
        await writer.write(buildSocks5Auth(px));
        const authReply = await stream.exact(2);
        if (authReply[0] !== 5 || authReply[1] !== 0) throw new Error("SOCKS5 authentication failed");
      } else if (greeting[1] !== 0) throw new Error("SOCKS5 rejected offered authentication methods");
      await writer.write(buildSocks5Connect(host, port));
      const reply = await stream.exact(4);
      if (reply[0] !== 5 || reply[1] !== 0) throw new Error(`SOCKS5 connect failed (${reply[1]})`);
      if (reply[3] === 1) await stream.exact(4);
      else if (reply[3] === 3) await stream.exact(1 + (await stream.exact(1))[0]);
      else if (reply[3] === 4) await stream.exact(16);
      else throw new Error("invalid SOCKS5 address reply");
    } else if (px.kind === "socks4") {
      await writer.write(buildSocks4Connect(host, port));
      const reply = await stream.exact(8);
      if (reply[0] !== 0 || reply[1] !== 90) throw new Error(`SOCKS4 connect failed (${reply[1]})`);
    } else if (px.kind === "http") {
      await writer.write(buildHttpConnect(px, host, port));
      const status = await stream.line();
      if (!/^HTTP\/1\.[01] 200(?:\s|$)/i.test(status)) throw new Error(`HTTP proxy connect failed (${status})`);
      while (true) {
        const line = await stream.line();
        if (!line) break;
      }
    } else throw new Error("unsupported proxy kind");
    await waitOpened(socket);
    return { socket, writer, reader: stream };
  } catch (error) {
    try {
      await writer.abort(error);
    } catch {
    }
    try {
      stream.reader.releaseLock();
    } catch {
    }
    try {
      socket.close();
    } catch {
    }
    throw error;
  }
}
__name(openThroughProxy, "openThroughProxy");
async function proxyHealth(px, connect2) {
  const started = Date.now();
  const { writer, reader, socket } = await openThroughProxy(px, "api.ipify.org", 80, connect2);
  try {
    await writer.write(Buffer.from("GET /json HTTP/1.1\r\nHost: api.ipify.org\r\nUser-Agent: IranXPanel/3\r\nAccept: application/json\r\nConnection: close\r\n\r\n"));
    const chunks = [];
    let size = 0;
    while (size < 131072) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      chunks.push(chunk);
      size += chunk.length;
    }
    const raw = Buffer.concat(chunks).toString();
    const match = raw.match(/\{[\s\S]*\}/);
    if (!match) throw new Error("proxy IP echo was unreadable");
    let data;
    try {
      data = JSON.parse(match[0]);
    } catch {
      throw new Error("proxy IP echo was invalid JSON");
    }
    const exitIp = String(data.query || data.ip || "").trim();
    if (!/^[0-9a-f:.]+$/i.test(exitIp)) throw new Error("proxy IP echo had no IP");
    return { ok: true, exit_ip: exitIp, country: "", country_name: "", city: "", isp: "", latency_ms: Date.now() - started };
  } finally {
    try {
      await writer.close();
    } catch {
    }
    try {
      reader.reader.releaseLock();
    } catch {
    }
    try {
      socket.close();
    } catch {
    }
  }
}
__name(proxyHealth, "proxyHealth");

// src/vless.js
async function readVlessFromStream(readable) {
  const reader = readable.getReader(), chunks = [];
  let size = 0;
  try {
    while (size < 18) {
      const { done, value } = await reader.read();
      if (done) throw new Error("closed before VLESS header");
      chunks.push(Buffer.from(value));
      size += value.length;
    }
    let b = Buffer.concat(chunks), p = 18 + b[17], type = b[p + 3];
    if (type === 1) p += 4;
    else if (type === 2) p += 1 + b[p + 4];
    else if (type === 3) p += 16;
    else throw new Error("unsupported address type");
    while (size < p) {
      const { done, value } = await reader.read();
      if (done) throw new Error("truncated VLESS header");
      chunks.push(Buffer.from(value));
      size += value.length;
      b = Buffer.concat(chunks);
    }
    return { request: buildVlessRequest(Buffer.concat(chunks)), reader };
  } catch (e) {
    reader.releaseLock();
    throw e;
  }
}
__name(readVlessFromStream, "readVlessFromStream");
async function pipeVlessWebSocket(pair, env, clientIp2, connect2, route = { direct: false, pid: 0 }) {
  const { request, reader } = await readVlessFromStream(pair.client);
  const row = await env.DB.prepare("SELECT * FROM users WHERE uuid=?").bind(request.uuid).first(), t = Date.now() / 1e3;
  if (!row || !row.enabled || row.expire_at && row.expire_at < t || row.quota_bytes && row.used_bytes >= row.quota_bytes || request.command !== 1) {
    await pair.server.close(1008, "unauthorized");
    return;
  }
  if (isBlockedHost(request.host)) {
    await pair.server.close(1008, "destination denied");
    return;
  }
  if (row.device_limit > 0) {
    const { results: devices = [] } = await env.DB.prepare("SELECT DISTINCT ip FROM user_ips WHERE user_id=? AND last_seen>?").bind(row.id, Date.now() - Number(env.DEVICE_WINDOW || 300) * 1e3).all();
    if (devices.length >= row.device_limit && !devices.some((device) => device.ip === clientIp2)) {
      await pair.server.close(1008, "device limit reached");
      return;
    }
  }
  let sock, writer, socketReader;
  if (route.pid) {
    const px = await env.DB.prepare("SELECT * FROM proxies WHERE id=? AND enabled=1").bind(route.pid).first();
    if (!px) {
      await pair.server.close(1008, "proxy unavailable");
      return;
    }
    try {
      ({ socket: sock, writer, reader: socketReader } = await openThroughProxy(px, request.host, request.port, connect2));
    } catch (e) {
      await env.DB.prepare("UPDATE proxies SET last_error=?,checked_at=? WHERE id=?").bind(String(e.message).slice(0, 200), Math.floor(Date.now() / 1e3), px.id).run().catch(() => {
      });
      await pair.server.close(1011, "proxy connect failed");
      return;
    }
  } else {
    sock = connect2({ hostname: request.host, port: request.port }, { secureTransport: "off", allowHalfOpen: true });
    writer = sock.writable.getWriter();
    socketReader = sock.readable.getReader();
  }
  const firstPayload = request.payload.length;
  let up = firstPayload, down = 0;
  if (firstPayload) await writer.write(request.payload);
  const uplink = (async () => {
    try {
      for (; ; ) {
        const { done, value } = await reader.read();
        if (done) break;
        up += value.length;
        await writer.write(value);
      }
    } catch {
    } finally {
      try {
        await writer.close();
      } catch {
      }
      ;
      try {
        sock.close();
      } catch {
      }
    }
  })();
  const send = (async () => {
    let first = true;
    try {
      for (; ; ) {
        const { done, value } = await socketReader.read();
        if (done) break;
        down += value.length;
        const out = first ? Buffer.concat([Buffer.from([0, 0]), value]) : value;
        first = false;
        await pair.server.send(out);
      }
    } catch {
    }
    try {
      await pair.server.close();
    } catch {
    }
  })();
  await Promise.all([uplink, send]);
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET used_bytes=used_bytes+? WHERE id=?").bind(up + down, row.id),
    env.DB.prepare("INSERT INTO user_ips(user_id,ip,proto,first_seen,last_seen,hits) VALUES(?,?,?,?,?,1) ON CONFLICT(user_id,ip) DO UPDATE SET last_seen=excluded.last_seen,hits=user_ips.hits+1").bind(row.id, clientIp2, route.pid ? "ws-proxy" : "ws", Date.now(), Date.now()),
    env.DB.prepare("INSERT INTO traffic_log(user_id,ts,up,down) VALUES(?,?,?,?)").bind(row.id, Date.now(), up, down)
  ]).catch(() => {
  });
}
__name(pipeVlessWebSocket, "pipeVlessWebSocket");

// src/vless-worker.js
var handleVlessWebSocket = pipeVlessWebSocket;

// src/ui.js
var _a;
var AUTH_HTML = String.raw(_a || (_a = __template([`<!DOCTYPE html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}}</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;800&display=swap" rel="stylesheet">
<style>body{font-family:Vazirmatn,system-ui,sans-serif}
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

.glow{background:radial-gradient(60% 55% at 50% 0%,color-mix(in srgb,var(--a1) 40%,transparent),transparent 70%)}
</style></head><body class="min-h-screen flex items-center justify-center p-4">
<script>
const I18N={
 fa:{dir:'rtl',
  setupTitle:'\u062A\u0639\u06CC\u06CC\u0646 \u0631\u0645\u0632 \u0639\u0628\u0648\u0631',setupSub:'\u0627\u0648\u0644\u06CC\u0646 \u0648\u0631\u0648\u062F \u2014 \u06CC\u06A9 \u0631\u0645\u0632 \u0628\u0631\u0627\u06CC \u067E\u0646\u0644 \u0627\u0646\u062A\u062E\u0627\u0628 \u06A9\u0646\u06CC\u062F',
  loginTitle:'\u0648\u0631\u0648\u062F \u0628\u0647 \u067E\u0646\u0644',loginSub:'\u0631\u0645\u0632 \u0639\u0628\u0648\u0631 \u062E\u0648\u062F \u0631\u0627 \u0648\u0627\u0631\u062F \u06A9\u0646\u06CC\u062F',
  password:'\u0631\u0645\u0632 \u0639\u0628\u0648\u0631',confirm:'\u062A\u06A9\u0631\u0627\u0631 \u0631\u0645\u0632 \u0639\u0628\u0648\u0631',enter:'\u0648\u0631\u0648\u062F',save:'\u0630\u062E\u06CC\u0631\u0647 \u0648 \u0648\u0631\u0648\u062F',
  pwRule:'\u062D\u062F\u0627\u0642\u0644 \u06F8 \u06A9\u0627\u0631\u0627\u06A9\u062A\u0631 \u0634\u0627\u0645\u0644 \u062D\u0631\u0641 \u0628\u0632\u0631\u06AF\u060C \u062D\u0631\u0641 \u06A9\u0648\u0686\u06A9 \u0648 \u0639\u062F\u062F',netErr:'\u062E\u0637\u0627\u06CC \u0634\u0628\u06A9\u0647',
  navDash:'\u062F\u0627\u0634\u0628\u0648\u0631\u062F',navUsers:'\u0645\u062F\u06CC\u0631\u06CC\u062A \u06A9\u0627\u0631\u0628\u0631\u0627\u0646',navClean:'Clean IP',
  navProxy:'\u067E\u0631\u0648\u06A9\u0633\u06CC',navLive:'\u0627\u062A\u0635\u0627\u0644\u0627\u062A \u0632\u0646\u062F\u0647',
  navSettings:'\u062A\u0646\u0638\u06CC\u0645\u0627\u062A \u067E\u0646\u0644',navLogs:'\u0631\u062E\u062F\u0627\u062F\u0647\u0627',menu:'\u0645\u0646\u0648',
  totalUsers:'\u06A9\u0644 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646',online:'\u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0622\u0646\u0644\u0627\u06CC\u0646',devices:'\u062F\u0633\u062A\u06AF\u0627\u0647\u200C\u0647\u0627\u06CC \u0645\u062A\u0635\u0644',
  traffic:'\u0645\u0635\u0631\u0641 \u06A9\u0644',cleanIps:'\u0622\u06CC\u200C\u067E\u06CC \u062A\u0645\u06CC\u0632',xSessions:'\u0633\u0634\u0646\u200C\u0647\u0627\u06CC XHTTP',liveTitle:'\u0627\u062A\u0635\u0627\u0644\u0627\u062A \u0632\u0646\u062F\u0647',liveEmpty:'\u0647\u06CC\u0686 \u0627\u062A\u0635\u0627\u0644\u06CC \u0641\u0639\u0627\u0644 \u0646\u06CC\u0633\u062A',
  chart24:'\u0645\u0635\u0631\u0641 \u06F2\u06F4 \u0633\u0627\u0639\u062A \u0627\u062E\u06CC\u0631',protoSplit:'\u062A\u0642\u0633\u06CC\u0645 \u0628\u0631 \u0627\u0633\u0627\u0633 \u062A\u0631\u0646\u0633\u067E\u0648\u0631\u062A',
  newUser:'\u0633\u0627\u062E\u062A \u06A9\u0627\u0631\u0628\u0631 \u062C\u062F\u06CC\u062F',users:'\u06A9\u0627\u0631\u0628\u0631\u0627\u0646',
  name:'\u0646\u0627\u0645 (\u0627\u0646\u06AF\u0644\u06CC\u0633\u06CC)',quota:'\u062D\u062C\u0645 (GB)',days:'\u0645\u062F\u062A (\u0631\u0648\u0632)',devLimit:'\u062A\u0639\u062F\u0627\u062F \u062F\u0633\u062A\u06AF\u0627\u0647',
  transport:'\u062A\u0631\u0646\u0633\u067E\u0648\u0631\u062A',trWs:'\u{1F50C} WS + TLS',trXhttp:'\u{1F680} XHTTP + TLS',trBoth:'\u{1F500} \u0647\u0631 \u062F\u0648',
  add:'\u0627\u0641\u0632\u0648\u062F\u0646',zeroInf:'\u06F0 = \u0628\u06CC\u200C\u0646\u0647\u0627\u06CC\u062A. \xAB\u062A\u0639\u062F\u0627\u062F \u062F\u0633\u062A\u06AF\u0627\u0647\xBB \u0628\u0631 \u0627\u0633\u0627\u0633 IP \u06CC\u06A9\u062A\u0627\u06CC \u0641\u0639\u0627\u0644 \u0645\u062D\u0627\u0633\u0628\u0647 \u0645\u06CC\u200C\u0634\u0648\u062F.',
  search:'\u062C\u0633\u062A\u062C\u0648\u2026',noUsers:'\u06A9\u0627\u0631\u0628\u0631\u06CC \u0646\u06CC\u0633\u062A',
  config:'\u06A9\u0627\u0646\u0641\u06CC\u06AF',ipsBtn:'IP \u0647\u0627',edit:'\u0648\u06CC\u0631\u0627\u06CC\u0634',
  used:'\u0645\u0635\u0631\u0641',expiry:'\u0627\u0646\u0642\u0636\u0627',never:'\u0628\u06CC\u200C\u0646\u0647\u0627\u06CC\u062A',
  subLink:'\u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9 (Subscription)',copySub:'\u06A9\u067E\u06CC \u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9',
  singleCfg:'\u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627\u06CC \u062A\u06A9\u06CC',copy:'\u06A9\u067E\u06CC',copied:'\u06A9\u067E\u06CC \u0634\u062F \u2713',
  devTitle:'\u062F\u0633\u062A\u06AF\u0627\u0647\u200C\u0647\u0627\u06CC \u0645\u062A\u0635\u0644',noConn:'\u0647\u0646\u0648\u0632 \u0627\u062A\u0635\u0627\u0644\u06CC \u062B\u0628\u062A \u0646\u0634\u062F\u0647',
  clearIps:'\u067E\u0627\u06A9 \u06A9\u0631\u062F\u0646 \u0644\u06CC\u0633\u062A IP',
  liveNow:'\u0627\u0644\u0627\u0646 \u0645\u062A\u0635\u0644',noneNow:'\u0647\u0645\u06CC\u0646 \u0627\u0644\u0627\u0646 \u0647\u06CC\u0686 \u062F\u0633\u062A\u06AF\u0627\u0647\u06CC \u0645\u062A\u0635\u0644 \u0646\u06CC\u0633\u062A',
  countedFor:'\u0634\u0645\u0631\u062F\u0647\u200C\u0634\u062F\u0647 \u0628\u0631\u0627\u06CC \u0645\u062D\u062F\u0648\u062F\u06CC\u062A',totalSeen:'\u06A9\u0644 IP \u0647\u0627\u06CC \u062F\u06CC\u062F\u0647\u200C\u0634\u062F\u0647',
  showHistory:'\u0646\u0645\u0627\u06CC\u0634 \u062A\u0627\u0631\u06CC\u062E\u0686\u0647',showLive:'\u0646\u0645\u0627\u06CC\u0634 \u0641\u0642\u0637 \u0645\u062A\u0635\u0644\u200C\u0647\u0627',
  inLast:'\u062F\u0631 %s \u062B\u0627\u0646\u06CC\u0647 \u0627\u062E\u06CC\u0631',refresh:'\u0628\u0647\u200C\u0631\u0648\u0632\u0631\u0633\u0627\u0646\u06CC',
  liveDevices:'\u062F\u0633\u062A\u06AF\u0627\u0647\u200C\u0647\u0627\u06CC \u0641\u0639\u0627\u0644 \u0627\u0644\u0627\u0646',
  editUser:'\u0648\u06CC\u0631\u0627\u06CC\u0634',remainDays:'\u0645\u062F\u062A \u0628\u0627\u0642\u06CC\u200C\u0645\u0627\u0646\u062F\u0647 (\u0631\u0648\u0632)',allowedDev:'\u062A\u0639\u062F\u0627\u062F \u062F\u0633\u062A\u06AF\u0627\u0647 \u0645\u062C\u0627\u0632',
  active:'\u0641\u0639\u0627\u0644',saveBtn:'\u0630\u062E\u06CC\u0631\u0647',resetTraffic:'\u0631\u06CC\u0633\u062A \u062D\u062C\u0645',newUuid:'UUID \u062C\u062F\u06CC\u062F',
  customUuid:'UUID \u062F\u0633\u062A\u06CC',del:'\u062D\u0630\u0641',
  obfLbl:'\u0645\u0628\u0647\u0645\u200C\u0633\u0627\u0632 (Fragment + Cipher mask)',
  uuidWarn:'UUID \u0639\u0648\u0636 \u0634\u0648\u062F\u061F \u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627\u06CC \u0642\u0628\u0644\u06CC \u0627\u0632 \u06A9\u0627\u0631 \u0645\u06CC\u200C\u0627\u0641\u062A\u0646\u062F.',delWarn:'\u0627\u06CC\u0646 \u06A9\u0627\u0631\u0628\u0631 \u062D\u0630\u0641 \u0634\u0648\u062F\u061F',
  cleanTitle:'\u0645\u062F\u06CC\u0631\u06CC\u062A Clean IP',
  cleanHint:'\u0622\u06CC\u200C\u067E\u06CC \u06CC\u0627 \u062F\u0627\u0645\u0646\u0647 \u062A\u0645\u06CC\u0632. \u062F\u0631 \u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9 \u0647\u0631 \u06A9\u0627\u0631\u0628\u0631 \u0628\u0647 \u0639\u0646\u0648\u0627\u0646 \u06A9\u0627\u0646\u0641\u06CC\u06AF \u0627\u0636\u0627\u0641\u06CC \u0627\u0636\u0627\u0641\u0647 \u0645\u06CC\u200C\u0634\u0648\u062F.',
  addrPh:'\u0645\u062B\u0644\u0627 1.2.3.4 \u06CC\u0627 cdn.example.com',remarkPh:'\u0628\u0631\u0686\u0633\u0628 (\u0627\u062E\u062A\u06CC\u0627\u0631\u06CC)',
  bulkPh:'\u0686\u0646\u062F \u0645\u0648\u0631\u062F\u060C \u0647\u0631 \u062E\u0637 \u06CC\u06A9\u06CC:\\n1.2.3.4 # \u0627\u06CC\u0631\u0627\u0646\u0633\u0644\\n5.6.7.8 # \u0647\u0645\u0631\u0627\u0647 \u0627\u0648\u0644',
  bulkAdd:'\u0627\u0641\u0632\u0648\u062F\u0646 \u0627\u0646\u0628\u0648\u0647',clearAll:'\u062D\u0630\u0641 \u0647\u0645\u0647',
  pxTitle:'\u067E\u0631\u0648\u06A9\u0633\u06CC \u062E\u0631\u0648\u062C\u06CC',
  pxHint:'\u0628\u0627 \u0641\u0639\u0627\u0644 \u06A9\u0631\u062F\u0646 \u06CC\u06A9 \u067E\u0631\u0648\u06A9\u0633\u06CC\u060C \u062A\u0645\u0627\u0645 \u062A\u0631\u0627\u0641\u06CC\u06A9 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0627\u0632 \u0647\u0645\u0627\u0646 \u0645\u0633\u06CC\u0631 \u062E\u0627\u0631\u062C \u0645\u06CC\u200C\u0634\u0648\u062F \u0648 \u0633\u0627\u06CC\u062A\u200C\u0647\u0627 \u0627\u06CC\u067E\u06CC \u067E\u0631\u0648\u06A9\u0633\u06CC \u0631\u0627 \u0645\u06CC\u200C\u0628\u06CC\u0646\u0646\u062F.',
  pxKind:'\u0646\u0648\u0639',pxHost:'\u0647\u0627\u0633\u062A / \u0627\u06CC\u067E\u06CC',pxPort:'\u067E\u0648\u0631\u062A',
  pxUser:'\u06CC\u0648\u0632\u0631\u0646\u06CC\u0645 (\u0627\u062E\u062A\u06CC\u0627\u0631\u06CC)',pxPass:'\u067E\u0633\u0648\u0631\u062F (\u0627\u062E\u062A\u06CC\u0627\u0631\u06CC)',
  pxAdd:'\u0627\u0641\u0632\u0648\u062F\u0646 \u0648 \u062A\u0633\u062A',pxTestAll:'\u062A\u0633\u062A \u0647\u0645\u0647',
  pxInSub:'\u062F\u0631 \u0633\u0627\u0628',
  pxAutoNote:'\u0647\u0631 \u067E\u0631\u0648\u06A9\u0633\u06CC \u06A9\u0647 \u0627\u0636\u0627\u0641\u0647 \u0634\u0648\u062F \u062E\u0648\u062F\u0628\u0647\u200C\u062E\u0648\u062F \u062F\u0631 \u0633\u0627\u0628 \u0647\u0645\u0647 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0645\u06CC\u200C\u0622\u06CC\u062F \u2014 \u0647\u0645\u0647 \u0628\u0627 \u0647\u0645\u060C \u0628\u062F\u0648\u0646 \u062F\u06A9\u0645\u0647. \u06A9\u0627\u0646\u0641\u06CC\u06AF \u0628\u062F\u0648\u0646 \u067E\u0631\u0648\u06A9\u0633\u06CC \u0647\u0645\u06CC\u0634\u0647 \u0633\u0631 \u062C\u0627\u06CC\u0634 \u0647\u0633\u062A\u061B \u0642\u0637\u0639\u06CC \u06CC\u0627 \u0646\u0627\u0645\u0648\u0641\u0642 \u0628\u0648\u062F\u0646 \u062A\u0633\u062A\u060C \u067E\u0631\u0648\u06A9\u0633\u06CC \u0631\u0627 \u0627\u0632 \u0633\u0627\u0628 \u062D\u0630\u0641 \u0646\u0645\u06CC\u200C\u06A9\u0646\u062F \u0648 \u0641\u0642\u0637 \u0628\u0627 \u063A\u06CC\u0631\u0641\u0639\u0627\u0644 \u06A9\u0631\u062F\u0646 \u06CC\u0627 \u062D\u0630\u0641 \u0627\u0632 \u067E\u0646\u0644 \u0628\u06CC\u0631\u0648\u0646 \u0645\u06CC\u200C\u0631\u0648\u062F.',
  pxLineHint:'\u0647\u0631 \u062E\u0637 \u06CC\u06A9 \u067E\u0631\u0648\u06A9\u0633\u06CC \u2014 \u0645\u0627\u0646\u0646\u062F socks5://1.1.1.1:5866 \u06CC\u0627 http://user:pass@2.2.2.2:8080',
  pxAddLines:'\u0627\u0641\u0632\u0648\u062F\u0646 \u0644\u06CC\u0633\u062A \u0648 \u062A\u0633\u062A',
  pxAdvanced:'\u0648\u0631\u0648\u062F \u062F\u0633\u062A\u06CC \u0641\u06CC\u0644\u062F\u0647\u0627',
  pxDirect:'\u0627\u062A\u0635\u0627\u0644 \u0645\u0633\u062A\u0642\u06CC\u0645 (\u0628\u062F\u0648\u0646 \u067E\u0631\u0648\u06A9\u0633\u06CC)',
  pxActive:'\u0641\u0639\u0627\u0644',pxArm:'\u0641\u0639\u0627\u0644 \u06A9\u0631\u062F\u0646',pxTest:'\u062A\u0633\u062A \u0633\u0644\u0627\u0645\u062A',
  pxHealthy:'\u0633\u0627\u0644\u0645',pxDown:'\u062E\u0631\u0627\u0628',pxUntested:'\u062A\u0633\u062A \u0646\u0634\u062F\u0647',
  pxExitIp:'\u0627\u06CC\u067E\u06CC \u062E\u0631\u0648\u062C\u06CC',pxLatency:'\u062A\u0627\u062E\u06CC\u0631',
  pxNone:'\u0647\u0646\u0648\u0632 \u067E\u0631\u0648\u06A9\u0633\u06CC \u0627\u0636\u0627\u0641\u0647 \u0646\u0634\u062F\u0647 \u0627\u0633\u062A',
  pxStrict:'\u062D\u0627\u0644\u062A \u0633\u062E\u062A\u06AF\u06CC\u0631\u0627\u0646\u0647',
  pxStrictHint:'\u0627\u06AF\u0631 \u067E\u0631\u0648\u06A9\u0633\u06CC \u0642\u0637\u0639 \u0634\u062F\u060C \u0627\u062A\u0635\u0627\u0644 \u0631\u062F \u0645\u06CC\u200C\u0634\u0648\u062F \u062A\u0627 \u0627\u06CC\u067E\u06CC \u0627\u0635\u0644\u06CC \u0633\u0631\u0648\u0631 \u0644\u0648 \u0646\u0631\u0648\u062F',
  pxFlagSrc:'\u0645\u0646\u0628\u0639 \u067E\u0631\u0686\u0645 \u0646\u0627\u0645 \u06A9\u0627\u0646\u0641\u06CC\u06AF',
  pxFlagProxy:'\u06A9\u0634\u0648\u0631 \u067E\u0631\u0648\u06A9\u0633\u06CC',pxFlagEntry:'\u06A9\u0634\u0648\u0631 \u0633\u0631\u0648\u0631 \u0648\u0631\u0648\u062F\u06CC',
  pxTesting:'\u062F\u0631 \u062D\u0627\u0644 \u062A\u0633\u062A...',pxArmed:'\u067E\u0631\u0648\u06A9\u0633\u06CC \u0641\u0639\u0627\u0644 \u0634\u062F',
  pxDelWarn:'\u0627\u06CC\u0646 \u067E\u0631\u0648\u06A9\u0633\u06CC \u062D\u0630\u0641 \u0634\u0648\u062F\u061F',
  addedN:'\u0627\u0641\u0632\u0648\u062F\u0647 \u0634\u062F',dupN:'\u062A\u06A9\u0631\u0627\u0631\u06CC',invalidN:'\u0646\u0627\u0645\u0639\u062A\u0628\u0631',noCleanIps:'\u0644\u06CC\u0633\u062A \u062E\u0627\u0644\u06CC \u0627\u0633\u062A',
  settings:'\u062A\u0646\u0638\u06CC\u0645\u0627\u062A',appearance:'\u0638\u0627\u0647\u0631',theme:'\u062A\u0645',language:'\u0632\u0628\u0627\u0646',
  thDark:'\u062A\u06CC\u0631\u0647 (\u0645\u0634\u06A9\u06CC \u0648 \u0622\u0628\u06CC)',thLight:'\u0631\u0648\u0634\u0646 (\u0633\u0641\u06CC\u062F \u0648 \u0622\u0628\u06CC)',thGray:'\u062E\u0627\u06A9\u0633\u062A\u0631\u06CC',
  country:'\u06A9\u0634\u0648\u0631',autoCountry:'\u062A\u0634\u062E\u06CC\u0635 \u062E\u0648\u062F\u06A9\u0627\u0631',mainCountry:'\u06A9\u0634\u0648\u0631 \u0633\u0631\u0648\u0631 \u0627\u0635\u0644\u06CC',
  flagsHint:'\u067E\u0631\u0686\u0645 \u06A9\u0634\u0648\u0631 \u0628\u0647 \u0627\u0628\u062A\u062F\u0627\u06CC \u0646\u0627\u0645 \u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627 \u062F\u0631 \u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9 \u0627\u0636\u0627\u0641\u0647 \u0645\u06CC\u200C\u0634\u0648\u062F',
  savedOk:'\u0630\u062E\u06CC\u0631\u0647 \u0634\u062F',save:'\u0630\u062E\u06CC\u0631\u0647',
  changePw:'\u062A\u063A\u06CC\u06CC\u0631 \u0631\u0645\u0632 \u0639\u0628\u0648\u0631',curPw:'\u0631\u0645\u0632 \u0641\u0639\u0644\u06CC',newPw:'\u0631\u0645\u0632 \u062C\u062F\u06CC\u062F',pwChanged:'\u0631\u0645\u0632 \u062A\u063A\u06CC\u06CC\u0631 \u06A9\u0631\u062F \u2713',
  serverInfo:'\u0627\u0637\u0644\u0627\u0639\u0627\u062A \u0633\u0631\u0648\u0631',wsPathLbl:'\u0645\u0633\u06CC\u0631 WebSocket',xhPathLbl:'\u0645\u0633\u06CC\u0631 XHTTP',
  xhModeLbl:'\u062D\u0627\u0644\u062A XHTTP',
  xhModeHint:'\u062D\u0627\u0644\u062A \u0631\u0648\u06CC packet-up \u0627\u0633\u062A \u0648 \u0628\u0631\u0627\u06CC \u0647\u0631 \u062A\u06A9\u0647 \u0622\u067E\u0644\u0648\u062F \u06CC\u06A9 \u0631\u06A9\u0648\u0626\u0633\u062A \u062C\u062F\u0627 \u0645\u06CC\u200C\u0641\u0631\u0633\u062A\u062F. \u0627\u06AF\u0631 \u0631\u0644\u0647 '
        +'\u06A9\u0644\u0627\u062F\u0641\u0644\u0631 \u062F\u0627\u0631\u06CC\u062F\u060C XHTTP_MODE \u0631\u0627 \u0628\u0647 stream-up \u062A\u063A\u06CC\u06CC\u0631 \u062F\u0647\u06CC\u062F \u062A\u0627 \u0647\u0631 \u0627\u062A\u0635\u0627\u0644 \u0641\u0642\u0637 \u06F2 \u0631\u06A9\u0648\u0626\u0633\u062A \u0634\u0648\u062F. '
        +'\u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627\u06CC \u0642\u0628\u0644\u06CC \u0647\u0645\u0686\u0646\u0627\u0646 \u06A9\u0627\u0631 \u0645\u06CC\u200C\u06A9\u0646\u0646\u062F\u060C \u0648\u0644\u06CC \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0628\u0627\u06CC\u062F \u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9 \u0631\u0627 \u06CC\u06A9 \u0628\u0627\u0631 \u0628\u0647\u200C\u0631\u0648\u0632 \u06A9\u0646\u0646\u062F.',
  trWarnTitle:'\u26A0\uFE0F \u0645\u0635\u0631\u0641 \u0631\u06A9\u0648\u0626\u0633\u062A XHTTP:',
  trWarn:'\u0645\u0635\u0631\u0641 \u0627\u06CC\u0646 \u062A\u0631\u0646\u0633\u067E\u0648\u0631\u062A \u0628\u0647 \u062D\u0627\u0644\u062A (mode) \u0628\u0633\u062A\u06AF\u06CC \u062F\u0627\u0631\u062F. \u062F\u0631 stream-up \u2014 \u06A9\u0647 \u067E\u06CC\u0634\u200C\u0641\u0631\u0636 \u0627\u06CC\u0646 \u067E\u0646\u0644 '
        +'\u0627\u0633\u062A \u2014 \u0647\u0631 \u0627\u062A\u0635\u0627\u0644 \u06F2 \u0631\u06A9\u0648\u0626\u0633\u062A \u0645\u06CC\u200C\u0634\u0648\u062F (\u06CC\u06A9 GET \u0628\u0631\u0627\u06CC \u062F\u0627\u0646\u0644\u0648\u062F \u0648 \u06CC\u06A9 POST \u0628\u0644\u0646\u062F\u0645\u062F\u062A \u0628\u0631\u0627\u06CC \u0622\u067E\u0644\u0648\u062F). '
        +'\u062F\u0631 packet-up \u0647\u0631 \u062A\u06A9\u0647 \u0627\u0632 \u0622\u067E\u0644\u0648\u062F \u06CC\u06A9 POST \u062C\u062F\u0627\u06AF\u0627\u0646\u0647 \u0627\u0633\u062A \u0648 \u06CC\u06A9 \u06A9\u0627\u0631\u0628\u0631 \u0641\u0639\u0627\u0644 \u062F\u0642\u06CC\u0642\u0647\u200C\u0627\u06CC \u0635\u062F\u0647\u0627 '
        +'\u0631\u06A9\u0648\u0626\u0633\u062A \u0645\u06CC\u200C\u0633\u0627\u0632\u062F \u06A9\u0647 \u0633\u0647\u0645\u06CC\u0647 \u0631\u0648\u0632\u0627\u0646\u0647 \u0648\u0631\u06A9\u0631 \u06A9\u0644\u0627\u062F\u0641\u0644\u0631 (\u06F1\u06F0\u06F0\u066C\u06F0\u06F0\u06F0) \u0631\u0627 \u0632\u0648\u062F \u067E\u0631 \u0645\u06CC\u200C\u06A9\u0646\u062F. WS \u0627\u0632 \u0647\u0645\u0647 '
        +'\u06A9\u0645\u200C\u0645\u0635\u0631\u0641\u200C\u062A\u0631 \u0627\u0633\u062A: \u0647\u0631 \u0627\u062A\u0635\u0627\u0644 \u0641\u0642\u0637 \u06F1 \u0631\u06A9\u0648\u0626\u0633\u062A\u060C \u0647\u0631 \u0686\u0642\u062F\u0631 \u0647\u0645 \u0637\u0648\u0644 \u0628\u06A9\u0634\u062F.',
  backupTitle:'\u{1F4E6} \u067E\u0634\u062A\u06CC\u0628\u0627\u0646\u200C\u06AF\u06CC\u0631\u06CC',
  backupHint:'\u06CC\u06A9 \u0641\u0627\u06CC\u0644 \u0628\u0627 \u067E\u0633\u0648\u0646\u062F .ixpbak \u06A9\u0647 \u0647\u0645\u0647\u0654 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 (\u0628\u0627 UUID \u0648 \u062A\u0648\u06A9\u0646 \u0627\u0634\u062A\u0631\u0627\u06A9\u0634\u0627\u0646)\u060C '
        +'\u0622\u06CC\u200C\u067E\u06CC\u200C\u0647\u0627\u06CC \u062A\u0645\u06CC\u0632\u060C \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627\u060C \u0631\u0645\u0632 \u067E\u0646\u0644 \u0648 \u062A\u0646\u0638\u06CC\u0645\u0627\u062A \u0631\u0627 \u0646\u06AF\u0647 \u0645\u06CC\u200C\u062F\u0627\u0631\u062F. \u0647\u0645\u06CC\u0646 \u0641\u0627\u06CC\u0644 \u0631\u0627 \u062F\u0631 \u067E\u0646\u0644 '
        +'\u062C\u062F\u06CC\u062F \u0648\u0627\u0631\u062F \u06A9\u0646\u06CC\u062F \u062A\u0627 \u0647\u0645\u0647 \u0686\u06CC\u0632 \u0628\u0631\u06AF\u0631\u062F\u062F \u2014 \u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627\u06CC \u062F\u0633\u062A \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0647\u0645 \u06A9\u0627\u0631 \u0645\u06CC\u200C\u06A9\u0646\u0646\u062F \u0686\u0648\u0646 '
        +'UUID \u0648 \u062A\u0648\u06A9\u0646\u200C\u0647\u0627 \u0639\u0648\u0636 \u0646\u0645\u06CC\u200C\u0634\u0648\u0646\u062F.',
  bkInclPw:'\u0631\u0645\u0632 \u067E\u0646\u0644 \u0647\u0645 \u0630\u062E\u06CC\u0631\u0647 \u0634\u0648\u062F',
  bkInclProxyCreds:'\u06CC\u0648\u0632\u0631 \u0648 \u067E\u0633\u0648\u0631\u062F \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627 \u0647\u0645 \u0630\u062E\u06CC\u0631\u0647 \u0634\u0648\u062F',
  bkInclTraffic:'\u062A\u0627\u0631\u06CC\u062E\u0686\u0647\u0654 \u0645\u0635\u0631\u0641 \u0647\u0645 \u0630\u062E\u06CC\u0631\u0647 \u0634\u0648\u062F (\u062D\u062C\u0645 \u0641\u0627\u06CC\u0644 \u0628\u06CC\u0634\u062A\u0631 \u0645\u06CC\u200C\u0634\u0648\u062F)',
  bkSecretWarn:'\u26A0\uFE0F \u0627\u06CC\u0646 \u0641\u0627\u06CC\u0644 \u0634\u0627\u0645\u0644 \u0631\u0645\u0632 \u067E\u0646\u0644 \u0648 \u067E\u0633\u0648\u0631\u062F \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627\u0633\u062A \u2014 \u0645\u062B\u0644 \u0631\u0645\u0632 \u0639\u0628\u0648\u0631 \u0627\u0632 \u0622\u0646 \u0645\u0631\u0627\u0642\u0628\u062A \u06A9\u0646\u06CC\u062F.',
  btnBackupLbl:'\u2B07\uFE0F \u062F\u0627\u0646\u0644\u0648\u062F \u0641\u0627\u06CC\u0644 \u067E\u0634\u062A\u06CC\u0628\u0627\u0646',
  restoreTitle:'\u267B\uFE0F \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC',
  restoreHint:'\u0641\u0627\u06CC\u0644 .ixpbak \u0631\u0627 \u0627\u0646\u062A\u062E\u0627\u0628 \u06A9\u0646\u06CC\u062F. \u0627\u0648\u0644 \u0645\u062D\u062A\u0648\u0627\u06CC\u0634 \u0646\u0645\u0627\u06CC\u0634 \u062F\u0627\u062F\u0647 \u0645\u06CC\u200C\u0634\u0648\u062F \u0648 \u062A\u0627 \u062A\u0623\u06CC\u06CC\u062F '
        +'\u0646\u06A9\u0646\u06CC\u062F \u0647\u06CC\u0686 \u0686\u06CC\u0632\u06CC \u062F\u0631 \u062F\u06CC\u062A\u0627\u0628\u06CC\u0633 \u0646\u0648\u0634\u062A\u0647 \u0646\u0645\u06CC\u200C\u0634\u0648\u062F.',
  restoreMode:'\u0646\u062D\u0648\u0647\u0654 \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC',
  bkMerge:'\u0627\u062F\u063A\u0627\u0645 \u2014 \u0645\u0648\u0627\u0631\u062F \u0645\u0648\u062C\u0648\u062F \u0628\u0647\u200C\u0631\u0648\u0632 \u0648 \u0628\u0642\u06CC\u0647 \u0627\u0636\u0627\u0641\u0647 \u0645\u06CC\u200C\u0634\u0648\u0646\u062F',
  bkReplace:'\u062C\u0627\u06CC\u06AF\u0632\u06CC\u0646\u06CC \u06A9\u0627\u0645\u0644 \u2014 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646\u060C \u0622\u06CC\u200C\u067E\u06CC\u200C\u0647\u0627 \u0648 \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627\u06CC \u0641\u0639\u0644\u06CC \u062D\u0630\u0641 \u0645\u06CC\u200C\u0634\u0648\u0646\u062F',
  bkRestorePwLbl:'\u0631\u0645\u0632 \u067E\u0646\u0644 \u0647\u0645 \u0627\u0632 \u0641\u0627\u06CC\u0644 \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC \u0634\u0648\u062F',
  btnRestoreLbl:'\u267B\uFE0F \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC \u06A9\u0646',
  bkReading:'\u062F\u0631 \u062D\u0627\u0644 \u062E\u0648\u0627\u0646\u062F\u0646 \u0641\u0627\u06CC\u0644\u2026',
  bkBadFile:'\u0641\u0627\u06CC\u0644 \u0642\u0627\u0628\u0644 \u062E\u0648\u0627\u0646\u062F\u0646 \u0646\u06CC\u0633\u062A \u06CC\u0627 \u067E\u0634\u062A\u06CC\u0628\u0627\u0646 \u0627\u06CC\u0646 \u067E\u0646\u0644 \u0646\u06CC\u0633\u062A',
  bkFrom:'\u0633\u0627\u062E\u062A\u0647\u200C\u0634\u062F\u0647 \u062F\u0631',bkUsersN:'\u06A9\u0627\u0631\u0628\u0631',bkCipsN:'\u0622\u06CC\u200C\u067E\u06CC \u062A\u0645\u06CC\u0632',bkProxN:'\u067E\u0631\u0648\u06A9\u0633\u06CC',
  bkTrafficN:'\u0631\u06A9\u0648\u0631\u062F \u0645\u0635\u0631\u0641',
  bkHasPw:'\u0634\u0627\u0645\u0644 \u0631\u0645\u0632 \u067E\u0646\u0644',bkNoPw:'\u0628\u062F\u0648\u0646 \u0631\u0645\u0632 \u067E\u0646\u0644',
  bkProxCreds:'\u067E\u0631\u0648\u06A9\u0633\u06CC \u0628\u0627 \u06CC\u0648\u0632\u0631/\u067E\u0633\u0648\u0631\u062F',
  bkEnvDiff:'\u26A0\uFE0F \u0627\u06CC\u0646 \u0645\u062A\u063A\u06CC\u0631\u0647\u0627 \u0628\u0627 \u067E\u0646\u0644 \u0641\u0639\u0644\u06CC \u062A\u0641\u0627\u0648\u062A \u062F\u0627\u0631\u0646\u062F \u0648 \u0628\u0627\u06CC\u062F \u062F\u0633\u062A\u06CC \u062F\u0631 Railway/Render \u0633\u062A \u0634\u0648\u0646\u062F:',
  bkReplaceWarn:'\u0647\u0645\u0647\u0654 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646\u060C \u0622\u06CC\u200C\u067E\u06CC\u200C\u0647\u0627\u06CC \u062A\u0645\u06CC\u0632 \u0648 \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627\u06CC \u0641\u0639\u0644\u06CC \u062D\u0630\u0641 \u0648 \u0628\u0627 \u0641\u0627\u06CC\u0644 \u062C\u0627\u06CC\u06AF\u0632\u06CC\u0646 \u0645\u06CC\u200C\u0634\u0648\u0646\u062F. \u0645\u0637\u0645\u0626\u0646\u06CC\u061F',
  bkPwChanged:"\u0631\u0645\u0632 \u067E\u0646\u0644 \u0627\u0632 \u0641\u0627\u06CC\u0644 \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC \u0634\u062F \u2014 \u062F\u0641\u0639\u0647\u0654 \u0628\u0639\u062F \u0628\u0627 \u0631\u0645\u0632 \u0642\u062F\u06CC\u0645\u06CC\u0650 \u0647\u0645\u0627\u0646 \u0641\u0627\u06CC\u0644 \u0648\u0627\u0631\u062F \u0634\u0648\u06CC\u062F.",
  bkDone:'\u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC \u0627\u0646\u062C\u0627\u0645 \u0634\u062F',
  bkAdded:'\u0627\u0636\u0627\u0641\u0647\u200C\u0634\u062F\u0647',bkUpdated:'\u0628\u0647\u200C\u0631\u0648\u0632\u0634\u062F\u0647',bkSkipped:'\u0631\u062F\u0634\u062F\u0647',
  relayLbl:'\u062F\u0627\u0645\u0646\u0647 \u0631\u0644\u0647',keepAliveLbl:'\u062C\u0644\u0648\u06AF\u06CC\u0631\u06CC \u0627\u0632 \u062E\u0648\u0627\u0628',relayNone:'\u0646\u062F\u0627\u0631\u062F',
  onLbl:'\u0641\u0639\u0627\u0644',offLbl:'\u062E\u0627\u0645\u0648\u0634',
  devWinLbl:'\u067E\u0646\u062C\u0631\u0647 \u0634\u0645\u0627\u0631\u0634 \u062F\u0633\u062A\u06AF\u0627\u0647',seconds:'\u062B\u0627\u0646\u06CC\u0647',
  envNote:'\u0627\u06CC\u0646 \u0645\u0642\u0627\u062F\u06CC\u0631 \u0627\u0632 \u0645\u062A\u063A\u06CC\u0631\u0647\u0627\u06CC \u0645\u062D\u06CC\u0637\u06CC \u062E\u0648\u0627\u0646\u062F\u0647 \u0645\u06CC\u200C\u0634\u0648\u0646\u062F \u0648 \u062F\u0631 Railway \u0642\u0627\u0628\u0644 \u062A\u063A\u06CC\u06CC\u0631\u0646\u062F.',
  logout:'\u062E\u0631\u0648\u062C',logs:'\u0631\u062E\u062F\u0627\u062F\u0647\u0627',noLogs:'\u0631\u062E\u062F\u0627\u062F\u06CC \u0646\u06CC\u0633\u062A',
  statusDisabled:'\u063A\u06CC\u0631\u0641\u0639\u0627\u0644',statusExpired:'\u0645\u0646\u0642\u0636\u06CC',statusQuota:'\u062D\u062C\u0645 \u062A\u0645\u0627\u0645',
 },
 en:{dir:'ltr',
  setupTitle:'Set a password',setupSub:'First run \u2014 choose your panel password',
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
  name:'Name',quota:'Quota (GB)',days:'Days',devLimit:'Devices',
  transport:'Transport',trWs:'\u{1F50C} WS + TLS',trXhttp:'\u{1F680} XHTTP + TLS',trBoth:'\u{1F500} Both',
  add:'Add',zeroInf:'0 = unlimited. Device count is based on distinct active IPs.',
  search:'Search\u2026',noUsers:'No users yet',
  config:'Config',ipsBtn:'IPs',edit:'Edit',
  used:'Used',expiry:'Expires',never:'Never',
  subLink:'Subscription link',copySub:'Copy subscription link',
  singleCfg:'Individual configs',copy:'Copy',copied:'Copied \u2713',
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
  obfLbl:'Obfuscation (Fragment + Cipher mask)',
  uuidWarn:'Rotate UUID? Existing configs will stop working.',delWarn:'Delete this user?',
  cleanTitle:'Clean IP manager',
  cleanHint:'Clean IPs or domains. Added to every subscription as extra configs.',
  addrPh:'e.g. 1.2.3.4 or cdn.example.com',remarkPh:'Label (optional)',
  bulkPh:'One per line:\\n1.2.3.4 # Irancell\\n5.6.7.8 # MCI',
  bulkAdd:'Bulk add',clearAll:'Delete all',
  pxTitle:'Outbound proxy',
  pxHint:'Arm a proxy and every user connection leaves through it, so target sites see the proxy IP.',
  pxKind:'Type',pxHost:'Host / IP',pxPort:'Port',
  pxUser:'Username (optional)',pxPass:'Password (optional)',
  pxAdd:'Add & test',pxTestAll:'Test all',
  pxInSub:'in subscriptions',
  pxAutoNote:'Every proxy you add joins all subscriptions automatically \u2014 all of them at once, no button. The no-proxy config is always there, and a failed health check or a dropped connection never removes a proxy: only disabling or deleting it in the panel does.',
  pxLineHint:'One proxy per line \u2014 e.g. socks5://1.1.1.1:5866 or http://user:pass@2.2.2.2:8080',
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
  pwChanged:'Password changed \u2713',
  serverInfo:'Server info',wsPathLbl:'WebSocket path',xhPathLbl:'XHTTP path',
  xhModeLbl:'XHTTP mode',
  xhModeHint:'The mode is packet-up, which spends one request per upload chunk. Behind a '
        +'Cloudflare relay, set XHTTP_MODE=stream-up to get 2 requests per connection instead. '
        +'Existing configs keep working, but users need to refresh their subscription once.',
  trWarnTitle:'\u26A0\uFE0F XHTTP request cost:',
  trWarn:"Cost depends on the mode. stream-up \u2014 this panel's default \u2014 is 2 requests per "
       +"connection (one GET downlink plus one long-lived POST uplink). packet-up sends every "
       +"upload chunk as its own POST, so one active client can be hundreds of requests a "
       +"minute and will drain a Cloudflare Worker's daily quota (100k). WS is cheapest of "
       +"all: 1 request per connection no matter how long it stays open.",
  backupTitle:'\u{1F4E6} Backup',
  backupHint:'A single .ixpbak file holding every user (with their UUID and subscription '
        +'token), your clean IPs, your proxies, the panel password and its settings. Import '
        +'it into a fresh panel and everything comes back \u2014 configs already handed out keep '
        +'working, because UUIDs and tokens are preserved.',
  bkInclPw:'include the panel password',
  bkInclProxyCreds:'include proxy usernames and passwords',
  bkInclTraffic:'include traffic history (larger file)',
  bkSecretWarn:'\u26A0\uFE0F This file contains the panel password and your proxy credentials \u2014 treat it like a password.',
  btnBackupLbl:'\u2B07\uFE0F Download backup',
  restoreTitle:'\u267B\uFE0F Restore',
  restoreHint:'Pick a .ixpbak file. Its contents are shown first and nothing is written '
        +'to the database until you confirm.',
  restoreMode:'Restore mode',
  bkMerge:'Merge \u2014 update matching entries, add the rest',
  bkReplace:'Replace \u2014 wipe current users, clean IPs and proxies first',
  bkRestorePwLbl:'also restore the panel password from the file',
  btnRestoreLbl:'\u267B\uFE0F Restore now',
  bkReading:'Reading file\u2026',
  bkBadFile:'File cannot be read, or is not a backup from this panel',
  bkFrom:'Created',bkUsersN:'users',bkCipsN:'clean IPs',bkProxN:'proxies',
  bkTrafficN:'traffic rows',
  bkHasPw:'includes the panel password',bkNoPw:'no panel password',
  bkProxCreds:'proxies with credentials',
  bkEnvDiff:'\u26A0\uFE0F These variables differ from this panel and must be set by hand in Railway/Render:',
  bkReplaceWarn:'All current users, clean IPs and proxies will be deleted and replaced by the file. Continue?',
  bkPwChanged:"The panel password was restored from the file \u2014 sign in with that file's password next time.",
  bkDone:'Restore complete',
  bkAdded:'added',bkUpdated:'updated',bkSkipped:'skipped',
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
<\/script>
<div class="glow fixed inset-0 pointer-events-none"></div>
<div class="relative w-full max-w-sm card rounded-3xl p-8 shadow-2xl backdrop-blur">
 <div class="flex justify-between mb-4">
  <select onchange="setLang(this.value)" id="langSel" class="inp rounded-lg px-2 py-1 text-xs">
   <option value="fa">\u{1F1EE}\u{1F1F7} \u0641\u0627\u0631\u0633\u06CC</option><option value="en">\u{1F1EC}\u{1F1E7} English</option></select>
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
<\/script></body></html>`], [`<!DOCTYPE html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}}</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;800&display=swap" rel="stylesheet">
<style>body{font-family:Vazirmatn,system-ui,sans-serif}
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

.glow{background:radial-gradient(60% 55% at 50% 0%,color-mix(in srgb,var(--a1) 40%,transparent),transparent 70%)}
</style></head><body class="min-h-screen flex items-center justify-center p-4">
<script>
const I18N={
 fa:{dir:'rtl',
  setupTitle:'\u062A\u0639\u06CC\u06CC\u0646 \u0631\u0645\u0632 \u0639\u0628\u0648\u0631',setupSub:'\u0627\u0648\u0644\u06CC\u0646 \u0648\u0631\u0648\u062F \u2014 \u06CC\u06A9 \u0631\u0645\u0632 \u0628\u0631\u0627\u06CC \u067E\u0646\u0644 \u0627\u0646\u062A\u062E\u0627\u0628 \u06A9\u0646\u06CC\u062F',
  loginTitle:'\u0648\u0631\u0648\u062F \u0628\u0647 \u067E\u0646\u0644',loginSub:'\u0631\u0645\u0632 \u0639\u0628\u0648\u0631 \u062E\u0648\u062F \u0631\u0627 \u0648\u0627\u0631\u062F \u06A9\u0646\u06CC\u062F',
  password:'\u0631\u0645\u0632 \u0639\u0628\u0648\u0631',confirm:'\u062A\u06A9\u0631\u0627\u0631 \u0631\u0645\u0632 \u0639\u0628\u0648\u0631',enter:'\u0648\u0631\u0648\u062F',save:'\u0630\u062E\u06CC\u0631\u0647 \u0648 \u0648\u0631\u0648\u062F',
  pwRule:'\u062D\u062F\u0627\u0642\u0644 \u06F8 \u06A9\u0627\u0631\u0627\u06A9\u062A\u0631 \u0634\u0627\u0645\u0644 \u062D\u0631\u0641 \u0628\u0632\u0631\u06AF\u060C \u062D\u0631\u0641 \u06A9\u0648\u0686\u06A9 \u0648 \u0639\u062F\u062F',netErr:'\u062E\u0637\u0627\u06CC \u0634\u0628\u06A9\u0647',
  navDash:'\u062F\u0627\u0634\u0628\u0648\u0631\u062F',navUsers:'\u0645\u062F\u06CC\u0631\u06CC\u062A \u06A9\u0627\u0631\u0628\u0631\u0627\u0646',navClean:'Clean IP',
  navProxy:'\u067E\u0631\u0648\u06A9\u0633\u06CC',navLive:'\u0627\u062A\u0635\u0627\u0644\u0627\u062A \u0632\u0646\u062F\u0647',
  navSettings:'\u062A\u0646\u0638\u06CC\u0645\u0627\u062A \u067E\u0646\u0644',navLogs:'\u0631\u062E\u062F\u0627\u062F\u0647\u0627',menu:'\u0645\u0646\u0648',
  totalUsers:'\u06A9\u0644 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646',online:'\u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0622\u0646\u0644\u0627\u06CC\u0646',devices:'\u062F\u0633\u062A\u06AF\u0627\u0647\u200C\u0647\u0627\u06CC \u0645\u062A\u0635\u0644',
  traffic:'\u0645\u0635\u0631\u0641 \u06A9\u0644',cleanIps:'\u0622\u06CC\u200C\u067E\u06CC \u062A\u0645\u06CC\u0632',xSessions:'\u0633\u0634\u0646\u200C\u0647\u0627\u06CC XHTTP',liveTitle:'\u0627\u062A\u0635\u0627\u0644\u0627\u062A \u0632\u0646\u062F\u0647',liveEmpty:'\u0647\u06CC\u0686 \u0627\u062A\u0635\u0627\u0644\u06CC \u0641\u0639\u0627\u0644 \u0646\u06CC\u0633\u062A',
  chart24:'\u0645\u0635\u0631\u0641 \u06F2\u06F4 \u0633\u0627\u0639\u062A \u0627\u062E\u06CC\u0631',protoSplit:'\u062A\u0642\u0633\u06CC\u0645 \u0628\u0631 \u0627\u0633\u0627\u0633 \u062A\u0631\u0646\u0633\u067E\u0648\u0631\u062A',
  newUser:'\u0633\u0627\u062E\u062A \u06A9\u0627\u0631\u0628\u0631 \u062C\u062F\u06CC\u062F',users:'\u06A9\u0627\u0631\u0628\u0631\u0627\u0646',
  name:'\u0646\u0627\u0645 (\u0627\u0646\u06AF\u0644\u06CC\u0633\u06CC)',quota:'\u062D\u062C\u0645 (GB)',days:'\u0645\u062F\u062A (\u0631\u0648\u0632)',devLimit:'\u062A\u0639\u062F\u0627\u062F \u062F\u0633\u062A\u06AF\u0627\u0647',
  transport:'\u062A\u0631\u0646\u0633\u067E\u0648\u0631\u062A',trWs:'\u{1F50C} WS + TLS',trXhttp:'\u{1F680} XHTTP + TLS',trBoth:'\u{1F500} \u0647\u0631 \u062F\u0648',
  add:'\u0627\u0641\u0632\u0648\u062F\u0646',zeroInf:'\u06F0 = \u0628\u06CC\u200C\u0646\u0647\u0627\u06CC\u062A. \xAB\u062A\u0639\u062F\u0627\u062F \u062F\u0633\u062A\u06AF\u0627\u0647\xBB \u0628\u0631 \u0627\u0633\u0627\u0633 IP \u06CC\u06A9\u062A\u0627\u06CC \u0641\u0639\u0627\u0644 \u0645\u062D\u0627\u0633\u0628\u0647 \u0645\u06CC\u200C\u0634\u0648\u062F.',
  search:'\u062C\u0633\u062A\u062C\u0648\u2026',noUsers:'\u06A9\u0627\u0631\u0628\u0631\u06CC \u0646\u06CC\u0633\u062A',
  config:'\u06A9\u0627\u0646\u0641\u06CC\u06AF',ipsBtn:'IP \u0647\u0627',edit:'\u0648\u06CC\u0631\u0627\u06CC\u0634',
  used:'\u0645\u0635\u0631\u0641',expiry:'\u0627\u0646\u0642\u0636\u0627',never:'\u0628\u06CC\u200C\u0646\u0647\u0627\u06CC\u062A',
  subLink:'\u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9 (Subscription)',copySub:'\u06A9\u067E\u06CC \u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9',
  singleCfg:'\u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627\u06CC \u062A\u06A9\u06CC',copy:'\u06A9\u067E\u06CC',copied:'\u06A9\u067E\u06CC \u0634\u062F \u2713',
  devTitle:'\u062F\u0633\u062A\u06AF\u0627\u0647\u200C\u0647\u0627\u06CC \u0645\u062A\u0635\u0644',noConn:'\u0647\u0646\u0648\u0632 \u0627\u062A\u0635\u0627\u0644\u06CC \u062B\u0628\u062A \u0646\u0634\u062F\u0647',
  clearIps:'\u067E\u0627\u06A9 \u06A9\u0631\u062F\u0646 \u0644\u06CC\u0633\u062A IP',
  liveNow:'\u0627\u0644\u0627\u0646 \u0645\u062A\u0635\u0644',noneNow:'\u0647\u0645\u06CC\u0646 \u0627\u0644\u0627\u0646 \u0647\u06CC\u0686 \u062F\u0633\u062A\u06AF\u0627\u0647\u06CC \u0645\u062A\u0635\u0644 \u0646\u06CC\u0633\u062A',
  countedFor:'\u0634\u0645\u0631\u062F\u0647\u200C\u0634\u062F\u0647 \u0628\u0631\u0627\u06CC \u0645\u062D\u062F\u0648\u062F\u06CC\u062A',totalSeen:'\u06A9\u0644 IP \u0647\u0627\u06CC \u062F\u06CC\u062F\u0647\u200C\u0634\u062F\u0647',
  showHistory:'\u0646\u0645\u0627\u06CC\u0634 \u062A\u0627\u0631\u06CC\u062E\u0686\u0647',showLive:'\u0646\u0645\u0627\u06CC\u0634 \u0641\u0642\u0637 \u0645\u062A\u0635\u0644\u200C\u0647\u0627',
  inLast:'\u062F\u0631 %s \u062B\u0627\u0646\u06CC\u0647 \u0627\u062E\u06CC\u0631',refresh:'\u0628\u0647\u200C\u0631\u0648\u0632\u0631\u0633\u0627\u0646\u06CC',
  liveDevices:'\u062F\u0633\u062A\u06AF\u0627\u0647\u200C\u0647\u0627\u06CC \u0641\u0639\u0627\u0644 \u0627\u0644\u0627\u0646',
  editUser:'\u0648\u06CC\u0631\u0627\u06CC\u0634',remainDays:'\u0645\u062F\u062A \u0628\u0627\u0642\u06CC\u200C\u0645\u0627\u0646\u062F\u0647 (\u0631\u0648\u0632)',allowedDev:'\u062A\u0639\u062F\u0627\u062F \u062F\u0633\u062A\u06AF\u0627\u0647 \u0645\u062C\u0627\u0632',
  active:'\u0641\u0639\u0627\u0644',saveBtn:'\u0630\u062E\u06CC\u0631\u0647',resetTraffic:'\u0631\u06CC\u0633\u062A \u062D\u062C\u0645',newUuid:'UUID \u062C\u062F\u06CC\u062F',
  customUuid:'UUID \u062F\u0633\u062A\u06CC',del:'\u062D\u0630\u0641',
  obfLbl:'\u0645\u0628\u0647\u0645\u200C\u0633\u0627\u0632 (Fragment + Cipher mask)',
  uuidWarn:'UUID \u0639\u0648\u0636 \u0634\u0648\u062F\u061F \u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627\u06CC \u0642\u0628\u0644\u06CC \u0627\u0632 \u06A9\u0627\u0631 \u0645\u06CC\u200C\u0627\u0641\u062A\u0646\u062F.',delWarn:'\u0627\u06CC\u0646 \u06A9\u0627\u0631\u0628\u0631 \u062D\u0630\u0641 \u0634\u0648\u062F\u061F',
  cleanTitle:'\u0645\u062F\u06CC\u0631\u06CC\u062A Clean IP',
  cleanHint:'\u0622\u06CC\u200C\u067E\u06CC \u06CC\u0627 \u062F\u0627\u0645\u0646\u0647 \u062A\u0645\u06CC\u0632. \u062F\u0631 \u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9 \u0647\u0631 \u06A9\u0627\u0631\u0628\u0631 \u0628\u0647 \u0639\u0646\u0648\u0627\u0646 \u06A9\u0627\u0646\u0641\u06CC\u06AF \u0627\u0636\u0627\u0641\u06CC \u0627\u0636\u0627\u0641\u0647 \u0645\u06CC\u200C\u0634\u0648\u062F.',
  addrPh:'\u0645\u062B\u0644\u0627 1.2.3.4 \u06CC\u0627 cdn.example.com',remarkPh:'\u0628\u0631\u0686\u0633\u0628 (\u0627\u062E\u062A\u06CC\u0627\u0631\u06CC)',
  bulkPh:'\u0686\u0646\u062F \u0645\u0648\u0631\u062F\u060C \u0647\u0631 \u062E\u0637 \u06CC\u06A9\u06CC:\\\\n1.2.3.4 # \u0627\u06CC\u0631\u0627\u0646\u0633\u0644\\\\n5.6.7.8 # \u0647\u0645\u0631\u0627\u0647 \u0627\u0648\u0644',
  bulkAdd:'\u0627\u0641\u0632\u0648\u062F\u0646 \u0627\u0646\u0628\u0648\u0647',clearAll:'\u062D\u0630\u0641 \u0647\u0645\u0647',
  pxTitle:'\u067E\u0631\u0648\u06A9\u0633\u06CC \u062E\u0631\u0648\u062C\u06CC',
  pxHint:'\u0628\u0627 \u0641\u0639\u0627\u0644 \u06A9\u0631\u062F\u0646 \u06CC\u06A9 \u067E\u0631\u0648\u06A9\u0633\u06CC\u060C \u062A\u0645\u0627\u0645 \u062A\u0631\u0627\u0641\u06CC\u06A9 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0627\u0632 \u0647\u0645\u0627\u0646 \u0645\u0633\u06CC\u0631 \u062E\u0627\u0631\u062C \u0645\u06CC\u200C\u0634\u0648\u062F \u0648 \u0633\u0627\u06CC\u062A\u200C\u0647\u0627 \u0627\u06CC\u067E\u06CC \u067E\u0631\u0648\u06A9\u0633\u06CC \u0631\u0627 \u0645\u06CC\u200C\u0628\u06CC\u0646\u0646\u062F.',
  pxKind:'\u0646\u0648\u0639',pxHost:'\u0647\u0627\u0633\u062A / \u0627\u06CC\u067E\u06CC',pxPort:'\u067E\u0648\u0631\u062A',
  pxUser:'\u06CC\u0648\u0632\u0631\u0646\u06CC\u0645 (\u0627\u062E\u062A\u06CC\u0627\u0631\u06CC)',pxPass:'\u067E\u0633\u0648\u0631\u062F (\u0627\u062E\u062A\u06CC\u0627\u0631\u06CC)',
  pxAdd:'\u0627\u0641\u0632\u0648\u062F\u0646 \u0648 \u062A\u0633\u062A',pxTestAll:'\u062A\u0633\u062A \u0647\u0645\u0647',
  pxInSub:'\u062F\u0631 \u0633\u0627\u0628',
  pxAutoNote:'\u0647\u0631 \u067E\u0631\u0648\u06A9\u0633\u06CC \u06A9\u0647 \u0627\u0636\u0627\u0641\u0647 \u0634\u0648\u062F \u062E\u0648\u062F\u0628\u0647\u200C\u062E\u0648\u062F \u062F\u0631 \u0633\u0627\u0628 \u0647\u0645\u0647 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0645\u06CC\u200C\u0622\u06CC\u062F \u2014 \u0647\u0645\u0647 \u0628\u0627 \u0647\u0645\u060C \u0628\u062F\u0648\u0646 \u062F\u06A9\u0645\u0647. \u06A9\u0627\u0646\u0641\u06CC\u06AF \u0628\u062F\u0648\u0646 \u067E\u0631\u0648\u06A9\u0633\u06CC \u0647\u0645\u06CC\u0634\u0647 \u0633\u0631 \u062C\u0627\u06CC\u0634 \u0647\u0633\u062A\u061B \u0642\u0637\u0639\u06CC \u06CC\u0627 \u0646\u0627\u0645\u0648\u0641\u0642 \u0628\u0648\u062F\u0646 \u062A\u0633\u062A\u060C \u067E\u0631\u0648\u06A9\u0633\u06CC \u0631\u0627 \u0627\u0632 \u0633\u0627\u0628 \u062D\u0630\u0641 \u0646\u0645\u06CC\u200C\u06A9\u0646\u062F \u0648 \u0641\u0642\u0637 \u0628\u0627 \u063A\u06CC\u0631\u0641\u0639\u0627\u0644 \u06A9\u0631\u062F\u0646 \u06CC\u0627 \u062D\u0630\u0641 \u0627\u0632 \u067E\u0646\u0644 \u0628\u06CC\u0631\u0648\u0646 \u0645\u06CC\u200C\u0631\u0648\u062F.',
  pxLineHint:'\u0647\u0631 \u062E\u0637 \u06CC\u06A9 \u067E\u0631\u0648\u06A9\u0633\u06CC \u2014 \u0645\u0627\u0646\u0646\u062F socks5://1.1.1.1:5866 \u06CC\u0627 http://user:pass@2.2.2.2:8080',
  pxAddLines:'\u0627\u0641\u0632\u0648\u062F\u0646 \u0644\u06CC\u0633\u062A \u0648 \u062A\u0633\u062A',
  pxAdvanced:'\u0648\u0631\u0648\u062F \u062F\u0633\u062A\u06CC \u0641\u06CC\u0644\u062F\u0647\u0627',
  pxDirect:'\u0627\u062A\u0635\u0627\u0644 \u0645\u0633\u062A\u0642\u06CC\u0645 (\u0628\u062F\u0648\u0646 \u067E\u0631\u0648\u06A9\u0633\u06CC)',
  pxActive:'\u0641\u0639\u0627\u0644',pxArm:'\u0641\u0639\u0627\u0644 \u06A9\u0631\u062F\u0646',pxTest:'\u062A\u0633\u062A \u0633\u0644\u0627\u0645\u062A',
  pxHealthy:'\u0633\u0627\u0644\u0645',pxDown:'\u062E\u0631\u0627\u0628',pxUntested:'\u062A\u0633\u062A \u0646\u0634\u062F\u0647',
  pxExitIp:'\u0627\u06CC\u067E\u06CC \u062E\u0631\u0648\u062C\u06CC',pxLatency:'\u062A\u0627\u062E\u06CC\u0631',
  pxNone:'\u0647\u0646\u0648\u0632 \u067E\u0631\u0648\u06A9\u0633\u06CC \u0627\u0636\u0627\u0641\u0647 \u0646\u0634\u062F\u0647 \u0627\u0633\u062A',
  pxStrict:'\u062D\u0627\u0644\u062A \u0633\u062E\u062A\u06AF\u06CC\u0631\u0627\u0646\u0647',
  pxStrictHint:'\u0627\u06AF\u0631 \u067E\u0631\u0648\u06A9\u0633\u06CC \u0642\u0637\u0639 \u0634\u062F\u060C \u0627\u062A\u0635\u0627\u0644 \u0631\u062F \u0645\u06CC\u200C\u0634\u0648\u062F \u062A\u0627 \u0627\u06CC\u067E\u06CC \u0627\u0635\u0644\u06CC \u0633\u0631\u0648\u0631 \u0644\u0648 \u0646\u0631\u0648\u062F',
  pxFlagSrc:'\u0645\u0646\u0628\u0639 \u067E\u0631\u0686\u0645 \u0646\u0627\u0645 \u06A9\u0627\u0646\u0641\u06CC\u06AF',
  pxFlagProxy:'\u06A9\u0634\u0648\u0631 \u067E\u0631\u0648\u06A9\u0633\u06CC',pxFlagEntry:'\u06A9\u0634\u0648\u0631 \u0633\u0631\u0648\u0631 \u0648\u0631\u0648\u062F\u06CC',
  pxTesting:'\u062F\u0631 \u062D\u0627\u0644 \u062A\u0633\u062A...',pxArmed:'\u067E\u0631\u0648\u06A9\u0633\u06CC \u0641\u0639\u0627\u0644 \u0634\u062F',
  pxDelWarn:'\u0627\u06CC\u0646 \u067E\u0631\u0648\u06A9\u0633\u06CC \u062D\u0630\u0641 \u0634\u0648\u062F\u061F',
  addedN:'\u0627\u0641\u0632\u0648\u062F\u0647 \u0634\u062F',dupN:'\u062A\u06A9\u0631\u0627\u0631\u06CC',invalidN:'\u0646\u0627\u0645\u0639\u062A\u0628\u0631',noCleanIps:'\u0644\u06CC\u0633\u062A \u062E\u0627\u0644\u06CC \u0627\u0633\u062A',
  settings:'\u062A\u0646\u0638\u06CC\u0645\u0627\u062A',appearance:'\u0638\u0627\u0647\u0631',theme:'\u062A\u0645',language:'\u0632\u0628\u0627\u0646',
  thDark:'\u062A\u06CC\u0631\u0647 (\u0645\u0634\u06A9\u06CC \u0648 \u0622\u0628\u06CC)',thLight:'\u0631\u0648\u0634\u0646 (\u0633\u0641\u06CC\u062F \u0648 \u0622\u0628\u06CC)',thGray:'\u062E\u0627\u06A9\u0633\u062A\u0631\u06CC',
  country:'\u06A9\u0634\u0648\u0631',autoCountry:'\u062A\u0634\u062E\u06CC\u0635 \u062E\u0648\u062F\u06A9\u0627\u0631',mainCountry:'\u06A9\u0634\u0648\u0631 \u0633\u0631\u0648\u0631 \u0627\u0635\u0644\u06CC',
  flagsHint:'\u067E\u0631\u0686\u0645 \u06A9\u0634\u0648\u0631 \u0628\u0647 \u0627\u0628\u062A\u062F\u0627\u06CC \u0646\u0627\u0645 \u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627 \u062F\u0631 \u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9 \u0627\u0636\u0627\u0641\u0647 \u0645\u06CC\u200C\u0634\u0648\u062F',
  savedOk:'\u0630\u062E\u06CC\u0631\u0647 \u0634\u062F',save:'\u0630\u062E\u06CC\u0631\u0647',
  changePw:'\u062A\u063A\u06CC\u06CC\u0631 \u0631\u0645\u0632 \u0639\u0628\u0648\u0631',curPw:'\u0631\u0645\u0632 \u0641\u0639\u0644\u06CC',newPw:'\u0631\u0645\u0632 \u062C\u062F\u06CC\u062F',pwChanged:'\u0631\u0645\u0632 \u062A\u063A\u06CC\u06CC\u0631 \u06A9\u0631\u062F \u2713',
  serverInfo:'\u0627\u0637\u0644\u0627\u0639\u0627\u062A \u0633\u0631\u0648\u0631',wsPathLbl:'\u0645\u0633\u06CC\u0631 WebSocket',xhPathLbl:'\u0645\u0633\u06CC\u0631 XHTTP',
  xhModeLbl:'\u062D\u0627\u0644\u062A XHTTP',
  xhModeHint:'\u062D\u0627\u0644\u062A \u0631\u0648\u06CC packet-up \u0627\u0633\u062A \u0648 \u0628\u0631\u0627\u06CC \u0647\u0631 \u062A\u06A9\u0647 \u0622\u067E\u0644\u0648\u062F \u06CC\u06A9 \u0631\u06A9\u0648\u0626\u0633\u062A \u062C\u062F\u0627 \u0645\u06CC\u200C\u0641\u0631\u0633\u062A\u062F. \u0627\u06AF\u0631 \u0631\u0644\u0647 '
        +'\u06A9\u0644\u0627\u062F\u0641\u0644\u0631 \u062F\u0627\u0631\u06CC\u062F\u060C XHTTP_MODE \u0631\u0627 \u0628\u0647 stream-up \u062A\u063A\u06CC\u06CC\u0631 \u062F\u0647\u06CC\u062F \u062A\u0627 \u0647\u0631 \u0627\u062A\u0635\u0627\u0644 \u0641\u0642\u0637 \u06F2 \u0631\u06A9\u0648\u0626\u0633\u062A \u0634\u0648\u062F. '
        +'\u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627\u06CC \u0642\u0628\u0644\u06CC \u0647\u0645\u0686\u0646\u0627\u0646 \u06A9\u0627\u0631 \u0645\u06CC\u200C\u06A9\u0646\u0646\u062F\u060C \u0648\u0644\u06CC \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0628\u0627\u06CC\u062F \u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9 \u0631\u0627 \u06CC\u06A9 \u0628\u0627\u0631 \u0628\u0647\u200C\u0631\u0648\u0632 \u06A9\u0646\u0646\u062F.',
  trWarnTitle:'\u26A0\uFE0F \u0645\u0635\u0631\u0641 \u0631\u06A9\u0648\u0626\u0633\u062A XHTTP:',
  trWarn:'\u0645\u0635\u0631\u0641 \u0627\u06CC\u0646 \u062A\u0631\u0646\u0633\u067E\u0648\u0631\u062A \u0628\u0647 \u062D\u0627\u0644\u062A (mode) \u0628\u0633\u062A\u06AF\u06CC \u062F\u0627\u0631\u062F. \u062F\u0631 stream-up \u2014 \u06A9\u0647 \u067E\u06CC\u0634\u200C\u0641\u0631\u0636 \u0627\u06CC\u0646 \u067E\u0646\u0644 '
        +'\u0627\u0633\u062A \u2014 \u0647\u0631 \u0627\u062A\u0635\u0627\u0644 \u06F2 \u0631\u06A9\u0648\u0626\u0633\u062A \u0645\u06CC\u200C\u0634\u0648\u062F (\u06CC\u06A9 GET \u0628\u0631\u0627\u06CC \u062F\u0627\u0646\u0644\u0648\u062F \u0648 \u06CC\u06A9 POST \u0628\u0644\u0646\u062F\u0645\u062F\u062A \u0628\u0631\u0627\u06CC \u0622\u067E\u0644\u0648\u062F). '
        +'\u062F\u0631 packet-up \u0647\u0631 \u062A\u06A9\u0647 \u0627\u0632 \u0622\u067E\u0644\u0648\u062F \u06CC\u06A9 POST \u062C\u062F\u0627\u06AF\u0627\u0646\u0647 \u0627\u0633\u062A \u0648 \u06CC\u06A9 \u06A9\u0627\u0631\u0628\u0631 \u0641\u0639\u0627\u0644 \u062F\u0642\u06CC\u0642\u0647\u200C\u0627\u06CC \u0635\u062F\u0647\u0627 '
        +'\u0631\u06A9\u0648\u0626\u0633\u062A \u0645\u06CC\u200C\u0633\u0627\u0632\u062F \u06A9\u0647 \u0633\u0647\u0645\u06CC\u0647 \u0631\u0648\u0632\u0627\u0646\u0647 \u0648\u0631\u06A9\u0631 \u06A9\u0644\u0627\u062F\u0641\u0644\u0631 (\u06F1\u06F0\u06F0\u066C\u06F0\u06F0\u06F0) \u0631\u0627 \u0632\u0648\u062F \u067E\u0631 \u0645\u06CC\u200C\u06A9\u0646\u062F. WS \u0627\u0632 \u0647\u0645\u0647 '
        +'\u06A9\u0645\u200C\u0645\u0635\u0631\u0641\u200C\u062A\u0631 \u0627\u0633\u062A: \u0647\u0631 \u0627\u062A\u0635\u0627\u0644 \u0641\u0642\u0637 \u06F1 \u0631\u06A9\u0648\u0626\u0633\u062A\u060C \u0647\u0631 \u0686\u0642\u062F\u0631 \u0647\u0645 \u0637\u0648\u0644 \u0628\u06A9\u0634\u062F.',
  backupTitle:'\u{1F4E6} \u067E\u0634\u062A\u06CC\u0628\u0627\u0646\u200C\u06AF\u06CC\u0631\u06CC',
  backupHint:'\u06CC\u06A9 \u0641\u0627\u06CC\u0644 \u0628\u0627 \u067E\u0633\u0648\u0646\u062F .ixpbak \u06A9\u0647 \u0647\u0645\u0647\u0654 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 (\u0628\u0627 UUID \u0648 \u062A\u0648\u06A9\u0646 \u0627\u0634\u062A\u0631\u0627\u06A9\u0634\u0627\u0646)\u060C '
        +'\u0622\u06CC\u200C\u067E\u06CC\u200C\u0647\u0627\u06CC \u062A\u0645\u06CC\u0632\u060C \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627\u060C \u0631\u0645\u0632 \u067E\u0646\u0644 \u0648 \u062A\u0646\u0638\u06CC\u0645\u0627\u062A \u0631\u0627 \u0646\u06AF\u0647 \u0645\u06CC\u200C\u062F\u0627\u0631\u062F. \u0647\u0645\u06CC\u0646 \u0641\u0627\u06CC\u0644 \u0631\u0627 \u062F\u0631 \u067E\u0646\u0644 '
        +'\u062C\u062F\u06CC\u062F \u0648\u0627\u0631\u062F \u06A9\u0646\u06CC\u062F \u062A\u0627 \u0647\u0645\u0647 \u0686\u06CC\u0632 \u0628\u0631\u06AF\u0631\u062F\u062F \u2014 \u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627\u06CC \u062F\u0633\u062A \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0647\u0645 \u06A9\u0627\u0631 \u0645\u06CC\u200C\u06A9\u0646\u0646\u062F \u0686\u0648\u0646 '
        +'UUID \u0648 \u062A\u0648\u06A9\u0646\u200C\u0647\u0627 \u0639\u0648\u0636 \u0646\u0645\u06CC\u200C\u0634\u0648\u0646\u062F.',
  bkInclPw:'\u0631\u0645\u0632 \u067E\u0646\u0644 \u0647\u0645 \u0630\u062E\u06CC\u0631\u0647 \u0634\u0648\u062F',
  bkInclProxyCreds:'\u06CC\u0648\u0632\u0631 \u0648 \u067E\u0633\u0648\u0631\u062F \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627 \u0647\u0645 \u0630\u062E\u06CC\u0631\u0647 \u0634\u0648\u062F',
  bkInclTraffic:'\u062A\u0627\u0631\u06CC\u062E\u0686\u0647\u0654 \u0645\u0635\u0631\u0641 \u0647\u0645 \u0630\u062E\u06CC\u0631\u0647 \u0634\u0648\u062F (\u062D\u062C\u0645 \u0641\u0627\u06CC\u0644 \u0628\u06CC\u0634\u062A\u0631 \u0645\u06CC\u200C\u0634\u0648\u062F)',
  bkSecretWarn:'\u26A0\uFE0F \u0627\u06CC\u0646 \u0641\u0627\u06CC\u0644 \u0634\u0627\u0645\u0644 \u0631\u0645\u0632 \u067E\u0646\u0644 \u0648 \u067E\u0633\u0648\u0631\u062F \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627\u0633\u062A \u2014 \u0645\u062B\u0644 \u0631\u0645\u0632 \u0639\u0628\u0648\u0631 \u0627\u0632 \u0622\u0646 \u0645\u0631\u0627\u0642\u0628\u062A \u06A9\u0646\u06CC\u062F.',
  btnBackupLbl:'\u2B07\uFE0F \u062F\u0627\u0646\u0644\u0648\u062F \u0641\u0627\u06CC\u0644 \u067E\u0634\u062A\u06CC\u0628\u0627\u0646',
  restoreTitle:'\u267B\uFE0F \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC',
  restoreHint:'\u0641\u0627\u06CC\u0644 .ixpbak \u0631\u0627 \u0627\u0646\u062A\u062E\u0627\u0628 \u06A9\u0646\u06CC\u062F. \u0627\u0648\u0644 \u0645\u062D\u062A\u0648\u0627\u06CC\u0634 \u0646\u0645\u0627\u06CC\u0634 \u062F\u0627\u062F\u0647 \u0645\u06CC\u200C\u0634\u0648\u062F \u0648 \u062A\u0627 \u062A\u0623\u06CC\u06CC\u062F '
        +'\u0646\u06A9\u0646\u06CC\u062F \u0647\u06CC\u0686 \u0686\u06CC\u0632\u06CC \u062F\u0631 \u062F\u06CC\u062A\u0627\u0628\u06CC\u0633 \u0646\u0648\u0634\u062A\u0647 \u0646\u0645\u06CC\u200C\u0634\u0648\u062F.',
  restoreMode:'\u0646\u062D\u0648\u0647\u0654 \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC',
  bkMerge:'\u0627\u062F\u063A\u0627\u0645 \u2014 \u0645\u0648\u0627\u0631\u062F \u0645\u0648\u062C\u0648\u062F \u0628\u0647\u200C\u0631\u0648\u0632 \u0648 \u0628\u0642\u06CC\u0647 \u0627\u0636\u0627\u0641\u0647 \u0645\u06CC\u200C\u0634\u0648\u0646\u062F',
  bkReplace:'\u062C\u0627\u06CC\u06AF\u0632\u06CC\u0646\u06CC \u06A9\u0627\u0645\u0644 \u2014 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646\u060C \u0622\u06CC\u200C\u067E\u06CC\u200C\u0647\u0627 \u0648 \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627\u06CC \u0641\u0639\u0644\u06CC \u062D\u0630\u0641 \u0645\u06CC\u200C\u0634\u0648\u0646\u062F',
  bkRestorePwLbl:'\u0631\u0645\u0632 \u067E\u0646\u0644 \u0647\u0645 \u0627\u0632 \u0641\u0627\u06CC\u0644 \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC \u0634\u0648\u062F',
  btnRestoreLbl:'\u267B\uFE0F \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC \u06A9\u0646',
  bkReading:'\u062F\u0631 \u062D\u0627\u0644 \u062E\u0648\u0627\u0646\u062F\u0646 \u0641\u0627\u06CC\u0644\u2026',
  bkBadFile:'\u0641\u0627\u06CC\u0644 \u0642\u0627\u0628\u0644 \u062E\u0648\u0627\u0646\u062F\u0646 \u0646\u06CC\u0633\u062A \u06CC\u0627 \u067E\u0634\u062A\u06CC\u0628\u0627\u0646 \u0627\u06CC\u0646 \u067E\u0646\u0644 \u0646\u06CC\u0633\u062A',
  bkFrom:'\u0633\u0627\u062E\u062A\u0647\u200C\u0634\u062F\u0647 \u062F\u0631',bkUsersN:'\u06A9\u0627\u0631\u0628\u0631',bkCipsN:'\u0622\u06CC\u200C\u067E\u06CC \u062A\u0645\u06CC\u0632',bkProxN:'\u067E\u0631\u0648\u06A9\u0633\u06CC',
  bkTrafficN:'\u0631\u06A9\u0648\u0631\u062F \u0645\u0635\u0631\u0641',
  bkHasPw:'\u0634\u0627\u0645\u0644 \u0631\u0645\u0632 \u067E\u0646\u0644',bkNoPw:'\u0628\u062F\u0648\u0646 \u0631\u0645\u0632 \u067E\u0646\u0644',
  bkProxCreds:'\u067E\u0631\u0648\u06A9\u0633\u06CC \u0628\u0627 \u06CC\u0648\u0632\u0631/\u067E\u0633\u0648\u0631\u062F',
  bkEnvDiff:'\u26A0\uFE0F \u0627\u06CC\u0646 \u0645\u062A\u063A\u06CC\u0631\u0647\u0627 \u0628\u0627 \u067E\u0646\u0644 \u0641\u0639\u0644\u06CC \u062A\u0641\u0627\u0648\u062A \u062F\u0627\u0631\u0646\u062F \u0648 \u0628\u0627\u06CC\u062F \u062F\u0633\u062A\u06CC \u062F\u0631 Railway/Render \u0633\u062A \u0634\u0648\u0646\u062F:',
  bkReplaceWarn:'\u0647\u0645\u0647\u0654 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646\u060C \u0622\u06CC\u200C\u067E\u06CC\u200C\u0647\u0627\u06CC \u062A\u0645\u06CC\u0632 \u0648 \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627\u06CC \u0641\u0639\u0644\u06CC \u062D\u0630\u0641 \u0648 \u0628\u0627 \u0641\u0627\u06CC\u0644 \u062C\u0627\u06CC\u06AF\u0632\u06CC\u0646 \u0645\u06CC\u200C\u0634\u0648\u0646\u062F. \u0645\u0637\u0645\u0626\u0646\u06CC\u061F',
  bkPwChanged:"\u0631\u0645\u0632 \u067E\u0646\u0644 \u0627\u0632 \u0641\u0627\u06CC\u0644 \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC \u0634\u062F \u2014 \u062F\u0641\u0639\u0647\u0654 \u0628\u0639\u062F \u0628\u0627 \u0631\u0645\u0632 \u0642\u062F\u06CC\u0645\u06CC\u0650 \u0647\u0645\u0627\u0646 \u0641\u0627\u06CC\u0644 \u0648\u0627\u0631\u062F \u0634\u0648\u06CC\u062F.",
  bkDone:'\u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC \u0627\u0646\u062C\u0627\u0645 \u0634\u062F',
  bkAdded:'\u0627\u0636\u0627\u0641\u0647\u200C\u0634\u062F\u0647',bkUpdated:'\u0628\u0647\u200C\u0631\u0648\u0632\u0634\u062F\u0647',bkSkipped:'\u0631\u062F\u0634\u062F\u0647',
  relayLbl:'\u062F\u0627\u0645\u0646\u0647 \u0631\u0644\u0647',keepAliveLbl:'\u062C\u0644\u0648\u06AF\u06CC\u0631\u06CC \u0627\u0632 \u062E\u0648\u0627\u0628',relayNone:'\u0646\u062F\u0627\u0631\u062F',
  onLbl:'\u0641\u0639\u0627\u0644',offLbl:'\u062E\u0627\u0645\u0648\u0634',
  devWinLbl:'\u067E\u0646\u062C\u0631\u0647 \u0634\u0645\u0627\u0631\u0634 \u062F\u0633\u062A\u06AF\u0627\u0647',seconds:'\u062B\u0627\u0646\u06CC\u0647',
  envNote:'\u0627\u06CC\u0646 \u0645\u0642\u0627\u062F\u06CC\u0631 \u0627\u0632 \u0645\u062A\u063A\u06CC\u0631\u0647\u0627\u06CC \u0645\u062D\u06CC\u0637\u06CC \u062E\u0648\u0627\u0646\u062F\u0647 \u0645\u06CC\u200C\u0634\u0648\u0646\u062F \u0648 \u062F\u0631 Railway \u0642\u0627\u0628\u0644 \u062A\u063A\u06CC\u06CC\u0631\u0646\u062F.',
  logout:'\u062E\u0631\u0648\u062C',logs:'\u0631\u062E\u062F\u0627\u062F\u0647\u0627',noLogs:'\u0631\u062E\u062F\u0627\u062F\u06CC \u0646\u06CC\u0633\u062A',
  statusDisabled:'\u063A\u06CC\u0631\u0641\u0639\u0627\u0644',statusExpired:'\u0645\u0646\u0642\u0636\u06CC',statusQuota:'\u062D\u062C\u0645 \u062A\u0645\u0627\u0645',
 },
 en:{dir:'ltr',
  setupTitle:'Set a password',setupSub:'First run \u2014 choose your panel password',
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
  name:'Name',quota:'Quota (GB)',days:'Days',devLimit:'Devices',
  transport:'Transport',trWs:'\u{1F50C} WS + TLS',trXhttp:'\u{1F680} XHTTP + TLS',trBoth:'\u{1F500} Both',
  add:'Add',zeroInf:'0 = unlimited. Device count is based on distinct active IPs.',
  search:'Search\u2026',noUsers:'No users yet',
  config:'Config',ipsBtn:'IPs',edit:'Edit',
  used:'Used',expiry:'Expires',never:'Never',
  subLink:'Subscription link',copySub:'Copy subscription link',
  singleCfg:'Individual configs',copy:'Copy',copied:'Copied \u2713',
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
  obfLbl:'Obfuscation (Fragment + Cipher mask)',
  uuidWarn:'Rotate UUID? Existing configs will stop working.',delWarn:'Delete this user?',
  cleanTitle:'Clean IP manager',
  cleanHint:'Clean IPs or domains. Added to every subscription as extra configs.',
  addrPh:'e.g. 1.2.3.4 or cdn.example.com',remarkPh:'Label (optional)',
  bulkPh:'One per line:\\\\n1.2.3.4 # Irancell\\\\n5.6.7.8 # MCI',
  bulkAdd:'Bulk add',clearAll:'Delete all',
  pxTitle:'Outbound proxy',
  pxHint:'Arm a proxy and every user connection leaves through it, so target sites see the proxy IP.',
  pxKind:'Type',pxHost:'Host / IP',pxPort:'Port',
  pxUser:'Username (optional)',pxPass:'Password (optional)',
  pxAdd:'Add & test',pxTestAll:'Test all',
  pxInSub:'in subscriptions',
  pxAutoNote:'Every proxy you add joins all subscriptions automatically \u2014 all of them at once, no button. The no-proxy config is always there, and a failed health check or a dropped connection never removes a proxy: only disabling or deleting it in the panel does.',
  pxLineHint:'One proxy per line \u2014 e.g. socks5://1.1.1.1:5866 or http://user:pass@2.2.2.2:8080',
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
  pwChanged:'Password changed \u2713',
  serverInfo:'Server info',wsPathLbl:'WebSocket path',xhPathLbl:'XHTTP path',
  xhModeLbl:'XHTTP mode',
  xhModeHint:'The mode is packet-up, which spends one request per upload chunk. Behind a '
        +'Cloudflare relay, set XHTTP_MODE=stream-up to get 2 requests per connection instead. '
        +'Existing configs keep working, but users need to refresh their subscription once.',
  trWarnTitle:'\u26A0\uFE0F XHTTP request cost:',
  trWarn:"Cost depends on the mode. stream-up \u2014 this panel's default \u2014 is 2 requests per "
       +"connection (one GET downlink plus one long-lived POST uplink). packet-up sends every "
       +"upload chunk as its own POST, so one active client can be hundreds of requests a "
       +"minute and will drain a Cloudflare Worker's daily quota (100k). WS is cheapest of "
       +"all: 1 request per connection no matter how long it stays open.",
  backupTitle:'\u{1F4E6} Backup',
  backupHint:'A single .ixpbak file holding every user (with their UUID and subscription '
        +'token), your clean IPs, your proxies, the panel password and its settings. Import '
        +'it into a fresh panel and everything comes back \u2014 configs already handed out keep '
        +'working, because UUIDs and tokens are preserved.',
  bkInclPw:'include the panel password',
  bkInclProxyCreds:'include proxy usernames and passwords',
  bkInclTraffic:'include traffic history (larger file)',
  bkSecretWarn:'\u26A0\uFE0F This file contains the panel password and your proxy credentials \u2014 treat it like a password.',
  btnBackupLbl:'\u2B07\uFE0F Download backup',
  restoreTitle:'\u267B\uFE0F Restore',
  restoreHint:'Pick a .ixpbak file. Its contents are shown first and nothing is written '
        +'to the database until you confirm.',
  restoreMode:'Restore mode',
  bkMerge:'Merge \u2014 update matching entries, add the rest',
  bkReplace:'Replace \u2014 wipe current users, clean IPs and proxies first',
  bkRestorePwLbl:'also restore the panel password from the file',
  btnRestoreLbl:'\u267B\uFE0F Restore now',
  bkReading:'Reading file\u2026',
  bkBadFile:'File cannot be read, or is not a backup from this panel',
  bkFrom:'Created',bkUsersN:'users',bkCipsN:'clean IPs',bkProxN:'proxies',
  bkTrafficN:'traffic rows',
  bkHasPw:'includes the panel password',bkNoPw:'no panel password',
  bkProxCreds:'proxies with credentials',
  bkEnvDiff:'\u26A0\uFE0F These variables differ from this panel and must be set by hand in Railway/Render:',
  bkReplaceWarn:'All current users, clean IPs and proxies will be deleted and replaced by the file. Continue?',
  bkPwChanged:"The panel password was restored from the file \u2014 sign in with that file's password next time.",
  bkDone:'Restore complete',
  bkAdded:'added',bkUpdated:'updated',bkSkipped:'skipped',
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
<\/script>
<div class="glow fixed inset-0 pointer-events-none"></div>
<div class="relative w-full max-w-sm card rounded-3xl p-8 shadow-2xl backdrop-blur">
 <div class="flex justify-between mb-4">
  <select onchange="setLang(this.value)" id="langSel" class="inp rounded-lg px-2 py-1 text-xs">
   <option value="fa">\u{1F1EE}\u{1F1F7} \u0641\u0627\u0631\u0633\u06CC</option><option value="en">\u{1F1EC}\u{1F1E7} English</option></select>
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
<\/script></body></html>`])));
var _b;
var PANEL_HTML = String.raw(_b || (_b = __template([`<!DOCTYPE html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}}</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"><\/script>
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"><\/script>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;800&display=swap" rel="stylesheet">
<style>body{font-family:Vazirmatn,system-ui,sans-serif}
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
</style>
</head><body class="min-h-screen">
<script>
const I18N={
 fa:{dir:'rtl',
  setupTitle:'\u062A\u0639\u06CC\u06CC\u0646 \u0631\u0645\u0632 \u0639\u0628\u0648\u0631',setupSub:'\u0627\u0648\u0644\u06CC\u0646 \u0648\u0631\u0648\u062F \u2014 \u06CC\u06A9 \u0631\u0645\u0632 \u0628\u0631\u0627\u06CC \u067E\u0646\u0644 \u0627\u0646\u062A\u062E\u0627\u0628 \u06A9\u0646\u06CC\u062F',
  loginTitle:'\u0648\u0631\u0648\u062F \u0628\u0647 \u067E\u0646\u0644',loginSub:'\u0631\u0645\u0632 \u0639\u0628\u0648\u0631 \u062E\u0648\u062F \u0631\u0627 \u0648\u0627\u0631\u062F \u06A9\u0646\u06CC\u062F',
  password:'\u0631\u0645\u0632 \u0639\u0628\u0648\u0631',confirm:'\u062A\u06A9\u0631\u0627\u0631 \u0631\u0645\u0632 \u0639\u0628\u0648\u0631',enter:'\u0648\u0631\u0648\u062F',save:'\u0630\u062E\u06CC\u0631\u0647 \u0648 \u0648\u0631\u0648\u062F',
  pwRule:'\u062D\u062F\u0627\u0642\u0644 \u06F8 \u06A9\u0627\u0631\u0627\u06A9\u062A\u0631 \u0634\u0627\u0645\u0644 \u062D\u0631\u0641 \u0628\u0632\u0631\u06AF\u060C \u062D\u0631\u0641 \u06A9\u0648\u0686\u06A9 \u0648 \u0639\u062F\u062F',netErr:'\u062E\u0637\u0627\u06CC \u0634\u0628\u06A9\u0647',
  navDash:'\u062F\u0627\u0634\u0628\u0648\u0631\u062F',navUsers:'\u0645\u062F\u06CC\u0631\u06CC\u062A \u06A9\u0627\u0631\u0628\u0631\u0627\u0646',navClean:'Clean IP',
  navProxy:'\u067E\u0631\u0648\u06A9\u0633\u06CC',navLive:'\u0627\u062A\u0635\u0627\u0644\u0627\u062A \u0632\u0646\u062F\u0647',
  navSettings:'\u062A\u0646\u0638\u06CC\u0645\u0627\u062A \u067E\u0646\u0644',navLogs:'\u0631\u062E\u062F\u0627\u062F\u0647\u0627',menu:'\u0645\u0646\u0648',
  totalUsers:'\u06A9\u0644 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646',online:'\u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0622\u0646\u0644\u0627\u06CC\u0646',devices:'\u062F\u0633\u062A\u06AF\u0627\u0647\u200C\u0647\u0627\u06CC \u0645\u062A\u0635\u0644',
  traffic:'\u0645\u0635\u0631\u0641 \u06A9\u0644',cleanIps:'\u0622\u06CC\u200C\u067E\u06CC \u062A\u0645\u06CC\u0632',xSessions:'\u0633\u0634\u0646\u200C\u0647\u0627\u06CC XHTTP',liveTitle:'\u0627\u062A\u0635\u0627\u0644\u0627\u062A \u0632\u0646\u062F\u0647',liveEmpty:'\u0647\u06CC\u0686 \u0627\u062A\u0635\u0627\u0644\u06CC \u0641\u0639\u0627\u0644 \u0646\u06CC\u0633\u062A',
  chart24:'\u0645\u0635\u0631\u0641 \u06F2\u06F4 \u0633\u0627\u0639\u062A \u0627\u062E\u06CC\u0631',protoSplit:'\u062A\u0642\u0633\u06CC\u0645 \u0628\u0631 \u0627\u0633\u0627\u0633 \u062A\u0631\u0646\u0633\u067E\u0648\u0631\u062A',
  newUser:'\u0633\u0627\u062E\u062A \u06A9\u0627\u0631\u0628\u0631 \u062C\u062F\u06CC\u062F',users:'\u06A9\u0627\u0631\u0628\u0631\u0627\u0646',
  name:'\u0646\u0627\u0645 (\u0627\u0646\u06AF\u0644\u06CC\u0633\u06CC)',quota:'\u062D\u062C\u0645 (GB)',days:'\u0645\u062F\u062A (\u0631\u0648\u0632)',devLimit:'\u062A\u0639\u062F\u0627\u062F \u062F\u0633\u062A\u06AF\u0627\u0647',
  transport:'\u062A\u0631\u0646\u0633\u067E\u0648\u0631\u062A',trWs:'\u{1F50C} WS + TLS',trXhttp:'\u{1F680} XHTTP + TLS',trBoth:'\u{1F500} \u0647\u0631 \u062F\u0648',
  add:'\u0627\u0641\u0632\u0648\u062F\u0646',zeroInf:'\u06F0 = \u0628\u06CC\u200C\u0646\u0647\u0627\u06CC\u062A. \xAB\u062A\u0639\u062F\u0627\u062F \u062F\u0633\u062A\u06AF\u0627\u0647\xBB \u0628\u0631 \u0627\u0633\u0627\u0633 IP \u06CC\u06A9\u062A\u0627\u06CC \u0641\u0639\u0627\u0644 \u0645\u062D\u0627\u0633\u0628\u0647 \u0645\u06CC\u200C\u0634\u0648\u062F.',
  search:'\u062C\u0633\u062A\u062C\u0648\u2026',noUsers:'\u06A9\u0627\u0631\u0628\u0631\u06CC \u0646\u06CC\u0633\u062A',
  config:'\u06A9\u0627\u0646\u0641\u06CC\u06AF',ipsBtn:'IP \u0647\u0627',edit:'\u0648\u06CC\u0631\u0627\u06CC\u0634',
  used:'\u0645\u0635\u0631\u0641',expiry:'\u0627\u0646\u0642\u0636\u0627',never:'\u0628\u06CC\u200C\u0646\u0647\u0627\u06CC\u062A',
  subLink:'\u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9 (Subscription)',copySub:'\u06A9\u067E\u06CC \u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9',
  singleCfg:'\u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627\u06CC \u062A\u06A9\u06CC',copy:'\u06A9\u067E\u06CC',copied:'\u06A9\u067E\u06CC \u0634\u062F \u2713',
  devTitle:'\u062F\u0633\u062A\u06AF\u0627\u0647\u200C\u0647\u0627\u06CC \u0645\u062A\u0635\u0644',noConn:'\u0647\u0646\u0648\u0632 \u0627\u062A\u0635\u0627\u0644\u06CC \u062B\u0628\u062A \u0646\u0634\u062F\u0647',
  clearIps:'\u067E\u0627\u06A9 \u06A9\u0631\u062F\u0646 \u0644\u06CC\u0633\u062A IP',
  liveNow:'\u0627\u0644\u0627\u0646 \u0645\u062A\u0635\u0644',noneNow:'\u0647\u0645\u06CC\u0646 \u0627\u0644\u0627\u0646 \u0647\u06CC\u0686 \u062F\u0633\u062A\u06AF\u0627\u0647\u06CC \u0645\u062A\u0635\u0644 \u0646\u06CC\u0633\u062A',
  countedFor:'\u0634\u0645\u0631\u062F\u0647\u200C\u0634\u062F\u0647 \u0628\u0631\u0627\u06CC \u0645\u062D\u062F\u0648\u062F\u06CC\u062A',totalSeen:'\u06A9\u0644 IP \u0647\u0627\u06CC \u062F\u06CC\u062F\u0647\u200C\u0634\u062F\u0647',
  showHistory:'\u0646\u0645\u0627\u06CC\u0634 \u062A\u0627\u0631\u06CC\u062E\u0686\u0647',showLive:'\u0646\u0645\u0627\u06CC\u0634 \u0641\u0642\u0637 \u0645\u062A\u0635\u0644\u200C\u0647\u0627',
  inLast:'\u062F\u0631 %s \u062B\u0627\u0646\u06CC\u0647 \u0627\u062E\u06CC\u0631',refresh:'\u0628\u0647\u200C\u0631\u0648\u0632\u0631\u0633\u0627\u0646\u06CC',
  liveDevices:'\u062F\u0633\u062A\u06AF\u0627\u0647\u200C\u0647\u0627\u06CC \u0641\u0639\u0627\u0644 \u0627\u0644\u0627\u0646',
  editUser:'\u0648\u06CC\u0631\u0627\u06CC\u0634',remainDays:'\u0645\u062F\u062A \u0628\u0627\u0642\u06CC\u200C\u0645\u0627\u0646\u062F\u0647 (\u0631\u0648\u0632)',allowedDev:'\u062A\u0639\u062F\u0627\u062F \u062F\u0633\u062A\u06AF\u0627\u0647 \u0645\u062C\u0627\u0632',
  active:'\u0641\u0639\u0627\u0644',saveBtn:'\u0630\u062E\u06CC\u0631\u0647',resetTraffic:'\u0631\u06CC\u0633\u062A \u062D\u062C\u0645',newUuid:'UUID \u062C\u062F\u06CC\u062F',
  customUuid:'UUID \u062F\u0633\u062A\u06CC',del:'\u062D\u0630\u0641',
  obfLbl:'\u0645\u0628\u0647\u0645\u200C\u0633\u0627\u0632 (Fragment + Cipher mask)',
  uuidWarn:'UUID \u0639\u0648\u0636 \u0634\u0648\u062F\u061F \u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627\u06CC \u0642\u0628\u0644\u06CC \u0627\u0632 \u06A9\u0627\u0631 \u0645\u06CC\u200C\u0627\u0641\u062A\u0646\u062F.',delWarn:'\u0627\u06CC\u0646 \u06A9\u0627\u0631\u0628\u0631 \u062D\u0630\u0641 \u0634\u0648\u062F\u061F',
  cleanTitle:'\u0645\u062F\u06CC\u0631\u06CC\u062A Clean IP',
  cleanHint:'\u0622\u06CC\u200C\u067E\u06CC \u06CC\u0627 \u062F\u0627\u0645\u0646\u0647 \u062A\u0645\u06CC\u0632. \u062F\u0631 \u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9 \u0647\u0631 \u06A9\u0627\u0631\u0628\u0631 \u0628\u0647 \u0639\u0646\u0648\u0627\u0646 \u06A9\u0627\u0646\u0641\u06CC\u06AF \u0627\u0636\u0627\u0641\u06CC \u0627\u0636\u0627\u0641\u0647 \u0645\u06CC\u200C\u0634\u0648\u062F.',
  addrPh:'\u0645\u062B\u0644\u0627 1.2.3.4 \u06CC\u0627 cdn.example.com',remarkPh:'\u0628\u0631\u0686\u0633\u0628 (\u0627\u062E\u062A\u06CC\u0627\u0631\u06CC)',
  bulkPh:'\u0686\u0646\u062F \u0645\u0648\u0631\u062F\u060C \u0647\u0631 \u062E\u0637 \u06CC\u06A9\u06CC:\\n1.2.3.4 # \u0627\u06CC\u0631\u0627\u0646\u0633\u0644\\n5.6.7.8 # \u0647\u0645\u0631\u0627\u0647 \u0627\u0648\u0644',
  bulkAdd:'\u0627\u0641\u0632\u0648\u062F\u0646 \u0627\u0646\u0628\u0648\u0647',clearAll:'\u062D\u0630\u0641 \u0647\u0645\u0647',
  pxTitle:'\u067E\u0631\u0648\u06A9\u0633\u06CC \u062E\u0631\u0648\u062C\u06CC',
  pxHint:'\u0628\u0627 \u0641\u0639\u0627\u0644 \u06A9\u0631\u062F\u0646 \u06CC\u06A9 \u067E\u0631\u0648\u06A9\u0633\u06CC\u060C \u062A\u0645\u0627\u0645 \u062A\u0631\u0627\u0641\u06CC\u06A9 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0627\u0632 \u0647\u0645\u0627\u0646 \u0645\u0633\u06CC\u0631 \u062E\u0627\u0631\u062C \u0645\u06CC\u200C\u0634\u0648\u062F \u0648 \u0633\u0627\u06CC\u062A\u200C\u0647\u0627 \u0627\u06CC\u067E\u06CC \u067E\u0631\u0648\u06A9\u0633\u06CC \u0631\u0627 \u0645\u06CC\u200C\u0628\u06CC\u0646\u0646\u062F.',
  pxKind:'\u0646\u0648\u0639',pxHost:'\u0647\u0627\u0633\u062A / \u0627\u06CC\u067E\u06CC',pxPort:'\u067E\u0648\u0631\u062A',
  pxUser:'\u06CC\u0648\u0632\u0631\u0646\u06CC\u0645 (\u0627\u062E\u062A\u06CC\u0627\u0631\u06CC)',pxPass:'\u067E\u0633\u0648\u0631\u062F (\u0627\u062E\u062A\u06CC\u0627\u0631\u06CC)',
  pxAdd:'\u0627\u0641\u0632\u0648\u062F\u0646 \u0648 \u062A\u0633\u062A',pxTestAll:'\u062A\u0633\u062A \u0647\u0645\u0647',
  pxInSub:'\u062F\u0631 \u0633\u0627\u0628',
  pxAutoNote:'\u0647\u0631 \u067E\u0631\u0648\u06A9\u0633\u06CC \u06A9\u0647 \u0627\u0636\u0627\u0641\u0647 \u0634\u0648\u062F \u062E\u0648\u062F\u0628\u0647\u200C\u062E\u0648\u062F \u062F\u0631 \u0633\u0627\u0628 \u0647\u0645\u0647 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0645\u06CC\u200C\u0622\u06CC\u062F \u2014 \u0647\u0645\u0647 \u0628\u0627 \u0647\u0645\u060C \u0628\u062F\u0648\u0646 \u062F\u06A9\u0645\u0647. \u06A9\u0627\u0646\u0641\u06CC\u06AF \u0628\u062F\u0648\u0646 \u067E\u0631\u0648\u06A9\u0633\u06CC \u0647\u0645\u06CC\u0634\u0647 \u0633\u0631 \u062C\u0627\u06CC\u0634 \u0647\u0633\u062A\u061B \u0642\u0637\u0639\u06CC \u06CC\u0627 \u0646\u0627\u0645\u0648\u0641\u0642 \u0628\u0648\u062F\u0646 \u062A\u0633\u062A\u060C \u067E\u0631\u0648\u06A9\u0633\u06CC \u0631\u0627 \u0627\u0632 \u0633\u0627\u0628 \u062D\u0630\u0641 \u0646\u0645\u06CC\u200C\u06A9\u0646\u062F \u0648 \u0641\u0642\u0637 \u0628\u0627 \u063A\u06CC\u0631\u0641\u0639\u0627\u0644 \u06A9\u0631\u062F\u0646 \u06CC\u0627 \u062D\u0630\u0641 \u0627\u0632 \u067E\u0646\u0644 \u0628\u06CC\u0631\u0648\u0646 \u0645\u06CC\u200C\u0631\u0648\u062F.',
  pxLineHint:'\u0647\u0631 \u062E\u0637 \u06CC\u06A9 \u067E\u0631\u0648\u06A9\u0633\u06CC \u2014 \u0645\u0627\u0646\u0646\u062F socks5://1.1.1.1:5866 \u06CC\u0627 http://user:pass@2.2.2.2:8080',
  pxAddLines:'\u0627\u0641\u0632\u0648\u062F\u0646 \u0644\u06CC\u0633\u062A \u0648 \u062A\u0633\u062A',
  pxAdvanced:'\u0648\u0631\u0648\u062F \u062F\u0633\u062A\u06CC \u0641\u06CC\u0644\u062F\u0647\u0627',
  pxDirect:'\u0627\u062A\u0635\u0627\u0644 \u0645\u0633\u062A\u0642\u06CC\u0645 (\u0628\u062F\u0648\u0646 \u067E\u0631\u0648\u06A9\u0633\u06CC)',
  pxActive:'\u0641\u0639\u0627\u0644',pxArm:'\u0641\u0639\u0627\u0644 \u06A9\u0631\u062F\u0646',pxTest:'\u062A\u0633\u062A \u0633\u0644\u0627\u0645\u062A',
  pxHealthy:'\u0633\u0627\u0644\u0645',pxDown:'\u062E\u0631\u0627\u0628',pxUntested:'\u062A\u0633\u062A \u0646\u0634\u062F\u0647',
  pxExitIp:'\u0627\u06CC\u067E\u06CC \u062E\u0631\u0648\u062C\u06CC',pxLatency:'\u062A\u0627\u062E\u06CC\u0631',
  pxNone:'\u0647\u0646\u0648\u0632 \u067E\u0631\u0648\u06A9\u0633\u06CC \u0627\u0636\u0627\u0641\u0647 \u0646\u0634\u062F\u0647 \u0627\u0633\u062A',
  pxStrict:'\u062D\u0627\u0644\u062A \u0633\u062E\u062A\u06AF\u06CC\u0631\u0627\u0646\u0647',
  pxStrictHint:'\u0627\u06AF\u0631 \u067E\u0631\u0648\u06A9\u0633\u06CC \u0642\u0637\u0639 \u0634\u062F\u060C \u0627\u062A\u0635\u0627\u0644 \u0631\u062F \u0645\u06CC\u200C\u0634\u0648\u062F \u062A\u0627 \u0627\u06CC\u067E\u06CC \u0627\u0635\u0644\u06CC \u0633\u0631\u0648\u0631 \u0644\u0648 \u0646\u0631\u0648\u062F',
  pxFlagSrc:'\u0645\u0646\u0628\u0639 \u067E\u0631\u0686\u0645 \u0646\u0627\u0645 \u06A9\u0627\u0646\u0641\u06CC\u06AF',
  pxFlagProxy:'\u06A9\u0634\u0648\u0631 \u067E\u0631\u0648\u06A9\u0633\u06CC',pxFlagEntry:'\u06A9\u0634\u0648\u0631 \u0633\u0631\u0648\u0631 \u0648\u0631\u0648\u062F\u06CC',
  pxTesting:'\u062F\u0631 \u062D\u0627\u0644 \u062A\u0633\u062A...',pxArmed:'\u067E\u0631\u0648\u06A9\u0633\u06CC \u0641\u0639\u0627\u0644 \u0634\u062F',
  pxDelWarn:'\u0627\u06CC\u0646 \u067E\u0631\u0648\u06A9\u0633\u06CC \u062D\u0630\u0641 \u0634\u0648\u062F\u061F',
  addedN:'\u0627\u0641\u0632\u0648\u062F\u0647 \u0634\u062F',dupN:'\u062A\u06A9\u0631\u0627\u0631\u06CC',invalidN:'\u0646\u0627\u0645\u0639\u062A\u0628\u0631',noCleanIps:'\u0644\u06CC\u0633\u062A \u062E\u0627\u0644\u06CC \u0627\u0633\u062A',
  settings:'\u062A\u0646\u0638\u06CC\u0645\u0627\u062A',appearance:'\u0638\u0627\u0647\u0631',theme:'\u062A\u0645',language:'\u0632\u0628\u0627\u0646',
  thDark:'\u062A\u06CC\u0631\u0647 (\u0645\u0634\u06A9\u06CC \u0648 \u0622\u0628\u06CC)',thLight:'\u0631\u0648\u0634\u0646 (\u0633\u0641\u06CC\u062F \u0648 \u0622\u0628\u06CC)',thGray:'\u062E\u0627\u06A9\u0633\u062A\u0631\u06CC',
  country:'\u06A9\u0634\u0648\u0631',autoCountry:'\u062A\u0634\u062E\u06CC\u0635 \u062E\u0648\u062F\u06A9\u0627\u0631',mainCountry:'\u06A9\u0634\u0648\u0631 \u0633\u0631\u0648\u0631 \u0627\u0635\u0644\u06CC',
  flagsHint:'\u067E\u0631\u0686\u0645 \u06A9\u0634\u0648\u0631 \u0628\u0647 \u0627\u0628\u062A\u062F\u0627\u06CC \u0646\u0627\u0645 \u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627 \u062F\u0631 \u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9 \u0627\u0636\u0627\u0641\u0647 \u0645\u06CC\u200C\u0634\u0648\u062F',
  savedOk:'\u0630\u062E\u06CC\u0631\u0647 \u0634\u062F',save:'\u0630\u062E\u06CC\u0631\u0647',
  changePw:'\u062A\u063A\u06CC\u06CC\u0631 \u0631\u0645\u0632 \u0639\u0628\u0648\u0631',curPw:'\u0631\u0645\u0632 \u0641\u0639\u0644\u06CC',newPw:'\u0631\u0645\u0632 \u062C\u062F\u06CC\u062F',pwChanged:'\u0631\u0645\u0632 \u062A\u063A\u06CC\u06CC\u0631 \u06A9\u0631\u062F \u2713',
  serverInfo:'\u0627\u0637\u0644\u0627\u0639\u0627\u062A \u0633\u0631\u0648\u0631',wsPathLbl:'\u0645\u0633\u06CC\u0631 WebSocket',xhPathLbl:'\u0645\u0633\u06CC\u0631 XHTTP',
  xhModeLbl:'\u062D\u0627\u0644\u062A XHTTP',
  xhModeHint:'\u062D\u0627\u0644\u062A \u0631\u0648\u06CC packet-up \u0627\u0633\u062A \u0648 \u0628\u0631\u0627\u06CC \u0647\u0631 \u062A\u06A9\u0647 \u0622\u067E\u0644\u0648\u062F \u06CC\u06A9 \u0631\u06A9\u0648\u0626\u0633\u062A \u062C\u062F\u0627 \u0645\u06CC\u200C\u0641\u0631\u0633\u062A\u062F. \u0627\u06AF\u0631 \u0631\u0644\u0647 '
        +'\u06A9\u0644\u0627\u062F\u0641\u0644\u0631 \u062F\u0627\u0631\u06CC\u062F\u060C XHTTP_MODE \u0631\u0627 \u0628\u0647 stream-up \u062A\u063A\u06CC\u06CC\u0631 \u062F\u0647\u06CC\u062F \u062A\u0627 \u0647\u0631 \u0627\u062A\u0635\u0627\u0644 \u0641\u0642\u0637 \u06F2 \u0631\u06A9\u0648\u0626\u0633\u062A \u0634\u0648\u062F. '
        +'\u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627\u06CC \u0642\u0628\u0644\u06CC \u0647\u0645\u0686\u0646\u0627\u0646 \u06A9\u0627\u0631 \u0645\u06CC\u200C\u06A9\u0646\u0646\u062F\u060C \u0648\u0644\u06CC \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0628\u0627\u06CC\u062F \u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9 \u0631\u0627 \u06CC\u06A9 \u0628\u0627\u0631 \u0628\u0647\u200C\u0631\u0648\u0632 \u06A9\u0646\u0646\u062F.',
  trWarnTitle:'\u26A0\uFE0F \u0645\u0635\u0631\u0641 \u0631\u06A9\u0648\u0626\u0633\u062A XHTTP:',
  trWarn:'\u0645\u0635\u0631\u0641 \u0627\u06CC\u0646 \u062A\u0631\u0646\u0633\u067E\u0648\u0631\u062A \u0628\u0647 \u062D\u0627\u0644\u062A (mode) \u0628\u0633\u062A\u06AF\u06CC \u062F\u0627\u0631\u062F. \u062F\u0631 stream-up \u2014 \u06A9\u0647 \u067E\u06CC\u0634\u200C\u0641\u0631\u0636 \u0627\u06CC\u0646 \u067E\u0646\u0644 '
        +'\u0627\u0633\u062A \u2014 \u0647\u0631 \u0627\u062A\u0635\u0627\u0644 \u06F2 \u0631\u06A9\u0648\u0626\u0633\u062A \u0645\u06CC\u200C\u0634\u0648\u062F (\u06CC\u06A9 GET \u0628\u0631\u0627\u06CC \u062F\u0627\u0646\u0644\u0648\u062F \u0648 \u06CC\u06A9 POST \u0628\u0644\u0646\u062F\u0645\u062F\u062A \u0628\u0631\u0627\u06CC \u0622\u067E\u0644\u0648\u062F). '
        +'\u062F\u0631 packet-up \u0647\u0631 \u062A\u06A9\u0647 \u0627\u0632 \u0622\u067E\u0644\u0648\u062F \u06CC\u06A9 POST \u062C\u062F\u0627\u06AF\u0627\u0646\u0647 \u0627\u0633\u062A \u0648 \u06CC\u06A9 \u06A9\u0627\u0631\u0628\u0631 \u0641\u0639\u0627\u0644 \u062F\u0642\u06CC\u0642\u0647\u200C\u0627\u06CC \u0635\u062F\u0647\u0627 '
        +'\u0631\u06A9\u0648\u0626\u0633\u062A \u0645\u06CC\u200C\u0633\u0627\u0632\u062F \u06A9\u0647 \u0633\u0647\u0645\u06CC\u0647 \u0631\u0648\u0632\u0627\u0646\u0647 \u0648\u0631\u06A9\u0631 \u06A9\u0644\u0627\u062F\u0641\u0644\u0631 (\u06F1\u06F0\u06F0\u066C\u06F0\u06F0\u06F0) \u0631\u0627 \u0632\u0648\u062F \u067E\u0631 \u0645\u06CC\u200C\u06A9\u0646\u062F. WS \u0627\u0632 \u0647\u0645\u0647 '
        +'\u06A9\u0645\u200C\u0645\u0635\u0631\u0641\u200C\u062A\u0631 \u0627\u0633\u062A: \u0647\u0631 \u0627\u062A\u0635\u0627\u0644 \u0641\u0642\u0637 \u06F1 \u0631\u06A9\u0648\u0626\u0633\u062A\u060C \u0647\u0631 \u0686\u0642\u062F\u0631 \u0647\u0645 \u0637\u0648\u0644 \u0628\u06A9\u0634\u062F.',
  backupTitle:'\u{1F4E6} \u067E\u0634\u062A\u06CC\u0628\u0627\u0646\u200C\u06AF\u06CC\u0631\u06CC',
  backupHint:'\u06CC\u06A9 \u0641\u0627\u06CC\u0644 \u0628\u0627 \u067E\u0633\u0648\u0646\u062F .ixpbak \u06A9\u0647 \u0647\u0645\u0647\u0654 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 (\u0628\u0627 UUID \u0648 \u062A\u0648\u06A9\u0646 \u0627\u0634\u062A\u0631\u0627\u06A9\u0634\u0627\u0646)\u060C '
        +'\u0622\u06CC\u200C\u067E\u06CC\u200C\u0647\u0627\u06CC \u062A\u0645\u06CC\u0632\u060C \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627\u060C \u0631\u0645\u0632 \u067E\u0646\u0644 \u0648 \u062A\u0646\u0638\u06CC\u0645\u0627\u062A \u0631\u0627 \u0646\u06AF\u0647 \u0645\u06CC\u200C\u062F\u0627\u0631\u062F. \u0647\u0645\u06CC\u0646 \u0641\u0627\u06CC\u0644 \u0631\u0627 \u062F\u0631 \u067E\u0646\u0644 '
        +'\u062C\u062F\u06CC\u062F \u0648\u0627\u0631\u062F \u06A9\u0646\u06CC\u062F \u062A\u0627 \u0647\u0645\u0647 \u0686\u06CC\u0632 \u0628\u0631\u06AF\u0631\u062F\u062F \u2014 \u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627\u06CC \u062F\u0633\u062A \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0647\u0645 \u06A9\u0627\u0631 \u0645\u06CC\u200C\u06A9\u0646\u0646\u062F \u0686\u0648\u0646 '
        +'UUID \u0648 \u062A\u0648\u06A9\u0646\u200C\u0647\u0627 \u0639\u0648\u0636 \u0646\u0645\u06CC\u200C\u0634\u0648\u0646\u062F.',
  bkInclPw:'\u0631\u0645\u0632 \u067E\u0646\u0644 \u0647\u0645 \u0630\u062E\u06CC\u0631\u0647 \u0634\u0648\u062F',
  bkInclProxyCreds:'\u06CC\u0648\u0632\u0631 \u0648 \u067E\u0633\u0648\u0631\u062F \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627 \u0647\u0645 \u0630\u062E\u06CC\u0631\u0647 \u0634\u0648\u062F',
  bkInclTraffic:'\u062A\u0627\u0631\u06CC\u062E\u0686\u0647\u0654 \u0645\u0635\u0631\u0641 \u0647\u0645 \u0630\u062E\u06CC\u0631\u0647 \u0634\u0648\u062F (\u062D\u062C\u0645 \u0641\u0627\u06CC\u0644 \u0628\u06CC\u0634\u062A\u0631 \u0645\u06CC\u200C\u0634\u0648\u062F)',
  bkSecretWarn:'\u26A0\uFE0F \u0627\u06CC\u0646 \u0641\u0627\u06CC\u0644 \u0634\u0627\u0645\u0644 \u0631\u0645\u0632 \u067E\u0646\u0644 \u0648 \u067E\u0633\u0648\u0631\u062F \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627\u0633\u062A \u2014 \u0645\u062B\u0644 \u0631\u0645\u0632 \u0639\u0628\u0648\u0631 \u0627\u0632 \u0622\u0646 \u0645\u0631\u0627\u0642\u0628\u062A \u06A9\u0646\u06CC\u062F.',
  btnBackupLbl:'\u2B07\uFE0F \u062F\u0627\u0646\u0644\u0648\u062F \u0641\u0627\u06CC\u0644 \u067E\u0634\u062A\u06CC\u0628\u0627\u0646',
  restoreTitle:'\u267B\uFE0F \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC',
  restoreHint:'\u0641\u0627\u06CC\u0644 .ixpbak \u0631\u0627 \u0627\u0646\u062A\u062E\u0627\u0628 \u06A9\u0646\u06CC\u062F. \u0627\u0648\u0644 \u0645\u062D\u062A\u0648\u0627\u06CC\u0634 \u0646\u0645\u0627\u06CC\u0634 \u062F\u0627\u062F\u0647 \u0645\u06CC\u200C\u0634\u0648\u062F \u0648 \u062A\u0627 \u062A\u0623\u06CC\u06CC\u062F '
        +'\u0646\u06A9\u0646\u06CC\u062F \u0647\u06CC\u0686 \u0686\u06CC\u0632\u06CC \u062F\u0631 \u062F\u06CC\u062A\u0627\u0628\u06CC\u0633 \u0646\u0648\u0634\u062A\u0647 \u0646\u0645\u06CC\u200C\u0634\u0648\u062F.',
  restoreMode:'\u0646\u062D\u0648\u0647\u0654 \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC',
  bkMerge:'\u0627\u062F\u063A\u0627\u0645 \u2014 \u0645\u0648\u0627\u0631\u062F \u0645\u0648\u062C\u0648\u062F \u0628\u0647\u200C\u0631\u0648\u0632 \u0648 \u0628\u0642\u06CC\u0647 \u0627\u0636\u0627\u0641\u0647 \u0645\u06CC\u200C\u0634\u0648\u0646\u062F',
  bkReplace:'\u062C\u0627\u06CC\u06AF\u0632\u06CC\u0646\u06CC \u06A9\u0627\u0645\u0644 \u2014 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646\u060C \u0622\u06CC\u200C\u067E\u06CC\u200C\u0647\u0627 \u0648 \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627\u06CC \u0641\u0639\u0644\u06CC \u062D\u0630\u0641 \u0645\u06CC\u200C\u0634\u0648\u0646\u062F',
  bkRestorePwLbl:'\u0631\u0645\u0632 \u067E\u0646\u0644 \u0647\u0645 \u0627\u0632 \u0641\u0627\u06CC\u0644 \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC \u0634\u0648\u062F',
  btnRestoreLbl:'\u267B\uFE0F \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC \u06A9\u0646',
  bkReading:'\u062F\u0631 \u062D\u0627\u0644 \u062E\u0648\u0627\u0646\u062F\u0646 \u0641\u0627\u06CC\u0644\u2026',
  bkBadFile:'\u0641\u0627\u06CC\u0644 \u0642\u0627\u0628\u0644 \u062E\u0648\u0627\u0646\u062F\u0646 \u0646\u06CC\u0633\u062A \u06CC\u0627 \u067E\u0634\u062A\u06CC\u0628\u0627\u0646 \u0627\u06CC\u0646 \u067E\u0646\u0644 \u0646\u06CC\u0633\u062A',
  bkFrom:'\u0633\u0627\u062E\u062A\u0647\u200C\u0634\u062F\u0647 \u062F\u0631',bkUsersN:'\u06A9\u0627\u0631\u0628\u0631',bkCipsN:'\u0622\u06CC\u200C\u067E\u06CC \u062A\u0645\u06CC\u0632',bkProxN:'\u067E\u0631\u0648\u06A9\u0633\u06CC',
  bkTrafficN:'\u0631\u06A9\u0648\u0631\u062F \u0645\u0635\u0631\u0641',
  bkHasPw:'\u0634\u0627\u0645\u0644 \u0631\u0645\u0632 \u067E\u0646\u0644',bkNoPw:'\u0628\u062F\u0648\u0646 \u0631\u0645\u0632 \u067E\u0646\u0644',
  bkProxCreds:'\u067E\u0631\u0648\u06A9\u0633\u06CC \u0628\u0627 \u06CC\u0648\u0632\u0631/\u067E\u0633\u0648\u0631\u062F',
  bkEnvDiff:'\u26A0\uFE0F \u0627\u06CC\u0646 \u0645\u062A\u063A\u06CC\u0631\u0647\u0627 \u0628\u0627 \u067E\u0646\u0644 \u0641\u0639\u0644\u06CC \u062A\u0641\u0627\u0648\u062A \u062F\u0627\u0631\u0646\u062F \u0648 \u0628\u0627\u06CC\u062F \u062F\u0633\u062A\u06CC \u062F\u0631 Railway/Render \u0633\u062A \u0634\u0648\u0646\u062F:',
  bkReplaceWarn:'\u0647\u0645\u0647\u0654 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646\u060C \u0622\u06CC\u200C\u067E\u06CC\u200C\u0647\u0627\u06CC \u062A\u0645\u06CC\u0632 \u0648 \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627\u06CC \u0641\u0639\u0644\u06CC \u062D\u0630\u0641 \u0648 \u0628\u0627 \u0641\u0627\u06CC\u0644 \u062C\u0627\u06CC\u06AF\u0632\u06CC\u0646 \u0645\u06CC\u200C\u0634\u0648\u0646\u062F. \u0645\u0637\u0645\u0626\u0646\u06CC\u061F',
  bkPwChanged:"\u0631\u0645\u0632 \u067E\u0646\u0644 \u0627\u0632 \u0641\u0627\u06CC\u0644 \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC \u0634\u062F \u2014 \u062F\u0641\u0639\u0647\u0654 \u0628\u0639\u062F \u0628\u0627 \u0631\u0645\u0632 \u0642\u062F\u06CC\u0645\u06CC\u0650 \u0647\u0645\u0627\u0646 \u0641\u0627\u06CC\u0644 \u0648\u0627\u0631\u062F \u0634\u0648\u06CC\u062F.",
  bkDone:'\u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC \u0627\u0646\u062C\u0627\u0645 \u0634\u062F',
  bkAdded:'\u0627\u0636\u0627\u0641\u0647\u200C\u0634\u062F\u0647',bkUpdated:'\u0628\u0647\u200C\u0631\u0648\u0632\u0634\u062F\u0647',bkSkipped:'\u0631\u062F\u0634\u062F\u0647',
  relayLbl:'\u062F\u0627\u0645\u0646\u0647 \u0631\u0644\u0647',keepAliveLbl:'\u062C\u0644\u0648\u06AF\u06CC\u0631\u06CC \u0627\u0632 \u062E\u0648\u0627\u0628',relayNone:'\u0646\u062F\u0627\u0631\u062F',
  onLbl:'\u0641\u0639\u0627\u0644',offLbl:'\u062E\u0627\u0645\u0648\u0634',
  devWinLbl:'\u067E\u0646\u062C\u0631\u0647 \u0634\u0645\u0627\u0631\u0634 \u062F\u0633\u062A\u06AF\u0627\u0647',seconds:'\u062B\u0627\u0646\u06CC\u0647',
  envNote:'\u0627\u06CC\u0646 \u0645\u0642\u0627\u062F\u06CC\u0631 \u0627\u0632 \u0645\u062A\u063A\u06CC\u0631\u0647\u0627\u06CC \u0645\u062D\u06CC\u0637\u06CC \u062E\u0648\u0627\u0646\u062F\u0647 \u0645\u06CC\u200C\u0634\u0648\u0646\u062F \u0648 \u062F\u0631 Railway \u0642\u0627\u0628\u0644 \u062A\u063A\u06CC\u06CC\u0631\u0646\u062F.',
  logout:'\u062E\u0631\u0648\u062C',logs:'\u0631\u062E\u062F\u0627\u062F\u0647\u0627',noLogs:'\u0631\u062E\u062F\u0627\u062F\u06CC \u0646\u06CC\u0633\u062A',
  statusDisabled:'\u063A\u06CC\u0631\u0641\u0639\u0627\u0644',statusExpired:'\u0645\u0646\u0642\u0636\u06CC',statusQuota:'\u062D\u062C\u0645 \u062A\u0645\u0627\u0645',
 },
 en:{dir:'ltr',
  setupTitle:'Set a password',setupSub:'First run \u2014 choose your panel password',
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
  name:'Name',quota:'Quota (GB)',days:'Days',devLimit:'Devices',
  transport:'Transport',trWs:'\u{1F50C} WS + TLS',trXhttp:'\u{1F680} XHTTP + TLS',trBoth:'\u{1F500} Both',
  add:'Add',zeroInf:'0 = unlimited. Device count is based on distinct active IPs.',
  search:'Search\u2026',noUsers:'No users yet',
  config:'Config',ipsBtn:'IPs',edit:'Edit',
  used:'Used',expiry:'Expires',never:'Never',
  subLink:'Subscription link',copySub:'Copy subscription link',
  singleCfg:'Individual configs',copy:'Copy',copied:'Copied \u2713',
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
  obfLbl:'Obfuscation (Fragment + Cipher mask)',
  uuidWarn:'Rotate UUID? Existing configs will stop working.',delWarn:'Delete this user?',
  cleanTitle:'Clean IP manager',
  cleanHint:'Clean IPs or domains. Added to every subscription as extra configs.',
  addrPh:'e.g. 1.2.3.4 or cdn.example.com',remarkPh:'Label (optional)',
  bulkPh:'One per line:\\n1.2.3.4 # Irancell\\n5.6.7.8 # MCI',
  bulkAdd:'Bulk add',clearAll:'Delete all',
  pxTitle:'Outbound proxy',
  pxHint:'Arm a proxy and every user connection leaves through it, so target sites see the proxy IP.',
  pxKind:'Type',pxHost:'Host / IP',pxPort:'Port',
  pxUser:'Username (optional)',pxPass:'Password (optional)',
  pxAdd:'Add & test',pxTestAll:'Test all',
  pxInSub:'in subscriptions',
  pxAutoNote:'Every proxy you add joins all subscriptions automatically \u2014 all of them at once, no button. The no-proxy config is always there, and a failed health check or a dropped connection never removes a proxy: only disabling or deleting it in the panel does.',
  pxLineHint:'One proxy per line \u2014 e.g. socks5://1.1.1.1:5866 or http://user:pass@2.2.2.2:8080',
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
  pwChanged:'Password changed \u2713',
  serverInfo:'Server info',wsPathLbl:'WebSocket path',xhPathLbl:'XHTTP path',
  xhModeLbl:'XHTTP mode',
  xhModeHint:'The mode is packet-up, which spends one request per upload chunk. Behind a '
        +'Cloudflare relay, set XHTTP_MODE=stream-up to get 2 requests per connection instead. '
        +'Existing configs keep working, but users need to refresh their subscription once.',
  trWarnTitle:'\u26A0\uFE0F XHTTP request cost:',
  trWarn:"Cost depends on the mode. stream-up \u2014 this panel's default \u2014 is 2 requests per "
       +"connection (one GET downlink plus one long-lived POST uplink). packet-up sends every "
       +"upload chunk as its own POST, so one active client can be hundreds of requests a "
       +"minute and will drain a Cloudflare Worker's daily quota (100k). WS is cheapest of "
       +"all: 1 request per connection no matter how long it stays open.",
  backupTitle:'\u{1F4E6} Backup',
  backupHint:'A single .ixpbak file holding every user (with their UUID and subscription '
        +'token), your clean IPs, your proxies, the panel password and its settings. Import '
        +'it into a fresh panel and everything comes back \u2014 configs already handed out keep '
        +'working, because UUIDs and tokens are preserved.',
  bkInclPw:'include the panel password',
  bkInclProxyCreds:'include proxy usernames and passwords',
  bkInclTraffic:'include traffic history (larger file)',
  bkSecretWarn:'\u26A0\uFE0F This file contains the panel password and your proxy credentials \u2014 treat it like a password.',
  btnBackupLbl:'\u2B07\uFE0F Download backup',
  restoreTitle:'\u267B\uFE0F Restore',
  restoreHint:'Pick a .ixpbak file. Its contents are shown first and nothing is written '
        +'to the database until you confirm.',
  restoreMode:'Restore mode',
  bkMerge:'Merge \u2014 update matching entries, add the rest',
  bkReplace:'Replace \u2014 wipe current users, clean IPs and proxies first',
  bkRestorePwLbl:'also restore the panel password from the file',
  btnRestoreLbl:'\u267B\uFE0F Restore now',
  bkReading:'Reading file\u2026',
  bkBadFile:'File cannot be read, or is not a backup from this panel',
  bkFrom:'Created',bkUsersN:'users',bkCipsN:'clean IPs',bkProxN:'proxies',
  bkTrafficN:'traffic rows',
  bkHasPw:'includes the panel password',bkNoPw:'no panel password',
  bkProxCreds:'proxies with credentials',
  bkEnvDiff:'\u26A0\uFE0F These variables differ from this panel and must be set by hand in Railway/Render:',
  bkReplaceWarn:'All current users, clean IPs and proxies will be deleted and replaced by the file. Continue?',
  bkPwChanged:"The panel password was restored from the file \u2014 sign in with that file's password next time.",
  bkDone:'Restore complete',
  bkAdded:'added',bkUpdated:'updated',bkSkipped:'skipped',
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
<\/script>

<!-- \u2500\u2500\u2500 top bar \u2500\u2500\u2500 -->
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

<!-- \u2500\u2500\u2500 drawer \u2500\u2500\u2500 -->
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
 <div class="navi" data-page="live" onclick="go('live')">
  <svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/>
  <path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1"/></svg>
  <span data-t="navLive"></span></div>
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
    <option value="fa">\u0641\u0627</option><option value="en">EN</option></select>
  </div>
  <button onclick="logout()" id="btnOut"
    class="w-full rounded-xl py-2 text-xs font-bold"
    style="background:color-mix(in srgb,var(--bad) 16%,transparent);color:var(--bad)"></button>
 </div>
</aside>

<main class="max-w-6xl mx-auto p-4">

 <!-- \u2550\u2550 DASHBOARD \u2550\u2550 -->
 <section data-pg="dash" class="space-y-4">
  <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="totalUsers"></p><p id="sUsers" class="text-2xl font-extrabold mt-1">\u2014</p></div>
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="online"></p><p id="sOnline" class="text-2xl font-extrabold mt-1" style="color:var(--ok)">\u2014</p></div>
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="liveDevices"></p><p id="sLive" class="text-2xl font-extrabold mt-1" style="color:var(--ok)">\u2014</p></div>
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="devices"></p><p id="sDev" class="text-2xl font-extrabold mt-1" style="color:var(--info)">\u2014</p></div>
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="traffic"></p><p id="sBytes" class="text-2xl font-extrabold mt-1" style="color:var(--a2)">\u2014</p></div>
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="cleanIps"></p><p id="sCip" class="text-2xl font-extrabold mt-1" style="color:var(--a1)">\u2014</p></div>
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="xSessions"></p><p id="sXs" class="text-2xl font-extrabold mt-1">\u2014</p></div>
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

 <!-- \u2550\u2550 USERS \u2550\u2550 -->
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
   <label class="flex items-center gap-2 text-xs mt-2">
    <input id="nObf" type="checkbox"><span data-t="obfLbl"></span></label>
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

 <!-- \u2550\u2550 CLEAN IP \u2550\u2550 -->
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

 <!-- \u2550\u2550 PROXY \u2550\u2550 -->
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

 <!-- \u2550\u2550 SETTINGS \u2550\u2550 -->
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
      <option value="fa">\u{1F1EE}\u{1F1F7} \u0641\u0627\u0631\u0633\u06CC</option><option value="en">\u{1F1EC}\u{1F1E7} English</option></select></div>
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

  <!-- \u2550\u2550 BACKUP & RESTORE \u2550\u2550 -->
  <div class="card rounded-2xl p-4 space-y-3">
   <p class="text-sm font-bold" data-t="backupTitle"></p>
   <p class="text-[11px] dim" data-t="backupHint"></p>
   <div id="bkInfo" class="text-[11px] space-y-1"></div>
   <div class="flex flex-wrap gap-2 text-xs">
    <label class="flex items-center gap-1.5 rounded-full soft px-3 py-1.5 cursor-pointer">
     <input type="checkbox" id="bkPw" checked> <span data-t="bkInclPw"></span></label>
    <label class="flex items-center gap-1.5 rounded-full soft px-3 py-1.5 cursor-pointer">
     <input type="checkbox" id="bkPxCreds" checked> <span data-t="bkInclProxyCreds"></span></label>
    <label class="flex items-center gap-1.5 rounded-full soft px-3 py-1.5 cursor-pointer">
     <input type="checkbox" id="bkTraffic"> <span data-t="bkInclTraffic"></span></label>
   </div>
   <p class="text-[11px] rounded-xl px-3 py-2 leading-relaxed"
      style="background:color-mix(in srgb,var(--warn) 14%,transparent);border:1px solid color-mix(in srgb,var(--warn) 45%,transparent);color:var(--warn)"
      data-t="bkSecretWarn"></p>
   <button onclick="doBackup()" id="btnBackup"
     class="grad rounded-xl py-2 px-4 font-bold text-sm text-white w-full sm:w-auto"></button>

   <div class="pt-3 border-t space-y-2" style="border-color:var(--line)">
    <p class="text-sm font-bold" data-t="restoreTitle"></p>
    <p class="text-[11px] dim" data-t="restoreHint"></p>
    <input type="file" id="bkFile" accept=".ixpbak,application/json,.json"
      onchange="pickBackup()" class="w-full inp rounded-xl px-3 py-2 text-xs">
    <div id="bkPreview" class="text-[11px] space-y-1"></div>
    <div id="bkOpts" class="hidden space-y-2">
     <label class="block text-xs dim" data-t="restoreMode"></label>
     <select id="bkMode" class="w-full inp rounded-xl px-3 py-2 text-sm">
      <option value="merge"></option><option value="replace"></option></select>
     <label class="flex items-center gap-2 text-xs">
      <input type="checkbox" id="bkRestorePw"> <span data-t="bkRestorePwLbl"></span></label>
     <button onclick="doRestore()" id="btnRestore"
       class="grad rounded-xl py-2 px-4 font-bold text-sm text-white w-full"></button>
    </div>
    <p id="bkMsg" class="text-xs"></p>
   </div>
  </div>
 </section>

 <!-- \u2550\u2550 LOGS \u2550\u2550 -->
 <section data-pg="logs" class="hidden">
  <div class="card rounded-2xl p-4">
   <p class="text-sm font-bold mb-3" data-t="logs"></p>
   <div id="logRows" class="space-y-1"></div>
  </div>
 </section>

 <!-- \u2550\u2550 LIVE CONNECTIONS \u2550\u2550 -->
 <section data-pg="live" class="hidden">
  <p class="text-sm font-bold mb-3 flex items-center gap-2">
   <span data-t="liveTitle"></span>
   <span id="liveCount" class="text-xs font-normal" style="color:var(--dim)"></span>
  </p>
  <div class="card rounded-2xl p-0 overflow-hidden">
   <div id="liveRows" class="divide-y" style="border-color:var(--line)"></div>
   <div id="liveEmpty" class="p-6 text-center text-sm" style="color:var(--dim)" data-t="liveEmpty"></div>
  </div>
 </section>
</main>

<div id="modal" class="fixed inset-0 z-[60] hidden items-center justify-center bg-black/70 p-4">
 <div class="card rounded-2xl w-full max-w-md p-5 max-h-[85vh] overflow-y-auto sheet">
  <div class="flex items-center mb-3"><p id="mTitle" class="font-bold"></p>
   <button onclick="closeModal()" class="ms-auto dim hover:opacity-70">\u2715</button></div>
  <div id="mBody" class="space-y-3 text-sm"></div>
 </div>
</div>

<script>
/* \u2500\u2500\u2500 drawer position depends on writing direction \u2500\u2500\u2500 */
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

/* \u2500\u2500\u2500 country flags + inline icons \u2500\u2500\u2500
   \`var\` and function declarations on purpose: paintStatic() runs during boot, before
   this point in the script, and \`const\` would throw a temporal-dead-zone error that
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

/* \u2500\u2500\u2500 routing \u2500\u2500\u2500 */
let PAGE=localStorage.getItem('page')||'dash';
function go(p){
 PAGE=p; localStorage.setItem('page',p);
 document.querySelectorAll('[data-pg]').forEach(s=>s.classList.toggle('hidden',s.dataset.pg!==p));
 document.querySelectorAll('.navi').forEach(n=>n.classList.toggle('on',n.dataset.page===p));
 crumb.textContent=T({dash:'navDash',users:'navUsers',clean:'navClean',
   proxy:'navProxy',live:'navLive',settings:'navSettings',logs:'navLogs'}[p]);
 toggleNav(false);
 if(p==='logs')loadLogs();
 if(p==='clean')loadCips();
 if(p==='settings'){renderServer();loadBackupInfo()}
 if(p==='live')loadLive(); else stopLive();
}

/* \u2500\u2500\u2500 helpers \u2500\u2500\u2500 */
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
 btnBackup.textContent=T('btnBackupLbl'); btnRestore.textContent=T('btnRestoreLbl');
 bkMode.options[0].textContent=T('bkMerge');
 bkMode.options[1].textContent=T('bkReplace');
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

/* \u2500\u2500\u2500 data \u2500\u2500\u2500 */
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
 protoBox.innerHTML=pairs.map(([k,lbl,col])=>\`
  <div class="rounded-xl soft px-3 py-2 flex items-center gap-2">
   <span class="h-2 w-2 rounded-full" style="background:\${col}"></span>
   <span>\${lbl}</span><span class="font-bold">\${bp[k]||0}</span></div>\`).join('');
}
function renderServer(){
 srvBox.innerHTML=[
  [T('wsPathLbl'),'/'+(stats.ws_path||'\u2014')],
  [T('xhPathLbl'),'/'+(stats.xhttp_path||'\u2014')],
  [T('xhModeLbl'),stats.xhttp_mode||'\u2014'],
  [T('devWinLbl'),(stats.device_window||'\u2014')+' '+T('seconds')],
  [T('xSessions'),stats.xhttp_sessions??'\u2014'],
  [T('relayLbl'),stats.relay_domain||T('relayNone')],
  [T('keepAliveLbl'),stats.keepalive?T('onLbl'):T('offLbl')],
 ].map(([k,v])=>\`<div class="flex items-center gap-2 rounded-xl soft px-3 py-2">
   <span class="dim">\${k}</span><span class="ms-auto mono">\${v}</span></div>\`).join('')
 +(stats.xhttp_mode==='packet-up'
   ?\`<p class="text-[11px] rounded-xl px-3 py-2 leading-relaxed mt-1"
       style="background:color-mix(in srgb,var(--warn) 14%,transparent);border:1px solid color-mix(in srgb,var(--warn) 45%,transparent)">
      <span class="font-bold" style="color:var(--warn)">\${T('trWarnTitle')}</span>
      <span class="dim">\${T('xhModeHint')}</span></p>\`
   :'');
}

async function loadStats(){
 stats=await api('/api/stats');
 sUsers.textContent=stats.users; sOnline.textContent=stats.online_users;
 sDev.textContent=stats.online_devices; sLive.textContent=stats.live_devices;
 sBytes.textContent=fmt(stats.total_bytes);
 sCip.textContent=stats.clean_ips; sXs.textContent=stats.xhttp_sessions;
 pill.textContent='/'+stats.ws_path+' \xB7 /'+stats.xhttp_path;
 paintChart(); renderProto();
 if(PAGE==='settings'){renderServer();loadBackupInfo()}
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
    liveCount.textContent=rows.length?\`(\${rows.length})\`:'';
    if(!rows.length){liveRows.innerHTML='';liveEmpty.style.display='';return}
    liveEmpty.style.display='none';
    const fmtDur=s=>{s=Math.max(0,Math.floor(s));const m=Math.floor(s/60),sec=s%60;
      return m?\`\${m}m \${sec}s\`:\`\${sec}s\`};
    liveRows.innerHTML=rows.map(c=>\`<div class="p-3 flex items-center gap-3 text-sm">
      <span class="text-[10px] px-2 py-0.5 rounded-full" style="background:color-mix(in srgb,var(--info) 16%,transparent);color:var(--info)">\${(c.transport||'').toUpperCase()}</span>
      <div class="flex-1 min-w-0">
        <p class="font-bold truncate">\${esc(c.user||'\u2014')}</p>
        <p class="text-xs truncate" style="color:var(--dim)">\${esc(c.ip||'')} \xB7 \${esc(c.route||'')}\${c.mux?' \xB7 mux':''}</p>
      </div>
      <span class="text-xs font-mono" style="color:var(--dim)">\${fmtDur(c.connected_for)}</span>
    </div>\`).join('');
  }catch(e){/* keep last render on transient error */}
  clearTimeout(liveTimer);
  liveTimer=setTimeout(loadLive,4000);   // auto-refresh every 4s
}
function stopLive(){clearTimeout(liveTimer);liveTimer=null}

function renderUsers(){
 const term=(q.value||'').toLowerCase();
 rows.innerHTML=users.filter(u=>u.name.toLowerCase().includes(term)).map(u=>{
  const pct=u.quota_bytes?Math.min(100,u.used_bytes/u.quota_bytes*100):0;
  const badge=u.active
   ?\`<span class="text-[10px] px-2 py-0.5 rounded-full" style="background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)">\${T('active')}</span>\`
   :\`<span class="text-[10px] px-2 py-0.5 rounded-full" style="background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)">\${statusTxt(u.status)}</span>\`;
  const dev=u.device_limit?\`\${u.devices_now}/\${u.device_limit}\`:\`\${u.devices_now}/\u267E\uFE0F\`;
  const liveTag=u.devices_live?\`<span class="text-[10px] px-1.5 py-0.5 rounded-full" style="background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)">\u25CF \${u.devices_live}</span>\`:'';
  const devCol=u.device_limit&&u.devices_now>=u.device_limit?'var(--bad)':'var(--info)';
  return \`<div class="p-4 border-b" style="border-color:var(--line)">
   <div class="flex items-center gap-2 flex-wrap">
    <p class="font-bold">\${u.name}</p>\${badge}
    <span class="text-[10px] px-2 py-0.5 rounded-full soft">\${trTxt(u.transport)}</span>
    <span class="text-[11px]" style="color:\${devCol}">\u{1F4F1} \${dev}</span>\${liveTag}
    <div class="flex-1"></div>
    <button onclick="showConfig(\${u.id})" class="text-[11px] px-2 py-1 rounded-lg" style="background:color-mix(in srgb,var(--a1) 22%,transparent)">\${T('config')}</button>
    <button onclick="showIps(\${u.id})" class="text-[11px] px-2 py-1 rounded-lg" style="background:color-mix(in srgb,var(--info) 20%,transparent)">\${T('ipsBtn')}</button>
    <button onclick="showEdit(\${u.id})" class="text-[11px] px-2 py-1 rounded-lg soft">\${T('edit')}</button>
   </div>
   <div class="mt-2 h-1.5 rounded-full overflow-hidden soft">
    <div class="h-full grad" style="width:\${pct}%"></div></div>
   <div class="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[11px] dim">
    <span>\${T('used')}: \${fmt(u.used_bytes)} / \${u.quota_bytes?fmt(u.quota_bytes):'\u267E\uFE0F'}</span>
    <span>\${T('expiry')}: \${dt(u.expire_at)}</span>
   </div></div>\`}).join('')||\`<p class="p-6 text-center text-sm dim">\${T('noUsers')}</p>\`;
}

function renderCips(){
 cipRows.innerHTML=cips.map(x=>\`
  <div class="flex items-center gap-2 rounded-xl soft px-3 py-2">
   <span class="h-2 w-2 rounded-full" style="background:\${x.enabled?'var(--ok)':'var(--dim)'}"></span>
   \${x.flag?\`<span class="text-sm">\${x.flag}</span>\`:''}
   <span class="mono text-[11px]">\${x.address}</span>
   \${x.remark?\`<span class="text-[10px] dim">\${x.remark}</span>\`:''}
   <div class="flex-1"></div>
   <button onclick="toggleCip(\${x.id})" class="icbox px-2 py-1 rounded-lg soft">\${x.enabled?SVG_PAUSE:SVG_PLAY}</button>
   <button onclick="delCip(\${x.id})" class="icbox px-2 py-1 rounded-lg" style="color:var(--bad)">\${SVG_X}</button>
  </div>\`).join('')||\`<p class="text-xs dim">\${T('noCleanIps')}</p>\`;
}

function renderLogs(){
 const box=document.getElementById('logRows');
 box.innerHTML=logItems.map(l=>\`
  <div class="flex items-center gap-2 rounded-xl soft px-3 py-2 text-[11px]">
   <span class="font-bold">\${l.event}</span>
   <span class="mono dim">\${l.ip||''}</span>
   <span class="dim">\${l.detail||''}</span>
   <span class="ms-auto dim">\${dt(l.ts)}</span></div>\`).join('')
  ||\`<p class="text-xs dim">\${T('noLogs')}</p>\`;
}

/* \u2500\u2500\u2500 actions \u2500\u2500\u2500 */
async function createUser(){
 cErr.textContent='';
 try{
  await api('/api/users',{method:'POST',body:JSON.stringify({
   name:nName.value.trim(),quota_gb:parseFloat(nQuota.value||0),
   expire_days:parseInt(nDays.value||0),device_limit:parseInt(nDev.value||0),
   transport:nTr.value,obfuscate:nObf.checked})});
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
  cipMsg.textContent=\`\${r.added} \${T('addedN')} \xB7 \${r.duplicates} \${T('dupN')} \xB7 \${r.invalid} \${T('invalidN')}\`;
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
  // An enabled proxy is already in every subscription \u2014 nothing to press.
  const on=PX_SUB.indexOf(x.id)>-1;
  const dot=x.healthy?'var(--ok)':(x.checked_at?'var(--bad)':'var(--dim)');
  const state=x.healthy?T('pxHealthy'):(x.checked_at?T('pxDown'):T('pxUntested'));
  const geo=[x.country_name||'',x.city||''].filter(Boolean).join(' \\u00b7 ');
  return \`<div class="rounded-xl soft px-3 py-2 \${on?'ring-2':''}" style="\${on?'outline:2px solid var(--a1)':''}">
   <div class="flex items-center gap-2 flex-wrap">
    <span class="h-2 w-2 rounded-full" style="background:\${dot}"></span>
    <span class="text-base">\${x.flag||'\\u{1F310}'}</span>
    <span class="mono text-[11px] min-w-0 break-all">\${x.label}</span>
    \${x.has_auth?'<span class="text-[10px] dim">\\u{1F511}</span>':''}
    \${on?\`<span class="text-[10px] font-bold" style="color:var(--a2)">\${T('pxInSub')}</span>\`:''}
    <div class="flex-1"></div>
    <button onclick="testProxy(\${x.id})" title="\${T('pxTest')}" class="icbox px-2 py-1 rounded-lg soft">\${SVG_PING}</button>
    <button onclick="toggleProxy(\${x.id},\${x.enabled?1:0})" class="icbox px-2 py-1 rounded-lg soft">\${x.enabled?SVG_PAUSE:SVG_PLAY}</button>
    <button onclick="delProxy(\${x.id})" class="icbox px-2 py-1 rounded-lg" style="color:var(--bad)">\${SVG_X}</button>
   </div>
   <div class="flex flex-wrap gap-x-3 gap-y-1 mt-1 text-[10px] dim">
    <span>\${state}</span>
    \${x.latency_ms?\`<span>\${T('pxLatency')}: \${x.latency_ms} ms</span>\`:''}
    \${x.exit_ip?\`<span class="mono">\${T('pxExitIp')}: \${x.exit_ip}</span>\`:''}
    \${geo?\`<span>\${geo}</span>\`:''}
    \${x.isp?\`<span>\${x.isp}</span>\`:''}
    \${x.remark?\`<span>\${x.remark}</span>\`:''}
    \${x.last_error?\`<span style="color:var(--bad)">\${x.last_error}</span>\`:''}
   </div>
  </div>\`}).join('')||\`<p class="text-xs dim">\${T('pxNone')}</p>\`;
}
async function addProxy(){
 pxMsg.textContent=T('pxTesting');
 try{const r=await api('/api/proxies',{method:'POST',body:JSON.stringify({
   kind:pKind.value,host:pHost.value.trim(),port:parseInt(pPort.value||'0',10),
   username:pUser.value.trim(),password:pPass.value,remark:pRem.value.trim()})});
  pxMsg.textContent=r.ok?\`\${r.flag||''} \${r.country_name||''} \\u00b7 \${r.exit_ip||''} \\u00b7 \${r.latency_ms}ms\`
                       :\`\${T('pxDown')}: \${r.error||''}\`;
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
    ?\`<span style="color:var(--ok)">\${x.flag||''} \${x.label} \xB7 \${x.country_name||''} \${x.latency_ms||0}ms</span>\`
    :\`<span style="color:var(--bad)">\${x.label}: \${x.error||''}</span>\`).join('<br>')+
   \`<br>\${good}/\${rows.length}\`;
  if(good)pBulk.value='';
  loadProxies();
 }catch(e){pxMsg.textContent=e.message}
}
async function testProxy(id){
 pxMsg.textContent=T('pxTesting');
 try{const r=await api('/api/proxies/'+id+'/test',{method:'POST'});
  pxMsg.textContent=r.ok?\`\${r.flag||''} \${r.country_name||''} \\u00b7 \${r.exit_ip||''} \\u00b7 \${r.latency_ms}ms\`
                       :\`\${T('pxDown')}: \${r.error||''}\`;
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
 const cfgs=c.configs.map(x=>\`
  <div class="rounded-xl soft p-2">
   <p class="text-[11px] font-bold mb-1">\${x.label}</p>
   <p class="mono text-[9px] break-all dim">\${x.uri}</p>
   <button onclick="copy(this,'\${x.uri.replace(/'/g,"\\\\'")}')" class="mt-1 w-full rounded-lg soft py-1 text-[10px]">\${T('copy')}</button>
  </div>\`).join('');
 openModal(T('config'),\`
  <p class="text-xs dim">\${T('subLink')}</p>
  <div class="rounded-xl soft p-2 mono text-[10px] break-all">\${c.sub_link}</div>
  <button onclick="copy(this,'\${c.sub_link}')" class="w-full grad rounded-xl py-2 text-xs font-bold text-white">\${T('copySub')}</button>
  <div id="qr" class="grid place-items-center bg-white p-3 rounded-xl"></div>
  <p class="text-xs dim pt-2">UUID</p>
  <div class="rounded-xl soft p-2 mono text-[10px] break-all">\${c.uuid}</div>
  <p class="text-xs dim pt-2">\${T('singleCfg')} \u2014 \${trTxt(c.transport)}</p>\${cfgs}\`);
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

 const rows=d.rows.length ? d.rows.map(x=>\`
  <div class="flex items-center gap-2 rounded-xl soft px-3 py-2">
   <span class="h-2 w-2 rounded-full" style="background:\${x.online?'var(--ok)':(x.counted?'var(--info)':'var(--dim)')}"></span>
   <span class="mono text-[11px]">\${x.ip}</span>
   <span class="text-[9px] px-1.5 py-0.5 rounded soft">\${x.proto||'ws'}</span>
   <span class="ms-auto text-[10px] dim">\${dt(x.last_seen)}</span>
  </div>\`).join('')
  : \`<p class="text-xs dim py-2">\${ipHistory?T('noConn'):T('noneNow')}</p>\`;

 const body=\`
  <div class="rounded-2xl p-4 text-center soft">
   <p class="text-[11px] dim">\${T('liveNow')}</p>
   <p class="text-4xl font-extrabold mt-1" style="color:\${d.live?'var(--ok)':'var(--dim)'}">\${d.live}</p>
   <p class="text-[10px] dim mt-1">\${T('inLast').replace('%s',d.live_window)}</p>
  </div>
  <div class="grid grid-cols-2 gap-2 text-[11px]">
   <div class="rounded-xl soft px-3 py-2"><span class="dim">\${T('countedFor')}</span>
    <span class="float-end font-bold" style="color:var(--info)">\${d.counted}</span></div>
   <div class="rounded-xl soft px-3 py-2"><span class="dim">\${T('totalSeen')}</span>
    <span class="float-end font-bold">\${d.total_seen}</span></div>
  </div>
  <div class="space-y-1">\${rows}</div>
  <button onclick="toggleIpHistory()" class="w-full rounded-xl soft py-2 text-xs">
   \${ipHistory?T('showLive'):T('showHistory')}</button>
  <button onclick="clearIps(\${ipUid})" class="w-full rounded-xl py-2 text-xs"
   style="background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)">\${T('clearIps')}</button>\`;

 if(quiet){ const b=document.getElementById('mBody'); if(b) b.innerHTML=body; }
 else openModal(T('devTitle'),body);
}

function toggleIpHistory(){ ipHistory=!ipHistory; paintIps(); }

async function clearIps(id){await api('/api/users/'+id+'/clear-ips',{method:'POST'});closeModal();loadUsers();loadStats()}

function showEdit(id){
 const u=users.find(x=>x.id===id);
 const days=u.expire_at?Math.max(0,Math.ceil((u.expire_at-Date.now()/1000)/86400)):0;
 const opt=v=>\`<option value="\${v}" \${u.transport===v?'selected':''}>\${trTxt(v)}</option>\`;
 openModal(T('editUser')+' \xB7 '+u.name,\`
  <label class="block text-xs dim">\${T('quota')}</label>
  <input id="eQ" type="number" step="0.5" value="\${(u.quota_bytes/1073741824).toFixed(2)}" class="w-full inp rounded-xl px-3 py-2">
  <label class="block text-xs dim">\${T('remainDays')}</label>
  <input id="eD" type="number" value="\${days}" class="w-full inp rounded-xl px-3 py-2">
  <label class="block text-xs dim">\${T('allowedDev')}</label>
  <input id="eV" type="number" value="\${u.device_limit}" class="w-full inp rounded-xl px-3 py-2">
  <label class="block text-xs dim">\${T('transport')}</label>
  <select id="eT" class="w-full inp rounded-xl px-3 py-2">\${opt('both')}\${opt('ws')}\${opt('xhttp')}</select>
  <label class="flex items-center gap-2 text-xs pt-1"><input id="eObf" type="checkbox" \${u.obfuscate?'checked':''}> \${T('obfLbl')}</label>
  <label class="block text-xs dim">\${T('customUuid')}</label>
  <input id="eU" value="\${u.uuid}" class="w-full inp rounded-xl px-3 py-2 mono text-[11px]">
  <label class="flex items-center gap-2 text-xs"><input id="eE" type="checkbox" \${u.enabled?'checked':''}> \${T('active')}</label>
  <button onclick="saveEdit(\${id})" class="w-full grad rounded-xl py-2 font-bold text-sm text-white">\${T('saveBtn')}</button>
  <div class="grid grid-cols-3 gap-2 pt-2">
   <button onclick="resetTraffic(\${id})" class="rounded-xl soft py-2 text-[11px]">\${T('resetTraffic')}</button>
   <button onclick="newUuid(\${id})" class="rounded-xl soft py-2 text-[11px]">\${T('newUuid')}</button>
   <button onclick="delUser(\${id})" class="rounded-xl py-2 text-[11px]" style="background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)">\${T('del')}</button>
  </div>
  <p id="eErr" class="text-xs" style="color:var(--bad)"></p>\`);
}
async function saveEdit(id){
 try{
  const u=users.find(x=>x.id===id);
  const payload={quota_gb:parseFloat(eQ.value||0),expire_days:parseInt(eD.value||0),
   device_limit:parseInt(eV.value||0),transport:eT.value,enabled:eE.checked,
   obfuscate:eObf.checked};
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

/* \u2500\u2500\u2500 backup & restore \u2500\u2500\u2500 */
let BK=null;                       // the parsed file waiting to be restored

const bkEsc=s=>(s==null?'':String(s)).replace(/[<>&"]/g,
 c=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c]));
const bkRow=(k,v)=>\`<div class="flex items-center gap-2 rounded-xl soft px-3 py-2">
 <span class="dim">\${k}</span><span class="ms-auto mono">\${v}</span></div>\`;

async function loadBackupInfo(){
 try{
  const i=await api('/api/backup/info');
  bkInfo.innerHTML=bkRow(T('bkUsersN'),i.users)+bkRow(T('bkCipsN'),i.clean_ips)
    +bkRow(T('bkProxN'),i.proxies)+bkRow(T('bkTrafficN'),i.traffic_rows);
 }catch(e){bkInfo.innerHTML=''}
}

function doBackup(){
 // A plain link download keeps the browser's Save dialog and the server-side filename.
 const qs='password='+(bkPw.checked?1:0)+'&traffic='+(bkTraffic.checked?1:0)
   +'&proxy_creds='+(bkPxCreds.checked?1:0);
 const a=document.createElement('a');
 a.href='/api/backup?'+qs; a.rel='noopener';
 document.body.appendChild(a); a.click(); a.remove();
 bkMsg.style.color='var(--ok)'; bkMsg.textContent='\u2713';
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
  // The server validates format, version and checksum; nothing is written yet.
  const p=await api('/api/restore/preview',{method:'POST',
    body:JSON.stringify({data:parsed})});
  BK=parsed;
  bkMsg.textContent='';
  let html=bkRow(T('bkFrom'),dt(p.created_at))+bkRow(T('bkUsersN'),p.users)
    +bkRow(T('bkCipsN'),p.clean_ips)+bkRow(T('bkProxN'),p.proxies);
  if(p.proxies_with_creds) html+=bkRow(T('bkProxCreds'),p.proxies_with_creds);
  if(p.traffic_rows) html+=bkRow(T('bkTrafficN'),p.traffic_rows);
  html+=bkRow('\u{1F510}',p.has_password?T('bkHasPw'):T('bkNoPw'));
  const diff=Object.entries(p.env_diff||{});
  if(diff.length){
   html+=\`<p class="text-[11px] rounded-xl px-3 py-2 leading-relaxed mt-1"
     style="background:color-mix(in srgb,var(--warn) 14%,transparent);border:1px solid color-mix(in srgb,var(--warn) 45%,transparent)">
     <span class="font-bold" style="color:var(--warn)">\${T('bkEnvDiff')}</span><br>\`
     +diff.map(([k,v])=>\`<span class="mono">\${bkEsc(k)}</span>: <span class="mono">\${bkEsc(v.current||'\u2014')}</span> \u2192 <span class="mono">\${bkEsc(v.backup||'\u2014')}</span>\`).join('<br>')
     +\`</p>\`;
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
 bkMsg.style.color='var(--dim)'; bkMsg.textContent='\u2026';
 try{
  const r=await api('/api/restore',{method:'POST',body:JSON.stringify({
    data:BK,mode,restore_password:bkRestorePw.checked})});
  bkMsg.style.color='var(--ok)';
  bkMsg.textContent=\`\${T('bkDone')} \u2014 \${T('bkUsersN')}: +\${r.users_added}/~\${r.users_updated}\`
    +\` \xB7 \${T('bkCipsN')}: +\${r.clean_ips_added}\`
    +\` \xB7 \${T('bkProxN')}: +\${r.proxies_added}/~\${r.proxies_updated}\`
    +(r.users_skipped||r.proxies_skipped||r.clean_ips_skipped
      ?\` \xB7 \${T('bkSkipped')}: \${r.users_skipped+r.proxies_skipped+r.clean_ips_skipped}\`:'');
  BK=null; bkFile.value=''; bkOpts.classList.add('hidden'); bkPreview.innerHTML='';
  loadUsers(); loadCips(); loadStats(); loadBackupInfo();
  if(typeof loadProxies==='function') loadProxies();
  if(r.password_restored) alert(T('bkPwChanged'));
 }catch(e){ bkMsg.style.color='var(--bad)'; bkMsg.textContent=e.message }
 finally{ btnRestore.disabled=false }
}

function copy(btn,t){navigator.clipboard.writeText(t);
 const old=btn.textContent;btn.textContent=T('copied');setTimeout(()=>btn.textContent=old,1200)}

go(PAGE);
loadStats();loadUsers();loadCips();loadMainCountry();loadProxies();
setInterval(()=>{loadStats();if(PAGE==='users')loadUsers()},15000);
<\/script></body></html>`], [`<!DOCTYPE html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}}</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"><\/script>
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"><\/script>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;800&display=swap" rel="stylesheet">
<style>body{font-family:Vazirmatn,system-ui,sans-serif}
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
</style>
</head><body class="min-h-screen">
<script>
const I18N={
 fa:{dir:'rtl',
  setupTitle:'\u062A\u0639\u06CC\u06CC\u0646 \u0631\u0645\u0632 \u0639\u0628\u0648\u0631',setupSub:'\u0627\u0648\u0644\u06CC\u0646 \u0648\u0631\u0648\u062F \u2014 \u06CC\u06A9 \u0631\u0645\u0632 \u0628\u0631\u0627\u06CC \u067E\u0646\u0644 \u0627\u0646\u062A\u062E\u0627\u0628 \u06A9\u0646\u06CC\u062F',
  loginTitle:'\u0648\u0631\u0648\u062F \u0628\u0647 \u067E\u0646\u0644',loginSub:'\u0631\u0645\u0632 \u0639\u0628\u0648\u0631 \u062E\u0648\u062F \u0631\u0627 \u0648\u0627\u0631\u062F \u06A9\u0646\u06CC\u062F',
  password:'\u0631\u0645\u0632 \u0639\u0628\u0648\u0631',confirm:'\u062A\u06A9\u0631\u0627\u0631 \u0631\u0645\u0632 \u0639\u0628\u0648\u0631',enter:'\u0648\u0631\u0648\u062F',save:'\u0630\u062E\u06CC\u0631\u0647 \u0648 \u0648\u0631\u0648\u062F',
  pwRule:'\u062D\u062F\u0627\u0642\u0644 \u06F8 \u06A9\u0627\u0631\u0627\u06A9\u062A\u0631 \u0634\u0627\u0645\u0644 \u062D\u0631\u0641 \u0628\u0632\u0631\u06AF\u060C \u062D\u0631\u0641 \u06A9\u0648\u0686\u06A9 \u0648 \u0639\u062F\u062F',netErr:'\u062E\u0637\u0627\u06CC \u0634\u0628\u06A9\u0647',
  navDash:'\u062F\u0627\u0634\u0628\u0648\u0631\u062F',navUsers:'\u0645\u062F\u06CC\u0631\u06CC\u062A \u06A9\u0627\u0631\u0628\u0631\u0627\u0646',navClean:'Clean IP',
  navProxy:'\u067E\u0631\u0648\u06A9\u0633\u06CC',navLive:'\u0627\u062A\u0635\u0627\u0644\u0627\u062A \u0632\u0646\u062F\u0647',
  navSettings:'\u062A\u0646\u0638\u06CC\u0645\u0627\u062A \u067E\u0646\u0644',navLogs:'\u0631\u062E\u062F\u0627\u062F\u0647\u0627',menu:'\u0645\u0646\u0648',
  totalUsers:'\u06A9\u0644 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646',online:'\u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0622\u0646\u0644\u0627\u06CC\u0646',devices:'\u062F\u0633\u062A\u06AF\u0627\u0647\u200C\u0647\u0627\u06CC \u0645\u062A\u0635\u0644',
  traffic:'\u0645\u0635\u0631\u0641 \u06A9\u0644',cleanIps:'\u0622\u06CC\u200C\u067E\u06CC \u062A\u0645\u06CC\u0632',xSessions:'\u0633\u0634\u0646\u200C\u0647\u0627\u06CC XHTTP',liveTitle:'\u0627\u062A\u0635\u0627\u0644\u0627\u062A \u0632\u0646\u062F\u0647',liveEmpty:'\u0647\u06CC\u0686 \u0627\u062A\u0635\u0627\u0644\u06CC \u0641\u0639\u0627\u0644 \u0646\u06CC\u0633\u062A',
  chart24:'\u0645\u0635\u0631\u0641 \u06F2\u06F4 \u0633\u0627\u0639\u062A \u0627\u062E\u06CC\u0631',protoSplit:'\u062A\u0642\u0633\u06CC\u0645 \u0628\u0631 \u0627\u0633\u0627\u0633 \u062A\u0631\u0646\u0633\u067E\u0648\u0631\u062A',
  newUser:'\u0633\u0627\u062E\u062A \u06A9\u0627\u0631\u0628\u0631 \u062C\u062F\u06CC\u062F',users:'\u06A9\u0627\u0631\u0628\u0631\u0627\u0646',
  name:'\u0646\u0627\u0645 (\u0627\u0646\u06AF\u0644\u06CC\u0633\u06CC)',quota:'\u062D\u062C\u0645 (GB)',days:'\u0645\u062F\u062A (\u0631\u0648\u0632)',devLimit:'\u062A\u0639\u062F\u0627\u062F \u062F\u0633\u062A\u06AF\u0627\u0647',
  transport:'\u062A\u0631\u0646\u0633\u067E\u0648\u0631\u062A',trWs:'\u{1F50C} WS + TLS',trXhttp:'\u{1F680} XHTTP + TLS',trBoth:'\u{1F500} \u0647\u0631 \u062F\u0648',
  add:'\u0627\u0641\u0632\u0648\u062F\u0646',zeroInf:'\u06F0 = \u0628\u06CC\u200C\u0646\u0647\u0627\u06CC\u062A. \xAB\u062A\u0639\u062F\u0627\u062F \u062F\u0633\u062A\u06AF\u0627\u0647\xBB \u0628\u0631 \u0627\u0633\u0627\u0633 IP \u06CC\u06A9\u062A\u0627\u06CC \u0641\u0639\u0627\u0644 \u0645\u062D\u0627\u0633\u0628\u0647 \u0645\u06CC\u200C\u0634\u0648\u062F.',
  search:'\u062C\u0633\u062A\u062C\u0648\u2026',noUsers:'\u06A9\u0627\u0631\u0628\u0631\u06CC \u0646\u06CC\u0633\u062A',
  config:'\u06A9\u0627\u0646\u0641\u06CC\u06AF',ipsBtn:'IP \u0647\u0627',edit:'\u0648\u06CC\u0631\u0627\u06CC\u0634',
  used:'\u0645\u0635\u0631\u0641',expiry:'\u0627\u0646\u0642\u0636\u0627',never:'\u0628\u06CC\u200C\u0646\u0647\u0627\u06CC\u062A',
  subLink:'\u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9 (Subscription)',copySub:'\u06A9\u067E\u06CC \u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9',
  singleCfg:'\u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627\u06CC \u062A\u06A9\u06CC',copy:'\u06A9\u067E\u06CC',copied:'\u06A9\u067E\u06CC \u0634\u062F \u2713',
  devTitle:'\u062F\u0633\u062A\u06AF\u0627\u0647\u200C\u0647\u0627\u06CC \u0645\u062A\u0635\u0644',noConn:'\u0647\u0646\u0648\u0632 \u0627\u062A\u0635\u0627\u0644\u06CC \u062B\u0628\u062A \u0646\u0634\u062F\u0647',
  clearIps:'\u067E\u0627\u06A9 \u06A9\u0631\u062F\u0646 \u0644\u06CC\u0633\u062A IP',
  liveNow:'\u0627\u0644\u0627\u0646 \u0645\u062A\u0635\u0644',noneNow:'\u0647\u0645\u06CC\u0646 \u0627\u0644\u0627\u0646 \u0647\u06CC\u0686 \u062F\u0633\u062A\u06AF\u0627\u0647\u06CC \u0645\u062A\u0635\u0644 \u0646\u06CC\u0633\u062A',
  countedFor:'\u0634\u0645\u0631\u062F\u0647\u200C\u0634\u062F\u0647 \u0628\u0631\u0627\u06CC \u0645\u062D\u062F\u0648\u062F\u06CC\u062A',totalSeen:'\u06A9\u0644 IP \u0647\u0627\u06CC \u062F\u06CC\u062F\u0647\u200C\u0634\u062F\u0647',
  showHistory:'\u0646\u0645\u0627\u06CC\u0634 \u062A\u0627\u0631\u06CC\u062E\u0686\u0647',showLive:'\u0646\u0645\u0627\u06CC\u0634 \u0641\u0642\u0637 \u0645\u062A\u0635\u0644\u200C\u0647\u0627',
  inLast:'\u062F\u0631 %s \u062B\u0627\u0646\u06CC\u0647 \u0627\u062E\u06CC\u0631',refresh:'\u0628\u0647\u200C\u0631\u0648\u0632\u0631\u0633\u0627\u0646\u06CC',
  liveDevices:'\u062F\u0633\u062A\u06AF\u0627\u0647\u200C\u0647\u0627\u06CC \u0641\u0639\u0627\u0644 \u0627\u0644\u0627\u0646',
  editUser:'\u0648\u06CC\u0631\u0627\u06CC\u0634',remainDays:'\u0645\u062F\u062A \u0628\u0627\u0642\u06CC\u200C\u0645\u0627\u0646\u062F\u0647 (\u0631\u0648\u0632)',allowedDev:'\u062A\u0639\u062F\u0627\u062F \u062F\u0633\u062A\u06AF\u0627\u0647 \u0645\u062C\u0627\u0632',
  active:'\u0641\u0639\u0627\u0644',saveBtn:'\u0630\u062E\u06CC\u0631\u0647',resetTraffic:'\u0631\u06CC\u0633\u062A \u062D\u062C\u0645',newUuid:'UUID \u062C\u062F\u06CC\u062F',
  customUuid:'UUID \u062F\u0633\u062A\u06CC',del:'\u062D\u0630\u0641',
  obfLbl:'\u0645\u0628\u0647\u0645\u200C\u0633\u0627\u0632 (Fragment + Cipher mask)',
  uuidWarn:'UUID \u0639\u0648\u0636 \u0634\u0648\u062F\u061F \u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627\u06CC \u0642\u0628\u0644\u06CC \u0627\u0632 \u06A9\u0627\u0631 \u0645\u06CC\u200C\u0627\u0641\u062A\u0646\u062F.',delWarn:'\u0627\u06CC\u0646 \u06A9\u0627\u0631\u0628\u0631 \u062D\u0630\u0641 \u0634\u0648\u062F\u061F',
  cleanTitle:'\u0645\u062F\u06CC\u0631\u06CC\u062A Clean IP',
  cleanHint:'\u0622\u06CC\u200C\u067E\u06CC \u06CC\u0627 \u062F\u0627\u0645\u0646\u0647 \u062A\u0645\u06CC\u0632. \u062F\u0631 \u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9 \u0647\u0631 \u06A9\u0627\u0631\u0628\u0631 \u0628\u0647 \u0639\u0646\u0648\u0627\u0646 \u06A9\u0627\u0646\u0641\u06CC\u06AF \u0627\u0636\u0627\u0641\u06CC \u0627\u0636\u0627\u0641\u0647 \u0645\u06CC\u200C\u0634\u0648\u062F.',
  addrPh:'\u0645\u062B\u0644\u0627 1.2.3.4 \u06CC\u0627 cdn.example.com',remarkPh:'\u0628\u0631\u0686\u0633\u0628 (\u0627\u062E\u062A\u06CC\u0627\u0631\u06CC)',
  bulkPh:'\u0686\u0646\u062F \u0645\u0648\u0631\u062F\u060C \u0647\u0631 \u062E\u0637 \u06CC\u06A9\u06CC:\\\\n1.2.3.4 # \u0627\u06CC\u0631\u0627\u0646\u0633\u0644\\\\n5.6.7.8 # \u0647\u0645\u0631\u0627\u0647 \u0627\u0648\u0644',
  bulkAdd:'\u0627\u0641\u0632\u0648\u062F\u0646 \u0627\u0646\u0628\u0648\u0647',clearAll:'\u062D\u0630\u0641 \u0647\u0645\u0647',
  pxTitle:'\u067E\u0631\u0648\u06A9\u0633\u06CC \u062E\u0631\u0648\u062C\u06CC',
  pxHint:'\u0628\u0627 \u0641\u0639\u0627\u0644 \u06A9\u0631\u062F\u0646 \u06CC\u06A9 \u067E\u0631\u0648\u06A9\u0633\u06CC\u060C \u062A\u0645\u0627\u0645 \u062A\u0631\u0627\u0641\u06CC\u06A9 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0627\u0632 \u0647\u0645\u0627\u0646 \u0645\u0633\u06CC\u0631 \u062E\u0627\u0631\u062C \u0645\u06CC\u200C\u0634\u0648\u062F \u0648 \u0633\u0627\u06CC\u062A\u200C\u0647\u0627 \u0627\u06CC\u067E\u06CC \u067E\u0631\u0648\u06A9\u0633\u06CC \u0631\u0627 \u0645\u06CC\u200C\u0628\u06CC\u0646\u0646\u062F.',
  pxKind:'\u0646\u0648\u0639',pxHost:'\u0647\u0627\u0633\u062A / \u0627\u06CC\u067E\u06CC',pxPort:'\u067E\u0648\u0631\u062A',
  pxUser:'\u06CC\u0648\u0632\u0631\u0646\u06CC\u0645 (\u0627\u062E\u062A\u06CC\u0627\u0631\u06CC)',pxPass:'\u067E\u0633\u0648\u0631\u062F (\u0627\u062E\u062A\u06CC\u0627\u0631\u06CC)',
  pxAdd:'\u0627\u0641\u0632\u0648\u062F\u0646 \u0648 \u062A\u0633\u062A',pxTestAll:'\u062A\u0633\u062A \u0647\u0645\u0647',
  pxInSub:'\u062F\u0631 \u0633\u0627\u0628',
  pxAutoNote:'\u0647\u0631 \u067E\u0631\u0648\u06A9\u0633\u06CC \u06A9\u0647 \u0627\u0636\u0627\u0641\u0647 \u0634\u0648\u062F \u062E\u0648\u062F\u0628\u0647\u200C\u062E\u0648\u062F \u062F\u0631 \u0633\u0627\u0628 \u0647\u0645\u0647 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0645\u06CC\u200C\u0622\u06CC\u062F \u2014 \u0647\u0645\u0647 \u0628\u0627 \u0647\u0645\u060C \u0628\u062F\u0648\u0646 \u062F\u06A9\u0645\u0647. \u06A9\u0627\u0646\u0641\u06CC\u06AF \u0628\u062F\u0648\u0646 \u067E\u0631\u0648\u06A9\u0633\u06CC \u0647\u0645\u06CC\u0634\u0647 \u0633\u0631 \u062C\u0627\u06CC\u0634 \u0647\u0633\u062A\u061B \u0642\u0637\u0639\u06CC \u06CC\u0627 \u0646\u0627\u0645\u0648\u0641\u0642 \u0628\u0648\u062F\u0646 \u062A\u0633\u062A\u060C \u067E\u0631\u0648\u06A9\u0633\u06CC \u0631\u0627 \u0627\u0632 \u0633\u0627\u0628 \u062D\u0630\u0641 \u0646\u0645\u06CC\u200C\u06A9\u0646\u062F \u0648 \u0641\u0642\u0637 \u0628\u0627 \u063A\u06CC\u0631\u0641\u0639\u0627\u0644 \u06A9\u0631\u062F\u0646 \u06CC\u0627 \u062D\u0630\u0641 \u0627\u0632 \u067E\u0646\u0644 \u0628\u06CC\u0631\u0648\u0646 \u0645\u06CC\u200C\u0631\u0648\u062F.',
  pxLineHint:'\u0647\u0631 \u062E\u0637 \u06CC\u06A9 \u067E\u0631\u0648\u06A9\u0633\u06CC \u2014 \u0645\u0627\u0646\u0646\u062F socks5://1.1.1.1:5866 \u06CC\u0627 http://user:pass@2.2.2.2:8080',
  pxAddLines:'\u0627\u0641\u0632\u0648\u062F\u0646 \u0644\u06CC\u0633\u062A \u0648 \u062A\u0633\u062A',
  pxAdvanced:'\u0648\u0631\u0648\u062F \u062F\u0633\u062A\u06CC \u0641\u06CC\u0644\u062F\u0647\u0627',
  pxDirect:'\u0627\u062A\u0635\u0627\u0644 \u0645\u0633\u062A\u0642\u06CC\u0645 (\u0628\u062F\u0648\u0646 \u067E\u0631\u0648\u06A9\u0633\u06CC)',
  pxActive:'\u0641\u0639\u0627\u0644',pxArm:'\u0641\u0639\u0627\u0644 \u06A9\u0631\u062F\u0646',pxTest:'\u062A\u0633\u062A \u0633\u0644\u0627\u0645\u062A',
  pxHealthy:'\u0633\u0627\u0644\u0645',pxDown:'\u062E\u0631\u0627\u0628',pxUntested:'\u062A\u0633\u062A \u0646\u0634\u062F\u0647',
  pxExitIp:'\u0627\u06CC\u067E\u06CC \u062E\u0631\u0648\u062C\u06CC',pxLatency:'\u062A\u0627\u062E\u06CC\u0631',
  pxNone:'\u0647\u0646\u0648\u0632 \u067E\u0631\u0648\u06A9\u0633\u06CC \u0627\u0636\u0627\u0641\u0647 \u0646\u0634\u062F\u0647 \u0627\u0633\u062A',
  pxStrict:'\u062D\u0627\u0644\u062A \u0633\u062E\u062A\u06AF\u06CC\u0631\u0627\u0646\u0647',
  pxStrictHint:'\u0627\u06AF\u0631 \u067E\u0631\u0648\u06A9\u0633\u06CC \u0642\u0637\u0639 \u0634\u062F\u060C \u0627\u062A\u0635\u0627\u0644 \u0631\u062F \u0645\u06CC\u200C\u0634\u0648\u062F \u062A\u0627 \u0627\u06CC\u067E\u06CC \u0627\u0635\u0644\u06CC \u0633\u0631\u0648\u0631 \u0644\u0648 \u0646\u0631\u0648\u062F',
  pxFlagSrc:'\u0645\u0646\u0628\u0639 \u067E\u0631\u0686\u0645 \u0646\u0627\u0645 \u06A9\u0627\u0646\u0641\u06CC\u06AF',
  pxFlagProxy:'\u06A9\u0634\u0648\u0631 \u067E\u0631\u0648\u06A9\u0633\u06CC',pxFlagEntry:'\u06A9\u0634\u0648\u0631 \u0633\u0631\u0648\u0631 \u0648\u0631\u0648\u062F\u06CC',
  pxTesting:'\u062F\u0631 \u062D\u0627\u0644 \u062A\u0633\u062A...',pxArmed:'\u067E\u0631\u0648\u06A9\u0633\u06CC \u0641\u0639\u0627\u0644 \u0634\u062F',
  pxDelWarn:'\u0627\u06CC\u0646 \u067E\u0631\u0648\u06A9\u0633\u06CC \u062D\u0630\u0641 \u0634\u0648\u062F\u061F',
  addedN:'\u0627\u0641\u0632\u0648\u062F\u0647 \u0634\u062F',dupN:'\u062A\u06A9\u0631\u0627\u0631\u06CC',invalidN:'\u0646\u0627\u0645\u0639\u062A\u0628\u0631',noCleanIps:'\u0644\u06CC\u0633\u062A \u062E\u0627\u0644\u06CC \u0627\u0633\u062A',
  settings:'\u062A\u0646\u0638\u06CC\u0645\u0627\u062A',appearance:'\u0638\u0627\u0647\u0631',theme:'\u062A\u0645',language:'\u0632\u0628\u0627\u0646',
  thDark:'\u062A\u06CC\u0631\u0647 (\u0645\u0634\u06A9\u06CC \u0648 \u0622\u0628\u06CC)',thLight:'\u0631\u0648\u0634\u0646 (\u0633\u0641\u06CC\u062F \u0648 \u0622\u0628\u06CC)',thGray:'\u062E\u0627\u06A9\u0633\u062A\u0631\u06CC',
  country:'\u06A9\u0634\u0648\u0631',autoCountry:'\u062A\u0634\u062E\u06CC\u0635 \u062E\u0648\u062F\u06A9\u0627\u0631',mainCountry:'\u06A9\u0634\u0648\u0631 \u0633\u0631\u0648\u0631 \u0627\u0635\u0644\u06CC',
  flagsHint:'\u067E\u0631\u0686\u0645 \u06A9\u0634\u0648\u0631 \u0628\u0647 \u0627\u0628\u062A\u062F\u0627\u06CC \u0646\u0627\u0645 \u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627 \u062F\u0631 \u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9 \u0627\u0636\u0627\u0641\u0647 \u0645\u06CC\u200C\u0634\u0648\u062F',
  savedOk:'\u0630\u062E\u06CC\u0631\u0647 \u0634\u062F',save:'\u0630\u062E\u06CC\u0631\u0647',
  changePw:'\u062A\u063A\u06CC\u06CC\u0631 \u0631\u0645\u0632 \u0639\u0628\u0648\u0631',curPw:'\u0631\u0645\u0632 \u0641\u0639\u0644\u06CC',newPw:'\u0631\u0645\u0632 \u062C\u062F\u06CC\u062F',pwChanged:'\u0631\u0645\u0632 \u062A\u063A\u06CC\u06CC\u0631 \u06A9\u0631\u062F \u2713',
  serverInfo:'\u0627\u0637\u0644\u0627\u0639\u0627\u062A \u0633\u0631\u0648\u0631',wsPathLbl:'\u0645\u0633\u06CC\u0631 WebSocket',xhPathLbl:'\u0645\u0633\u06CC\u0631 XHTTP',
  xhModeLbl:'\u062D\u0627\u0644\u062A XHTTP',
  xhModeHint:'\u062D\u0627\u0644\u062A \u0631\u0648\u06CC packet-up \u0627\u0633\u062A \u0648 \u0628\u0631\u0627\u06CC \u0647\u0631 \u062A\u06A9\u0647 \u0622\u067E\u0644\u0648\u062F \u06CC\u06A9 \u0631\u06A9\u0648\u0626\u0633\u062A \u062C\u062F\u0627 \u0645\u06CC\u200C\u0641\u0631\u0633\u062A\u062F. \u0627\u06AF\u0631 \u0631\u0644\u0647 '
        +'\u06A9\u0644\u0627\u062F\u0641\u0644\u0631 \u062F\u0627\u0631\u06CC\u062F\u060C XHTTP_MODE \u0631\u0627 \u0628\u0647 stream-up \u062A\u063A\u06CC\u06CC\u0631 \u062F\u0647\u06CC\u062F \u062A\u0627 \u0647\u0631 \u0627\u062A\u0635\u0627\u0644 \u0641\u0642\u0637 \u06F2 \u0631\u06A9\u0648\u0626\u0633\u062A \u0634\u0648\u062F. '
        +'\u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627\u06CC \u0642\u0628\u0644\u06CC \u0647\u0645\u0686\u0646\u0627\u0646 \u06A9\u0627\u0631 \u0645\u06CC\u200C\u06A9\u0646\u0646\u062F\u060C \u0648\u0644\u06CC \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0628\u0627\u06CC\u062F \u0644\u06CC\u0646\u06A9 \u0627\u0634\u062A\u0631\u0627\u06A9 \u0631\u0627 \u06CC\u06A9 \u0628\u0627\u0631 \u0628\u0647\u200C\u0631\u0648\u0632 \u06A9\u0646\u0646\u062F.',
  trWarnTitle:'\u26A0\uFE0F \u0645\u0635\u0631\u0641 \u0631\u06A9\u0648\u0626\u0633\u062A XHTTP:',
  trWarn:'\u0645\u0635\u0631\u0641 \u0627\u06CC\u0646 \u062A\u0631\u0646\u0633\u067E\u0648\u0631\u062A \u0628\u0647 \u062D\u0627\u0644\u062A (mode) \u0628\u0633\u062A\u06AF\u06CC \u062F\u0627\u0631\u062F. \u062F\u0631 stream-up \u2014 \u06A9\u0647 \u067E\u06CC\u0634\u200C\u0641\u0631\u0636 \u0627\u06CC\u0646 \u067E\u0646\u0644 '
        +'\u0627\u0633\u062A \u2014 \u0647\u0631 \u0627\u062A\u0635\u0627\u0644 \u06F2 \u0631\u06A9\u0648\u0626\u0633\u062A \u0645\u06CC\u200C\u0634\u0648\u062F (\u06CC\u06A9 GET \u0628\u0631\u0627\u06CC \u062F\u0627\u0646\u0644\u0648\u062F \u0648 \u06CC\u06A9 POST \u0628\u0644\u0646\u062F\u0645\u062F\u062A \u0628\u0631\u0627\u06CC \u0622\u067E\u0644\u0648\u062F). '
        +'\u062F\u0631 packet-up \u0647\u0631 \u062A\u06A9\u0647 \u0627\u0632 \u0622\u067E\u0644\u0648\u062F \u06CC\u06A9 POST \u062C\u062F\u0627\u06AF\u0627\u0646\u0647 \u0627\u0633\u062A \u0648 \u06CC\u06A9 \u06A9\u0627\u0631\u0628\u0631 \u0641\u0639\u0627\u0644 \u062F\u0642\u06CC\u0642\u0647\u200C\u0627\u06CC \u0635\u062F\u0647\u0627 '
        +'\u0631\u06A9\u0648\u0626\u0633\u062A \u0645\u06CC\u200C\u0633\u0627\u0632\u062F \u06A9\u0647 \u0633\u0647\u0645\u06CC\u0647 \u0631\u0648\u0632\u0627\u0646\u0647 \u0648\u0631\u06A9\u0631 \u06A9\u0644\u0627\u062F\u0641\u0644\u0631 (\u06F1\u06F0\u06F0\u066C\u06F0\u06F0\u06F0) \u0631\u0627 \u0632\u0648\u062F \u067E\u0631 \u0645\u06CC\u200C\u06A9\u0646\u062F. WS \u0627\u0632 \u0647\u0645\u0647 '
        +'\u06A9\u0645\u200C\u0645\u0635\u0631\u0641\u200C\u062A\u0631 \u0627\u0633\u062A: \u0647\u0631 \u0627\u062A\u0635\u0627\u0644 \u0641\u0642\u0637 \u06F1 \u0631\u06A9\u0648\u0626\u0633\u062A\u060C \u0647\u0631 \u0686\u0642\u062F\u0631 \u0647\u0645 \u0637\u0648\u0644 \u0628\u06A9\u0634\u062F.',
  backupTitle:'\u{1F4E6} \u067E\u0634\u062A\u06CC\u0628\u0627\u0646\u200C\u06AF\u06CC\u0631\u06CC',
  backupHint:'\u06CC\u06A9 \u0641\u0627\u06CC\u0644 \u0628\u0627 \u067E\u0633\u0648\u0646\u062F .ixpbak \u06A9\u0647 \u0647\u0645\u0647\u0654 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 (\u0628\u0627 UUID \u0648 \u062A\u0648\u06A9\u0646 \u0627\u0634\u062A\u0631\u0627\u06A9\u0634\u0627\u0646)\u060C '
        +'\u0622\u06CC\u200C\u067E\u06CC\u200C\u0647\u0627\u06CC \u062A\u0645\u06CC\u0632\u060C \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627\u060C \u0631\u0645\u0632 \u067E\u0646\u0644 \u0648 \u062A\u0646\u0638\u06CC\u0645\u0627\u062A \u0631\u0627 \u0646\u06AF\u0647 \u0645\u06CC\u200C\u062F\u0627\u0631\u062F. \u0647\u0645\u06CC\u0646 \u0641\u0627\u06CC\u0644 \u0631\u0627 \u062F\u0631 \u067E\u0646\u0644 '
        +'\u062C\u062F\u06CC\u062F \u0648\u0627\u0631\u062F \u06A9\u0646\u06CC\u062F \u062A\u0627 \u0647\u0645\u0647 \u0686\u06CC\u0632 \u0628\u0631\u06AF\u0631\u062F\u062F \u2014 \u06A9\u0627\u0646\u0641\u06CC\u06AF\u200C\u0647\u0627\u06CC \u062F\u0633\u062A \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0647\u0645 \u06A9\u0627\u0631 \u0645\u06CC\u200C\u06A9\u0646\u0646\u062F \u0686\u0648\u0646 '
        +'UUID \u0648 \u062A\u0648\u06A9\u0646\u200C\u0647\u0627 \u0639\u0648\u0636 \u0646\u0645\u06CC\u200C\u0634\u0648\u0646\u062F.',
  bkInclPw:'\u0631\u0645\u0632 \u067E\u0646\u0644 \u0647\u0645 \u0630\u062E\u06CC\u0631\u0647 \u0634\u0648\u062F',
  bkInclProxyCreds:'\u06CC\u0648\u0632\u0631 \u0648 \u067E\u0633\u0648\u0631\u062F \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627 \u0647\u0645 \u0630\u062E\u06CC\u0631\u0647 \u0634\u0648\u062F',
  bkInclTraffic:'\u062A\u0627\u0631\u06CC\u062E\u0686\u0647\u0654 \u0645\u0635\u0631\u0641 \u0647\u0645 \u0630\u062E\u06CC\u0631\u0647 \u0634\u0648\u062F (\u062D\u062C\u0645 \u0641\u0627\u06CC\u0644 \u0628\u06CC\u0634\u062A\u0631 \u0645\u06CC\u200C\u0634\u0648\u062F)',
  bkSecretWarn:'\u26A0\uFE0F \u0627\u06CC\u0646 \u0641\u0627\u06CC\u0644 \u0634\u0627\u0645\u0644 \u0631\u0645\u0632 \u067E\u0646\u0644 \u0648 \u067E\u0633\u0648\u0631\u062F \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627\u0633\u062A \u2014 \u0645\u062B\u0644 \u0631\u0645\u0632 \u0639\u0628\u0648\u0631 \u0627\u0632 \u0622\u0646 \u0645\u0631\u0627\u0642\u0628\u062A \u06A9\u0646\u06CC\u062F.',
  btnBackupLbl:'\u2B07\uFE0F \u062F\u0627\u0646\u0644\u0648\u062F \u0641\u0627\u06CC\u0644 \u067E\u0634\u062A\u06CC\u0628\u0627\u0646',
  restoreTitle:'\u267B\uFE0F \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC',
  restoreHint:'\u0641\u0627\u06CC\u0644 .ixpbak \u0631\u0627 \u0627\u0646\u062A\u062E\u0627\u0628 \u06A9\u0646\u06CC\u062F. \u0627\u0648\u0644 \u0645\u062D\u062A\u0648\u0627\u06CC\u0634 \u0646\u0645\u0627\u06CC\u0634 \u062F\u0627\u062F\u0647 \u0645\u06CC\u200C\u0634\u0648\u062F \u0648 \u062A\u0627 \u062A\u0623\u06CC\u06CC\u062F '
        +'\u0646\u06A9\u0646\u06CC\u062F \u0647\u06CC\u0686 \u0686\u06CC\u0632\u06CC \u062F\u0631 \u062F\u06CC\u062A\u0627\u0628\u06CC\u0633 \u0646\u0648\u0634\u062A\u0647 \u0646\u0645\u06CC\u200C\u0634\u0648\u062F.',
  restoreMode:'\u0646\u062D\u0648\u0647\u0654 \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC',
  bkMerge:'\u0627\u062F\u063A\u0627\u0645 \u2014 \u0645\u0648\u0627\u0631\u062F \u0645\u0648\u062C\u0648\u062F \u0628\u0647\u200C\u0631\u0648\u0632 \u0648 \u0628\u0642\u06CC\u0647 \u0627\u0636\u0627\u0641\u0647 \u0645\u06CC\u200C\u0634\u0648\u0646\u062F',
  bkReplace:'\u062C\u0627\u06CC\u06AF\u0632\u06CC\u0646\u06CC \u06A9\u0627\u0645\u0644 \u2014 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646\u060C \u0622\u06CC\u200C\u067E\u06CC\u200C\u0647\u0627 \u0648 \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627\u06CC \u0641\u0639\u0644\u06CC \u062D\u0630\u0641 \u0645\u06CC\u200C\u0634\u0648\u0646\u062F',
  bkRestorePwLbl:'\u0631\u0645\u0632 \u067E\u0646\u0644 \u0647\u0645 \u0627\u0632 \u0641\u0627\u06CC\u0644 \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC \u0634\u0648\u062F',
  btnRestoreLbl:'\u267B\uFE0F \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC \u06A9\u0646',
  bkReading:'\u062F\u0631 \u062D\u0627\u0644 \u062E\u0648\u0627\u0646\u062F\u0646 \u0641\u0627\u06CC\u0644\u2026',
  bkBadFile:'\u0641\u0627\u06CC\u0644 \u0642\u0627\u0628\u0644 \u062E\u0648\u0627\u0646\u062F\u0646 \u0646\u06CC\u0633\u062A \u06CC\u0627 \u067E\u0634\u062A\u06CC\u0628\u0627\u0646 \u0627\u06CC\u0646 \u067E\u0646\u0644 \u0646\u06CC\u0633\u062A',
  bkFrom:'\u0633\u0627\u062E\u062A\u0647\u200C\u0634\u062F\u0647 \u062F\u0631',bkUsersN:'\u06A9\u0627\u0631\u0628\u0631',bkCipsN:'\u0622\u06CC\u200C\u067E\u06CC \u062A\u0645\u06CC\u0632',bkProxN:'\u067E\u0631\u0648\u06A9\u0633\u06CC',
  bkTrafficN:'\u0631\u06A9\u0648\u0631\u062F \u0645\u0635\u0631\u0641',
  bkHasPw:'\u0634\u0627\u0645\u0644 \u0631\u0645\u0632 \u067E\u0646\u0644',bkNoPw:'\u0628\u062F\u0648\u0646 \u0631\u0645\u0632 \u067E\u0646\u0644',
  bkProxCreds:'\u067E\u0631\u0648\u06A9\u0633\u06CC \u0628\u0627 \u06CC\u0648\u0632\u0631/\u067E\u0633\u0648\u0631\u062F',
  bkEnvDiff:'\u26A0\uFE0F \u0627\u06CC\u0646 \u0645\u062A\u063A\u06CC\u0631\u0647\u0627 \u0628\u0627 \u067E\u0646\u0644 \u0641\u0639\u0644\u06CC \u062A\u0641\u0627\u0648\u062A \u062F\u0627\u0631\u0646\u062F \u0648 \u0628\u0627\u06CC\u062F \u062F\u0633\u062A\u06CC \u062F\u0631 Railway/Render \u0633\u062A \u0634\u0648\u0646\u062F:',
  bkReplaceWarn:'\u0647\u0645\u0647\u0654 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646\u060C \u0622\u06CC\u200C\u067E\u06CC\u200C\u0647\u0627\u06CC \u062A\u0645\u06CC\u0632 \u0648 \u067E\u0631\u0648\u06A9\u0633\u06CC\u200C\u0647\u0627\u06CC \u0641\u0639\u0644\u06CC \u062D\u0630\u0641 \u0648 \u0628\u0627 \u0641\u0627\u06CC\u0644 \u062C\u0627\u06CC\u06AF\u0632\u06CC\u0646 \u0645\u06CC\u200C\u0634\u0648\u0646\u062F. \u0645\u0637\u0645\u0626\u0646\u06CC\u061F',
  bkPwChanged:"\u0631\u0645\u0632 \u067E\u0646\u0644 \u0627\u0632 \u0641\u0627\u06CC\u0644 \u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC \u0634\u062F \u2014 \u062F\u0641\u0639\u0647\u0654 \u0628\u0639\u062F \u0628\u0627 \u0631\u0645\u0632 \u0642\u062F\u06CC\u0645\u06CC\u0650 \u0647\u0645\u0627\u0646 \u0641\u0627\u06CC\u0644 \u0648\u0627\u0631\u062F \u0634\u0648\u06CC\u062F.",
  bkDone:'\u0628\u0627\u0632\u06AF\u0631\u062F\u0627\u0646\u06CC \u0627\u0646\u062C\u0627\u0645 \u0634\u062F',
  bkAdded:'\u0627\u0636\u0627\u0641\u0647\u200C\u0634\u062F\u0647',bkUpdated:'\u0628\u0647\u200C\u0631\u0648\u0632\u0634\u062F\u0647',bkSkipped:'\u0631\u062F\u0634\u062F\u0647',
  relayLbl:'\u062F\u0627\u0645\u0646\u0647 \u0631\u0644\u0647',keepAliveLbl:'\u062C\u0644\u0648\u06AF\u06CC\u0631\u06CC \u0627\u0632 \u062E\u0648\u0627\u0628',relayNone:'\u0646\u062F\u0627\u0631\u062F',
  onLbl:'\u0641\u0639\u0627\u0644',offLbl:'\u062E\u0627\u0645\u0648\u0634',
  devWinLbl:'\u067E\u0646\u062C\u0631\u0647 \u0634\u0645\u0627\u0631\u0634 \u062F\u0633\u062A\u06AF\u0627\u0647',seconds:'\u062B\u0627\u0646\u06CC\u0647',
  envNote:'\u0627\u06CC\u0646 \u0645\u0642\u0627\u062F\u06CC\u0631 \u0627\u0632 \u0645\u062A\u063A\u06CC\u0631\u0647\u0627\u06CC \u0645\u062D\u06CC\u0637\u06CC \u062E\u0648\u0627\u0646\u062F\u0647 \u0645\u06CC\u200C\u0634\u0648\u0646\u062F \u0648 \u062F\u0631 Railway \u0642\u0627\u0628\u0644 \u062A\u063A\u06CC\u06CC\u0631\u0646\u062F.',
  logout:'\u062E\u0631\u0648\u062C',logs:'\u0631\u062E\u062F\u0627\u062F\u0647\u0627',noLogs:'\u0631\u062E\u062F\u0627\u062F\u06CC \u0646\u06CC\u0633\u062A',
  statusDisabled:'\u063A\u06CC\u0631\u0641\u0639\u0627\u0644',statusExpired:'\u0645\u0646\u0642\u0636\u06CC',statusQuota:'\u062D\u062C\u0645 \u062A\u0645\u0627\u0645',
 },
 en:{dir:'ltr',
  setupTitle:'Set a password',setupSub:'First run \u2014 choose your panel password',
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
  name:'Name',quota:'Quota (GB)',days:'Days',devLimit:'Devices',
  transport:'Transport',trWs:'\u{1F50C} WS + TLS',trXhttp:'\u{1F680} XHTTP + TLS',trBoth:'\u{1F500} Both',
  add:'Add',zeroInf:'0 = unlimited. Device count is based on distinct active IPs.',
  search:'Search\u2026',noUsers:'No users yet',
  config:'Config',ipsBtn:'IPs',edit:'Edit',
  used:'Used',expiry:'Expires',never:'Never',
  subLink:'Subscription link',copySub:'Copy subscription link',
  singleCfg:'Individual configs',copy:'Copy',copied:'Copied \u2713',
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
  obfLbl:'Obfuscation (Fragment + Cipher mask)',
  uuidWarn:'Rotate UUID? Existing configs will stop working.',delWarn:'Delete this user?',
  cleanTitle:'Clean IP manager',
  cleanHint:'Clean IPs or domains. Added to every subscription as extra configs.',
  addrPh:'e.g. 1.2.3.4 or cdn.example.com',remarkPh:'Label (optional)',
  bulkPh:'One per line:\\\\n1.2.3.4 # Irancell\\\\n5.6.7.8 # MCI',
  bulkAdd:'Bulk add',clearAll:'Delete all',
  pxTitle:'Outbound proxy',
  pxHint:'Arm a proxy and every user connection leaves through it, so target sites see the proxy IP.',
  pxKind:'Type',pxHost:'Host / IP',pxPort:'Port',
  pxUser:'Username (optional)',pxPass:'Password (optional)',
  pxAdd:'Add & test',pxTestAll:'Test all',
  pxInSub:'in subscriptions',
  pxAutoNote:'Every proxy you add joins all subscriptions automatically \u2014 all of them at once, no button. The no-proxy config is always there, and a failed health check or a dropped connection never removes a proxy: only disabling or deleting it in the panel does.',
  pxLineHint:'One proxy per line \u2014 e.g. socks5://1.1.1.1:5866 or http://user:pass@2.2.2.2:8080',
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
  pwChanged:'Password changed \u2713',
  serverInfo:'Server info',wsPathLbl:'WebSocket path',xhPathLbl:'XHTTP path',
  xhModeLbl:'XHTTP mode',
  xhModeHint:'The mode is packet-up, which spends one request per upload chunk. Behind a '
        +'Cloudflare relay, set XHTTP_MODE=stream-up to get 2 requests per connection instead. '
        +'Existing configs keep working, but users need to refresh their subscription once.',
  trWarnTitle:'\u26A0\uFE0F XHTTP request cost:',
  trWarn:"Cost depends on the mode. stream-up \u2014 this panel's default \u2014 is 2 requests per "
       +"connection (one GET downlink plus one long-lived POST uplink). packet-up sends every "
       +"upload chunk as its own POST, so one active client can be hundreds of requests a "
       +"minute and will drain a Cloudflare Worker's daily quota (100k). WS is cheapest of "
       +"all: 1 request per connection no matter how long it stays open.",
  backupTitle:'\u{1F4E6} Backup',
  backupHint:'A single .ixpbak file holding every user (with their UUID and subscription '
        +'token), your clean IPs, your proxies, the panel password and its settings. Import '
        +'it into a fresh panel and everything comes back \u2014 configs already handed out keep '
        +'working, because UUIDs and tokens are preserved.',
  bkInclPw:'include the panel password',
  bkInclProxyCreds:'include proxy usernames and passwords',
  bkInclTraffic:'include traffic history (larger file)',
  bkSecretWarn:'\u26A0\uFE0F This file contains the panel password and your proxy credentials \u2014 treat it like a password.',
  btnBackupLbl:'\u2B07\uFE0F Download backup',
  restoreTitle:'\u267B\uFE0F Restore',
  restoreHint:'Pick a .ixpbak file. Its contents are shown first and nothing is written '
        +'to the database until you confirm.',
  restoreMode:'Restore mode',
  bkMerge:'Merge \u2014 update matching entries, add the rest',
  bkReplace:'Replace \u2014 wipe current users, clean IPs and proxies first',
  bkRestorePwLbl:'also restore the panel password from the file',
  btnRestoreLbl:'\u267B\uFE0F Restore now',
  bkReading:'Reading file\u2026',
  bkBadFile:'File cannot be read, or is not a backup from this panel',
  bkFrom:'Created',bkUsersN:'users',bkCipsN:'clean IPs',bkProxN:'proxies',
  bkTrafficN:'traffic rows',
  bkHasPw:'includes the panel password',bkNoPw:'no panel password',
  bkProxCreds:'proxies with credentials',
  bkEnvDiff:'\u26A0\uFE0F These variables differ from this panel and must be set by hand in Railway/Render:',
  bkReplaceWarn:'All current users, clean IPs and proxies will be deleted and replaced by the file. Continue?',
  bkPwChanged:"The panel password was restored from the file \u2014 sign in with that file's password next time.",
  bkDone:'Restore complete',
  bkAdded:'added',bkUpdated:'updated',bkSkipped:'skipped',
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
<\/script>

<!-- \u2500\u2500\u2500 top bar \u2500\u2500\u2500 -->
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

<!-- \u2500\u2500\u2500 drawer \u2500\u2500\u2500 -->
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
 <div class="navi" data-page="live" onclick="go('live')">
  <svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/>
  <path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1"/></svg>
  <span data-t="navLive"></span></div>
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
    <option value="fa">\u0641\u0627</option><option value="en">EN</option></select>
  </div>
  <button onclick="logout()" id="btnOut"
    class="w-full rounded-xl py-2 text-xs font-bold"
    style="background:color-mix(in srgb,var(--bad) 16%,transparent);color:var(--bad)"></button>
 </div>
</aside>

<main class="max-w-6xl mx-auto p-4">

 <!-- \u2550\u2550 DASHBOARD \u2550\u2550 -->
 <section data-pg="dash" class="space-y-4">
  <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="totalUsers"></p><p id="sUsers" class="text-2xl font-extrabold mt-1">\u2014</p></div>
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="online"></p><p id="sOnline" class="text-2xl font-extrabold mt-1" style="color:var(--ok)">\u2014</p></div>
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="liveDevices"></p><p id="sLive" class="text-2xl font-extrabold mt-1" style="color:var(--ok)">\u2014</p></div>
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="devices"></p><p id="sDev" class="text-2xl font-extrabold mt-1" style="color:var(--info)">\u2014</p></div>
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="traffic"></p><p id="sBytes" class="text-2xl font-extrabold mt-1" style="color:var(--a2)">\u2014</p></div>
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="cleanIps"></p><p id="sCip" class="text-2xl font-extrabold mt-1" style="color:var(--a1)">\u2014</p></div>
   <div class="card rounded-2xl p-4"><p class="text-xs dim" data-t="xSessions"></p><p id="sXs" class="text-2xl font-extrabold mt-1">\u2014</p></div>
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

 <!-- \u2550\u2550 USERS \u2550\u2550 -->
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
   <label class="flex items-center gap-2 text-xs mt-2">
    <input id="nObf" type="checkbox"><span data-t="obfLbl"></span></label>
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

 <!-- \u2550\u2550 CLEAN IP \u2550\u2550 -->
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

 <!-- \u2550\u2550 PROXY \u2550\u2550 -->
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

 <!-- \u2550\u2550 SETTINGS \u2550\u2550 -->
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
      <option value="fa">\u{1F1EE}\u{1F1F7} \u0641\u0627\u0631\u0633\u06CC</option><option value="en">\u{1F1EC}\u{1F1E7} English</option></select></div>
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

  <!-- \u2550\u2550 BACKUP & RESTORE \u2550\u2550 -->
  <div class="card rounded-2xl p-4 space-y-3">
   <p class="text-sm font-bold" data-t="backupTitle"></p>
   <p class="text-[11px] dim" data-t="backupHint"></p>
   <div id="bkInfo" class="text-[11px] space-y-1"></div>
   <div class="flex flex-wrap gap-2 text-xs">
    <label class="flex items-center gap-1.5 rounded-full soft px-3 py-1.5 cursor-pointer">
     <input type="checkbox" id="bkPw" checked> <span data-t="bkInclPw"></span></label>
    <label class="flex items-center gap-1.5 rounded-full soft px-3 py-1.5 cursor-pointer">
     <input type="checkbox" id="bkPxCreds" checked> <span data-t="bkInclProxyCreds"></span></label>
    <label class="flex items-center gap-1.5 rounded-full soft px-3 py-1.5 cursor-pointer">
     <input type="checkbox" id="bkTraffic"> <span data-t="bkInclTraffic"></span></label>
   </div>
   <p class="text-[11px] rounded-xl px-3 py-2 leading-relaxed"
      style="background:color-mix(in srgb,var(--warn) 14%,transparent);border:1px solid color-mix(in srgb,var(--warn) 45%,transparent);color:var(--warn)"
      data-t="bkSecretWarn"></p>
   <button onclick="doBackup()" id="btnBackup"
     class="grad rounded-xl py-2 px-4 font-bold text-sm text-white w-full sm:w-auto"></button>

   <div class="pt-3 border-t space-y-2" style="border-color:var(--line)">
    <p class="text-sm font-bold" data-t="restoreTitle"></p>
    <p class="text-[11px] dim" data-t="restoreHint"></p>
    <input type="file" id="bkFile" accept=".ixpbak,application/json,.json"
      onchange="pickBackup()" class="w-full inp rounded-xl px-3 py-2 text-xs">
    <div id="bkPreview" class="text-[11px] space-y-1"></div>
    <div id="bkOpts" class="hidden space-y-2">
     <label class="block text-xs dim" data-t="restoreMode"></label>
     <select id="bkMode" class="w-full inp rounded-xl px-3 py-2 text-sm">
      <option value="merge"></option><option value="replace"></option></select>
     <label class="flex items-center gap-2 text-xs">
      <input type="checkbox" id="bkRestorePw"> <span data-t="bkRestorePwLbl"></span></label>
     <button onclick="doRestore()" id="btnRestore"
       class="grad rounded-xl py-2 px-4 font-bold text-sm text-white w-full"></button>
    </div>
    <p id="bkMsg" class="text-xs"></p>
   </div>
  </div>
 </section>

 <!-- \u2550\u2550 LOGS \u2550\u2550 -->
 <section data-pg="logs" class="hidden">
  <div class="card rounded-2xl p-4">
   <p class="text-sm font-bold mb-3" data-t="logs"></p>
   <div id="logRows" class="space-y-1"></div>
  </div>
 </section>

 <!-- \u2550\u2550 LIVE CONNECTIONS \u2550\u2550 -->
 <section data-pg="live" class="hidden">
  <p class="text-sm font-bold mb-3 flex items-center gap-2">
   <span data-t="liveTitle"></span>
   <span id="liveCount" class="text-xs font-normal" style="color:var(--dim)"></span>
  </p>
  <div class="card rounded-2xl p-0 overflow-hidden">
   <div id="liveRows" class="divide-y" style="border-color:var(--line)"></div>
   <div id="liveEmpty" class="p-6 text-center text-sm" style="color:var(--dim)" data-t="liveEmpty"></div>
  </div>
 </section>
</main>

<div id="modal" class="fixed inset-0 z-[60] hidden items-center justify-center bg-black/70 p-4">
 <div class="card rounded-2xl w-full max-w-md p-5 max-h-[85vh] overflow-y-auto sheet">
  <div class="flex items-center mb-3"><p id="mTitle" class="font-bold"></p>
   <button onclick="closeModal()" class="ms-auto dim hover:opacity-70">\u2715</button></div>
  <div id="mBody" class="space-y-3 text-sm"></div>
 </div>
</div>

<script>
/* \u2500\u2500\u2500 drawer position depends on writing direction \u2500\u2500\u2500 */
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

/* \u2500\u2500\u2500 country flags + inline icons \u2500\u2500\u2500
   \\\`var\\\` and function declarations on purpose: paintStatic() runs during boot, before
   this point in the script, and \\\`const\\\` would throw a temporal-dead-zone error that
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

/* \u2500\u2500\u2500 routing \u2500\u2500\u2500 */
let PAGE=localStorage.getItem('page')||'dash';
function go(p){
 PAGE=p; localStorage.setItem('page',p);
 document.querySelectorAll('[data-pg]').forEach(s=>s.classList.toggle('hidden',s.dataset.pg!==p));
 document.querySelectorAll('.navi').forEach(n=>n.classList.toggle('on',n.dataset.page===p));
 crumb.textContent=T({dash:'navDash',users:'navUsers',clean:'navClean',
   proxy:'navProxy',live:'navLive',settings:'navSettings',logs:'navLogs'}[p]);
 toggleNav(false);
 if(p==='logs')loadLogs();
 if(p==='clean')loadCips();
 if(p==='settings'){renderServer();loadBackupInfo()}
 if(p==='live')loadLive(); else stopLive();
}

/* \u2500\u2500\u2500 helpers \u2500\u2500\u2500 */
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
 btnBackup.textContent=T('btnBackupLbl'); btnRestore.textContent=T('btnRestoreLbl');
 bkMode.options[0].textContent=T('bkMerge');
 bkMode.options[1].textContent=T('bkReplace');
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

/* \u2500\u2500\u2500 data \u2500\u2500\u2500 */
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
 protoBox.innerHTML=pairs.map(([k,lbl,col])=>\\\`
  <div class="rounded-xl soft px-3 py-2 flex items-center gap-2">
   <span class="h-2 w-2 rounded-full" style="background:\\\${col}"></span>
   <span>\\\${lbl}</span><span class="font-bold">\\\${bp[k]||0}</span></div>\\\`).join('');
}
function renderServer(){
 srvBox.innerHTML=[
  [T('wsPathLbl'),'/'+(stats.ws_path||'\u2014')],
  [T('xhPathLbl'),'/'+(stats.xhttp_path||'\u2014')],
  [T('xhModeLbl'),stats.xhttp_mode||'\u2014'],
  [T('devWinLbl'),(stats.device_window||'\u2014')+' '+T('seconds')],
  [T('xSessions'),stats.xhttp_sessions??'\u2014'],
  [T('relayLbl'),stats.relay_domain||T('relayNone')],
  [T('keepAliveLbl'),stats.keepalive?T('onLbl'):T('offLbl')],
 ].map(([k,v])=>\\\`<div class="flex items-center gap-2 rounded-xl soft px-3 py-2">
   <span class="dim">\\\${k}</span><span class="ms-auto mono">\\\${v}</span></div>\\\`).join('')
 +(stats.xhttp_mode==='packet-up'
   ?\\\`<p class="text-[11px] rounded-xl px-3 py-2 leading-relaxed mt-1"
       style="background:color-mix(in srgb,var(--warn) 14%,transparent);border:1px solid color-mix(in srgb,var(--warn) 45%,transparent)">
      <span class="font-bold" style="color:var(--warn)">\\\${T('trWarnTitle')}</span>
      <span class="dim">\\\${T('xhModeHint')}</span></p>\\\`
   :'');
}

async function loadStats(){
 stats=await api('/api/stats');
 sUsers.textContent=stats.users; sOnline.textContent=stats.online_users;
 sDev.textContent=stats.online_devices; sLive.textContent=stats.live_devices;
 sBytes.textContent=fmt(stats.total_bytes);
 sCip.textContent=stats.clean_ips; sXs.textContent=stats.xhttp_sessions;
 pill.textContent='/'+stats.ws_path+' \xB7 /'+stats.xhttp_path;
 paintChart(); renderProto();
 if(PAGE==='settings'){renderServer();loadBackupInfo()}
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
    liveCount.textContent=rows.length?\\\`(\\\${rows.length})\\\`:'';
    if(!rows.length){liveRows.innerHTML='';liveEmpty.style.display='';return}
    liveEmpty.style.display='none';
    const fmtDur=s=>{s=Math.max(0,Math.floor(s));const m=Math.floor(s/60),sec=s%60;
      return m?\\\`\\\${m}m \\\${sec}s\\\`:\\\`\\\${sec}s\\\`};
    liveRows.innerHTML=rows.map(c=>\\\`<div class="p-3 flex items-center gap-3 text-sm">
      <span class="text-[10px] px-2 py-0.5 rounded-full" style="background:color-mix(in srgb,var(--info) 16%,transparent);color:var(--info)">\\\${(c.transport||'').toUpperCase()}</span>
      <div class="flex-1 min-w-0">
        <p class="font-bold truncate">\\\${esc(c.user||'\u2014')}</p>
        <p class="text-xs truncate" style="color:var(--dim)">\\\${esc(c.ip||'')} \xB7 \\\${esc(c.route||'')}\\\${c.mux?' \xB7 mux':''}</p>
      </div>
      <span class="text-xs font-mono" style="color:var(--dim)">\\\${fmtDur(c.connected_for)}</span>
    </div>\\\`).join('');
  }catch(e){/* keep last render on transient error */}
  clearTimeout(liveTimer);
  liveTimer=setTimeout(loadLive,4000);   // auto-refresh every 4s
}
function stopLive(){clearTimeout(liveTimer);liveTimer=null}

function renderUsers(){
 const term=(q.value||'').toLowerCase();
 rows.innerHTML=users.filter(u=>u.name.toLowerCase().includes(term)).map(u=>{
  const pct=u.quota_bytes?Math.min(100,u.used_bytes/u.quota_bytes*100):0;
  const badge=u.active
   ?\\\`<span class="text-[10px] px-2 py-0.5 rounded-full" style="background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)">\\\${T('active')}</span>\\\`
   :\\\`<span class="text-[10px] px-2 py-0.5 rounded-full" style="background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)">\\\${statusTxt(u.status)}</span>\\\`;
  const dev=u.device_limit?\\\`\\\${u.devices_now}/\\\${u.device_limit}\\\`:\\\`\\\${u.devices_now}/\u267E\uFE0F\\\`;
  const liveTag=u.devices_live?\\\`<span class="text-[10px] px-1.5 py-0.5 rounded-full" style="background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)">\u25CF \\\${u.devices_live}</span>\\\`:'';
  const devCol=u.device_limit&&u.devices_now>=u.device_limit?'var(--bad)':'var(--info)';
  return \\\`<div class="p-4 border-b" style="border-color:var(--line)">
   <div class="flex items-center gap-2 flex-wrap">
    <p class="font-bold">\\\${u.name}</p>\\\${badge}
    <span class="text-[10px] px-2 py-0.5 rounded-full soft">\\\${trTxt(u.transport)}</span>
    <span class="text-[11px]" style="color:\\\${devCol}">\u{1F4F1} \\\${dev}</span>\\\${liveTag}
    <div class="flex-1"></div>
    <button onclick="showConfig(\\\${u.id})" class="text-[11px] px-2 py-1 rounded-lg" style="background:color-mix(in srgb,var(--a1) 22%,transparent)">\\\${T('config')}</button>
    <button onclick="showIps(\\\${u.id})" class="text-[11px] px-2 py-1 rounded-lg" style="background:color-mix(in srgb,var(--info) 20%,transparent)">\\\${T('ipsBtn')}</button>
    <button onclick="showEdit(\\\${u.id})" class="text-[11px] px-2 py-1 rounded-lg soft">\\\${T('edit')}</button>
   </div>
   <div class="mt-2 h-1.5 rounded-full overflow-hidden soft">
    <div class="h-full grad" style="width:\\\${pct}%"></div></div>
   <div class="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[11px] dim">
    <span>\\\${T('used')}: \\\${fmt(u.used_bytes)} / \\\${u.quota_bytes?fmt(u.quota_bytes):'\u267E\uFE0F'}</span>
    <span>\\\${T('expiry')}: \\\${dt(u.expire_at)}</span>
   </div></div>\\\`}).join('')||\\\`<p class="p-6 text-center text-sm dim">\\\${T('noUsers')}</p>\\\`;
}

function renderCips(){
 cipRows.innerHTML=cips.map(x=>\\\`
  <div class="flex items-center gap-2 rounded-xl soft px-3 py-2">
   <span class="h-2 w-2 rounded-full" style="background:\\\${x.enabled?'var(--ok)':'var(--dim)'}"></span>
   \\\${x.flag?\\\`<span class="text-sm">\\\${x.flag}</span>\\\`:''}
   <span class="mono text-[11px]">\\\${x.address}</span>
   \\\${x.remark?\\\`<span class="text-[10px] dim">\\\${x.remark}</span>\\\`:''}
   <div class="flex-1"></div>
   <button onclick="toggleCip(\\\${x.id})" class="icbox px-2 py-1 rounded-lg soft">\\\${x.enabled?SVG_PAUSE:SVG_PLAY}</button>
   <button onclick="delCip(\\\${x.id})" class="icbox px-2 py-1 rounded-lg" style="color:var(--bad)">\\\${SVG_X}</button>
  </div>\\\`).join('')||\\\`<p class="text-xs dim">\\\${T('noCleanIps')}</p>\\\`;
}

function renderLogs(){
 const box=document.getElementById('logRows');
 box.innerHTML=logItems.map(l=>\\\`
  <div class="flex items-center gap-2 rounded-xl soft px-3 py-2 text-[11px]">
   <span class="font-bold">\\\${l.event}</span>
   <span class="mono dim">\\\${l.ip||''}</span>
   <span class="dim">\\\${l.detail||''}</span>
   <span class="ms-auto dim">\\\${dt(l.ts)}</span></div>\\\`).join('')
  ||\\\`<p class="text-xs dim">\\\${T('noLogs')}</p>\\\`;
}

/* \u2500\u2500\u2500 actions \u2500\u2500\u2500 */
async function createUser(){
 cErr.textContent='';
 try{
  await api('/api/users',{method:'POST',body:JSON.stringify({
   name:nName.value.trim(),quota_gb:parseFloat(nQuota.value||0),
   expire_days:parseInt(nDays.value||0),device_limit:parseInt(nDev.value||0),
   transport:nTr.value,obfuscate:nObf.checked})});
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
  cipMsg.textContent=\\\`\\\${r.added} \\\${T('addedN')} \xB7 \\\${r.duplicates} \\\${T('dupN')} \xB7 \\\${r.invalid} \\\${T('invalidN')}\\\`;
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
  // An enabled proxy is already in every subscription \u2014 nothing to press.
  const on=PX_SUB.indexOf(x.id)>-1;
  const dot=x.healthy?'var(--ok)':(x.checked_at?'var(--bad)':'var(--dim)');
  const state=x.healthy?T('pxHealthy'):(x.checked_at?T('pxDown'):T('pxUntested'));
  const geo=[x.country_name||'',x.city||''].filter(Boolean).join(' \\\\u00b7 ');
  return \\\`<div class="rounded-xl soft px-3 py-2 \\\${on?'ring-2':''}" style="\\\${on?'outline:2px solid var(--a1)':''}">
   <div class="flex items-center gap-2 flex-wrap">
    <span class="h-2 w-2 rounded-full" style="background:\\\${dot}"></span>
    <span class="text-base">\\\${x.flag||'\\\\u{1F310}'}</span>
    <span class="mono text-[11px] min-w-0 break-all">\\\${x.label}</span>
    \\\${x.has_auth?'<span class="text-[10px] dim">\\\\u{1F511}</span>':''}
    \\\${on?\\\`<span class="text-[10px] font-bold" style="color:var(--a2)">\\\${T('pxInSub')}</span>\\\`:''}
    <div class="flex-1"></div>
    <button onclick="testProxy(\\\${x.id})" title="\\\${T('pxTest')}" class="icbox px-2 py-1 rounded-lg soft">\\\${SVG_PING}</button>
    <button onclick="toggleProxy(\\\${x.id},\\\${x.enabled?1:0})" class="icbox px-2 py-1 rounded-lg soft">\\\${x.enabled?SVG_PAUSE:SVG_PLAY}</button>
    <button onclick="delProxy(\\\${x.id})" class="icbox px-2 py-1 rounded-lg" style="color:var(--bad)">\\\${SVG_X}</button>
   </div>
   <div class="flex flex-wrap gap-x-3 gap-y-1 mt-1 text-[10px] dim">
    <span>\\\${state}</span>
    \\\${x.latency_ms?\\\`<span>\\\${T('pxLatency')}: \\\${x.latency_ms} ms</span>\\\`:''}
    \\\${x.exit_ip?\\\`<span class="mono">\\\${T('pxExitIp')}: \\\${x.exit_ip}</span>\\\`:''}
    \\\${geo?\\\`<span>\\\${geo}</span>\\\`:''}
    \\\${x.isp?\\\`<span>\\\${x.isp}</span>\\\`:''}
    \\\${x.remark?\\\`<span>\\\${x.remark}</span>\\\`:''}
    \\\${x.last_error?\\\`<span style="color:var(--bad)">\\\${x.last_error}</span>\\\`:''}
   </div>
  </div>\\\`}).join('')||\\\`<p class="text-xs dim">\\\${T('pxNone')}</p>\\\`;
}
async function addProxy(){
 pxMsg.textContent=T('pxTesting');
 try{const r=await api('/api/proxies',{method:'POST',body:JSON.stringify({
   kind:pKind.value,host:pHost.value.trim(),port:parseInt(pPort.value||'0',10),
   username:pUser.value.trim(),password:pPass.value,remark:pRem.value.trim()})});
  pxMsg.textContent=r.ok?\\\`\\\${r.flag||''} \\\${r.country_name||''} \\\\u00b7 \\\${r.exit_ip||''} \\\\u00b7 \\\${r.latency_ms}ms\\\`
                       :\\\`\\\${T('pxDown')}: \\\${r.error||''}\\\`;
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
    ?\\\`<span style="color:var(--ok)">\\\${x.flag||''} \\\${x.label} \xB7 \\\${x.country_name||''} \\\${x.latency_ms||0}ms</span>\\\`
    :\\\`<span style="color:var(--bad)">\\\${x.label}: \\\${x.error||''}</span>\\\`).join('<br>')+
   \\\`<br>\\\${good}/\\\${rows.length}\\\`;
  if(good)pBulk.value='';
  loadProxies();
 }catch(e){pxMsg.textContent=e.message}
}
async function testProxy(id){
 pxMsg.textContent=T('pxTesting');
 try{const r=await api('/api/proxies/'+id+'/test',{method:'POST'});
  pxMsg.textContent=r.ok?\\\`\\\${r.flag||''} \\\${r.country_name||''} \\\\u00b7 \\\${r.exit_ip||''} \\\\u00b7 \\\${r.latency_ms}ms\\\`
                       :\\\`\\\${T('pxDown')}: \\\${r.error||''}\\\`;
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
 const cfgs=c.configs.map(x=>\\\`
  <div class="rounded-xl soft p-2">
   <p class="text-[11px] font-bold mb-1">\\\${x.label}</p>
   <p class="mono text-[9px] break-all dim">\\\${x.uri}</p>
   <button onclick="copy(this,'\\\${x.uri.replace(/'/g,"\\\\\\\\'")}')" class="mt-1 w-full rounded-lg soft py-1 text-[10px]">\\\${T('copy')}</button>
  </div>\\\`).join('');
 openModal(T('config'),\\\`
  <p class="text-xs dim">\\\${T('subLink')}</p>
  <div class="rounded-xl soft p-2 mono text-[10px] break-all">\\\${c.sub_link}</div>
  <button onclick="copy(this,'\\\${c.sub_link}')" class="w-full grad rounded-xl py-2 text-xs font-bold text-white">\\\${T('copySub')}</button>
  <div id="qr" class="grid place-items-center bg-white p-3 rounded-xl"></div>
  <p class="text-xs dim pt-2">UUID</p>
  <div class="rounded-xl soft p-2 mono text-[10px] break-all">\\\${c.uuid}</div>
  <p class="text-xs dim pt-2">\\\${T('singleCfg')} \u2014 \\\${trTxt(c.transport)}</p>\\\${cfgs}\\\`);
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

 const rows=d.rows.length ? d.rows.map(x=>\\\`
  <div class="flex items-center gap-2 rounded-xl soft px-3 py-2">
   <span class="h-2 w-2 rounded-full" style="background:\\\${x.online?'var(--ok)':(x.counted?'var(--info)':'var(--dim)')}"></span>
   <span class="mono text-[11px]">\\\${x.ip}</span>
   <span class="text-[9px] px-1.5 py-0.5 rounded soft">\\\${x.proto||'ws'}</span>
   <span class="ms-auto text-[10px] dim">\\\${dt(x.last_seen)}</span>
  </div>\\\`).join('')
  : \\\`<p class="text-xs dim py-2">\\\${ipHistory?T('noConn'):T('noneNow')}</p>\\\`;

 const body=\\\`
  <div class="rounded-2xl p-4 text-center soft">
   <p class="text-[11px] dim">\\\${T('liveNow')}</p>
   <p class="text-4xl font-extrabold mt-1" style="color:\\\${d.live?'var(--ok)':'var(--dim)'}">\\\${d.live}</p>
   <p class="text-[10px] dim mt-1">\\\${T('inLast').replace('%s',d.live_window)}</p>
  </div>
  <div class="grid grid-cols-2 gap-2 text-[11px]">
   <div class="rounded-xl soft px-3 py-2"><span class="dim">\\\${T('countedFor')}</span>
    <span class="float-end font-bold" style="color:var(--info)">\\\${d.counted}</span></div>
   <div class="rounded-xl soft px-3 py-2"><span class="dim">\\\${T('totalSeen')}</span>
    <span class="float-end font-bold">\\\${d.total_seen}</span></div>
  </div>
  <div class="space-y-1">\\\${rows}</div>
  <button onclick="toggleIpHistory()" class="w-full rounded-xl soft py-2 text-xs">
   \\\${ipHistory?T('showLive'):T('showHistory')}</button>
  <button onclick="clearIps(\\\${ipUid})" class="w-full rounded-xl py-2 text-xs"
   style="background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)">\\\${T('clearIps')}</button>\\\`;

 if(quiet){ const b=document.getElementById('mBody'); if(b) b.innerHTML=body; }
 else openModal(T('devTitle'),body);
}

function toggleIpHistory(){ ipHistory=!ipHistory; paintIps(); }

async function clearIps(id){await api('/api/users/'+id+'/clear-ips',{method:'POST'});closeModal();loadUsers();loadStats()}

function showEdit(id){
 const u=users.find(x=>x.id===id);
 const days=u.expire_at?Math.max(0,Math.ceil((u.expire_at-Date.now()/1000)/86400)):0;
 const opt=v=>\\\`<option value="\\\${v}" \\\${u.transport===v?'selected':''}>\\\${trTxt(v)}</option>\\\`;
 openModal(T('editUser')+' \xB7 '+u.name,\\\`
  <label class="block text-xs dim">\\\${T('quota')}</label>
  <input id="eQ" type="number" step="0.5" value="\\\${(u.quota_bytes/1073741824).toFixed(2)}" class="w-full inp rounded-xl px-3 py-2">
  <label class="block text-xs dim">\\\${T('remainDays')}</label>
  <input id="eD" type="number" value="\\\${days}" class="w-full inp rounded-xl px-3 py-2">
  <label class="block text-xs dim">\\\${T('allowedDev')}</label>
  <input id="eV" type="number" value="\\\${u.device_limit}" class="w-full inp rounded-xl px-3 py-2">
  <label class="block text-xs dim">\\\${T('transport')}</label>
  <select id="eT" class="w-full inp rounded-xl px-3 py-2">\\\${opt('both')}\\\${opt('ws')}\\\${opt('xhttp')}</select>
  <label class="flex items-center gap-2 text-xs pt-1"><input id="eObf" type="checkbox" \\\${u.obfuscate?'checked':''}> \\\${T('obfLbl')}</label>
  <label class="block text-xs dim">\\\${T('customUuid')}</label>
  <input id="eU" value="\\\${u.uuid}" class="w-full inp rounded-xl px-3 py-2 mono text-[11px]">
  <label class="flex items-center gap-2 text-xs"><input id="eE" type="checkbox" \\\${u.enabled?'checked':''}> \\\${T('active')}</label>
  <button onclick="saveEdit(\\\${id})" class="w-full grad rounded-xl py-2 font-bold text-sm text-white">\\\${T('saveBtn')}</button>
  <div class="grid grid-cols-3 gap-2 pt-2">
   <button onclick="resetTraffic(\\\${id})" class="rounded-xl soft py-2 text-[11px]">\\\${T('resetTraffic')}</button>
   <button onclick="newUuid(\\\${id})" class="rounded-xl soft py-2 text-[11px]">\\\${T('newUuid')}</button>
   <button onclick="delUser(\\\${id})" class="rounded-xl py-2 text-[11px]" style="background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)">\\\${T('del')}</button>
  </div>
  <p id="eErr" class="text-xs" style="color:var(--bad)"></p>\\\`);
}
async function saveEdit(id){
 try{
  const u=users.find(x=>x.id===id);
  const payload={quota_gb:parseFloat(eQ.value||0),expire_days:parseInt(eD.value||0),
   device_limit:parseInt(eV.value||0),transport:eT.value,enabled:eE.checked,
   obfuscate:eObf.checked};
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

/* \u2500\u2500\u2500 backup & restore \u2500\u2500\u2500 */
let BK=null;                       // the parsed file waiting to be restored

const bkEsc=s=>(s==null?'':String(s)).replace(/[<>&"]/g,
 c=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c]));
const bkRow=(k,v)=>\\\`<div class="flex items-center gap-2 rounded-xl soft px-3 py-2">
 <span class="dim">\\\${k}</span><span class="ms-auto mono">\\\${v}</span></div>\\\`;

async function loadBackupInfo(){
 try{
  const i=await api('/api/backup/info');
  bkInfo.innerHTML=bkRow(T('bkUsersN'),i.users)+bkRow(T('bkCipsN'),i.clean_ips)
    +bkRow(T('bkProxN'),i.proxies)+bkRow(T('bkTrafficN'),i.traffic_rows);
 }catch(e){bkInfo.innerHTML=''}
}

function doBackup(){
 // A plain link download keeps the browser's Save dialog and the server-side filename.
 const qs='password='+(bkPw.checked?1:0)+'&traffic='+(bkTraffic.checked?1:0)
   +'&proxy_creds='+(bkPxCreds.checked?1:0);
 const a=document.createElement('a');
 a.href='/api/backup?'+qs; a.rel='noopener';
 document.body.appendChild(a); a.click(); a.remove();
 bkMsg.style.color='var(--ok)'; bkMsg.textContent='\u2713';
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
  // The server validates format, version and checksum; nothing is written yet.
  const p=await api('/api/restore/preview',{method:'POST',
    body:JSON.stringify({data:parsed})});
  BK=parsed;
  bkMsg.textContent='';
  let html=bkRow(T('bkFrom'),dt(p.created_at))+bkRow(T('bkUsersN'),p.users)
    +bkRow(T('bkCipsN'),p.clean_ips)+bkRow(T('bkProxN'),p.proxies);
  if(p.proxies_with_creds) html+=bkRow(T('bkProxCreds'),p.proxies_with_creds);
  if(p.traffic_rows) html+=bkRow(T('bkTrafficN'),p.traffic_rows);
  html+=bkRow('\u{1F510}',p.has_password?T('bkHasPw'):T('bkNoPw'));
  const diff=Object.entries(p.env_diff||{});
  if(diff.length){
   html+=\\\`<p class="text-[11px] rounded-xl px-3 py-2 leading-relaxed mt-1"
     style="background:color-mix(in srgb,var(--warn) 14%,transparent);border:1px solid color-mix(in srgb,var(--warn) 45%,transparent)">
     <span class="font-bold" style="color:var(--warn)">\\\${T('bkEnvDiff')}</span><br>\\\`
     +diff.map(([k,v])=>\\\`<span class="mono">\\\${bkEsc(k)}</span>: <span class="mono">\\\${bkEsc(v.current||'\u2014')}</span> \u2192 <span class="mono">\\\${bkEsc(v.backup||'\u2014')}</span>\\\`).join('<br>')
     +\\\`</p>\\\`;
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
 bkMsg.style.color='var(--dim)'; bkMsg.textContent='\u2026';
 try{
  const r=await api('/api/restore',{method:'POST',body:JSON.stringify({
    data:BK,mode,restore_password:bkRestorePw.checked})});
  bkMsg.style.color='var(--ok)';
  bkMsg.textContent=\\\`\\\${T('bkDone')} \u2014 \\\${T('bkUsersN')}: +\\\${r.users_added}/~\\\${r.users_updated}\\\`
    +\\\` \xB7 \\\${T('bkCipsN')}: +\\\${r.clean_ips_added}\\\`
    +\\\` \xB7 \\\${T('bkProxN')}: +\\\${r.proxies_added}/~\\\${r.proxies_updated}\\\`
    +(r.users_skipped||r.proxies_skipped||r.clean_ips_skipped
      ?\\\` \xB7 \\\${T('bkSkipped')}: \\\${r.users_skipped+r.proxies_skipped+r.clean_ips_skipped}\\\`:'');
  BK=null; bkFile.value=''; bkOpts.classList.add('hidden'); bkPreview.innerHTML='';
  loadUsers(); loadCips(); loadStats(); loadBackupInfo();
  if(typeof loadProxies==='function') loadProxies();
  if(r.password_restored) alert(T('bkPwChanged'));
 }catch(e){ bkMsg.style.color='var(--bad)'; bkMsg.textContent=e.message }
 finally{ btnRestore.disabled=false }
}

function copy(btn,t){navigator.clipboard.writeText(t);
 const old=btn.textContent;btn.textContent=T('copied');setTimeout(()=>btn.textContent=old,1200)}

go(PAGE);
loadStats();loadUsers();loadCips();loadMainCountry();loadProxies();
setInterval(()=>{loadStats();if(PAGE==='users')loadUsers()},15000);
<\/script></body></html>`])));
var escapeTitle = /* @__PURE__ */ __name((s) => String(s ?? "").replace(/[&<>"\']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]), "escapeTitle");
function loginHtml(title, mode) {
  return AUTH_HTML.replaceAll("{{TITLE}}", escapeTitle(title)).replaceAll("{{MODE}}", mode);
}
__name(loginHtml, "loginHtml");
function panelHtml(title) {
  return PANEL_HTML.replaceAll("{{TITLE}}", escapeTitle(title));
}
__name(panelHtml, "panelHtml");
function subscriptionHtml(user, text) {
  const e = String(text ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
  return `<!doctype html><html lang=fa dir=rtl><meta charset=utf-8><body><h1>${escapeTitle(user.name)}</h1><textarea style="width:95%;height:300px">${e}</textarea></body></html>`;
}
__name(subscriptionHtml, "subscriptionHtml");

// src/index.js
var json = /* @__PURE__ */ __name((x, status = 200, extra = {}) => Response.json(x, { status, headers: { "cache-control": "no-store", ...extra } }), "json");
var err = /* @__PURE__ */ __name((e, status = 400) => json({ error: String(e?.message || e) }, status), "err");
var now = /* @__PURE__ */ __name(() => Math.floor(Date.now() / 1e3), "now");
var int = /* @__PURE__ */ __name((v, fallback = 0) => Number.isFinite(Number(v)) ? Math.trunc(Number(v)) : fallback, "int");
var bool01 = /* @__PURE__ */ __name((v) => v === true || v === 1 || v === "1" ? 1 : 0, "bool01");
async function one(db, sql, ...args) {
  return db.prepare(sql).bind(...args).first();
}
__name(one, "one");
async function all(db, sql, ...args) {
  return (await db.prepare(sql).bind(...args).all()).results || [];
}
__name(all, "all");
async function setting(db, k) {
  return (await one(db, "SELECT value FROM settings WHERE key=?", k))?.value || "";
}
__name(setting, "setting");
async function putSetting(db, k, v) {
  await db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(k, String(v)).run();
}
__name(putSetting, "putSetting");
async function passwordSet(db) {
  return Boolean(await setting(db, "password_hash"));
}
__name(passwordSet, "passwordSet");
var randomSecret = /* @__PURE__ */ __name(() => [...crypto.getRandomValues(new Uint8Array(32))].map((x) => x.toString(16).padStart(2, "0")).join(""), "randomSecret");
async function sessionSecret(env) {
  return env.SECRET_KEY || await setting(env.DB, "session_secret");
}
__name(sessionSecret, "sessionSecret");
async function isAdmin(request, env) {
  return verifySession(readCookie(request, "session"), await sessionSecret(env));
}
__name(isAdmin, "isAdmin");
function sessionCookie(token) {
  return `session=${encodeURIComponent(token)}; Path=/; Max-Age=43200; HttpOnly; Secure; SameSite=Lax`;
}
__name(sessionCookie, "sessionCookie");
function clientIp(r) {
  return r.headers.get("cf-connecting-ip") || r.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "0.0.0.0";
}
__name(clientIp, "clientIp");
async function publicHost(request, env) {
  return env.RELAY_DOMAIN || env.DOMAIN || new URL(request.url).host;
}
__name(publicHost, "publicHost");
async function body(request) {
  const b = await request.json();
  if (!b || typeof b !== "object" || Array.isArray(b)) throw new Error("invalid body");
  return b;
}
__name(body, "body");
function countryCode(v) {
  return String(v || "").replace(/[^A-Za-z]/g, "").slice(0, 2).toUpperCase();
}
__name(countryCode, "countryCode");
function flagOf(cc) {
  const n = Number(String(cc).toUpperCase().codePointAt(0));
  return Number.isFinite(n) ? String.fromCodePoint(127397 + n) : "\u{1F310}";
}
__name(flagOf, "flagOf");
function proxyOut(r) {
  const { password, ...safe } = r;
  return { ...safe, has_auth: Boolean(r.username), flag: flagOf(r.country || ""), label: `${r.kind}://${r.host}:${r.port}` };
}
__name(proxyOut, "proxyOut");
function proxyParse(line) {
  let raw = String(line || "").trim(), remark = "";
  if (!raw || raw.startsWith("#") || raw.startsWith("//")) return null;
  if (raw.includes("#")) {
    [raw, remark] = raw.split("#", 2);
    raw = raw.trim();
    remark = remark.trim().slice(0, 80);
  }
  let kind = "socks5", rest = raw;
  const m = raw.match(/^([A-Za-z][A-Za-z0-9+.-]*):\/\/(.*)$/);
  if (m) {
    kind = m[1].toLowerCase();
    rest = m[2];
  }
  if ({ socks5h: "socks5", socks4a: "socks4", https: "http" }[kind]) kind = { socks5h: "socks5", socks4a: "socks4", https: "http" }[kind];
  if (!["socks5", "socks4", "http"].includes(kind)) throw new Error("kind must be socks5, socks4 or http");
  let username = "", password = "";
  const at = rest.lastIndexOf("@");
  if (at >= 0) {
    const auth = rest.slice(0, at);
    rest = rest.slice(at + 1);
    [username, password = ""] = auth.split(":", 2);
  }
  const hp = rest.match(/^\[?([^\]]+)\]?:(\d{1,5})\/?$/);
  if (!hp) throw new Error("use kind://host:port");
  const host = hp[1].trim(), port = int(hp[2]);
  if (!host || host.length > 255 || /\s/.test(host) || port < 1 || port > 65535) throw new Error("invalid proxy host or port");
  if (isBlockedHost(host)) throw new Error("private proxy endpoint is not allowed");
  if (kind === "socks4") password = "";
  return { kind, host, port, username, password, remark };
}
__name(proxyParse, "proxyParse");
async function proxyTest(env, id) {
  const px = await one(env.DB, "SELECT * FROM proxies WHERE id=?", id);
  if (!px) throw new Error("proxy not found");
  try {
    const r = await proxyHealth(px, connect);
    await env.DB.prepare("UPDATE proxies SET healthy=1,latency_ms=?,exit_ip=?,country=?,country_name=?,city=?,isp=?,last_error='',checked_at=? WHERE id=?").bind(r.latency_ms, r.exit_ip, r.country, r.country_name, r.city, r.isp, now(), id).run();
    return { ...r, id, label: `${px.kind}://${px.host}:${px.port}` };
  } catch (e) {
    const error = String(e?.message || e).slice(0, 200);
    await env.DB.prepare("UPDATE proxies SET healthy=0,last_error=?,checked_at=? WHERE id=?").bind(error, now(), id).run();
    return { ok: false, id, label: `${px.kind}://${px.host}:${px.port}`, error };
  }
}
__name(proxyTest, "proxyTest");
async function subscriptionText(request, env, user) {
  return buildSubscription({ user, host: await publicHost(request, env), cleanIps: await all(env.DB, "SELECT * FROM clean_ips WHERE enabled=1"), proxies: await all(env.DB, "SELECT id,country,country_name,city,remark,host,enabled FROM proxies WHERE enabled=1 ORDER BY id"), wsPath: env.WS_PATH || "ws", xhttpPath: env.XHTTP_PATH || "xh" });
}
__name(subscriptionText, "subscriptionText");
function canonical(v) {
  if (Array.isArray(v)) return v.map(canonical);
  if (v && typeof v === "object") return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical(v[k])]));
  return v;
}
__name(canonical, "canonical");
async function checksum(v) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(canonical(v)))))].map((x) => x.toString(16).padStart(2, "0")).join("");
}
__name(checksum, "checksum");
function backupPayload(p) {
  return { created_at: nonNegative(p.created_at || now()), panel_version: 3, env: p.env || {}, users: Array.isArray(p.users) ? p.users : [], clean_ips: Array.isArray(p.clean_ips) ? p.clean_ips : [], proxies: Array.isArray(p.proxies) ? p.proxies : [], settings: p.settings && typeof p.settings === "object" ? p.settings : {}, traffic_log: Array.isArray(p.traffic_log) ? p.traffic_log : [] };
}
__name(backupPayload, "backupPayload");
async function validateBackup(doc, force = false) {
  if (doc?.format !== "iranx-panel-backup" || !doc.payload || int(doc.version) < 1) throw new Error("invalid backup");
  const p = backupPayload(doc.payload);
  if (p.users.length > 1e4 || p.clean_ips.length > 1e4 || p.proxies.length > 1e4) throw new Error("backup is too large");
  if (doc.checksum && !force && await checksum(p) !== doc.checksum) throw new Error("backup checksum mismatch");
  if (p.users.some((u) => !isValidName(u.name) || !UUID_RE.test(String(u.uuid)) || !["ws", "xhttp", "both"].includes(u.transport || "both"))) throw new Error("invalid users in backup");
  if (p.clean_ips.some((x) => !isValidAddress(x.address))) throw new Error("invalid clean IPs in backup");
  return p;
}
__name(validateBackup, "validateBackup");
async function handleApi(request, env, alreadyAuth = false) {
  const path = new URL(request.url).pathname, m = request.method;
  try {
    if (path === "/api/state" && m === "GET") return json({ needs_setup: !await passwordSet(env.DB) && !env.ADMIN_PASSWORD, logged_in: await isAdmin(request, env) });
    if (path === "/api/setup" && m === "POST") {
      if (await passwordSet(env.DB)) return err("password already set", 409);
      const b = await body(request), initial = String(env.ADMIN_PASSWORD || "");
      if (!initial && (b.password !== b.confirm || !passwordPolicy(b.password))) return err("passwords must match and meet password policy");
      if (initial && !passwordPolicy(initial)) return err("ADMIN_PASSWORD does not meet password policy");
      const password = initial || b.password, h = await hashPassword(password), sessionKey = env.SECRET_KEY || randomSecret();
      const writes = [env.DB.prepare("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)").bind("password_hash", JSON.stringify(h))];
      if (!env.SECRET_KEY) writes.push(env.DB.prepare("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)").bind("session_secret", sessionKey));
      const written = await env.DB.batch(writes);
      if (Number(written?.[0]?.meta?.changes || 0) !== 1) return err("password already set", 409);
      await putSetting(env.DB, "password_salt", h.salt);
      return json({ ok: true }, 200, { "set-cookie": sessionCookie(await makeSession(sessionKey)) });
    }
    if (path === "/api/login" && m === "POST") {
      const b = await body(request);
      if (!await passwordSet(env.DB)) return err("setup required", 409);
      const h = JSON.parse(await setting(env.DB, "password_hash"));
      if (!await verifyPassword(b.password || "", h)) return err("wrong password", 401);
      return json({ ok: true }, 200, { "set-cookie": sessionCookie(await makeSession(await sessionSecret(env))) });
    }
    if (path === "/api/logout" && m === "POST") return json({ ok: true }, 200, { "set-cookie": "session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax" });
    if (path === "/api/change-password" && m === "POST") {
      if (!alreadyAuth && !await isAdmin(request, env)) return err("not authenticated", 401);
      const b = await body(request), old = JSON.parse(await setting(env.DB, "password_hash"));
      if (!await verifyPassword(b.current || "", old) || !passwordPolicy(b.new)) return err("invalid current or new password");
      const h = await hashPassword(b.new);
      await env.DB.batch([env.DB.prepare("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)").bind("password_hash", JSON.stringify(h)), env.DB.prepare("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)").bind("password_salt", h.salt)]);
      return json({ ok: true });
    }
    if (!path.startsWith("/api/")) return json({ error: "not found" }, 404);
    if (!alreadyAuth && !await isAdmin(request, env)) return err("not authenticated", 401);
    if (path === "/api/users" && m === "GET") return json((await all(env.DB, "SELECT * FROM users ORDER BY id DESC")).map(publicUser));
    if (path === "/api/users" && m === "POST") {
      const b = await body(request);
      if (!isValidName(b.name)) return err("invalid name");
      if (!["ws", "xhttp", "both"].includes(b.transport || "both")) return err("invalid transport");
      const id = crypto.randomUUID(), sub = crypto.randomUUID().replaceAll("-", "");
      const r = await env.DB.prepare("INSERT INTO users(name,uuid,sub_token,note,enabled,quota_bytes,used_bytes,expire_at,device_limit,transport,obfuscate,created_at) VALUES(?,?,?,?,?,?,0,?,?,?,?,?)").bind(b.name.trim(), id, sub, String(b.note || "").slice(0, 200), b.enabled === false ? 0 : 1, nonNegative(b.quota_gb) * 1073741824, int(b.expire_days) > 0 ? now() + int(b.expire_days) * 86400 : 0, nonNegative(b.device_limit === void 0 ? 1 : b.device_limit), b.transport || "both", bool01(b.obfuscate), now()).run();
      return json(publicUser(await one(env.DB, "SELECT * FROM users WHERE id=?", r.meta.last_row_id)), 201);
    }
    let mm;
    if ((mm = path.match(/^\/api\/users\/(\d+)$/)) && m === "PATCH") {
      const id = +mm[1], b = await body(request), sets = [], v = [];
      if (b.name !== void 0) {
        if (!isValidName(b.name)) return err("invalid name");
        sets.push("name=?");
        v.push(b.name.trim());
      }
      if (b.uuid !== void 0) {
        if (!UUID_RE.test(String(b.uuid))) return err("invalid UUID");
        sets.push("uuid=?");
        v.push(b.uuid);
      }
      if (b.transport !== void 0) {
        if (!["ws", "xhttp", "both"].includes(b.transport)) return err("invalid transport");
        sets.push("transport=?");
        v.push(b.transport);
      }
      if (b.device_limit !== void 0) {
        if (int(b.device_limit, -1) < 0) return err("invalid device limit");
        sets.push("device_limit=?");
        v.push(int(b.device_limit));
      }
      for (const [k, col] of [["enabled", "enabled"], ["quota_gb", "quota_bytes"], ["obfuscate", "obfuscate"]]) if (b[k] !== void 0) {
        sets.push(`${col}=?`);
        v.push(k === "quota_gb" ? nonNegative(b[k]) * 1073741824 : bool01(b[k]));
      }
      if (b.note !== void 0) {
        sets.push("note=?");
        v.push(String(b.note).slice(0, 200));
      }
      if (b.expire_days !== void 0) {
        sets.push("expire_at=?");
        v.push(int(b.expire_days) > 0 ? now() + int(b.expire_days) * 86400 : 0);
      }
      if (sets.length) {
        sets.push("updated_at=?");
        v.push(now());
        try {
          await env.DB.prepare(`UPDATE users SET ${sets.join(",")} WHERE id=?`).bind(...v, id).run();
        } catch {
          return err("name or UUID already used", 409);
        }
      }
      return json(publicUser(await one(env.DB, "SELECT * FROM users WHERE id=?", id)));
    }
    if ((mm = path.match(/^\/api\/users\/(\d+)$/)) && m === "DELETE") {
      const id = +mm[1];
      await env.DB.batch([env.DB.prepare("DELETE FROM users WHERE id=?").bind(id), env.DB.prepare("DELETE FROM user_ips WHERE user_id=?").bind(id), env.DB.prepare("DELETE FROM traffic_log WHERE user_id=?").bind(id)]);
      return json({ ok: true });
    }
    if ((mm = path.match(/^\/api\/users\/(\d+)\/(new-uuid|new-sub-token|reset-traffic|clear-ips)$/)) && m === "POST") {
      const id = +mm[1], a = mm[2];
      if (a === "new-uuid") {
        const uuid = crypto.randomUUID();
        await env.DB.prepare("UPDATE users SET uuid=?,updated_at=? WHERE id=?").bind(uuid, now(), id).run();
        return json({ ok: true, uuid });
      }
      if (a === "new-sub-token") {
        const token = crypto.randomUUID().replaceAll("-", "");
        await env.DB.prepare("UPDATE users SET sub_token=?,updated_at=? WHERE id=?").bind(token, now(), id).run();
        return json({ ok: true, token });
      }
      await env.DB.prepare(a === "reset-traffic" ? "UPDATE users SET used_bytes=0,updated_at=? WHERE id=?" : "DELETE FROM user_ips WHERE user_id=?").bind(...a === "reset-traffic" ? [now(), id] : [id]).run();
      return json({ ok: true });
    }
    if ((mm = path.match(/^\/api\/users\/(\d+)\/ips$/)) && m === "GET") {
      const id = +mm[1], history = new URL(request.url).searchParams.has("history"), rows = await all(env.DB, "SELECT ip,proto,first_seen,last_seen,hits FROM user_ips WHERE user_id=? ORDER BY last_seen DESC LIMIT 200", id), liveWindow = int(env.LIVE_WINDOW, 60), deviceWindow = int(env.DEVICE_WINDOW, 300);
      return json({ rows, live: rows.filter((x) => x.last_seen > now() - liveWindow).length, live_window: liveWindow, counted: rows.filter((x) => x.last_seen > now() - deviceWindow).length, total_seen: rows.length, online: rows.some((x) => x.last_seen > now() - liveWindow) });
    }
    if ((mm = path.match(/^\/api\/users\/(\d+)\/config$/)) && m === "GET") {
      const id = +mm[1], u = await one(env.DB, "SELECT * FROM users WHERE id=?", id);
      if (!u) return err("not found", 404);
      const text = await subscriptionText(request, env, u);
      return json({ sub_link: `https://${await publicHost(request, env)}/sub/${u.sub_token}`, config: text, configs: text.split("\n").filter((x) => x.startsWith("vless://")).map((uri, i) => ({ label: uri.includes("/xh") ? "XHTTP" : "WebSocket", uri })) });
    }
    if (path === "/api/clean-ips" && m === "GET") return json((await all(env.DB, "SELECT * FROM clean_ips ORDER BY id DESC")).map((x) => ({ ...x, country: countryCode(x.country), flag: flagOf(x.country) })));
    if (path === "/api/clean-ips" && m === "POST") {
      const b = await body(request);
      if (!isValidAddress(b.address)) return err("invalid address");
      try {
        await env.DB.prepare("INSERT INTO clean_ips(address,remark,country,enabled,added_at) VALUES(?,?,?,1,?)").bind(b.address.trim(), String(b.remark || "").slice(0, 40), countryCode(b.country), now()).run();
      } catch {
        return err("already exists", 409);
      }
      return json({ ok: true }, 201);
    }
    if (path === "/api/clean-ips/bulk" && m === "POST") {
      const b = await body(request), raws = String(b.text || "").split(/[\n,;]+/).slice(0, 1e3);
      let added = 0, duplicates = 0, invalid = 0;
      for (const raw of raws) {
        const x = raw.split("#")[0].trim();
        if (!x) {
          invalid++;
          continue;
        }
        if (!isValidAddress(x)) {
          invalid++;
          continue;
        }
        try {
          await env.DB.prepare("INSERT INTO clean_ips(address,remark,country,enabled,added_at) VALUES(?,?,?,1,?)").bind(x, raw.split("#")[1]?.trim().slice(0, 40) || "", "", now()).run();
          added++;
        } catch {
          duplicates++;
        }
      }
      return json({ added, duplicates, invalid });
    }
    if (path === "/api/clean-ips" && m === "DELETE") {
      await env.DB.prepare("DELETE FROM clean_ips").run();
      return json({ ok: true });
    }
    if (path === "/api/main-country" && m === "GET") {
      const country = countryCode(await setting(env.DB, "main_country"));
      return json({ country, flag: flagOf(country) });
    }
    if (path === "/api/main-country" && m === "POST") {
      const country = countryCode((await body(request)).country);
      await putSetting(env.DB, "main_country", country);
      return json({ ok: true, country, flag: flagOf(country) });
    }
    if ((mm = path.match(/^\/api\/clean-ips\/(\d+)$/)) && ["PATCH", "DELETE"].includes(m)) {
      const id = +mm[1];
      if (m === "DELETE") await env.DB.prepare("DELETE FROM clean_ips WHERE id=?").bind(id).run();
      else await env.DB.prepare("UPDATE clean_ips SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?").bind(id).run();
      return json({ ok: true });
    }
    if (path === "/api/proxies" && m === "GET") {
      const rows = await all(env.DB, "SELECT * FROM proxies ORDER BY id DESC"), subIds = await all(env.DB, "SELECT id FROM proxies WHERE enabled=1 ORDER BY id"), act = await setting(env.DB, "active_proxy");
      return json({ proxies: rows.map(proxyOut), sub_ids: subIds.map((x) => x.id), active_id: int(act), strict: await setting(env.DB, "proxy_strict") === "1", flag_source: await setting(env.DB, "flag_source") || "proxy" });
    }
    if (path === "/api/proxies" && m === "POST") {
      const b = await body(request), p = proxyParse(`${String(b.kind || "socks5").toLowerCase().replace(/^socks5h$/, "socks5").replace(/^socks4a$/, "socks4").replace(/^https$/, "http")}://${String(b.username || "").trim()}${b.password ? `:${b.password}@` : ""}${String(b.host || "").trim().replace(/^\[|\]$/g, "")}:${int(b.port)}#${String(b.remark || "")}`);
      p.remark = String(b.remark || "").slice(0, 80);
      p.country = countryCode(b.country);
      try {
        const r = await env.DB.prepare("INSERT INTO proxies(kind,host,port,username,password,remark,country,enabled,added_at) VALUES(?,?,?,?,?,?,?,1,?)").bind(p.kind, p.host, p.port, p.username, p.password, p.remark, p.country, now()).run();
        return json(await proxyTest(env, r.meta.last_row_id), 201);
      } catch (e) {
        if (/UNIQUE/i.test(e.message)) return err("this proxy is already in the list", 409);
        throw e;
      }
    }
    if (path === "/api/proxies/bulk" && m === "POST") {
      const results = [];
      for (const line of String((await body(request)).text || "").split(/\n/).slice(0, 50)) {
        const shown = line.trim().slice(0, 60);
        if (!shown || shown.startsWith("#")) continue;
        try {
          const p = proxyParse(line), r = await env.DB.prepare("INSERT INTO proxies(kind,host,port,username,password,remark,country,enabled,added_at) VALUES(?,?,?,?,?,?,?,1,?)").bind(p.kind, p.host, p.port, p.username, p.password, p.remark, "", now()).run();
          results.push({ ...await proxyTest(env, r.meta.last_row_id), label: `${p.kind}://${p.host}:${p.port}` });
        } catch (e) {
          results.push({ ok: false, label: shown, error: e.message });
        }
      }
      return json({ results });
    }
    if (path === "/api/proxies/mode" && m === "POST") {
      const b = await body(request);
      if (b.strict !== void 0) await putSetting(env.DB, "proxy_strict", bool01(b.strict));
      if (b.flag_source !== void 0) await putSetting(env.DB, "flag_source", b.flag_source === "entry" ? "entry" : "proxy");
      return json({ ok: true, strict: await setting(env.DB, "proxy_strict") === "1", flag_source: await setting(env.DB, "flag_source") || "proxy" });
    }
    if (path === "/api/proxies/test-all" && m === "POST") {
      const rows = await all(env.DB, "SELECT id FROM proxies ORDER BY id");
      return json({ results: await Promise.all(rows.map((x) => proxyTest(env, x.id))) });
    }
    if ((mm = path.match(/^\/api\/proxies\/(\d+)\/test$/)) && m === "POST") return json(await proxyTest(env, +mm[1]));
    if ((mm = path.match(/^\/api\/proxies\/(\d+)\/activate$/)) && m === "POST") {
      const id = +mm[1];
      if (!id) {
        await putSetting(env.DB, "active_proxy", "");
        return json({ ok: true, active_id: 0 });
      }
      const px = await one(env.DB, "SELECT * FROM proxies WHERE id=?", id);
      if (!px) return err("proxy not found", 404);
      const r = await proxyTest(env, id);
      await putSetting(env.DB, "active_proxy", id);
      return json({ ok: true, active_id: id, ...r });
    }
    if ((mm = path.match(/^\/api\/proxies\/(\d+)$/)) && m === "PATCH") {
      const id = +mm[1], b = await body(request), sets = [], v = [];
      if (b.enabled !== void 0) {
        sets.push("enabled=?");
        v.push(bool01(b.enabled));
      }
      if (b.remark !== void 0) {
        sets.push("remark=?");
        v.push(String(b.remark).slice(0, 80));
      }
      if (b.country !== void 0) {
        sets.push("country=?");
        v.push(countryCode(b.country));
      }
      if (sets.length) await env.DB.prepare(`UPDATE proxies SET ${sets.join(",")} WHERE id=?`).bind(...v, id).run();
      if (b.enabled === false && int(await setting(env.DB, "active_proxy")) === id) await putSetting(env.DB, "active_proxy", "");
      return json({ ok: true });
    }
    if ((mm = path.match(/^\/api\/proxies\/(\d+)$/)) && m === "DELETE") {
      const id = +mm[1];
      await env.DB.prepare("DELETE FROM proxies WHERE id=?").bind(id).run();
      if (int(await setting(env.DB, "active_proxy")) === id) await putSetting(env.DB, "active_proxy", "");
      return json({ ok: true });
    }
    if (path === "/api/live" && m === "GET") {
      const rows = await all(env.DB, "SELECT u.name user,u.uuid,ip,proto,last_seen FROM user_ips ip LEFT JOIN users u ON u.id=ip.user_id WHERE ip.last_seen>? ORDER BY ip.last_seen DESC LIMIT 200", now() - int(env.LIVE_WINDOW, 60));
      return json({ count: rows.length, connections: rows.map((x) => ({ ...x, user: x.user || "", transport: x.proto || "ws", route: `/${x.proto === "xhttp" ? env.XHTTP_PATH || "xh" : env.WS_PATH || "ws"}`, mux: false, connected_for: Math.max(0, now() - x.last_seen) })) });
    }
    if (path === "/api/stats" && m === "GET") {
      const u = await one(env.DB, "SELECT COUNT(*) users,COALESCE(SUM(used_bytes),0) total_bytes,SUM(enabled) active_users FROM users"), dw = now() - int(env.DEVICE_WINDOW, 300), lw = now() - int(env.LIVE_WINDOW, 60), dev = await one(env.DB, "SELECT COUNT(*) n,COUNT(DISTINCT user_id) users FROM user_ips WHERE last_seen>?", dw), live = await one(env.DB, "SELECT COUNT(*) n,COUNT(DISTINCT user_id) users FROM user_ips WHERE last_seen>?", lw), c = await one(env.DB, "SELECT COUNT(*) n FROM clean_ips WHERE enabled=1"), series = await all(env.DB, "SELECT ts/3600*3600 h,SUM(up) up,SUM(down) down FROM traffic_log WHERE ts>? GROUP BY h ORDER BY h", now() - 86400);
      return json({ ...u, online_users: dev.users, online_devices: dev.n, live_users: live.users, live_devices: live.n, clean_ips: c.n, by_proto: {}, xhttp_sessions: 0, series, ws_path: env.WS_PATH || "ws", xhttp_path: env.XHTTP_PATH || "xh", device_window: int(env.DEVICE_WINDOW, 300), live_window: int(env.LIVE_WINDOW, 60), relay_domain: env.RELAY_DOMAIN || "" });
    }
    if (path === "/api/logs" && m === "GET") return json(await all(env.DB, "SELECT * FROM audit_log ORDER BY id DESC LIMIT 80"));
    if (path === "/api/backup/info" && m === "GET") {
      const u = await one(env.DB, "SELECT COUNT(*) n FROM users"), ci = await one(env.DB, "SELECT COUNT(*) n FROM clean_ips"), px = await one(env.DB, "SELECT COUNT(*) n FROM proxies"), tl = await one(env.DB, "SELECT COUNT(*) n FROM traffic_log");
      return json({ users: u.n, clean_ips: ci.n, proxies: px.n, traffic_rows: tl.n, format: "iranx-panel-backup", version: 3 });
    }
    if (path === "/api/backup" && m === "GET") {
      const q = new URL(request.url).searchParams, rows = await Promise.all([all(env.DB, "SELECT * FROM users ORDER BY id"), all(env.DB, "SELECT * FROM clean_ips ORDER BY id"), all(env.DB, "SELECT * FROM proxies ORDER BY id"), all(env.DB, "SELECT * FROM settings")]), settings = Object.fromEntries(rows[3].map((x) => [x.key, x.value]));
      if (!bool01(q.get("password"))) {
        for (const k of Object.keys(settings)) if (k.startsWith("password")) delete settings[k];
      }
      let proxies = rows[2].map((x) => ({ ...x, ...!bool01(q.get("proxy_creds")) ? { username: "", password: "" } : {} }));
      const payload = backupPayload({ created_at: now(), env: { DOMAIN: env.DOMAIN || "", RELAY_DOMAIN: env.RELAY_DOMAIN || "", WS_PATH: env.WS_PATH || "ws", XHTTP_PATH: env.XHTTP_PATH || "xh", PANEL_TITLE: env.PANEL_TITLE || "IranX Panel", DEVICE_WINDOW: env.DEVICE_WINDOW || "300", LIVE_WINDOW: env.LIVE_WINDOW || "60", SESSION_IDLE: env.SESSION_IDLE || "90" }, users: rows[0], clean_ips: rows[1], proxies, settings, traffic_log: bool01(q.get("traffic")) ? await all(env.DB, "SELECT user_id,ts,up,down FROM traffic_log ORDER BY id") : [] }), doc = { format: "iranx-panel-backup", version: 3, checksum: await checksum(payload), payload };
      return new Response(JSON.stringify(doc, null, 1), { headers: { "content-type": "application/json", "content-disposition": 'attachment; filename="iranx-panel.ixpbak"', "cache-control": "no-store" } });
    }
    if (path === "/api/restore/preview" && m === "POST") {
      const b = await body(request), p = await validateBackup(b.data, b.force), liveEnv = { DOMAIN: env.DOMAIN || "", RELAY_DOMAIN: env.RELAY_DOMAIN || "", WS_PATH: env.WS_PATH || "ws", XHTTP_PATH: env.XHTTP_PATH || "xh", PANEL_TITLE: env.PANEL_TITLE || "IranX Panel", DEVICE_WINDOW: env.DEVICE_WINDOW || "300", LIVE_WINDOW: env.LIVE_WINDOW || "60", SESSION_IDLE: env.SESSION_IDLE || "90" }, diff = {};
      for (const k of Object.keys(liveEnv)) if ((p.env || {})[k] !== void 0 && (p.env || {})[k] !== liveEnv[k]) diff[k] = { backup: p.env[k], current: liveEnv[k] };
      return json({ ok: true, created_at: p.created_at, users: p.users.length, clean_ips: p.clean_ips.length, proxies: p.proxies.length, proxies_with_creds: p.proxies.filter((x) => x.username).length, traffic_rows: p.traffic_log.length, has_password: Boolean(p.settings.password_hash), env: p.env || {}, env_diff: diff });
    }
    if (path === "/api/restore" && m === "POST") {
      const b = await body(request), p = await validateBackup(b.data, b.force), mode = String(b.mode || "merge").toLowerCase();
      if (!["merge", "replace"].includes(mode)) return err("mode must be merge or replace");
      const st = [];
      if (mode === "replace") st.push(env.DB.prepare("DELETE FROM users"), env.DB.prepare("DELETE FROM clean_ips"), env.DB.prepare("DELETE FROM proxies"), env.DB.prepare("DELETE FROM user_ips"), env.DB.prepare("DELETE FROM traffic_log"));
      for (const u of p.users) st.push(env.DB.prepare("INSERT INTO users(name,uuid,sub_token,note,enabled,quota_bytes,used_bytes,expire_at,device_limit,transport,obfuscate,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(uuid) DO UPDATE SET name=excluded.name,note=excluded.note,enabled=excluded.enabled,quota_bytes=excluded.quota_bytes,used_bytes=excluded.used_bytes,expire_at=excluded.expire_at,device_limit=excluded.device_limit,transport=excluded.transport,obfuscate=excluded.obfuscate").bind(u.name, u.uuid, u.sub_token || crypto.randomUUID().replaceAll("-", ""), u.note || "", int(u.enabled, 1), nonNegative(u.quota_bytes), nonNegative(u.used_bytes), nonNegative(u.expire_at), nonNegative(u.device_limit || 1), u.transport || "both", bool01(u.obfuscate), nonNegative(u.created_at || now())));
      for (const x of p.clean_ips) st.push(env.DB.prepare("INSERT INTO clean_ips(address,remark,country,enabled,added_at) VALUES(?,?,?,?,?) ON CONFLICT(address) DO UPDATE SET remark=excluded.remark,country=excluded.country,enabled=excluded.enabled").bind(x.address, String(x.remark || "").slice(0, 40), countryCode(x.country), int(x.enabled, 1), nonNegative(x.added_at || now())));
      for (const x of p.proxies) st.push(env.DB.prepare("INSERT INTO proxies(kind,host,port,username,password,remark,country,country_name,city,isp,exit_ip,healthy,latency_ms,last_error,checked_at,enabled,added_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(kind,host,port,username) DO UPDATE SET password=excluded.password,remark=excluded.remark,country=excluded.country,enabled=excluded.enabled").bind(x.kind, x.host, int(x.port), x.username || "", x.password || "", String(x.remark || "").slice(0, 80), countryCode(x.country), x.country_name || "", x.city || "", x.isp || "", x.exit_ip || "", bool01(x.healthy), nonNegative(x.latency_ms), x.last_error || "", nonNegative(x.checked_at), int(x.enabled, 1), nonNegative(x.added_at || now())));
      for (const [k, v] of Object.entries(p.settings || {})) if (b.restore_password || !k.startsWith("password")) st.push(env.DB.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(k, String(v)));
      for (const x of p.traffic_log) st.push(env.DB.prepare("INSERT INTO traffic_log(user_id,ts,up,down) VALUES(?,?,?,?)").bind(int(x.user_id), nonNegative(x.ts), nonNegative(x.up), nonNegative(x.down)));
      if (st.length) await env.DB.batch(st.slice(0, 100));
      return json({ ok: true, users_added: p.users.length, users_updated: p.users.length, clean_ips_added: p.clean_ips.length, proxies_added: p.proxies.length, proxies_updated: p.proxies.length, password_restored: Boolean(b.restore_password && p.settings.password_hash) });
    }
    return json({ error: "not found" }, 404);
  } catch (e) {
    if (alreadyAuth || !String(e.message).includes("invalid body")) console.error("api_error", e);
    return json({ error: alreadyAuth ? "internal error" : e.message }, alreadyAuth ? 500 : 400);
  }
}
__name(handleApi, "handleApi");
async function handleRequest(request, env, ctx) {
  const url = new URL(request.url), p = url.pathname;
  if (p === "/healthz" && request.method === "GET") return json({ ok: true, platform: "cloudflare" });
  if (p === "/setup" || p === "/login") return new Response(loginHtml(env.PANEL_TITLE || "IranX Panel", p.slice(1)), { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
  if (p === "/" && request.method === "GET") {
    const setup = !await passwordSet(env.DB) && !env.ADMIN_PASSWORD;
    if (setup) return Response.redirect(new URL("/setup", url), 302);
    return Response.redirect(new URL(await isAdmin(request, env) ? "/panel" : "/login", url), 302);
  }
  const sub = p.match(/^\/sub\/([A-Za-z0-9_-]{8,64})$/);
  if (sub && request.method === "GET") {
    const u = await one(env.DB, "SELECT * FROM users WHERE sub_token=?", sub[1]);
    if (!u) return new Response("not found", { status: 404 });
    const text = await subscriptionText(request, env, u), ua = request.headers.get("user-agent") || "";
    if (ua.includes("Mozilla") || url.searchParams.has("page")) return new Response(subscriptionHtml(u, text), { headers: { "content-type": "text/html; charset=utf-8" } });
    return new Response(Buffer.from(text).toString("base64"), { headers: { "content-type": "text/plain; charset=utf-8", "content-disposition": "profile-update-interval=12", "profile-title": `base64:${Buffer.from(u.name).toString("base64")}`, "subscription-userinfo": `upload=0; download=${u.used_bytes}; total=${u.quota_bytes}; expire=${u.expire_at}` } });
  }
  if (request.headers.get("upgrade")?.toLowerCase() === "websocket" && request.method === "GET") {
    const base = env.WS_PATH || "ws", plain = p.slice(1), direct = plain === `${base}-d`, pm = plain.match(new RegExp(`^${base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}-p([1-9]\\d{0,8})$`));
    if (plain !== base && !direct && !pm) return new Response("Not found", { status: 404 });
    const route = { direct, pid: pm ? +pm[1] : 0 }, pair = new WebSocketPair();
    handleVlessWebSocket({ server: pair.server, client: pair.client }, env, clientIp(request), connect, route).catch((e) => {
      try {
        pair.server.close(1011, e.message);
      } catch {
      }
    });
    return new Response(null, { status: 101, webSocket: pair.client });
  }
  if (p.startsWith("/api/")) return handleApi(request, env);
  if (p === "/panel" && request.method === "GET") {
    if (!await isAdmin(request, env)) return Response.redirect(new URL("/login", url), 302);
    return new Response(panelHtml(env.PANEL_TITLE || "IranX Panel"), { headers: { "content-type": "text/html; charset=utf-8" } });
  }
  return new Response("Not found", { status: 404 });
}
__name(handleRequest, "handleRequest");
var index_default = { async fetch(request, env, ctx) {
  try {
    return await handleRequest(request, env, ctx);
  } catch (e) {
    console.error("request_error", e);
    return new Response("internal error", { status: 500 });
  }
} };
export {
  index_default as default,
  handleApi,
  handleRequest
};
