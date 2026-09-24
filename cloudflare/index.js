var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __esm = (fn, res, err2) => function __init() {
  if (err2) throw err2[0];
  try {
    return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
  } catch (e) {
    throw err2 = [e], e;
  }
};
var __export = (target, all2) => {
  for (var name in all2)
    __defProp(target, name, { get: all2[name], enumerable: true });
};

// src/ui.js
var ui_exports = {};
__export(ui_exports, {
  loginHtml: () => loginHtml,
  panelHtml: () => panelHtml,
  subscriptionHtml: () => subscriptionHtml
});
function loginHtml(title, mode) {
  return shell(title, `<div class="card"><h2>${mode === "setup" ? "\u062A\u0639\u06CC\u06CC\u0646 \u0631\u0645\u0632 \u0639\u0628\u0648\u0631" : "\u0648\u0631\u0648\u062F \u0628\u0647 \u067E\u0646\u0644"}</h2><form id="f"><input id="p" type="password" placeholder="\u0631\u0645\u0632 \u0639\u0628\u0648\u0631" required>${mode === "setup" ? '<input id="c" type="password" placeholder="\u062A\u06A9\u0631\u0627\u0631 \u0631\u0645\u0632" required>' : ""}<button>\u0627\u062F\u0627\u0645\u0647</button></form><p id="m" class="bad"></p></div>`, `f.onsubmit=async e=>{e.preventDefault();m.textContent='';let r=await fetch('/api/${mode}',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:p.value,confirm:c?.value||p.value})});let j=await r.json();if(!r.ok)return m.textContent=j.error;location='/panel'}`);
}
function panelHtml(title) {
  return shell(title, `<nav><button onclick="loadUsers()">\u06A9\u0627\u0631\u0628\u0631\u0627\u0646</button><button onclick="loadIps()">IP \u062A\u0645\u06CC\u0632</button><button onclick="loadStats()">\u0622\u0645\u0627\u0631</button><button onclick="backup()">\u067E\u0634\u062A\u06CC\u0628\u0627\u0646</button><button onclick="logout()">\u062E\u0631\u0648\u062C</button></nav><div id="app"></div>`, `async function api(p,o={}){let r=await fetch(p,{headers:{'content-type':'application/json'},...o}),j=await r.json();if(!r.ok)throw Error(j.error);return j}
async function loadUsers(){let a=await api('/api/users');app.innerHTML='<div class=card><h2>\u06A9\u0627\u0631\u0628\u0631\u0627\u0646</h2><form onsubmit="return addUser(event)"><input id=n placeholder="\u0646\u0627\u0645" required><input id=q type=number placeholder="\u062D\u062C\u0645 GB" value=0><input id=d type=number placeholder="\u0631\u0648\u0632" value=0><button>\u0627\u0641\u0632\u0648\u062F\u0646</button></form></div>'+a.map(u=>'<div class=card><b>'+esc(u.name)+'</b> \xB7 '+esc(u.status)+'<br><span class=muted>'+esc(u.uuid)+'</span><br><button onclick="delUser('+u.id+')">\u062D\u0630\u0641</button></div>').join('')}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}async function addUser(e){e.preventDefault();try{await api('/api/users',{method:'POST',body:JSON.stringify({name:n.value,quota_gb:+q.value,expire_days:+d.value,device_limit:1,transport:'both'})});loadUsers()}catch(x){alert(x.message)}}async function delUser(id){if(confirm('\u062D\u0630\u0641 \u0634\u0648\u062F\u061F')){await api('/api/users/'+id,{method:'DELETE'});loadUsers()}}
async function loadIps(){let a=await api('/api/clean-ips');app.innerHTML='<div class=card><h2>IP \u062A\u0645\u06CC\u0632</h2><textarea id=t rows=5 style="width:95%"></textarea><button onclick="addIps()">\u0627\u0641\u0632\u0648\u062F\u0646</button></div>'+a.map(x=>'<div class=card>'+esc(x.address)+' <button onclick="toggleIp('+x.id+')">'+(x.enabled?'\u0641\u0639\u0627\u0644':'\u063A\u06CC\u0631\u0641\u0639\u0627\u0644')+'</button></div>').join('')}async function addIps(){await api('/api/clean-ips/bulk',{method:'POST',body:JSON.stringify({text:t.value})});loadIps()}async function toggleIp(id){await api('/api/clean-ips/'+id,{method:'PATCH'});loadIps()}
async function loadStats(){app.innerHTML='<div class=card><h2>\u0622\u0645\u0627\u0631</h2><pre>'+esc(JSON.stringify(await api('/api/stats'),null,2))+'</pre></div>'}async function backup(){location='/api/backup'}async function logout(){await api('/api/logout',{method:'POST'});location='/login'}loadUsers();`);
}
function subscriptionHtml(user, text) {
  return shell("\u0627\u0634\u062A\u0631\u0627\u06A9 " + user.name, `<div class="card"><h2>${esc(user.name)}</h2><p class="muted">\u062D\u062C\u0645: ${(user.used_bytes / 1073741824).toFixed(2)} GB</p><textarea style="width:95%;height:300px">${esc(text)}</textarea></div>`);
}
var shell, esc;
var init_ui = __esm({
  "src/ui.js"() {
    shell = /* @__PURE__ */ __name((title, body2, script = "") => `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${esc(title)}</title><style>body{margin:0;background:#080b12;color:#eef4ff;font:15px system-ui}.box{max-width:1000px;margin:30px auto;padding:20px}.card{background:#101725;border:1px solid #26344d;border-radius:14px;padding:18px;margin:12px 0}input,select,button{padding:10px;border-radius:9px;border:1px solid #34445f;background:#080d16;color:#fff;margin:4px}button{background:#2563eb;cursor:pointer}table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #26344d;text-align:right}.ok{color:#4ade80}.bad{color:#fb7185}.muted{color:#91a4c3}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:8px}nav{display:flex;gap:8px;flex-wrap:wrap}a{color:#60a5fa}</style></head><body><div class="box"><h1>${esc(title)}</h1>${body2}</div><script>${script}<\/script></body></html>`, "shell");
    esc = /* @__PURE__ */ __name((s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]), "esc");
    __name(loginHtml, "loginHtml");
    __name(panelHtml, "panelHtml");
    __name(subscriptionHtml, "subscriptionHtml");
  }
});

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
function vlessLink({ user, host, type, path, ip }) {
  const address = ip || host;
  const q = new URLSearchParams({ encryption: "none", security: "tls", sni: host, type, host, path });
  return `vless://${user.uuid}@${address}:443?${q}#${encodeURIComponent(`IranX ${user.name} ${type.toUpperCase()}`)}`;
}
__name(vlessLink, "vlessLink");
async function buildSubscription({ user, host, cleanIps = [], wsPath = "ws", xhttpPath = "xh" }) {
  const [ok] = userStatus(user);
  if (!ok) return "";
  const info = `\u{1F4CA} ${user.name} | ${(user.used_bytes / 1073741824).toFixed(2)}GB used`;
  const links = [];
  if (["ws", "both"].includes(user.transport)) {
    links.push(vlessLink({ user, host, type: "ws", path: `/${wsPath}` }));
    for (const row of cleanIps.filter((x) => x.enabled)) links.push(vlessLink({ user, host, type: "ws", path: `/${wsPath}`, ip: row.address }));
  }
  if (["xhttp", "both"].includes(user.transport)) {
    const session = crypto.randomUUID().replaceAll("-", "").slice(0, 16);
    links.push(vlessLink({ user, host, type: "xhttp", path: `/${xhttpPath}/${session}` }));
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
function isBlockedHost(host) {
  const h = String(host || "").toLowerCase().replace(/\.$/, "");
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal") || h === "::1" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80:")) return true;
  const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const a = m.slice(1).map(Number);
  return a[0] === 127 || a[0] === 10 || a[0] === 0 || a[0] === 169 && a[1] === 254 || a[0] === 172 && a[1] >= 16 && a[1] <= 31 || a[0] === 192 && a[1] === 168;
}
__name(isBlockedHost, "isBlockedHost");

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
async function pipeVlessWebSocket(pair, env, clientIp2, connect2) {
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
  const sock = connect2({ hostname: request.host, port: request.port }, { secureTransport: "off", allowHalfOpen: true });
  await sock.opened;
  const writer = sock.writable.getWriter(), socketReader = sock.readable.getReader();
  let up = request.payload.length, down = 0;
  if (request.payload.length) await writer.write(request.payload);
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
    env.DB.prepare("INSERT INTO user_ips(user_id,ip,proto,first_seen,last_seen,hits) VALUES(?,?,?,?,?,1) ON CONFLICT(user_id,ip) DO UPDATE SET last_seen=excluded.last_seen,hits=user_ips.hits+1").bind(row.id, clientIp2, "ws", Date.now(), Date.now()),
    env.DB.prepare("INSERT INTO traffic_log(user_id,ts,up,down) VALUES(?,?,?,?)").bind(row.id, Date.now(), up, down)
  ]).catch(() => {
  });
}
__name(pipeVlessWebSocket, "pipeVlessWebSocket");

// src/vless-worker.js
var handleVlessWebSocket = pipeVlessWebSocket;

// src/index.js
init_ui();
var json = /* @__PURE__ */ __name((x, status = 200, extra = {}) => Response.json(x, { status, headers: { "cache-control": "no-store", ...extra } }), "json");
var err = /* @__PURE__ */ __name((e, status = 400) => json({ error: String(e?.message || e) }, status), "err");
var now = /* @__PURE__ */ __name(() => Math.floor(Date.now() / 1e3), "now");
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
async function subscriptionText(request, env, user) {
  return buildSubscription({ user, host: await publicHost(request, env), cleanIps: await all(env.DB, "SELECT * FROM clean_ips WHERE enabled=1"), wsPath: env.WS_PATH || "ws", xhttpPath: env.XHTTP_PATH || "xh" });
}
__name(subscriptionText, "subscriptionText");
async function body(request) {
  const b = await request.json();
  if (!b || typeof b !== "object" || Array.isArray(b)) throw new Error("invalid body");
  return b;
}
__name(body, "body");
async function handleApi(request, env, alreadyAuth = false) {
  const path = new URL(request.url).pathname, m = request.method;
  try {
    if (path === "/api/state" && m === "GET") return json({ needs_setup: !await passwordSet(env.DB) && !env.ADMIN_PASSWORD, logged_in: await isAdmin(request, env) });
    if (path === "/api/setup" && m === "POST") {
      if (await passwordSet(env.DB)) return err("password already set", 409);
      const b = await body(request);
      const initial = String(env.ADMIN_PASSWORD || "");
      if (!initial && (b.password !== b.confirm || !passwordPolicy(b.password))) return err("passwords must match and meet password policy");
      if (initial && !passwordPolicy(initial)) return err("ADMIN_PASSWORD does not meet password policy");
      const password = initial || b.password;
      const h = await hashPassword(password);
      const sessionKey = env.SECRET_KEY || randomSecret();
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
      const r = await env.DB.prepare("INSERT INTO users(name,uuid,sub_token,note,enabled,quota_bytes,used_bytes,expire_at,device_limit,transport,created_at) VALUES(?,?,?,?,?,?,0,?,?,?,?)").bind(b.name.trim(), id, sub, String(b.note || "").slice(0, 200), b.enabled === false ? 0 : 1, Math.max(0, Number(b.quota_gb || 0) * 1073741824), Number(b.expire_days || 0) > 0 ? now() + Number(b.expire_days) * 86400 : 0, Math.max(0, Number(b.device_limit || 1)), b.transport || "both", now()).run();
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
      if (b.uuid !== void 0 && !UUID_RE.test(String(b.uuid))) return err("invalid UUID");
      if (b.transport !== void 0 && !["ws", "xhttp", "both"].includes(b.transport)) return err("invalid transport");
      if (b.device_limit !== void 0 && (!Number.isInteger(Number(b.device_limit)) || Number(b.device_limit) < 0)) return err("invalid device limit");
      for (const [k, col] of [["enabled", "enabled"], ["quota_gb", "quota_bytes"], ["device_limit", "device_limit"], ["transport", "transport"], ["note", "note"], ["uuid", "uuid"]]) if (b[k] !== void 0) {
        sets.push(`${col}=?`);
        v.push(k === "quota_gb" ? Math.max(0, Number(b[k]) * 1073741824) : b[k]);
      }
      if (sets.length) {
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
        await env.DB.prepare("UPDATE users SET uuid=? WHERE id=?").bind(uuid, id).run();
        return json({ ok: true, uuid });
      }
      if (a === "new-sub-token") {
        const token = crypto.randomUUID().replaceAll("-", "");
        await env.DB.prepare("UPDATE users SET sub_token=? WHERE id=?").bind(token, id).run();
        return json({ ok: true, token });
      }
      const q = a === "reset-traffic" ? "UPDATE users SET used_bytes=0 WHERE id=?" : "DELETE FROM user_ips WHERE user_id=?";
      await env.DB.prepare(q).bind(id).run();
      return json({ ok: true });
    }
    if ((mm = path.match(/^\/api\/users\/(\d+)\/ips$/)) && m === "GET") {
      const id = +mm[1], rows = await all(env.DB, "SELECT ip,proto,first_seen,last_seen,hits FROM user_ips WHERE user_id=? ORDER BY last_seen DESC LIMIT 200", id);
      return json({ rows, live: rows.filter((x) => x.last_seen > Date.now() - 6e4).length });
    }
    if ((mm = path.match(/^\/api\/users\/(\d+)\/config$/)) && m === "GET") {
      const id = +mm[1], u = await one(env.DB, "SELECT * FROM users WHERE id=?", id);
      if (!u) return err("not found", 404);
      const text = await subscriptionText(request, env, u);
      return json({ sub_link: `https://${await publicHost(request, env)}/sub/${u.sub_token}`, config: text });
    }
    if (path === "/api/clean-ips" && m === "GET") return json(await all(env.DB, "SELECT * FROM clean_ips ORDER BY id DESC"));
    if (path === "/api/clean-ips" && m === "POST") {
      const b = await body(request);
      if (!isValidAddress(b.address)) return err("invalid address");
      try {
        await env.DB.prepare("INSERT INTO clean_ips(address,remark,country,enabled,added_at) VALUES(?,?,?,1,?)").bind(b.address.trim(), String(b.remark || "").slice(0, 40), String(b.country || "").slice(0, 2), now()).run();
      } catch {
        return err("already exists", 409);
      }
      return json({ ok: true }, 201);
    }
    if (path === "/api/clean-ips/bulk" && m === "POST") {
      const b = await body(request), raws = String(b.text || "").split(/[\n,;]+/).slice(0, 1e3);
      let added = 0;
      for (const raw of raws) {
        const x = raw.split("#")[0].trim();
        if (!isValidAddress(x)) continue;
        try {
          await env.DB.prepare("INSERT INTO clean_ips(address,remark,enabled,added_at) VALUES(?,?,1,?)").bind(x, raw.split("#")[1]?.trim().slice(0, 40) || "", now()).run();
          added++;
        } catch {
        }
      }
      return json({ added });
    }
    if ((mm = path.match(/^\/api\/clean-ips\/(\d+)$/)) && ["PATCH", "DELETE"].includes(m)) {
      if (m === "DELETE") await env.DB.prepare("DELETE FROM clean_ips WHERE id=?").bind(+mm[1]).run();
      else await env.DB.prepare("UPDATE clean_ips SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?").bind(+mm[1]).run();
      return json({ ok: true });
    }
    if (path === "/api/stats" && m === "GET") {
      const u = await one(env.DB, "SELECT COUNT(*) users,COALESCE(SUM(used_bytes),0) total_bytes,SUM(enabled) active_users FROM users"), d = await one(env.DB, "SELECT COUNT(*) n FROM user_ips WHERE last_seen>?", Date.now() - Number(env.DEVICE_WINDOW || 300) * 1e3), c = await one(env.DB, "SELECT COUNT(*) n FROM clean_ips WHERE enabled=1");
      return json({ ...u, online_devices: d.n, clean_ips: c.n });
    }
    if (path === "/api/logs" && m === "GET") return json(await all(env.DB, "SELECT * FROM audit_log ORDER BY id DESC LIMIT 80"));
    if (path === "/api/backup" && m === "GET") {
      const doc = { format: "iranx-panel-backup", version: 4, payload: { users: await all(env.DB, "SELECT * FROM users"), clean_ips: await all(env.DB, "SELECT * FROM clean_ips"), settings: await all(env.DB, "SELECT * FROM settings"), created_at: now() } };
      return new Response(JSON.stringify(doc), { headers: { "content-type": "application/json", "content-disposition": 'attachment; filename="iranx-backup.ixpbak"', "cache-control": "no-store" } });
    }
    if (path === "/api/restore/preview" && m === "POST") {
      const b = await body(request), p = b?.data?.payload || b?.data;
      if (b?.data?.format !== "iranx-panel-backup" || !p || !Array.isArray(p.users) || !Array.isArray(p.clean_ips) || p.users.length > 1e4 || p.clean_ips.length > 1e4) return err("invalid backup");
      return json({ users: p.users.length, clean_ips: p.clean_ips.length });
    }
    if (path === "/api/restore" && m === "POST") {
      const b = await body(request), p = b?.data?.payload;
      if (b?.data?.format !== "iranx-panel-backup" || !p || !Array.isArray(p.users) || !Array.isArray(p.clean_ips) || p.users.length > 1e4 || p.clean_ips.length > 1e4) return err("invalid backup");
      if (p.users.some((u) => !isValidName(u.name) || !UUID_RE.test(String(u.uuid)) || !["ws", "xhttp", "both"].includes(u.transport || "both")) || p.clean_ips.some((x) => !isValidAddress(x.address))) return err("invalid backup rows");
      const st = [];
      if (b.mode === "replace") {
        st.push(env.DB.prepare("DELETE FROM users"), env.DB.prepare("DELETE FROM clean_ips"));
      }
      for (const u of p.users || []) st.push(env.DB.prepare("INSERT OR REPLACE INTO users(name,uuid,sub_token,note,enabled,quota_bytes,used_bytes,expire_at,device_limit,transport,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)").bind(u.name, u.uuid, u.sub_token, u.note || "", u.enabled ?? 1, nonNegative(u.quota_bytes), nonNegative(u.used_bytes), nonNegative(u.expire_at), nonNegative(u.device_limit || 1), u.transport || "both", nonNegative(u.created_at || now())));
      for (const x of p.clean_ips || []) st.push(env.DB.prepare("INSERT OR REPLACE INTO clean_ips(address,remark,country,enabled,added_at) VALUES(?,?,?,?,?)").bind(x.address, x.remark || "", x.country || "", x.enabled ?? 1, nonNegative(x.added_at || now())));
      await env.DB.batch(st);
      return json({ ok: true });
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
    const auth = await isAdmin(request, env);
    return Response.redirect(new URL(auth ? "/panel" : "/login", url), 302);
  }
  const sub = p.match(/^\/sub\/([A-Za-z0-9_-]{8,64})$/);
  if (sub && request.method === "GET") {
    const u = await one(env.DB, "SELECT * FROM users WHERE sub_token=?", sub[1]);
    if (!u) return new Response("not found", { status: 404 });
    const text = await subscriptionText(request, env, u);
    const ua = request.headers.get("user-agent") || "";
    if (ua.includes("Mozilla") || url.searchParams.has("page")) return new Response((await Promise.resolve().then(() => (init_ui(), ui_exports))).subscriptionHtml(u, text), { headers: { "content-type": "text/html; charset=utf-8" } });
    const body2 = Buffer.from(text).toString("base64");
    return new Response(body2, { headers: { "content-type": "text/plain; charset=utf-8", "content-disposition": "profile-update-interval=12", "profile-title": `base64:${Buffer.from(u.name).toString("base64")}`, "subscription-userinfo": `upload=0; download=${u.used_bytes}; total=${u.quota_bytes}; expire=${u.expire_at}` } });
  }
  if (request.headers.get("upgrade")?.toLowerCase() === "websocket" && request.method === "GET") {
    const urlPath = new URL(request.url).pathname;
    if (urlPath !== `/${env.WS_PATH || "ws"}`) return new Response("Not found", { status: 404 });
    const pair = new WebSocketPair();
    handleVlessWebSocket({ server: pair.server, client: pair.client }, env, clientIp(request), connect).catch((e) => {
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
//# sourceMappingURL=index.js.map
