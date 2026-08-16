"""
frag_addon.py — IranX Panel
مبهم‌سازی کانفیگ‌های ساب برای میزبان‌هایی که دامنه/رله‌شان فیلتر است.

نصب: این فایل را کنار main.py بگذار و پنج خط انتهای main.py را اضافه کن.

متغیرهای محیطی:
    FRAG_MODE   off | auto | on   (پیش‌فرض auto)
    FRAG_STYLE  extra | only      (پیش‌فرض extra — کانفیگ عادی هم می‌ماند)
    FRAG_FP     پیش‌فرض unsafe
    FRAG_IP     آی‌پی تمیز کلادفلر (خالی = همان دامنه/رله)
    FRAG_MARK   نشان کانفیگ مبهم (پیش‌فرض ⚡)
    FRAG_CS     بازنویسی لیست سایفرها
    FRAG_FM     بازنویسی JSON فاینال‌ماسک
"""

import json
import os
from urllib.parse import quote, parse_qsl

__all__ = ["install", "optimize", "apply", "wanted"]


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


MODE = _env("FRAG_MODE", "auto").lower()      # off | auto | on
STYLE = _env("FRAG_STYLE", "extra").lower()   # extra | only
FP = _env("FRAG_FP", "unsafe")
CDN_IP = _env("FRAG_IP", "")
MARK = os.getenv("FRAG_MARK", "\u26a1")

CS_DEFAULT = ":".join([
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
])
CS = _env("FRAG_CS") or CS_DEFAULT

# شکل رسمی FinalMask در Xray: هر ماسک = {"type": "fragment", "settings": {...}}
# شکل تخت قدیمی ({"fragment": ...}) باعث می‌شد کانفیگ دیده شود ولی اتصال رد شود.
FM_DEFAULT = {
    "tcp": [
        {"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["5", "94", "1"], "delays": ["0"], "maxSplit": "0"}},
        {"type": "fragment", "settings": {"packets": "1-1", "lengths": ["109", "1"], "delays": ["1"], "maxSplit": "355"}},
    ]
}


def _mask(entry):
    """یک ماسک را به شکل رسمی type/settings تبدیل می‌کند."""
    if not isinstance(entry, dict):
        return entry
    if "type" in entry or "settings" in entry:
        return entry
    e = dict(entry)
    packets = e.pop("fragment", None) or e.pop("packets", None) or "tlshello"
    return {"type": "fragment", "settings": {"packets": packets, **e}}


def _norm_fm(fm):
    """شکل قدیمی یا دستیِ FRAG_FM را هم نرمال می‌کند."""
    if not isinstance(fm, dict):
        return FM_DEFAULT
    out = {}
    for k in ("tcp", "udp"):
        if isinstance(fm.get(k), list):
            out[k] = [_mask(x) for x in fm[k]]
    if isinstance(fm.get("quicParams"), dict):
        out["quicParams"] = fm["quicParams"]
    return out or FM_DEFAULT


try:
    _fm_env = _env("FRAG_FM")
    FM = json.dumps(_norm_fm(json.loads(_fm_env) if _fm_env else FM_DEFAULT),
                    separators=(",", ":"), ensure_ascii=False)
except Exception:
    FM = json.dumps(FM_DEFAULT, separators=(",", ":"), ensure_ascii=False)

# ترتیب ثابت پارامترها، معادل خروجی cf-optimizor؛ کلیدهای ناشناس آخر می‌مانند.
PARAM_ORDER = ["cs", "path", "security", "alpn", "encryption", "fm", "insecure",
               "host", "fp", "type", "allowInsecure", "sni", "mode"]

# mux با fragment جمع نمی‌شود، پس در کانفیگ مبهم حذف می‌شود.
DROP_KEYS = ("mux",)

NAME_KEYS = ("name", "label", "remark", "title", "tag")
URI_KEYS = ("uri", "link", "url", "config", "vless", "value")


def wanted(host: str = "", relay: str = "") -> bool:
    """فقط جایی که لازم است روشن می‌شود."""
    if MODE == "on":
        return True
    if MODE == "off":
        return False
    if relay:
        return True
    h = (host or "").lower()
    if "onrender.com" in h or "workers.dev" in h:
        return True
    if os.getenv("RENDER") or os.getenv("RENDER_SERVICE_ID"):
        return True
    return False


def _split_hostport(hostport: str):
    """جدا کردن هاست و پورت، با پشتیبانی IPv6 مانند [::1]:443."""
    if hostport.startswith("["):
        end = hostport.find("]")
        if end != -1:
            return hostport[:end + 1], hostport[end + 1:]
    if ":" in hostport:
        h, _, p = hostport.rpartition(":")
        return h, ":" + p
    return hostport, ""


def optimize(uri: str, cdn_ip: str = "") -> str:
    """یک لینک vless را مبهم می‌کند و بقیه اجزا را دست‌نخورده نگه می‌دارد."""
    if not isinstance(uri, str) or not uri.startswith("vless://"):
        return uri
    head, sep, frag = uri.partition("#")
    rest = head[len("vless://"):]
    userinfo, at, hostpart = rest.partition("@")
    if not at:
        return uri
    hostport, _, query = hostpart.partition("?")
    host, port = _split_hostport(hostport)

    ip = (cdn_ip or CDN_IP).strip()
    if ip:
        host = "[" + ip + "]" if (":" in ip and not ip.startswith("[")) else ip

    merged, order = {}, []
    for k, v in parse_qsl(query, keep_blank_values=True):
        if k in DROP_KEYS:
            continue
        if k not in merged:
            order.append(k)
        merged[k] = v
    # مقادیر موجود جای‌گزین می‌شوند، نه تکراری اضافه شود.
    for k, v in (("fp", FP), ("cs", CS), ("fm", FM)):
        if k not in merged:
            order.append(k)
        merged[k] = v

    keys = [k for k in PARAM_ORDER if k in merged]
    keys += [k for k in order if k not in PARAM_ORDER]
    query_out = "&".join(quote(k, safe="") + "=" + quote(merged[k], safe="") for k in keys)
    out = "vless://" + userinfo + "@" + host + port + "?" + query_out
    return out + (("#" + frag) if sep else "")


def _uri_key(item: dict):
    """کلیدی که متن کانفیگ درونش است."""
    for k in URI_KEYS:
        v = item.get(k)
        if isinstance(v, str) and v.startswith("vless://"):
            return k
    for k, v in item.items():
        if isinstance(v, str) and v.startswith("vless://"):
            return k
    return None


def _rename(uri: str, name: str) -> str:
    """نشان ⚡ را به انتهای نام کانفیگ می‌چسباند."""
    if not MARK:
        return uri
    base, sep, tail = uri.partition("#")
    label = (name or "").strip()
    if not label and sep:
        return base + "#" + tail + "%20" + quote(MARK)
    if not label:
        return uri
    return base + "#" + quote((label + " " + MARK).strip())


def apply(configs, host: str = "", want=None, relay: str = ""):
    """کانفیگ مبهم را کنار کانفیگ عادی می‌گذارد (extra) یا جایش می‌نشاند (only)."""
    if want is None:
        want = wanted(host, relay)
    if not want or not configs:
        return configs

    out = []
    for c in configs:
        if isinstance(c, str):
            if not c.startswith("vless://") or "security=none" in c:
                out.append(c)
                continue
            opt = optimize(c)
            if STYLE == "only":
                out.append(opt)
            else:
                out.append(c)
                out.append(opt)
            continue

        if not isinstance(c, dict):
            out.append(c)
            continue

        key = _uri_key(c)
        uri = c.get(key) if key else ""
        # کانفیگ اطلاعاتی بالای لیست (security=none) دست‌نخورده می‌ماند
        if not key or "security=none" in uri:
            out.append(c)
            continue

        name = ""
        for nk in NAME_KEYS:
            if isinstance(c.get(nk), str) and c[nk]:
                name = c[nk]
                break

        opt_item = dict(c)
        opt_item[key] = _rename(optimize(uri), name)
        if name and MARK:
            for nk in NAME_KEYS:
                if isinstance(opt_item.get(nk), str) and opt_item[nk] == name:
                    opt_item[nk] = (name + " " + MARK).strip()

        if STYLE == "only":
            out.append(opt_item)
        else:
            out.append(c)
            out.append(opt_item)
    return out


def install(mod):
    """build_configs پنل را با نسخه مبهم‌ساز جایگزین می‌کند."""
    plain = getattr(mod, "build_configs", None)
    if plain is None:
        print("frag: build_configs not found, add-on disabled")
        return None
    if getattr(plain, "_frag", False):
        return plain

    def relay():
        return getattr(mod, "RELAY_DOMAIN", "") or ""

    def build_configs(*args, **kwargs):
        host = kwargs.get("host", args[1] if len(args) > 1 else "")
        return apply(plain(*args, **kwargs), host, None, relay())

    build_configs._frag = True
    build_configs.__name__ = "build_configs"
    build_configs.__doc__ = plain.__doc__

    mod.build_configs = build_configs
    mod.optimize_vless = optimize
    mod.frag_apply = apply
    mod.frag_wanted = lambda host="": wanted(host, relay())
    mod.FRAG_MODE, mod.FRAG_STYLE = MODE, STYLE
    mod.FRAG_FP, mod.FRAG_IP = FP, CDN_IP

    print("frag: installed (mode=%s style=%s fp=%s cdn_ip=%s)"
          % (MODE, STYLE, FP, CDN_IP or "-"))
    return build_configs