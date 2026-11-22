#!/usr/bin/env python3
"""Generate a small, random, self-contained website.

Useful as the first stage of a deployment: put this lightweight static site on the
host first — it is a few kilobytes, has no scripts, no fonts and no third-party
requests, so nothing about it points at what runs behind it — and swap the real
application in afterwards, on the same domain.

    python cover_site.py --out ./site            # write the files
    python cover_site.py --out ./site --serve 8080   # write them and serve locally
    python cover_site.py --brand "Acme Studio"   # pin the name

Every run picks a new name, palette and set of pages unless --seed is given.
"""

import argparse
import hashlib
import os
import random
import sys

A = ["Lumen", "North", "Cedar", "Atlas", "Kite", "Verde", "Solace", "Harbor",
     "Ember", "Quill", "Aster", "Nimbus", "Onyx", "Willow", "Copper", "Fable",
     "Beacon", "Cobalt", "Marlow", "Rowan", "Sable", "Terra", "Vela", "Wren"]
B = ["Atelier", "Studio", "Works", "Collective", "Labs", "Design", "Supply",
     "Press", "Roasters", "Gallery", "Type Foundry", "Craft", "House"]
TAGS = ["Small things, made carefully", "Slow work for everyday use",
        "A workshop, not a factory", "Objects with a long life",
        "Quiet design, honest materials", "Made to order, shipped weekly"]
CITIES = ["Lisbon", "Porto", "Tbilisi", "Istanbul", "Athens", "Tallinn",
          "Ljubljana", "Brno", "Bergen", "Taipei", "Melbourne", "Trieste",
          "Valencia", "Cape Town", "Kyoto", "Utrecht"]
STREETS = ["Rua do Norte", "Kastanienallee", "Rue Basse", "Södergatan",
           "Kerkstraat", "Via Roma", "Molenweg", "Harju mnt"]
SERVICES = [
    ("Brand identity", "Naming, marks and a type system that survives contact with the real world."),
    ("Web design", "Small, fast pages that finish loading before the visitor changes their mind."),
    ("Print & packaging", "Posters, cards and boxes, printed locally and delivered flat."),
    ("Ceramics", "Wheel-thrown pieces fired in small batches; every one is a little different."),
    ("Coffee & tea", "Single-origin beans, ground to order, dispatched every Tuesday."),
    ("Repairs", "Fixing what you already own before replacing it. Diagnostics on the house."),
    ("Photography", "Editorial and product work, on film and digital."),
    ("Consulting", "Two-hour sessions that end with a written plan instead of a slide deck."),
]
ABOUT = [
    "We started in a rented room with a single workbench and have stayed small on purpose. "
    "Everything that leaves the shop passes through the same pair of hands.",
    "The work is slow and the queue is short. We take on a limited number of projects each "
    "season, so nothing leaves half-finished.",
    "Much of what we make comes back for a second visit, which tells us more than any review.",
]

CSS = """
:root{--bg:#fbfaf8;--fg:#1b1b1f;--dim:#6b6b74;--line:#e6e3dd;--card:#fff;--acc:%s;--acc2:%s}
@media (prefers-color-scheme:dark){:root{--bg:#121316;--fg:#ececed;--dim:#9a9aa4;--line:#26262b;--card:#181a1e;--acc:%s;--acc2:%s}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:960px;margin:0 auto;padding:0 22px}
header{border-bottom:1px solid var(--line);background:var(--card);position:sticky;top:0;z-index:5}
header .wrap{display:flex;align-items:center;gap:20px;height:62px}
.brand{display:flex;align-items:center;gap:10px;font-weight:650;letter-spacing:-.01em;margin-right:auto}
.mark{width:28px;height:28px;border-radius:8px;background:var(--acc);color:#fff;display:grid;place-items:center;font-size:13px;font-weight:700}
nav a{color:var(--dim);text-decoration:none;font-size:14.5px;margin-left:18px}
nav a:hover{color:var(--fg)}
h1{font-size:clamp(30px,5vw,46px);line-height:1.12;letter-spacing:-.02em;margin:0 0 16px}
h2{font-size:22px;letter-spacing:-.01em;margin:52px 0 14px}
p{color:var(--dim);margin:0 0 16px}
.hero{padding:78px 0 26px}
.hero p{max-width:56ch}
.btn{display:inline-block;margin-top:12px;padding:11px 20px;border-radius:10px;background:var(--acc);color:#fff;text-decoration:none;font-size:15px;font-weight:550}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;margin-top:8px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px}
.card h3{margin:0 0 6px;font-size:16px}
.card p{margin:0;font-size:14.5px}
.list{list-style:none;padding:0;margin:0}
.list li{display:flex;gap:12px;padding:11px 0;border-bottom:1px solid var(--line);font-size:15px}
.list li span{color:var(--dim);min-width:96px;font-size:13.5px}
footer{border-top:1px solid var(--line);margin-top:64px;padding:24px 0;color:var(--dim);font-size:13.5px}
.kicker{color:var(--acc2);font-size:13px;letter-spacing:.09em;text-transform:uppercase;font-weight:600}
@media (max-width:640px){nav a{margin-left:12px;font-size:13.5px}.hero{padding:52px 0 18px}}
"""


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def build(seed=None, brand=None):
    if seed is None:
        seed = os.urandom(8).hex()
    rnd = random.Random(int(hashlib.sha256(str(seed).encode()).hexdigest()[:16], 16))
    name = brand or ("%s %s" % (rnd.choice(A), rnd.choice(B)))
    city = rnd.choice(CITIES)
    hue = rnd.randint(0, 359)
    hue2 = (hue + rnd.randint(120, 220)) % 360
    acc, acc2 = "hsl(%d 58%% 42%%)" % hue, "hsl(%d 62%% 46%%)" % hue2
    css = CSS % (acc, acc2, acc, acc2)
    tag = rnd.choice(TAGS)
    about = " ".join(rnd.sample(ABOUT, 2))
    svc = rnd.sample(SERVICES, rnd.randint(3, 5))
    domain = rnd.choice(A).lower() + rnd.choice([".com", ".studio", ".co", ".works"])
    mail = rnd.choice(A).lower() + "@" + domain
    phone = "+%d %03d %04d %04d" % (rnd.randint(20, 99), rnd.randint(100, 999),
                                    rnd.randint(1000, 9999), rnd.randint(1000, 9999))
    street = "%d %s" % (rnd.randint(1, 180), rnd.choice(STREETS))
    hours = "%s – %s" % (rnd.choice(["09:00", "10:00", "08:30"]),
                         rnd.choice(["17:30", "18:00", "19:00", "16:00"]))
    initial = name.strip()[0].upper()
    pages = [("Home", "index.html"), ("About", "about.html"),
             ("Services", "services.html"), ("Contact", "contact.html")]
    keep = rnd.sample(pages, rnd.randint(3, 4))
    keep.sort(key=lambda p: pages.index(p))

    def head(title):
        links = "".join('<a href="%s">%s</a>' % (h, t) for t, h in keep)
        return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                '<title>%s — %s</title><link rel="icon" href="favicon.svg" type="image/svg+xml">'
                '<meta name="description" content="%s."><style>%s</style></head><body>'
                '<header><div class="wrap"><div class="brand"><div class="mark">%s</div>%s</div>'
                '<nav>%s</nav></div></header><main class="wrap">'
                % (esc(title), esc(name), esc(tag), css, esc(initial), esc(name), links))

    def foot():
        return ('</main><footer><div class="wrap">%s — %s · %s</div></footer></body></html>'
                % (esc(name), esc(city), esc(str(rnd.randint(2014, 2026)))))

    def cards():
        return '<div class="grid">%s</div>' % "".join(
            '<div class="card"><h3>%s</h3><p>%s</p></div>' % (esc(n), esc(d)) for n, d in svc)

    html = {
        "index.html": (head(tag) +
                       '<section class="hero"><div class="kicker">%s</div><h1>%s</h1>'
                       '<p>%s</p><a class="btn" href="contact.html">Get in touch</a></section>'
                       '<h2>What we do</h2>%s%s' % (esc(city), esc(tag), esc(about), cards(), foot())),
        "about.html": (head("About") +
                       '<section class="hero"><div class="kicker">About</div><h1>%s</h1>'
                       '<p>%s</p><p>%s</p></section><h2>Studio</h2><ul class="list">'
                       '<li><span>Based in</span>%s</li><li><span>Working since</span>%d</li>'
                       '<li><span>Team</span>Two people and a very patient cat</li>'
                       '<li><span>Languages</span>English, and enough of the local one</li></ul>%s'
                       % (esc(name), esc(about), esc(rnd.choice(ABOUT)), esc(city),
                          rnd.randint(2014, 2022), foot())),
        "services.html": (head("Services") +
                          '<section class="hero"><div class="kicker">Services</div><h1>%s</h1>'
                          '<p>%s</p></section>%s<h2>How it works</h2><ul class="list">'
                          '<li><span>Step one</span>A short conversation about what you need</li>'
                          '<li><span>Step two</span>A written proposal with fixed prices</li>'
                          '<li><span>Step three</span>The work, with photos at every stage</li>'
                          '</ul>%s' % (esc(tag), esc(rnd.choice(ABOUT)), cards(), foot())),
        "contact.html": (head("Contact") +
                         '<section class="hero"><div class="kicker">Contact</div><h1>Say hello</h1>'
                         '<p>%s</p></section><ul class="list"><li><span>Email</span>%s</li>'
                         '<li><span>Phone</span>%s</li><li><span>Studio</span>%s, %s</li>'
                         '<li><span>Hours</span>%s, Monday to Friday</li></ul>%s'
                         % (esc(rnd.choice(ABOUT)), esc(mail), esc(phone), esc(street),
                            esc(city), esc(hours), foot())),
    }
    icon = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
            '<rect width="64" height="64" rx="16" fill="%s"/>'
            '<text x="32" y="43" font-family="system-ui,sans-serif" font-size="30" '
            'font-weight="700" fill="#fff" text-anchor="middle">%s</text></svg>' % (acc, initial))
    files = {k: v for k, v in html.items()}
    files["favicon.svg"] = icon
    files["robots.txt"] = "User-agent: *\nAllow: /\n"
    return name, files


def main():
    ap = argparse.ArgumentParser(description="Generate a small random static website.")
    ap.add_argument("--out", default="./site", help="output directory (default ./site)")
    ap.add_argument("--brand", default="", help="pin the site name")
    ap.add_argument("--seed", default=None, help="same seed → same site")
    ap.add_argument("--serve", type=int, default=0, metavar="PORT",
                    help="also serve the generated files on PORT")
    args = ap.parse_args()

    name, files = build(args.seed, args.brand or None)
    os.makedirs(args.out, exist_ok=True)
    for fn, body in files.items():
        path = os.path.join(args.out, fn)
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)
        print("wrote %s (%d bytes)" % (path, len(body)))
    print("\nsite: %s — %d files, %d bytes total" % (
        name, len(files), sum(len(v) for v in files.values())))

    if args.serve:
        import functools
        import http.server
        import socketserver
        handler = functools.partial(http.server.SimpleHTTPRequestHandler,
                                    directory=os.path.abspath(args.out))
        with socketserver.TCPServer(("", args.serve), handler) as httpd:
            print("serving on http://127.0.0.1:%d — Ctrl-C to stop" % args.serve)
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
