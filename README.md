# Single-file web panel

A self-contained FastAPI application that runs on any ASGI host: one Python file,
pinned dependencies, no database server, no Docker image, no certificates.

It ships with a **decoy cover site**: out of the box the application answers every
public path with a small random website (a few kilobytes, no scripts, no fonts, no
third-party requests) instead of its own UI. The real interface sits behind a secret
path, so a visitor — or an automated scanner — sees an ordinary small site.

```bash
pip install -r requirements.txt
gunicorn -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:$PORT --timeout 0
```

---

## The cover site

| | |
|---|---|
| `COVER_MODE` | `1` (default) serves the cover on public paths, `0` turns it off |
| `COVER_KEY` | the secret path segment that lifts the cover (default: derived from `SECRET_KEY`) |
| `COVER_REVEAL` | seconds after boot at which the cover lifts by itself (`0` = only the key lifts it) |
| `COVER_BRAND` | pin the cover site name |
| `COVER_SEED` | pin the random seed — the same seed always yields the same site |

The unlock path is printed once at start-up:

```
[cover] public paths answer with a random site (Vela Supply). Panel unlock path: /5eadb001f2b7
```

Opening `/<COVER_KEY>` sets a long-lived cookie and the application answers normally
from then on. While the cover is up the following keep working, because clients need
them: the proxy inbounds, the subscription links, the flag SVGs and `/healthz`.
Everything under `/api/` answers `404` until the cover is lifted.

**Two-stage deployment.** `cover_site.py` writes the same kind of site as plain files,
so the host can run the lightweight site first and the application second, on the same
domain:

```bash
python cover_site.py --out ./site        # index/about/services/contact + icon + robots.txt
python cover_site.py --out ./site --serve 8080
```

---

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SECRET_KEY` | random | signs the session cookie — **set it**, it is also the seed of the cover key |
| `DOMAIN` | – | public host name, no scheme |
| `WS_PATH` | `ws` | path of the first inbound |
| `XHTTP_PATH` | `xh` | path of the second inbound (must differ) |
| `XHTTP_MODE` | `stream-up` | uplink shape advertised in generated links |
| `RELAY_DOMAIN` | – | host of a relay in front; every generated link points there |
| `RELAY_LOW_COST` | `1` with a relay | new accounts start on the cheap transport |
| `ADMIN_PASSWORD` | – | pre-seeds the password and skips the setup page |
| `DB_PATH` | `/tmp/panel.db` | SQLite file — point it at a volume to keep it |
| `DEVICE_WINDOW` | `300` | seconds an IP counts as an active device |
| `SESSION_IDLE` | `90` | seconds before a detached session is dropped |
| `PANEL_TITLE` | `Panel` | title shown in the UI |
| `KEEPALIVE` | `0` | ping the public URL so an idle host does not sleep the service |
| `KEEPALIVE_MINUTES` | `10` | ping interval |
| `COVER_*` | see above | the decoy cover site |

`panel-config.toml` holds the same list with comments.

---

## Relay cost

A relay in front of the application is billed **per request**, and the transports do
not cost the same:

| Route | Requests per connection |
|---|---|
| `ws` | **1** — one request for the whole life of the tunnel |
| `xhttp` (`stream-up`) | 2 — a streamed `GET` down, one long-lived `POST` up |
| `xhttp` (`packet-up`) | 1 + one per uploaded chunk — hundreds a minute per client |

So, to spend as little as possible:

* keep `XHTTP_MODE=stream-up` (the default);
* with a relay configured, new accounts default to `ws` — one request each. Set
  `RELAY_LOW_COST=0` to turn that off;
* never use `packet-up` behind a metered relay; the server accepts it either way, so
  links already handed out keep working.

---

## Storage

The database is SQLite. Point `DB_PATH` at a mounted volume (`/data/panel.db`) or it
is wiped on every redeploy. New columns are added automatically, so upgrading in place
is safe.

## Backup and restore

*Panel → Settings → Backup* writes one JSON file with every account, its identifier
and subscription token, the address list, the password hash and the environment the
application was running under. Restore takes it back, either merged into the current
data or as a replacement. Identifiers are preserved, so configurations already
installed on clients keep working after a migration.

## License

MIT
