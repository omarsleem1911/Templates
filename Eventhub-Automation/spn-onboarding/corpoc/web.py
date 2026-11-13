"""A tiny local web server and the shared page pieces (stands in for the cor. Hub UI)."""

import html
import os
import re
import pathlib
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

esc = html.escape

STATIC = pathlib.Path(__file__).resolve().parent / "static"

CSS = """
:root{--bg:#eef0f4;--card:#fff;--ink:#1d2330;--muted:#5d6675;--line:#dde1e7;--accent:#3b3fd8;--accent2:#7c3aed;
--nav:#151a33;--brand:#f5a524;--ok:#12805c;--warn:#a35c00;--bad:#b42318;--okbg:#e3f5ec;--warnbg:#fff2dc;--badbg:#fdecea;
--soft:#f6f7fb}
@media (prefers-color-scheme:dark){:root{--bg:#0f1220;--card:#181c2b;--ink:#e6e9ee;--muted:#9aa3b2;--line:#2a3042;
--accent:#8b8ff7;--accent2:#b18cff;--nav:#0b0e1a;--ok:#5fd08b;--warn:#f0b35a;--bad:#ff8a80;--okbg:#16301f;--warnbg:#33270f;
--badbg:#3a1d1b;--soft:#1f2436}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 "Segoe UI",system-ui,sans-serif}
a{color:var(--accent)}
.topbar{background:var(--nav);color:#fff;display:flex;align-items:center;gap:28px;padding:0 28px;height:58px}
.topbar .logo{display:flex;align-items:center;height:58px}.topbar .logo img,.topbar .logo svg{height:36px}
.topbar nav{display:flex;gap:6px;height:100%}.topbar nav a{color:#aab0c4;text-decoration:none;font-size:14px;display:flex;
align-items:center;padding:0 12px;border-bottom:3px solid transparent}.topbar nav a.on{color:#fff;border-bottom-color:var(--brand)}
.topbar .tag{margin-left:auto;color:#aab0c4;font-size:13px}
.shell{max-width:1180px;margin:0 auto;padding:26px 20px 40px}
.pagehead{font-size:21px;margin:0 0 12px;font-weight:600}
.progress{height:7px;background:var(--line);border-radius:6px 6px 0 0;overflow:hidden}
.progress span{display:block;height:100%;background:linear-gradient(90deg,var(--accent2),var(--accent));border-radius:6px}
.panel{background:var(--card);border-radius:0 0 10px 10px;padding:40px 44px;box-shadow:0 1px 3px rgba(20,25,50,.08)}
.panel.plain{border-radius:10px}
.split{display:grid;grid-template-columns:minmax(240px,1fr) 2fr;gap:44px}
@media (max-width:860px){.split{grid-template-columns:1fr}.panel{padding:24px 18px}}
.eyebrow{color:var(--accent);font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;margin:0 0 6px}
h1{font-size:27px;margin:0 0 16px;line-height:1.25}h2{font-size:17px;margin:22px 0 8px}
.lead{color:var(--muted)}.lead b{color:var(--ink)}
.stepcard,.permcard{display:flex;gap:18px;align-items:flex-start;border:1px solid var(--line);border-radius:8px;
padding:20px 22px;margin:0 0 14px;background:var(--card)}
.stepcard .txt,.permcard .txt{flex:1}.stepcard h3,.permcard h3{margin:2px 0 4px;font-size:17px;font-weight:600}
.stepcard p,.permcard p{margin:0;color:var(--muted)}
.ill{width:92px;height:70px;flex:none;color:var(--accent)}
.ico{width:44px;height:44px;flex:none;color:var(--accent2)}
.badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 7px;border-radius:3px;vertical-align:2px;margin-left:8px}
.badge.ro{background:#16a36b;color:#fff}.badge.rw{background:#d97706;color:#fff}.badge.info{background:var(--soft);color:var(--muted)}
details summary{cursor:pointer;color:var(--accent);margin-top:10px;font-size:14px;list-style:none}
details summary::-webkit-details-marker{display:none}
details ul{margin:8px 0 0;padding-left:18px;color:var(--muted);font-size:13.5px}details code{font-size:12.5px}
.actions{display:flex;justify-content:space-between;align-items:center;margin-top:30px;gap:12px;flex-wrap:wrap}
.actions .right{margin-left:auto}
.btn{display:inline-flex;align-items:center;gap:10px;background:var(--accent);color:#fff;border:0;border-radius:4px;
padding:11px 26px;font:inherit;font-size:14px;font-weight:600;text-decoration:none;cursor:pointer}
.btn.secondary{background:var(--card);color:var(--ink);border:1px solid var(--line)}.btn.danger{background:#c62828}
.btn.ms{background:#2f2f2f}.btn svg{width:18px;height:18px}
.pick{display:block;border:1px solid var(--line);border-radius:8px;padding:14px 16px 14px 46px;position:relative;cursor:pointer;
margin:0;background:var(--card)}.pick input{position:absolute;left:16px;top:17px;width:17px;height:17px;accent-color:var(--accent)}
.pick b{display:block;font-weight:600}.pick span{color:var(--muted);font-size:13.5px}
.pick:has(input:checked){border-color:var(--accent);background:var(--soft)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px}
.field{display:block;margin:0 0 18px}.field>span{display:block;font-weight:600;margin-bottom:6px}
.note{background:var(--soft);border-left:3px solid var(--accent);padding:12px 16px;border-radius:4px;margin:0 0 18px;font-size:14px}
.note.warn{border-left-color:var(--warn)}
.kv{font-size:14px;margin:0}.kv dt{color:var(--muted);font-size:12.5px;margin-top:10px}.kv dd{margin:2px 0 0}.kv code{word-break:normal;white-space:nowrap}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px 18px;margin:12px 0}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:9px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}code{font-size:13px;background:var(--soft);padding:1px 5px;border-radius:4px;word-break:break-all}
.muted{color:var(--muted)}.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:700}
.OK{background:var(--okbg);color:var(--ok)}.PARTIAL,.PENDING,.NOT{background:var(--warnbg);color:var(--warn)}
.FAIL,.MISSING,.ERROR{background:var(--badbg);color:var(--bad)}
.steps{padding-left:22px}.steps li{margin:6px 0}.steps .ok::marker{content:"✔  ";color:var(--ok)}
.steps .warn::marker{content:"!  ";color:var(--warn)}.steps .fail::marker{content:"✖  ";color:var(--bad)}
label{display:block;margin:6px 0}
input[type=text],input[type=number]{font:inherit;padding:9px 11px;border:1px solid var(--line);border-radius:4px;
background:var(--card);color:var(--ink);width:100%;max-width:380px}
.footer{color:var(--muted);font-size:12.5px;text-align:center;margin-top:22px}
"""

# The text wordmark, used until an official logo is dropped in corpoc/static/.
WORDMARK = ("<svg viewBox='0 0 76 44' xmlns='http://www.w3.org/2000/svg' role='img' aria-label='cor.'>"
            "<text x='0' y='34' font-family='Segoe UI,Arial,sans-serif' font-size='40' font-weight='300' "
            "letter-spacing='1' fill='#f5a524'>cor</text><circle cx='67' cy='31' r='4.6' fill='#f5a524'/></svg>")


def logo_html():
    """The official logo if corpoc/static/cor-logo.svg (or cor-logo-header.png) exists, else the wordmark."""
    import base64
    for name, mime in (("cor-logo.svg", "image/svg+xml"), ("cor-logo-header.png", "image/png")):
        f = STATIC / name
        if f.exists():
            data = base64.b64encode(f.read_bytes()).decode()
            return f"<img src='data:{mime};base64,{data}' alt='cor.'>"
    return WORDMARK


class Redirect:
    def __init__(self, url):
        self.url = url


class Raw:
    """A non-HTML response (e.g. the ARM template the Azure portal downloads)."""

    def __init__(self, body, content_type="application/json", headers=None, status=200):
        self.body = body.encode() if isinstance(body, str) else body
        self.content_type = content_type
        self.headers = headers or {}
        self.status = status


# The Azure portal downloads the template from the admin's browser: allow it
# cross-origin and, for a localhost Hub, from a public page (Private Network Access).
CORS = {"Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Private-Network": "true"}

SECTIONS = {
    "m365": ("Connect Microsoft 365", "cor. · the SPN is created in, and owned by, your tenant"),
    "eventhub": ("Connect Event Hub", "cor. · the Event Hub and storage are deployed in, and owned by, your subscription"),
}


def page(title, body, product="PoC", step=None, plain=None, section="m365"):
    """A cor. Hub page. step (0-100) draws the wizard progress bar; plain pages keep the
    old single-column layout with the title as a heading."""
    plain = step is None if plain is None else plain
    bar = "" if step is None else f"<div class='progress'><span style='width:{int(step)}%'></span></div>"
    inner = f"<h1>{esc(title)}</h1>{body}" if plain else body
    head, footer = SECTIONS[section]
    nav = f"<a class='on' href='/'>{esc(head)}</a>"
    return (f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{esc(title)} · cor.</title><style>{CSS}</style></head><body>"
            f"<div class='topbar'><a class='logo' href='/'>{logo_html()}</a><nav>"
            f"{nav}<a href='/#connections'>Connections</a></nav>"
            f"<span class='tag'>{esc(product)}</span></div>"
            f"<div class='shell'><div class='pagehead'>{esc(head)}</div>{bar}"
            f"<div class='panel{'' if bar else ' plain'}'>{inner}</div>"
            f"<div class='footer'>{esc(footer)}</div></div></body></html>")


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def serve(port, get_routes, post_routes=None, product="PoC"):
    class Handler(BaseHTTPRequestHandler):
        def _dispatch(self, routes, params):
            url = urllib.parse.urlparse(self.path)
            handler = routes.get(url.path)
            if handler is None:
                return self._send(404, page("Not found", "<p>Not found.</p>", product))
            query = {}
            for k, v in urllib.parse.parse_qs(url.query).items():
                query[k] = v if len(v) > 1 else v[0]
            query.update(params)
            try:
                result = handler(query)
            except Exception:
                result = (500, page("Error", f"<pre>{esc(traceback.format_exc())}</pre>", product))
            if isinstance(result, Raw):
                return self._send(result.status, result.body, result.content_type, result.headers)
            if isinstance(result, Redirect):
                self.send_response(302)
                self.send_header("Location", result.url)
                self.end_headers()
                return
            status, body = result if isinstance(result, tuple) else (200, result)
            self._send(status, body)

        def do_GET(self):
            self._dispatch(get_routes, {})

        def do_OPTIONS(self):
            self.send_response(204)
            for k, v in CORS.items():
                self.send_header(k, v)
            self.send_header("Access-Control-Max-Age", "600")
            self.end_headers()

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
            form = {k: v if len(v) > 1 else v[0] for k, v in urllib.parse.parse_qs(raw).items()}
            self._dispatch(post_routes or {}, form)

        def _send(self, status, body, content_type="text/html; charset=utf-8", headers=None):
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt, *args):
            # Drop query strings: they can carry sign-in codes and state.
            print("  " + re.sub(r"\?\S*", "", fmt % args))

    class Server(ThreadingHTTPServer):
        # On Windows SO_REUSEADDR lets a second process bind the same port and steal
        # requests: refuse instead, so two Hubs on one port fail loudly.
        allow_reuse_address = os.name != "nt"

    try:
        server = Server(("localhost", port), Handler)
    except OSError as exc:
        raise SystemExit(f"Port {port} is already in use ({exc}). Stop the other Hub first.")
    print(f"{product}: http://localhost:{port}/  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def mask(secret):
    return f"•••••••• {secret[-4:]}" if secret else "—"


def verification_html(rows, api_notes, values, recheck_url):
    """The required-permissions check, as the Hub would show it."""
    ok = sum(1 for r in rows if r["status"] == "OK")
    waiting = any("few minutes" in r["detail"] or r["status"] == "PARTIAL" for r in rows)
    summary = ("All capabilities are ready." if ok == len(rows)
               else f"{ok} of {len(rows)} capabilities ready."
               + (" Permissions can take a few minutes to apply: re-check shortly." if waiting else ""))
    trs = []
    for r in rows:
        status_cls = r["status"].split()[0]
        missing = ("<div class='muted'>Missing: " + esc(", ".join(r["missing"])) + "</div>") if r["missing"] and r["granted"] else ""
        trs.append(f"<tr><td>{esc(r['title'])}</td><td><span class='pill {status_cls}'>{esc(r['status'])}</span></td>"
                   f"<td>{r['granted']}/{r['total']}</td><td>{esc(r['detail'])}{missing}</td></tr>")
    notes = "".join(f"<li><b>{esc(a)}</b>: {n['granted']} permission(s) in the token"
                    f"{(' — ' + esc(n['note'])) if n['note'] else ''}</li>" for a, n in api_notes.items())
    vals = "".join(f"<tr><th>{esc(k)}</th><td><code>{esc(v)}</code></td></tr>" for k, v in values.items())
    return (f"<div class='card'><b>{esc(summary)}</b>"
            f"<table><tr><th>Capability</th><th>Status</th><th>Permissions</th><th>Detail</th></tr>{''.join(trs)}</table>"
            f"<p><a class='btn secondary' href='{esc(recheck_url)}'>Re-check</a></p></div>"
            f"<h2>Tokens per API</h2><div class='card'><ul>{notes}</ul></div>"
            f"<h2>What the Hub stores for the connectors</h2><div class='card'><table>{vals}</table>"
            f"<p class='muted'>The connectors receive these as today (Tenant ID, Client ID, Client Secret): no connector changes.</p></div>")
