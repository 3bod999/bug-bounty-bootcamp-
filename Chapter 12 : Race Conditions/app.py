"""
Race Condition CTF Training Lab
================================
A deliberately vulnerable Flask application for practicing the race
condition techniques from Bug Bounty Bootcamp Chapter 12 and the
PortSwigger Web Security Academy "Race conditions" material.

RUN LOCALLY ONLY. Every endpoint here is intentionally built WITHOUT the
synchronization a real app needs (no locks, no atomic transactions, and
an artificial delay added between "check" and "use" to widen the race
window so you can reliably exploit it with ordinary concurrent requests
instead of needing exotic single-packet timing).

Start with:
    pip install flask
    python app.py
Then open http://127.0.0.1:5000/

Fire concurrent requests with the included race_client.py helper, or with
plain curl using '&' to background requests (see README.md).
"""

import os
import time
import random
import threading
import secrets
from flask import (
    Flask, request, render_template_string, redirect,
    url_for, session, flash, jsonify
)

app = Flask(__name__)
app.secret_key = os.urandom(16)

FLAGS = {
    1: "flag{l1m1t_0v3rrun_d1sc0unt_r4c3}",
    2: "flag{b4nk_tr4nsf3r_0v3rdr4ft}",
    3: "flag{v0t3_tw1c3_t0ct0u}",
    4: "flag{p4rt1al_c0nstruct10n_empty_k3y}",
    5: "flag{s1ngl3_3ndp01nt_t0k3n_c0ll1s10n}",
    6: "flag{byp4ss_s3ss10n_l0ck_n3w_c00k13}",
}

RACE_DELAY = 1.0  # artificial delay between "check" and "use", in seconds

# ----------------------------------------------------------------------
# In-memory state for each level (reset via each level's /reset route)
# ----------------------------------------------------------------------

state_lock_free = {}  # per-level dicts, intentionally NOT behind a lock


def reset_level1():
    state_lock_free["l1_used"] = False
    state_lock_free["l1_count"] = 0


def reset_level2():
    state_lock_free["l2_balance"] = 500
    state_lock_free["l2_withdrawn_total"] = 0


def reset_level3():
    state_lock_free["l3_voted"] = False
    state_lock_free["l3_votes"] = 0


def reset_level4():
    state_lock_free["l4_users"] = {}  # username -> {"api_key": None/str}


LEVEL5_SESSIONS = {}  # server-side session store: sid -> {"reset_user":.., "reset_token":..}


def reset_level5():
    state_lock_free["l5_tokens_sent"] = {}     # username -> token
    state_lock_free["l5_token_owner"] = {}     # token -> username it was generated for
    state_lock_free["l5_passwords"] = {"victim": "victim-original-pw", "attacker": "attacker-pw"}
    LEVEL5_SESSIONS.clear()


SESSION_LOCKS = {}
GIFT_STATE = {"used": False, "count": 0}


def reset_level6():
    GIFT_STATE["used"] = False
    GIFT_STATE["count"] = 0
    SESSION_LOCKS.clear()


reset_level1()
reset_level2()
reset_level3()
reset_level4()
reset_level5()
reset_level6()


# ----------------------------------------------------------------------
# Shared layout
# ----------------------------------------------------------------------

BASE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Race Condition CTF Lab</title>
<style>
  body { font-family: -apple-system, Segoe UI, Arial, sans-serif; max-width: 880px;
         margin: 32px auto; padding: 0 16px; background: #0f1115; color: #e7e9ee; }
  a { color: #7fb3ff; }
  nav { margin-bottom: 24px; }
  nav a { margin-right: 14px; }
  .card { background: #1a1d24; border: 1px solid #2a2e38; border-radius: 10px;
          padding: 18px 20px; margin-bottom: 18px; }
  .hint { background: #13202a; border-left: 3px solid #3aa0ff; padding: 10px 14px;
          font-size: 0.92em; margin: 12px 0; border-radius: 4px; }
  input[type=text], input[type=password], input[type=number] {
    background: #0f1115; border: 1px solid #3a3f4a; color: #e7e9ee;
    padding: 7px 10px; border-radius: 6px; width: 260px; font-family: monospace;
  }
  button { background: #3aa0ff; border: none; color: #04101c; font-weight: 600;
           padding: 8px 16px; border-radius: 6px; cursor: pointer; margin-right: 6px; }
  button:hover { background: #5cb3ff; }
  button.secondary { background: #2a2e38; color: #e7e9ee; }
  pre { background: #0b0d11; padding: 12px; border-radius: 6px; overflow-x: auto;
        white-space: pre-wrap; word-break: break-word; }
  .ok { color: #45d483; font-weight: 600; }
  .err { color: #ff6b6b; }
  .flag-box { margin-top: 14px; display: flex; gap: 8px; }
  .solved-badge { background: #123d26; color: #45d483; padding: 2px 10px;
                  border-radius: 999px; font-size: 0.8em; margin-left: 8px; }
  code { background: #0b0d11; padding: 1px 5px; border-radius: 4px; }
</style>
</head>
<body>
<nav>
  <a href="{{ url_for('index') }}">Home</a>
  {% for i in range(1,7) %}
    <a href="{{ url_for('level' ~ i) }}">Level {{ i }}{% if i in session.get('solved', []) %} ✓{% endif %}</a>
  {% endfor %}
</nav>
{% with messages = get_flashed_messages(with_categories=true) %}
  {% for cat, msg in messages %}
    <div class="card {{ 'ok' if cat=='ok' else 'err' }}">{{ msg }}</div>
  {% endfor %}
{% endwith %}
{{ body|safe }}
</body>
</html>
"""


def render(body_html, **ctx):
    from flask import render_template_string as rts
    body = rts(body_html, **ctx)
    return rts(BASE, body=body)


def flag_form(level):
    solved = level in session.get("solved", [])
    badge = '<span class="solved-badge">SOLVED</span>' if solved else ""
    return f"""
    <div class="card">
      <form class="flag-box" method="post" action="{url_for('submit_flag')}">
        <input type="hidden" name="level" value="{level}">
        <input type="text" name="flag" placeholder="flag{{...}}" style="flex:1">
        <button type="submit">Submit flag</button>
      </form>
      {badge}
    </div>
    """


# ----------------------------------------------------------------------
# Home / flag submission
# ----------------------------------------------------------------------

@app.route("/")
def index():
    body = """
    <div class="card">
      <h1>Race Condition CTF Training Lab</h1>
      <p>Six levels, each practicing a different race condition technique from
      Chapter 12 of <em>Bug Bounty Bootcamp</em> and the PortSwigger "Race conditions"
      material. Every endpoint has an artificial delay built in between its "check"
      and "use" steps so you can exploit it reliably by firing a handful of
      <strong>concurrent</strong> requests — see <code>race_client.py</code> and the README.</p>
      <ul>
        <li><a href="{{ url_for('level1') }}">Level 1 — Limit overrun (discount code)</a></li>
        <li><a href="{{ url_for('level2') }}">Level 2 — Bank transfer overdraft</a></li>
        <li><a href="{{ url_for('level3') }}">Level 3 — Vote twice (TOCTOU)</a></li>
        <li><a href="{{ url_for('level4') }}">Level 4 — Partial construction (empty API key)</a></li>
        <li><a href="{{ url_for('level5') }}">Level 5 — Single-endpoint token collision</a></li>
        <li><a href="{{ url_for('level6') }}">Level 6 — Bypass a session-based lock</a></li>
      </ul>
      <p>Progress: <strong>{{ session.get('solved', [])|length }}/6</strong> solved.</p>
    </div>
    """
    return render(body)


@app.route("/submit", methods=["POST"])
def submit_flag():
    level = int(request.form.get("level", 0))
    submitted = request.form.get("flag", "").strip()
    if FLAGS.get(level) == submitted:
        solved = session.get("solved", [])
        if level not in solved:
            solved.append(level)
        session["solved"] = solved
        flash("Correct! Flag accepted.", "ok")
    else:
        flash("Not quite — that flag doesn't match.", "err")
    return redirect(url_for(f"level{level}"))


# ----------------------------------------------------------------------
# Level 1 — Limit overrun: one-time discount code
# ----------------------------------------------------------------------

@app.route("/level1", methods=["GET"])
def level1():
    body = """
    <div class="card">
      <h2>Level 1 — Limit Overrun: One-Time Discount Code</h2>
      <p>This endpoint is supposed to let you redeem a discount code <strong>once</strong>:</p>
      <pre>1. check if code already used
2. (artificial delay)
3. mark code as used, count the redemption</pre>
      <div class="hint">Goal: redeem the code <strong>more than once</strong> by sending
      several <code>POST /level1/redeem</code> requests at the same time. Use
      <code>race_client.py</code> (see README) or several backgrounded curl commands.</div>
      <p>
        <button onclick="fetch('/level1/reset',{method:'POST'}).then(()=>location.reload())">Reset state</button>
      </p>
      <p>Current redemption count: <strong>{{ count }}</strong></p>
      <pre id="out">POST /level1/redeem  (fire this one concurrently, several times at once)</pre>
      {% if flag %}<pre class="ok">{{ flag }}</pre>{% endif %}
    </div>
    """ + flag_form(1)
    flag = FLAGS[1] if state_lock_free.get("l1_count", 0) > 1 else None
    return render(body, count=state_lock_free.get("l1_count", 0), flag=flag)


@app.route("/level1/reset", methods=["POST"])
def level1_reset():
    reset_level1()
    return jsonify(status="reset")


@app.route("/level1/redeem", methods=["POST"])
def level1_redeem():
    if not state_lock_free.get("l1_used", False):
        time.sleep(RACE_DELAY)
        state_lock_free["l1_used"] = True
        state_lock_free["l1_count"] = state_lock_free.get("l1_count", 0) + 1
        return jsonify(status="redeemed", count=state_lock_free["l1_count"])
    return jsonify(status="already used", count=state_lock_free.get("l1_count", 0))


# ----------------------------------------------------------------------
# Level 2 — Bank transfer overdraft
# ----------------------------------------------------------------------

@app.route("/level2", methods=["GET"])
def level2():
    body = """
    <div class="card">
      <h2>Level 2 — Bank Transfer Overdraft</h2>
      <p>Your account has a $500 balance. A transfer is supposed to work like this:</p>
      <pre>1. check balance >= amount
2. (artificial delay)
3. subtract amount from balance, add to total withdrawn</pre>
      <div class="hint">Goal: withdraw <strong>more than $500 total</strong> by sending several
      <code>POST /level2/transfer</code> requests (amount=500) at the same time.</div>
      <p>
        <button onclick="fetch('/level2/reset',{method:'POST'}).then(()=>location.reload())">Reset state</button>
      </p>
      <p>Balance: <strong>${{ balance }}</strong> &middot; Total withdrawn: <strong>${{ withdrawn }}</strong></p>
      <pre>POST /level2/transfer  body: amount=500  (fire concurrently, several times)</pre>
      {% if flag %}<pre class="ok">{{ flag }}</pre>{% endif %}
    </div>
    """ + flag_form(2)
    withdrawn = state_lock_free.get("l2_withdrawn_total", 0)
    flag = FLAGS[2] if withdrawn > 500 else None
    return render(body, balance=state_lock_free.get("l2_balance", 500), withdrawn=withdrawn, flag=flag)


@app.route("/level2/reset", methods=["POST"])
def level2_reset():
    reset_level2()
    return jsonify(status="reset")


@app.route("/level2/transfer", methods=["POST"])
def level2_transfer():
    try:
        amount = int(request.form.get("amount", "0"))
    except ValueError:
        amount = 0
    if state_lock_free.get("l2_balance", 0) >= amount:
        time.sleep(RACE_DELAY)
        state_lock_free["l2_balance"] -= amount
        state_lock_free["l2_withdrawn_total"] = state_lock_free.get("l2_withdrawn_total", 0) + amount
        return jsonify(status="transferred", balance=state_lock_free["l2_balance"],
                        withdrawn=state_lock_free["l2_withdrawn_total"])
    return jsonify(status="insufficient funds", balance=state_lock_free.get("l2_balance", 0))


# ----------------------------------------------------------------------
# Level 3 — Vote twice (TOCTOU)
# ----------------------------------------------------------------------

@app.route("/level3", methods=["GET"])
def level3():
    body = """
    <div class="card">
      <h2>Level 3 — Vote Twice (TOCTOU)</h2>
      <p>A voting endpoint is supposed to let your account vote <strong>once</strong>:</p>
      <pre>1. check if this voter has already voted
2. (artificial delay)
3. add a vote, mark voter as "already voted"</pre>
      <div class="hint">Goal: get the vote count above 1 by sending several
      <code>POST /level3/vote</code> requests at the same time.</div>
      <p>
        <button onclick="fetch('/level3/reset',{method:'POST'}).then(()=>location.reload())">Reset state</button>
      </p>
      <p>Votes recorded: <strong>{{ votes }}</strong></p>
      <pre>POST /level3/vote  (fire concurrently, several times)</pre>
      {% if flag %}<pre class="ok">{{ flag }}</pre>{% endif %}
    </div>
    """ + flag_form(3)
    votes = state_lock_free.get("l3_votes", 0)
    flag = FLAGS[3] if votes > 1 else None
    return render(body, votes=votes, flag=flag)


@app.route("/level3/reset", methods=["POST"])
def level3_reset():
    reset_level3()
    return jsonify(status="reset")


@app.route("/level3/vote", methods=["POST"])
def level3_vote():
    if not state_lock_free.get("l3_voted", False):
        time.sleep(RACE_DELAY)
        state_lock_free["l3_voted"] = True
        state_lock_free["l3_votes"] = state_lock_free.get("l3_votes", 0) + 1
        return jsonify(status="voted", votes=state_lock_free["l3_votes"])
    return jsonify(status="already voted", votes=state_lock_free.get("l3_votes", 0))


# ----------------------------------------------------------------------
# Level 4 — Partial construction: empty/uninitialized API key
# ----------------------------------------------------------------------

@app.route("/level4", methods=["GET"])
def level4():
    body = """
    <div class="card">
      <h2>Level 4 — Partial Construction: Empty API Key</h2>
      <p>Registering a user is done in two separate steps, just like a real app
      might use two separate SQL statements:</p>
      <pre>1. create the user record (api_key = None)
2. (artificial delay — the user exists, but their key isn't set yet!)
3. generate and set the real api_key</pre>
      <div class="hint">Goal: during that window, authenticate as the new user using
      an <strong>empty array-style parameter</strong> instead of a real key — the
      classic PHP <code>param[]=</code> trick, which some frameworks turn into an
      empty value or <code>null</code>.
      <br><br>
      1. <code>POST /level4/register</code> with <code>username=bob</code> (this takes ~{{ delay }}s to finish)<br>
      2. Immediately, <strong>while that request is still in flight</strong>, call
      <code>GET /level4/api?user=bob&api-key[]=</code><br>
      If your timing lands inside the window, you're in before the real key exists.</div>
      <p>
        <button onclick="fetch('/level4/reset',{method:'POST'}).then(()=>location.reload())">Reset state</button>
      </p>
      {% if flag %}<pre class="ok">{{ flag }}</pre>{% endif %}
    </div>
    """ + flag_form(4)
    flag = FLAGS[4] if state_lock_free.get("l4_solved") else None
    return render(body, delay=RACE_DELAY, flag=flag)


@app.route("/level4/reset", methods=["POST"])
def level4_reset():
    reset_level4()
    state_lock_free.pop("l4_solved", None)
    return jsonify(status="reset")


@app.route("/level4/register", methods=["POST"])
def level4_register():
    username = request.form.get("username", "")
    users = state_lock_free.setdefault("l4_users", {})
    users[username] = {"api_key": None}  # step 1: created, key not set yet
    time.sleep(RACE_DELAY)               # step 2: the vulnerable window
    users[username]["api_key"] = secrets.token_hex(8)  # step 3: real key set
    return jsonify(status="registered", username=username)


@app.route("/level4/api", methods=["GET"])
def level4_api():
    username = request.args.get("user", "")
    users = state_lock_free.setdefault("l4_users", {})
    user = users.get(username)
    if user is None:
        return jsonify(status="no such user"), 404

    supplied_key = request.args.get("api-key", None)
    supplied_array = request.args.getlist("api-key[]")

    # Emulate PHP-style parsing: api-key[]= with no value becomes an empty list,
    # which some frameworks treat as an empty/falsy value when compared.
    if "api-key[]" in request.args:
        matched = (user["api_key"] is None) and (supplied_array == [""] or supplied_array == [])
    else:
        matched = supplied_key is not None and supplied_key == user["api_key"]

    if matched:
        state_lock_free["l4_solved"] = True
        return jsonify(status="authenticated", note="matched uninitialized key!", flag=FLAGS[4])
    return jsonify(status="unauthorized")


# ----------------------------------------------------------------------
# Level 5 — Single-endpoint race: password reset token collision
# ----------------------------------------------------------------------

@app.route("/level5", methods=["GET"])
def level5():
    body = """
    <div class="card">
      <h2>Level 5 — Single-Endpoint Token Collision</h2>
      <p>A password-reset flow stores the user ID and token in the <strong>session</strong>
      (shared across requests using the same session cookie) instead of per-request:</p>
      <pre>1. session['pending'] = username
2. (artificial delay)
3. session['reset_user'] = username
   session['reset_token'] = new token
   "email" the token to that username's inbox</pre>
      <div class="hint">Goal: using <strong>one shared session cookie</strong>, send two
      concurrent <code>POST /level5/request_reset</code> requests — one for
      <code>victim</code>, one for <code>attacker</code>. If they interleave right,
      <code>session['reset_user']</code> can end up as <code>victim</code> while
      <code>session['reset_token']</code> is the token that was actually emailed to
      <code>attacker</code>.
      <br><br>
      Check <code>GET /level5/inbox?user=attacker</code> for the token "sent" to that
      inbox, then call <code>POST /level5/confirm</code> with that token and a new
      password. If the session's current <code>reset_user</code> is <code>victim</code>,
      you just reset the victim's password using attacker's own token.
      <br><br>
      <strong>Important:</strong> first call <code>GET /level5/init</code> once to establish a
      session cookie, then reuse that <strong>same cookie</strong> (a cookie jar, e.g.
      <code>curl -b cookies.txt -c cookies.txt</code>) for both concurrent requests, so they
      share one session.</div>
      <p>
        <button onclick="fetch('/level5/reset',{method:'POST'}).then(()=>location.reload())">Reset state</button>
      </p>
      <p>Current passwords: <code>{{ passwords }}</code></p>
      {% if flag %}<pre class="ok">{{ flag }}</pre>{% endif %}
    </div>
    """ + flag_form(5)
    flag = FLAGS[5] if state_lock_free.get("l5_solved") else None
    return render(body, passwords=state_lock_free.get("l5_passwords", {}), flag=flag)


@app.route("/level5/reset", methods=["POST"])
def level5_reset():
    reset_level5()
    state_lock_free.pop("l5_solved", None)
    return jsonify(status="reset")


@app.route("/level5/init", methods=["GET"])
def level5_init():
    """Establish a session cookie BEFORE firing the two concurrent requests,
    so they actually share one mutable server-side session (LEVEL5_SESSIONS[sid]),
    the way a real app's server-side session store would behave."""
    sid = request.cookies.get("l5sid") or secrets.token_hex(8)
    LEVEL5_SESSIONS.setdefault(sid, {})
    resp = jsonify(status="session ready")
    resp.set_cookie("l5sid", sid)
    return resp


@app.route("/level5/request_reset", methods=["POST"])
def level5_request_reset():
    username = request.form.get("username", "")
    if username not in state_lock_free.get("l5_passwords", {}):
        return jsonify(status="no such user"), 404
    sid = request.cookies.get("l5sid")
    if sid is None:
        return jsonify(status="call /level5/init first to get a session cookie"), 400
    sess = LEVEL5_SESSIONS.setdefault(sid, {})
    sess["pending"] = username
    # Jitter (like real network/server timing variance) so the two concurrent
    # requests don't always resolve in the same fixed order.
    time.sleep(RACE_DELAY + random.uniform(-0.2, 0.2))
    token = secrets.token_hex(4)
    sess["reset_user"] = username
    # A second, independently-jittered window between setting WHO the reset is
    # for and WHICH token belongs to it -- this is what lets the two writes
    # cross over (one request "wins" the user field, the other "wins" the
    # token field).
    time.sleep(0.4 + random.uniform(-0.35, 0.35))
    sess["reset_token"] = token
    state_lock_free.setdefault("l5_tokens_sent", {})[username] = token
    state_lock_free.setdefault("l5_token_owner", {})[token] = username
    return jsonify(status="reset requested for " + username)


@app.route("/level5/inbox", methods=["GET"])
def level5_inbox():
    username = request.args.get("user", "")
    token = state_lock_free.get("l5_tokens_sent", {}).get(username)
    return jsonify(user=username, token=token)


@app.route("/level5/confirm", methods=["POST"])
def level5_confirm():
    token = request.form.get("token", "")
    new_password = request.form.get("new_password", "")
    sid = request.cookies.get("l5sid")
    sess = LEVEL5_SESSIONS.get(sid, {})
    session_user = sess.get("reset_user")
    session_token = sess.get("reset_token")
    if not session_user or session_token != token:
        return jsonify(status="invalid token"), 400

    token_owner = state_lock_free.get("l5_token_owner", {}).get(token)
    state_lock_free.setdefault("l5_passwords", {})[session_user] = new_password

    if token_owner and token_owner != session_user:
        state_lock_free["l5_solved"] = True
        return jsonify(status="password changed", changed_user=session_user,
                        note=f"token was sent to '{token_owner}' but reset '{session_user}'!",
                        flag=FLAGS[5])
    return jsonify(status="password changed", changed_user=session_user)


# ----------------------------------------------------------------------
# Level 6 — Bypass a session-based lock
# ----------------------------------------------------------------------

@app.route("/level6", methods=["GET"])
def level6():
    body = """
    <div class="card">
      <h2>Level 6 — Bypass a Session-Based Lock</h2>
      <p>This gift-card redemption endpoint is protected by a lock tied to your
      <strong>session</strong> (like PHP's native session handler, which processes one
      request per session at a time):</p>
      <pre>with per-session lock:
    if not used: (artificial delay); mark used; count += 1</pre>
      <div class="hint">Goal: redeem more than once anyway. If you send concurrent
      requests <strong>using the same session cookie</strong>, the lock will force them
      to run one at a time — the race fails. The trick from the article: send each
      request with a <strong>different (or no) session cookie</strong> so each one gets
      its own lock, letting them run truly concurrently against the shared counter
      underneath.</div>
      <p>
        <button onclick="fetch('/level6/reset',{method:'POST'}).then(()=>location.reload())">Reset state</button>
      </p>
      <p>Redemption count: <strong>{{ count }}</strong></p>
      <pre>POST /level6/redeem  (send WITHOUT sharing cookies between requests, concurrently)</pre>
      {% if flag %}<pre class="ok">{{ flag }}</pre>{% endif %}
    </div>
    """ + flag_form(6)
    flag = FLAGS[6] if GIFT_STATE["count"] > 1 else None
    return render(body, count=GIFT_STATE["count"], flag=flag)


@app.route("/level6/reset", methods=["POST"])
def level6_reset():
    reset_level6()
    return jsonify(status="reset")


@app.route("/level6/redeem", methods=["POST"])
def level6_redeem():
    sid = session.get("sid")
    if sid is None:
        sid = secrets.token_hex(4)
        session["sid"] = sid
    lock = SESSION_LOCKS.setdefault(sid, threading.Lock())
    with lock:
        if not GIFT_STATE["used"]:
            time.sleep(RACE_DELAY)
            GIFT_STATE["used"] = True
            GIFT_STATE["count"] += 1
            return jsonify(status="redeemed", count=GIFT_STATE["count"], session_id=sid)
    return jsonify(status="already used", count=GIFT_STATE["count"], session_id=sid)


if __name__ == "__main__":
    print("Race condition lab starting on http://127.0.0.1:5000/")
    # threaded=True is required so Flask's dev server actually handles
    # concurrent requests in parallel instead of queueing them.
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
