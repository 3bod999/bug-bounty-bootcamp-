# Race Condition CTF Training Lab

A deliberately vulnerable Flask app for practicing the race condition
techniques from *Bug Bounty Bootcamp* Chapter 12 and the PortSwigger Web
Security Academy "Race conditions" material.

**Run this locally only.** Every endpoint is missing the synchronization a
real app needs on purpose, and has an artificial delay added between its
"check" and "use" steps — this widens the race window so you can exploit
it reliably with ordinary concurrent requests, instead of needing
millisecond-precision network tricks.

## Setup

```bash
pip install flask requests
python app.py
```

Then open **http://127.0.0.1:5000/** in your browser.

## Firing concurrent requests

Shell `curl ... &` backgrounding works, but Python's GIL/thread timing is
more reliable for this. Use the included helper:

```bash
python race_client.py level1   # ... through level6
```

Open `race_client.py` to see exactly how each exploit is built — it's
meant to be read, not just run.

## Levels

| # | Technique | Maps to |
|---|-----------|---------|
| 1 | Limit overrun — one-time discount code | Ch.12 discount-code example; PortSwigger "Limit overrun race conditions" |
| 2 | Bank transfer overdraft | Ch.12 bank transfer example |
| 3 | Vote twice (TOCTOU) | Ch.12 voting example |
| 4 | Partial construction — empty/uninitialized API key | PortSwigger "Partial construction race conditions" |
| 5 | Single-endpoint token collision (password reset) | PortSwigger "Single-endpoint race conditions" |
| 6 | Bypass a session-based lock | PortSwigger "Session-based locking mechanisms" |

Each level page explains the vulnerable flow, gives a hint, and has a flag
submission box. Levels can be **reset** from their page (state is held in
memory, not a database) — race conditions often need a few tries, so reset
and retry freely.

## How each level is built (read after solving)

- **Level 1 — `/level1/redeem`**: `if not used: sleep(1); mark used; count += 1`.
  No lock — concurrent requests all pass the `if not used` check before any
  of them finishes marking it used.
- **Level 2 — `/level2/transfer`**: same pattern, but with a balance check
  and a withdrawal amount. Send several `$500` transfers at once against a
  $500 balance.
- **Level 3 — `/level3/vote`**: same pattern applied to a "has this voter
  already voted" check.
- **Level 4 — `/level4/register`**: creates the user record first, *then*
  sleeps, *then* sets the real API key — simulating two separate database
  writes. During the sleep, the key is `None`. Hitting
  `/level4/api?user=bob&api-key[]=` during that window sends an *empty
  list* for `api-key[]` (the classic PHP `param[]=` trick), which the
  endpoint treats as matching the uninitialized key.
- **Level 5 — `/level5/request_reset`**: stores the reset token in a
  **server-side session** shared by a cookie (`l5sid`), not a database.
  Two concurrent requests for `victim` and `attacker`, sharing one session
  cookie, can have their writes interleave: the session ends up pointing
  at `victim` as the user to reset, but holding the token that was
  actually emailed to `attacker`. Call `/level5/init` once first to get
  the shared cookie before racing — a real app's server-side session
  store works the same way. This genuinely depends on timing, so
  `race_client.py`'s version retries automatically.
- **Level 6 — `/level6/redeem`**: wrapped in a lock keyed by your session
  ID, simulating frameworks (like PHP's native session handler) that
  process one request per session at a time. Requests sharing a session
  cookie get serialized and the race fails — but requests sent **without**
  sharing a cookie each get their own lock and race freely against the
  same underlying counter.

## Fixing it yourself (optional exercise)

Once you've captured all six flags, try patching each level with a real
fix:
- Levels 1–3: wrap the check-then-write in a single `threading.Lock()` (or,
  in a real app, a database transaction / atomic update).
- Level 4: create the user record with its API key already set, in one
  atomic write — no partially-constructed state to exploit.
- Level 5: generate and store the reset token in one atomic step, and
  never let two different reset flows share session state.
- Level 6: this one is a reminder that a *lock* only protects you if every
  request that should collide actually goes through the *same* lock —
  the fix is tying the lock to the resource being modified (the gift card),
  not to the session making the request.
