"""Benign shopper traffic for OWASP Juice Shop, sent through the proxy's benign port.

Journeys: browse and search the catalogue, read and write product reviews, register,
log in, check who is logged in, add to and view the basket, track an order, leave
feedback. Values come from the shop's own catalogue and from fixed word lists.

  python benign.py --base http://127.0.0.1:9001 --seed S --max-requests N [--stop-file F]
"""
from __future__ import annotations

import argparse
import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

FIRST = ("anna", "ben", "chloe", "david", "emma", "felix", "grace", "hiro", "ines", "jamal", "kofi", "lena",
         "mateo", "nadia", "omar", "priya", "quinn", "rosa", "sven", "tara", "uche", "vera", "wanjiru", "yusuf")
LAST = ("smith", "obrien", "garcia", "kamau", "nguyen", "muller", "rossi", "tanaka", "silva", "kowalski")
ADJ = ("great", "decent", "lovely", "solid", "okay", "excellent", "cheap", "tasty", "fresh", "fine", "bland")
REVIEW = ("{adj} product, would buy again.", "It's {adj}. Arrived on time!", "Pretty {adj} for the price, thanks.",
          "Not bad, a bit {adj}... my kids liked it.", "{Adj}! 5 stars from me.", "Honestly {adj}; shipping was quick.",
          "Bought two of these (one as a gift) and both were {adj}.", "Works as described - {adj} value.")
FEEDBACK = ("Love the shop, keep it up!", "Checkout was smooth.", "Could you add more juice flavours?",
            "Delivery took 3 days, which is fine.", "Great prices & friendly support.", "The search works well :)")


class Client:
    def __init__(self, base: str, rng: random.Random):
        self.base, self.rng = base.rstrip("/"), rng
        self.token = None
        self.basket = None
        self.email = None
        self.sent = 0

    def call(self, method: str, path: str, body=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Accept": "application/json, text/plain, */*", "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        self.sent += 1
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            raw = e.read()
        try:
            return json.loads(raw or b"null")
        except ValueError:
            return None


def word_pool(products) -> list[str]:
    words = set()
    for p in products:
        for w in (p.get("name") or "").replace("(", " ").replace(")", " ").split():
            if w.isalpha() and len(w) > 2:
                words.add(w.lower())
    return sorted(words) or ["apple", "juice", "banana"]


def journey(c: Client, products, words):
    rng = c.rng
    pid = rng.choice(products)["id"] if products else 1
    kind = rng.choices(("browse", "search", "reviews", "account", "basket", "track", "feedback"),
                       (20, 25, 15, 10, 15, 8, 7))[0]
    if kind == "browse":
        c.call("GET", "/rest/products/search?q=")
        c.call("GET", f"/api/Products/{pid}")
    elif kind == "search":
        q = " ".join(rng.choice(words) for _ in range(rng.choice((1, 1, 2))))
        c.call("GET", "/rest/products/search?q=" + urllib.parse.quote(q))
    elif kind == "reviews":
        c.call("GET", f"/rest/products/{pid}/reviews")
        if c.token and rng.random() < 0.5:
            adj = rng.choice(ADJ)
            msg = rng.choice(REVIEW).format(adj=adj, Adj=adj.capitalize())
            c.call("PUT", f"/rest/products/{pid}/reviews", {"message": msg, "author": c.email})
    elif kind == "account":
        if c.token is None:
            name = f"{rng.choice(FIRST)}.{rng.choice(LAST)}{rng.randint(1, 999)}"
            c.email = f"{name}@example.com"
            pw = rng.choice(("Spring", "Garden", "Sunset", "Coffee")) + str(rng.randint(10, 99)) + rng.choice("!#$%")
            c.call("POST", "/api/Users", {"email": c.email, "password": pw, "passwordRepeat": pw,
                                          "securityQuestion": {"id": rng.randint(1, 10)},
                                          "securityAnswer": rng.choice(LAST).capitalize()})
            res = c.call("POST", "/rest/user/login", {"email": c.email, "password": pw})
            auth = (res or {}).get("authentication") or {}
            c.token, c.basket = auth.get("token"), auth.get("bid")
        else:
            c.call("GET", "/rest/user/whoami")
    elif kind == "basket":
        if c.token and c.basket:
            c.call("POST", "/api/BasketItems/", {"ProductId": pid, "BasketId": str(c.basket), "quantity": rng.randint(1, 3)})
            c.call("GET", f"/rest/basket/{c.basket}")
        else:
            c.call("GET", "/api/Quantitys/")
    elif kind == "track":
        oid = "".join(rng.choice("0123456789abcdef") for _ in range(4)) + "-" + \
              "".join(rng.choice("0123456789abcdef") for _ in range(16))
        c.call("GET", "/rest/track-order/" + oid)
    else:
        cap = c.call("GET", "/rest/captcha/") or {}
        if "captchaId" in cap:
            c.call("POST", "/api/Feedbacks/", {"captchaId": cap["captchaId"], "captcha": str(cap.get("answer", "")),
                                               "comment": rng.choice(FEEDBACK) + f" ({c.email or 'anonymous'})",
                                               "rating": rng.randint(3, 5)})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--max-requests", type=int, required=True)
    ap.add_argument("--stop-file", type=Path)
    ap.add_argument("--pause", type=float, default=0.0)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    shoppers = [Client(a.base, random.Random(rng.random())) for _ in range(12)]
    products = (shoppers[0].call("GET", "/api/Products") or {}).get("data") or []
    words = word_pool(products)
    while sum(s.sent for s in shoppers) < a.max_requests:
        if a.stop_file and a.stop_file.exists():
            break
        journey(rng.choice(shoppers), products, words)
        if a.pause:
            time.sleep(a.pause)
    print("benign requests sent:", sum(s.sent for s in shoppers), flush=True)


if __name__ == "__main__":
    main()
