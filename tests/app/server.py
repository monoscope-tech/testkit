"""Fixture app for testkit's self-test suite: a tiny orders app (HTML + JSON API), stdlib only.

Prints `listening on :PORT` once ready. `--port 0` picks a free port.
"""
import json, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PUBLIC = Path(__file__).parent / "public"
STATE = {"orders": [{"id": 1042, "customer": "Bob", "plan": "Starter", "status": "paid"}], "next": 1043}
LOCK = threading.Lock()
PAGES = {"/": "index.html", "/login": "login.html", "/dashboard": "dashboard.html", "/orders": "orders.html",
         "/orders/new": "new.html", "/broken": "broken.html", "/slow": "slow.html", "/popup": "popup.html", "/shift": "shift.html",
         "/a11y": "a11y.html", "/widgets": "widgets.html", "/frames": "frames.html", "/inner": "inner.html", "/clock": "clock.html"}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        if "--verbose" in sys.argv:
            sys.stderr.write("%s %s\n" % (self.command, self.path))

    def send(self, code, body, ctype="application/json", headers=()):
        data = body if isinstance(body, bytes) else (json.dumps(body) if ctype == "application/json" else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return {}

    def authed(self):
        return "sid=s3cret" in (self.headers.get("Cookie") or "")

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in PAGES or (path.startswith("/orders/") and path[8:].isdigit()):
            page = PAGES.get(path, "order.html")
            return self.send(200, (PUBLIC / page).read_text(), "text/html; charset=utf-8")
        if path == "/api/orders":
            with LOCK:
                return self.send(200, STATE["orders"])
        if path.startswith("/api/orders/"):
            oid = path.rsplit("/", 1)[1]
            with LOCK:
                o = next((o for o in STATE["orders"] if str(o["id"]) == oid), None)
            return self.send(200, o) if o else self.send(404, {"error": "not found"})
        if path == "/api/me":
            return self.send(200, {"email": "admin@acme.com"}) if self.authed() else self.send(401, {"error": "login required"})
        if path == "/api/slow":
            time.sleep(0.8)
            return self.send(200, {"ready": True})
        if path == "/api/plans":
            return self.send(200, ["Starter", "Pro", "Enterprise"])
        if path == "/download":
            return self.send(200, b"id,customer\n1042,Bob\n", "text/csv", [("Content-Disposition", 'attachment; filename="orders.csv"')])
        if path == "/health":
            return self.send(200, {"ok": True})
        self.send(404, "not found", "text/plain")

    def do_POST(self):
        path = self.path.split("?")[0]
        data = self.body()
        if path == "/api/session":
            if data.get("email") == "admin@acme.com" and data.get("password") == "hunter22":
                return self.send(200, {"ok": True}, headers=[("Set-Cookie", "sid=s3cret; Path=/")])
            return self.send(401, {"error": "Invalid email or password"})
        if path == "/api/orders":
            if not data.get("customer"):
                return self.send(422, {"error": "customer is required"})
            with LOCK:
                o = {"id": STATE["next"], "customer": data["customer"], "plan": data.get("plan", "Starter"), "status": "pending"}
                STATE["next"] += 1
                STATE["orders"].append(o)
            return self.send(201, o)
        if path == "/api/reset":
            with LOCK:
                STATE["orders"] = [{"id": 1042, "customer": "Bob", "plan": "Starter", "status": "paid"}]
                STATE["next"] = 1043
            return self.send(200, {"ok": True})
        self.send(404, {"error": "not found"})

    def do_DELETE(self):
        oid = self.path.rsplit("/", 1)[1]
        with LOCK:
            before = len(STATE["orders"])
            STATE["orders"] = [o for o in STATE["orders"] if str(o["id"]) != oid]
            gone = before != len(STATE["orders"])
        self.send(200 if gone else 404, {"deleted": gone})


if __name__ == "__main__":
    port = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else 0
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    print("listening on :%d" % srv.server_address[1], flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("shutdown complete", flush=True)
