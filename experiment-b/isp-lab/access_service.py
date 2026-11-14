"""Disposable simulated ISP access-service endpoint; NOT a real telecom control plane."""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN=os.environ.get("LAB_ACCESS_TOKEN","")
lock=threading.Lock()
isolation=False
class Handler(BaseHTTPRequestHandler):
    def reply(self,status,payload):
        body=json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if self.path=="/healthz":
            return self.reply(200,{"status":"ready"})
        if self.path!="/protected":
            return self.reply(404,{"error":"unsupported"})
        with lock: denied=isolation
        return self.reply(403 if denied else 200,
            {"service":"simulated-broadband-access","decision":"DENY" if denied else "ALLOW"})
    def do_POST(self):
        global isolation
        if not TOKEN or self.headers.get("X-Lab-Access-Token")!=TOKEN:
            return self.reply(403,{"error":"invalid lab control token"})
        if self.path not in ("/admin/isolate","/admin/restore"):
            return self.reply(404,{"error":"unsupported"})
        with lock:isolation=self.path=="/admin/isolate"
        return self.reply(200,{"acknowledged":True})
    def log_message(self,*args):pass
if __name__=="__main__":
    if len(TOKEN)<24:raise RuntimeError("Fresh disposable token required")
    ThreadingHTTPServer(("0.0.0.0",8080),Handler).serve_forever()
