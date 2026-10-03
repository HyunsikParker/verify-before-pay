"""Loopback-only, no-log interface. All analysis stays in this process."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import argparse
import hashlib
import json

from core import SpamModel, analyze

ROOT = Path(__file__).resolve().parent
FILES = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
         "/style.css": ("style.css", "text/css")}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8763)
    args = parser.parse_args()
    model_bytes = args.model.read_bytes()
    if hashlib.sha256(model_bytes).hexdigest() != "e3a024c6b54156da921b03ce9878cd4d043557ce590a4aeb9363d89bd7f321de":
        raise ValueError("Model identity differs from the frozen opening evaluation")
    model = SpamModel.load(json.loads(model_bytes))

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Do not persist messages, URLs, or request logs.

        def reply(self, status, body, content_type="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            resource = FILES.get(self.path)
            if not resource:
                return self.reply(404, b'{"error":"Not found"}')
            filename, mime = resource
            self.reply(200, (ROOT / filename).read_bytes(), mime)

        def do_POST(self):
            if self.path != "/analyze":
                return self.reply(404, b'{"error":"Not found"}')
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self.reply(415, b'{"error":"JSON required"}')
            if self.headers.get("Origin") not in {None, f"http://127.0.0.1:{args.port}"}:
                return self.reply(403, b'{"error":"Local origin required"}')
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 65536:
                    return self.reply(413, b'{"error":"Message is too large"}')
                data = json.loads(self.rfile.read(length))
                if not isinstance(data, dict):
                    raise ValueError("Expected an object")
                result = analyze(data.get("text"), model, data.get("domain", ""))
            except (ValueError, UnicodeError):
                return self.reply(400, b'{"error":"Enter valid message text and, optionally, an independent hostname."}')
            self.reply(200, json.dumps(result, ensure_ascii=False).encode())

    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    httpd.daemon_threads = True
    print(f"Local interface: http://127.0.0.1:{args.port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
