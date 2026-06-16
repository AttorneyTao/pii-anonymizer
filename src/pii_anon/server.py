"""常驻 HTTP 脱敏服务: POST /anonymize, 检测转发到后台 GLiNER2 服务。"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import anonymize, detect, DetectorError, DETECTOR_URL, OPERATORS

USAGE = {
    "service": "pii-anonymizer",
    "detector": DETECTOR_URL,
    "endpoints": {
        "GET  /health": "存活检查",
        "POST /anonymize": {"text": "...", "operator?": list(OPERATORS),
                            "threshold?": 0.5, "labels?": [], "key?": "(encrypt 用)"},
        "POST /detect": {"text": "...", "threshold?": 0.5, "labels?": []},
    },
}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"{}") if n else {}

    def do_GET(self):
        if self.path.rstrip("/") in ("", "/"):
            return self._send(200, USAGE)
        if self.path == "/health":
            return self._send(200, {"status": "ok", "detector": DETECTOR_URL})
        self._send(404, {"error": "not found", "see": "/"})

    def do_POST(self):
        try:
            b = self._body()
            p = self.path.rstrip("/")
            if p == "/anonymize":
                result = anonymize(b["text"], b.get("operator", "replace"),
                                   b.get("threshold", 0.5), b.get("labels"),
                                   b.get("detector_url"), b.get("key"))
                self._send(200, {"result": result, "operator": b.get("operator", "replace")})
            elif p == "/detect":
                _, ents = detect(b["text"], b.get("threshold", 0.5), b.get("labels"))
                self._send(200, {"entities": ents})
            else:
                self._send(404, {"error": "not found", "see": "/"})
        except KeyError as e:
            self._send(400, {"error": f"missing field {e}"})
        except DetectorError as e:
            self._send(502, {"error": str(e), "hint": "确认后台 GLiNER2 服务在跑"})
        except ValueError as e:
            self._send(400, {"error": str(e)})
        except Exception as e:
            self._send(500, {"error": repr(e)})

    def log_message(self, fmt, *args):
        print(f"[http] {self.address_string()} {fmt % args}", flush=True)


def run(host="127.0.0.1", port=8100):
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"pii-anonymizer serving on http://{host}:{port}  (detector={DETECTOR_URL})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
