"""常驻 HTTP 脱敏服务: POST /anonymize, 检测可融合 GLiNER2 + presidio-analyzer; 内置 Web 前端。"""
import json
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import (anonymize, detect_results, serialize, analyzer_available,
               DetectorError, AnalyzerUnavailable, DETECTOR_URL, OPERATORS, MODES)

USAGE = {
    "service": "pii-anonymizer",
    "detector": DETECTOR_URL,
    "modes": list(MODES),
    "endpoints": {
        "GET  /": "Web 前端 (HTML)",
        "GET  /api": "本说明 (JSON)",
        "GET  /health": "存活 + 各检测来源可用性",
        "POST /anonymize": {"text": "...", "operator?": list(OPERATORS),
                            "mode?": list(MODES), "threshold?": 0.5,
                            "labels?": [], "key?": "(encrypt 用)"},
        "POST /detect": {"text": "...", "mode?": list(MODES), "threshold?": 0.5},
    },
}

_UI_HTML = (Path(__file__).parent / "ui.html").read_text(encoding="utf-8")


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

    def _send_html(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = self.path.rstrip("/")
        if p in ("", "/ui"):
            return self._send_html(_UI_HTML)
        if p == "/api":
            return self._send(200, USAGE)
        if self.path == "/health":
            return self._send(200, {
                "status": "ok",
                "detector_gliner": DETECTOR_URL,
                "presidio_analyzer": analyzer_available(),   # 容器内 True, 宿主 False
            })
        self._send(404, {"error": "not found", "see": "/"})

    def do_POST(self):
        try:
            b = self._body()
            p = self.path.rstrip("/")
            if p == "/anonymize":
                result = anonymize(b["text"], b.get("operator", "replace"),
                                   b.get("threshold", 0.5), b.get("labels"),
                                   b.get("detector_url"), b.get("key"),
                                   b.get("mode", "auto"))
                self._send(200, {"result": result, "operator": b.get("operator", "replace"),
                                 "mode": b.get("mode", "auto")})
            elif p == "/detect":
                spans, sources = detect_results(b["text"], b.get("threshold", 0.5),
                                                b.get("labels"), b.get("detector_url"),
                                                b.get("mode", "auto"))
                self._send(200, {"sources": sources, "entities": serialize(spans, b["text"])})
            else:
                self._send(404, {"error": "not found", "see": "/"})
        except KeyError as e:
            self._send(400, {"error": f"missing field {e}"})
        except DetectorError as e:
            self._send(502, {"error": str(e), "hint": "起后台 GLiNER2 服务, 或用 mode=presidio"})
        except AnalyzerUnavailable as e:
            self._send(501, {"error": str(e)})
        except ValueError as e:
            self._send(400, {"error": str(e)})
        except Exception as e:
            self._send(500, {"error": repr(e)})

    def log_message(self, fmt, *args):
        print(f"[http] {self.address_string()} {fmt % args}", flush=True)


def run(host="127.0.0.1", port=8100):
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"pii-anonymizer serving on http://{host}:{port}  "
          f"(detector={DETECTOR_URL}, presidio_analyzer={analyzer_available()})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
