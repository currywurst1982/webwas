#!/usr/bin/env python3
"""
nGrinder 부하테스트 대시보드 - 중계(프록시) 서버

하는 일
  1) 같은 폴더의 index.html(대시보드 화면)을 브라우저에 보여줍니다.
  2) 화면에서 /api/... 로 오는 요청을 nGrinder 컨트롤러로 대신 전달합니다.
     (브라우저가 다른 주소의 nGrinder에 직접 요청하면 보안 정책(CORS)에 막히고,
      비밀번호를 화면 코드에 넣지 않기 위해 이 서버가 중간에서 전달합니다.)

필요한 것: Python 3.8 이상 (추가 설치 없음)

실행 예시
  NGRINDER_URL=http://10.0.0.5:8080 NGRINDER_USER=admin NGRINDER_PASSWORD=비밀번호 python3 server.py
  → 브라우저에서 http://localhost:8000 접속
"""
import base64
import http.server
import os
import socketserver
import sys
import urllib.error
import urllib.request

NGRINDER_URL = os.environ.get("NGRINDER_URL", "http://localhost:8080").rstrip("/")
NGRINDER_USER = os.environ.get("NGRINDER_USER", "")
NGRINDER_PASSWORD = os.environ.get("NGRINDER_PASSWORD", "")
HOST = os.environ.get("DASHBOARD_HOST", "127.0.0.1")
PORT = int(os.environ.get("DASHBOARD_PORT", "8000"))

# nGrinder API 중 대시보드가 쓰는 경로만 허용 (그 외 경로는 전달하지 않음)
ALLOWED_PREFIXES = ("/perftest/api", "/agent/api")

HERE = os.path.dirname(os.path.abspath(__file__))


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=HERE, **kwargs)

    # ---- /api/... 요청은 nGrinder로 전달 ----
    def _proxy(self, method):
        target_path = self.path[len("/api"):]
        if not target_path.startswith(ALLOWED_PREFIXES):
            self._send(403, b'{"error":"path not allowed"}')
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        req = urllib.request.Request(NGRINDER_URL + target_path, data=body, method=method)
        req.add_header("Accept", "application/json")
        if body is not None:
            req.add_header("Content-Type", self.headers.get("Content-Type", "application/json"))
        if NGRINDER_USER:
            token = base64.b64encode(f"{NGRINDER_USER}:{NGRINDER_PASSWORD}".encode()).decode()
            req.add_header("Authorization", "Basic " + token)
        try:
            with urllib.request.urlopen(req, timeout=15) as res:
                self._send(res.status, res.read(), res.headers.get("Content-Type"))
        except urllib.error.HTTPError as e:
            self._send(e.code, e.read() or b"{}", e.headers.get("Content-Type"))
        except Exception as e:  # 연결 실패 등
            msg = f'{{"error":"nGrinder 연결 실패: {type(e).__name__}"}}'.encode()
            self._send(502, msg)

    def _send(self, code, data, ctype="application/json; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype or "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/api/"):
            return self._proxy("GET")
        if self.path == "/config.json":
            cfg = f'{{"ngrinderUrl":"{NGRINDER_URL}","hasUser":{str(bool(NGRINDER_USER)).lower()}}}'
            return self._send(200, cfg.encode())
        return super().do_GET()

    def do_POST(self):
        if self.path.startswith("/api/"):
            return self._proxy("POST")
        self._send(405, b"{}")

    def do_PUT(self):
        if self.path.startswith("/api/"):
            return self._proxy("PUT")
        self._send(405, b"{}")

    def log_message(self, fmt, *args):
        sys.stderr.write("[dashboard] " + (fmt % args) + "\n")


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    print(f"nGrinder 주소     : {NGRINDER_URL}")
    print(f"nGrinder 계정     : {NGRINDER_USER or '(미설정 - 데모 모드로만 사용 가능)'}")
    print(f"대시보드 접속 주소: http://{'localhost' if HOST == '127.0.0.1' else HOST}:{PORT}")
    print("종료하려면 Ctrl + C")
    with Server((HOST, PORT), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n종료합니다.")
