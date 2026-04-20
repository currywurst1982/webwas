#!/usr/bin/env python3
"""
🔐 인증서 만료일 확인 서버
사용법:
  python3 cert_checker.py            # 기본 포트 8500
  python3 cert_checker.py --port 9000
"""
import argparse
import json
import logging
import re
import socket
import ssl
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S')
log = logging.getLogger(__name__)

HTML_FILE = Path(__file__).parent / 'cert-monitor.html'

# ─── 인증서 파싱 (openssl 서브프로세스) ──────────────────────────────
def _parse_pem(pem: str) -> dict | None:
    """openssl x509 로 PEM 파싱 → dict 반환"""
    try:
        proc = subprocess.run(
            ['openssl', 'x509', '-noout', '-dates', '-subject', '-issuer'],
            input=pem.encode(), capture_output=True, timeout=10
        )
        out = proc.stdout.decode(errors='ignore')
        if not out.strip():
            return None

        result = {'san': []}

        m = re.search(r'notAfter=(.+)', out)
        if m:
            try:
                dt = datetime.strptime(m.group(1).strip(), '%b %d %H:%M:%S %Y %Z')
                result['not_after'] = dt.strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                result['not_after'] = m.group(1).strip()

        m = re.search(r'notBefore=(.+)', out)
        if m:
            try:
                dt = datetime.strptime(m.group(1).strip(), '%b %d %H:%M:%S %Y %Z')
                result['not_before'] = dt.strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                result['not_before'] = m.group(1).strip()

        # subject=C=KR, O=ACME, CN=*.example.com
        m = re.search(r'subject=(.+)', out)
        if m:
            cn = re.search(r'CN\s*=\s*([^,/\n]+)', m.group(1))
            result['subject_cn'] = cn.group(1).strip() if cn else ''

        m = re.search(r'issuer=(.+)', out)
        if m:
            org = re.search(r'O\s*=\s*([^,/\n]+)', m.group(1))
            cn  = re.search(r'CN\s*=\s*([^,/\n]+)', m.group(1))
            result['issuer_o'] = (org.group(1).strip() if org
                                  else (cn.group(1).strip() if cn else ''))

        # SAN: get from -text
        proc2 = subprocess.run(
            ['openssl', 'x509', '-noout', '-text'],
            input=pem.encode(), capture_output=True, timeout=10
        )
        text = proc2.stdout.decode(errors='ignore')
        san_m = re.search(r'Subject Alternative Name:\s*\n\s*(.+)', text)
        if san_m:
            result['san'] = [
                s.strip().replace('DNS:', '')
                for s in san_m.group(1).split(',')
                if s.strip().startswith('DNS:')
            ][:8]

        return result if 'not_after' in result else None
    except Exception as e:
        log.debug('_parse_pem error: %s', e)
        return None


def check_cert(host: str, port: int = 443, timeout: int = 10) -> dict:
    res = {
        'host': host, 'port': port,
        'not_after': None, 'not_before': None,
        'subject_cn': None, 'issuer_o': None,
        'san': [], 'verified': False, 'error': None,
    }

    # ── STEP 1: 인증서 취득 (만료/자체서명 포함) ────────────────────
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)

        if not der:
            res['error'] = '인증서 데이터 없음'
            return res

        pem = ssl.DER_cert_to_PEM_cert(der)
        parsed = _parse_pem(pem)
        if parsed:
            res.update(parsed)
        else:
            res['error'] = '인증서 파싱 실패'
            return res

    except socket.timeout:
        res['error'] = f'연결 시간 초과 ({timeout}초)'
        return res
    except socket.gaierror as e:
        res['error'] = f'DNS 오류: {e.strerror}'
        return res
    except ConnectionRefusedError:
        res['error'] = f'포트 {port} 연결 거부'
        return res
    except ssl.SSLError as e:
        res['error'] = f'SSL 오류: {str(e)[:60]}'
        return res
    except OSError as e:
        res['error'] = str(e)[:80]
        return res
    except Exception as e:
        res['error'] = str(e)[:80]
        return res

    # ── STEP 2: 인증서 유효성 검증 (호스트명 + 체인) ─────────────────
    try:
        ctx2 = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as s2:
            with ctx2.wrap_socket(s2, server_hostname=host):
                pass
        res['verified'] = True
    except ssl.CertificateError:
        res['verified'] = False  # 도메인 불일치
    except ssl.SSLError:
        res['verified'] = False  # 체인 오류(만료 포함)
    except Exception:
        res['verified'] = False

    return res


def check_cert_entry(entry: dict) -> dict:
    host   = entry.get('host', '')
    port   = int(entry.get('port') or 443)
    row_id = entry.get('row_id')
    result = check_cert(host, port)
    if row_id is not None:
        result['row_id'] = row_id
    log.info('%-40s  port=%-5s  not_after=%-20s  err=%s',
             host, port, result.get('not_after') or '—', result.get('error') or '—')
    return result


# ─── HTTP 서버 ───────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # 기본 로그 억제

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if self.path.split('?')[0] in ('/', '/cert-monitor.html'):
            if HTML_FILE.exists():
                data = HTML_FILE.read_bytes()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(data)))
                self._cors()
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_error(404, 'cert-monitor.html 파일이 없습니다')
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == '/api/check':
            try:
                length  = int(self.headers.get('Content-Length', 0))
                body    = json.loads(self.rfile.read(length) or b'{}')
                entries = body.get('domains', [])

                workers = min(20, max(1, len(entries)))
                results = []
                with ThreadPoolExecutor(max_workers=workers) as ex:
                    futs = {ex.submit(check_cert_entry, e): e for e in entries}
                    for f in as_completed(futs):
                        try:
                            results.append(f.result())
                        except Exception as exc:
                            e = futs[f]
                            results.append({
                                'host': e.get('host', ''),
                                'port': e.get('port', 443),
                                'row_id': e.get('row_id'),
                                'error': str(exc)[:80],
                            })

                resp = json.dumps(results, ensure_ascii=False).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('Content-Length', str(len(resp)))
                self._cors()
                self.end_headers()
                self.wfile.write(resp)
            except Exception as e:
                self.send_error(500, str(e))
        else:
            self.send_error(404)


def main():
    ap = argparse.ArgumentParser(description='인증서 만료일 확인 서버')
    ap.add_argument('--port', type=int, default=8500)
    ap.add_argument('--bind', default='0.0.0.0')
    args = ap.parse_args()

    server = HTTPServer((args.bind, args.port), Handler)
    log.info('━' * 50)
    log.info('🔐 인증서 만료일 확인 서버 시작')
    log.info('   브라우저: http://localhost:%d', args.port)
    log.info('━' * 50)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info('서버 종료')


if __name__ == '__main__':
    main()
