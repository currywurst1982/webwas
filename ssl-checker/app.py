import ssl
import socket
import json
import subprocess
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)


def check_ssl_cert(hostname, port=443, timeout=10):
    """
    주어진 호스트의 SSL 인증서 만료 정보를 반환합니다.
    """
    result = {
        "hostname": hostname,
        "port": port,
        "status": "unknown",
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # Subject
        subject_dict = dict(x[0] for x in cert.get("subject", []))
        result["subject"] = subject_dict.get("commonName", hostname)

        # Issuer
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        result["issuer"] = issuer_dict.get("organizationName", "Unknown")

        # 유효 기간
        not_before_str = cert.get("notBefore", "")
        not_after_str = cert.get("notAfter", "")

        fmt = "%b %d %H:%M:%S %Y %Z"
        not_before = datetime.strptime(not_before_str, fmt).replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(not_after_str, fmt).replace(tzinfo=timezone.utc)

        result["not_before"] = not_before.strftime("%Y-%m-%d %H:%M:%S UTC")
        result["not_after"] = not_after.strftime("%Y-%m-%d %H:%M:%S UTC")

        now = datetime.now(timezone.utc)
        days_remaining = (not_after - now).days
        result["days_remaining"] = days_remaining

        if days_remaining < 0:
            result["status"] = "expired"
        elif days_remaining <= 14:
            result["status"] = "critical"
        elif days_remaining <= 30:
            result["status"] = "warning"
        else:
            result["status"] = "ok"

    except ssl.SSLCertVerificationError as e:
        result["status"] = "error"
        result["error"] = f"인증서 검증 실패: {str(e)}"
    except socket.timeout:
        result["status"] = "error"
        result["error"] = "연결 시간 초과"
    except socket.gaierror:
        result["status"] = "error"
        result["error"] = "호스트를 찾을 수 없습니다"
    except ConnectionRefusedError:
        result["status"] = "error"
        result["error"] = f"포트 {port} 연결 거부됨"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result


def get_apache_vhosts():
    """
    로컬 Apache 설정에서 SSL VirtualHost 도메인 목록을 추출합니다.
    """
    domains = []
    try:
        result = subprocess.run(
            ["apache2ctl", "-S"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr
        for line in output.splitlines():
            line = line.strip()
            if ":443" in line:
                parts = line.split()
                for part in parts:
                    if part.startswith("namevhost") or (
                        "." in part and not part.startswith("-")
                    ):
                        domain = part.replace("namevhost", "").strip()
                        if domain and not domain.startswith("/") and "." in domain:
                            domains.append(domain)
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass

    # apachectl 도 시도
    if not domains:
        try:
            result = subprocess.run(
                ["apachectl", "-S"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout + result.stderr
            for line in output.splitlines():
                if ":443" in line and "namevhost" in line:
                    parts = line.split("namevhost")
                    if len(parts) > 1:
                        domain = parts[1].strip().split()[0]
                        if domain and "." in domain:
                            domains.append(domain)
        except Exception:
            pass

    return list(set(domains))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/check", methods=["POST"])
def api_check():
    """
    POST body: {"hosts": ["example.com", "example.com:8443"]}
    """
    data = request.get_json(silent=True) or {}
    hosts_input = data.get("hosts", [])

    if not hosts_input:
        return jsonify({"error": "hosts 목록이 비어 있습니다."}), 400

    results = []
    for entry in hosts_input:
        entry = entry.strip()
        if not entry:
            continue
        if ":" in entry:
            parts = entry.rsplit(":", 1)
            hostname = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                port = 443
        else:
            hostname = entry
            port = 443
        results.append(check_ssl_cert(hostname, port))

    results.sort(key=lambda r: (r["days_remaining"] is None, r["days_remaining"] if r["days_remaining"] is not None else 9999))
    return jsonify({"results": results, "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")})


@app.route("/api/apache-vhosts", methods=["GET"])
def api_apache_vhosts():
    """
    로컬 Apache VirtualHost에서 HTTPS 도메인 목록을 반환합니다.
    """
    domains = get_apache_vhosts()
    return jsonify({"domains": domains})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
