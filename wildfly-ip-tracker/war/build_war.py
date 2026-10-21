#!/usr/bin/env python3
"""사내망 전용 IP 추적기 WAR 파일을 만든다.

사용 예
  python3 war/build_war.py                                  # 기본 사내 대역 허용
  python3 war/build_war.py --allow 10.20.0.0/16 192.168.5.*  # 우리 회사 대역만 허용

결과: war/dist/ip-tracker.war  →  WildFly 의 standalone/deployments/ 에 복사하면 배포된다.
"""
import argparse, os, re, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# 사설 IP 대역(RFC 1918) + 서버 자기 자신
DEFAULT_ALLOW = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1", "0:0:0:0:0:0:0:1"]
RULE_RE = re.compile(r"^[0-9a-fA-F:.*]+(/\d{1,3})?$")


def page_html() -> str:
    body = open(os.path.join(ROOT, "web", "index.html"), encoding="utf-8").read()
    # 사내망 전용: 외부(Google Fonts)로 나가는 요청을 없앤다. 글꼴은 PC 기본 글꼴로 대체됨.
    body = re.sub(r'<link rel="stylesheet" href="https://fonts\.googleapis\.com[^>]*>\n?', "", body)
    body = body.replace('<meta name="claude:viewport-fit-sides" content="cover">\n', "")
    return ('<!doctype html>\n<html lang="ko"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
            + body.replace("</style>", "</style>\n</head><body>", 1) + "\n</body></html>\n")


def handlers_conf(allow) -> str:
    acl = ", ".join(f"'{a} allow'" for a in allow)
    # 주의: 이 파일은 주석(#)을 지원하지 않는다 (WildFly 37에서 배포 실패 확인). 설명은 여기 코드에만 둔다.
    # 1) 허용 목록에 없는 IP는 403 거부
    # 2) 보안 헤더: iframe 끼워넣기 금지, MIME 추측 금지, 외부 리소스 금지, 캐시 금지
    return (
        f"ip-access-control(default-allow=false, acl={{{acl}}})\n"
        "set(attribute='%{o,X-Frame-Options}', value='DENY')\n"
        "set(attribute='%{o,X-Content-Type-Options}', value='nosniff')\n"
        "set(attribute='%{o,Content-Security-Policy}', value=\"default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; frame-ancestors 'none'\")\n"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--allow", nargs="+", default=DEFAULT_ALLOW,
                    help="접속 허용 IP/대역 (예: 10.20.0.0/16, 192.168.5.*, 10.1.2.3)")
    ap.add_argument("--out", default=os.path.join(HERE, "dist", "ip-tracker.war"))
    a = ap.parse_args()
    for r in a.allow:
        if not RULE_RE.match(r):
            raise SystemExit(f"잘못된 IP 규칙: {r}")
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with zipfile.ZipFile(a.out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nCreated-By: build_war.py\r\n\r\n")
        z.writestr("index.html", page_html())
        z.write(os.path.join(HERE, "WEB-INF", "web.xml"), "WEB-INF/web.xml")
        z.write(os.path.join(HERE, "WEB-INF", "jboss-web.xml"), "WEB-INF/jboss-web.xml")
        z.writestr("WEB-INF/undertow-handlers.conf", handlers_conf(a.allow))
    print(f"생성: {a.out}")
    print("허용 IP:", ", ".join(a.allow))


if __name__ == "__main__":
    main()
