#!/usr/bin/env python3
"""
nginx 공식 보안 공지(security_advisories.xml) → nginx_precheck.sh 내장 CVE 목록 생성.

  python3 -I tools/gen_nginx_cve.py security_advisories.xml > rows.txt

원본: https://raw.githubusercontent.com/nginx/nginx.org/main/xml/en/security_advisories.xml
      (https://nginx.org/en/security_advisories.html 의 원본 XML)

행 형식: CVE|등급(nginx 원문)|필요 기능|영향 구간(;로 구분)|수정 버전(;로 구분)|제목
필요 기능은 공지 제목으로 정함 (대시보드 CveFeed.nginxFeature 와 같은 규칙. 바꾸면 둘 다 바꿀 것).
"""
import re
import sys

# (제목에 들어 있는 말, 필요 기능) — 위에서부터 처음 맞는 것
RULES = [
    (r'Windows', 'windows'),
    (r'HTTP/3|v3_module', 'http3'),
    (r'SPDY', 'spdy'),
    (r'proxy_v2|grpc', 'grpc'),
    (r'ngx_http_proxy_module', 'proxy'),
    (r'HTTP/2', 'http2'),
    (r'mp4', 'mp4'),
    (r'slice', 'slice'),
    (r'ssi_module', 'ssi'),
    (r'dav_module', 'dav'),
    (r'charset', 'charset'),
    (r'scgi|uwsgi', 'scgi'),
    (r'mail|smtp|SMTP|CRAM-MD5|APOP|auth_http|XCLIENT|STARTTLS', 'mail'),
    (r'OCSP.*stream|stream.*OCSP', 'stream_ocsp'),
    (r'OCSP', 'ocsp'),
    (r'resolver', 'resolver'),
    (r'alias', 'alias'),
    (r'map and regex', 'map'),
    (r'rewrite', 'rewrite'),
    (r'AIO|asynchronous file I/O', 'aio'),
    (r'SSL upstream', 'proxy_ssl'),
    (r'TLS session tickets|SSL session reuse', 'ssl'),
]


def feature(name):
    for pat, f in RULES:
        if re.search(pat, name):
            return f
    return 'core'


def rows(xml):
    out = []
    # <item ...> 와 한 줄로 닫힌 <item ... /> 가 섞여 있으므로 여는 태그만 읽음 (본문까지 맞추면 /> 뒤의 항목을 놓침)
    for attrs in re.findall(r'<item\b([^>]*)>', xml):
        d = dict(re.findall(r'(\w+)="([^"]*)"', attrs))
        if 'cve' not in d or 'vulnerable' not in d:
            continue
        cve = 'CVE-' + d['cve'].strip()
        sev = d.get('severity', 'medium').strip().lower()
        vuln = d['vulnerable'].replace('nginx/Windows', '').strip()
        vuln = ';'.join(x.strip() for x in vuln.split(',') if x.strip())
        good = ';'.join(x.strip() for x in d.get('good', '').split(',') if x.strip())
        name = re.sub(r'\s+', ' ', d.get('name', '')).replace('|', '/').strip()
        if not re.fullmatch(r'CVE-\d{4}-\d{4,7}', cve) or not re.fullmatch(r'[0-9.;-]+', vuln):
            continue
        if not re.fullmatch(r'[0-9.;+]*', good):
            good = ''
        out.append(f'{cve}|{sev}|{feature(name)}|{vuln}|{good}|{name}')
    return out


if __name__ == '__main__':
    print('\n'.join(rows(open(sys.argv[1], encoding='utf-8').read())))
