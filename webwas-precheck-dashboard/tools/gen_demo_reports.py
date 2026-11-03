"""
화면 시험용: src/test/resources 의 실제 리포트를 본떠 서버 300대(인스턴스 약 360개) 분량의 가짜 리포트를 만듭니다.
실제 점검 결과가 아니므로 운영 대시보드의 리포트 폴더에 넣지 마세요.

사용법:  python3 tools/gen_demo_reports.py /tmp/demo-data/reports
         → 대시보드를 -Dwebwas.precheck.data.dir=/tmp/demo-data 로 띄워 서버 현황판을 확인
"""
import os, random, re, sys
random.seed(7)
SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src', 'test', 'resources') + os.sep
OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)
T = {k: open(SRC + v, encoding='utf-8').read() for k, v in {
    'a_risk': 'apache_precheck_vm_20261015_073443.txt',
    't_comp': 'tomcat_precheck_vm_20261103_074010.txt',
    't_warn': 'tomcat_precheck_vm_20261103_074324.txt',
    'w_risk': 'wildfly_precheck_vm_20261016_050340_pid4068.txt',
    'w_warn': 'wildfly_precheck_vm_20261016_050342_pid4072.txt',
    'w_comp': 'wildfly_precheck_vm_20261016_050344_pid4154.txt',
}.items()}


def ok_version(text):
    """[주의]/[위험] 을 없애 '양호' 리포트로 (요약 줄도 0건)"""
    lines = [l for l in text.split('\n') if not l.startswith('[주의]') and not l.startswith('[위험]')]
    t = '\n'.join(lines)
    return re.sub(r'\[위험\] \d+건\s+\[주의\] \d+건', '[위험] 0건   [주의] 0건', t)


def warn_apache(text):
    lines = [l for l in text.split('\n') if not l.startswith('[위험]')]
    return re.sub(r'\[위험\] \d+건', '[위험] 0건', '\n'.join(lines))


def pick(kind, prod):
    if prod == 'apache':
        base = T['a_risk']
        return {'ok': ok_version(base), 'warn': warn_apache(base), 'risk': base, 'comp': base}[kind]
    if prod == 'tomcat':
        return {'ok': ok_version(T['t_warn']), 'warn': T['t_warn'], 'risk': T['t_comp'].replace('[위험] 웹쉘', '[주의] 웹쉘'), 'comp': T['t_comp']}[kind]
    return {'ok': ok_version(T['w_warn']), 'warn': T['w_warn'], 'risk': T['w_risk'], 'comp': T['w_comp']}[kind]


def kind():
    x = random.random()
    return 'ok' if x < 0.55 else 'warn' if x < 0.82 else 'risk' if x < 0.97 else 'comp'


def write(prod, host, ip, k, day, agent, j=0):
    text = pick(k, prod)
    hdr = text.split('\n', 1)
    when = f'2026-{day[0]:02d}-{day[1]:02d} 0{random.randint(1, 9)}:{random.randint(10, 59)}:{random.randint(10, 59)}'
    first = re.sub(r'호스트: \S+\s+\|\s+일시: .*$', f'호스트: {host}  |  일시: {when}', hdr[0])
    body = re.sub(r'\[정보\] 서버 IP: .*', f'[정보] 서버 IP: {ip}', hdr[1])
    if '[정보] 서버 IP:' not in body:
        body = f'[정보] 서버 IP: {ip}\n' + body
    if j:
        body = f'[정보] 인스턴스 구분: base=/srv/{prod}{j}\n' + body
    stamp = when.replace('-', '').replace(':', '').replace(' ', '_')
    name = f'{prod}_precheck_{host}_{stamp}' + (f'_pid{1000 + j}' if j else '') + '.txt'
    if agent:
        name = f'agent-{agent}__{name}'
    open(os.path.join(OUT, name), 'w', encoding='utf-8').write(first + '\n' + body)


n = 0
for i in range(1, 301):
    zone = 'zone-a' if i <= 120 else 'zone-b' if i <= 230 else ''
    subnet = 10 + (i - 1) // 60
    ip = f'10.20.{subnet}.{(i - 1) % 60 + 11}'
    stale = random.random() < 0.06
    day = (10, random.randint(1, 20)) if stale else (11, random.randint(1, 3))
    if i <= 110:
        host, prods = f'web{i:03d}', ['apache'] + (['tomcat'] if i % 4 == 0 else [])
    elif i <= 230:
        host, prods = f'was-tc{i - 110:03d}', ['tomcat'] * (2 if i % 9 == 0 else 1)
    else:
        host, prods = f'was-wf{i - 230:03d}', ['wildfly'] * (3 if i % 7 == 0 else 1)
    for j, p in enumerate(prods):
        write(p, host, ip, kind(), day, zone if zone else None, j)
        n += 1
print('reports', n)
