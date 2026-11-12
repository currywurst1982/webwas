# Web·WAS 사전점검 통합 대시보드 (webwas-precheck-dashboard)

기존 **Apache 사전점검 대시보드(precheck-dashboard)** 와 **WildFly 사전점검 대시보드(wildfly-precheck-dashboard)** 를
하나로 합치고, **Tomcat·Nginx 점검**을 새로 넣은 대시보드입니다. WildFly(자바 WAS)에 배포하는 `.war` 파일 하나로 만들어집니다.

```
 [서버 A: Apache]          에이전트 ─┐  1분마다 "점검할 차례인가요?"  (서버 → 대시보드 방향 연결만 사용)
 [서버 B: Apache+Tomcat]   에이전트 ─┼─────────────────────────────▶ [대시보드] ◀── 브라우저(로그인)
 [서버 C: WildFly]         에이전트 ─┘  차례면: 최신 CVE 목록 받기 →        │
                                        실행 중인 제품의 점검 스크립트 실행 → 리포트 전송
                                                                            │ 12시간마다
                                                     Apache 보안팀 CVE JSON · OSV 취약점 DB · nginx.org 보안 공지 · 공식 배포 목록
```

## 무엇이 바뀌었나 (기존 두 대시보드 대비)

| 항목 | 내용 |
|---|---|
| 하나의 화면 | Apache · WildFly · Tomcat · Nginx 결과를 한 화면에서 봅니다. 화면 위 **제품 탭(전체/Apache/WildFly/Tomcat/Nginx)** 으로 거를 수 있고, 표·차트·PDF 에 제품이 표시됩니다 |
| 에이전트 하나 | 서버마다 에이전트를 **하나만** 설치합니다. 점검할 때마다 실행 중인 제품을 자동으로 찾아(`PRODUCTS=auto`) 해당 스크립트만 실행합니다 |
| Tomcat 점검 추가 | 새 스크립트 `tomcat_precheck.sh` (아래 "Tomcat 점검 항목") |
| **CVE 목록 자동 업데이트** | 대시보드가 12시간마다 공개 취약점 DB 에서 세 제품의 CVE 목록을 새로 만들고, 에이전트가 점검 직전에 받아 스크립트에 넘깁니다. 스크립트를 다시 배포하지 않아도 새 CVE 가 판정에 들어갑니다 |
| 최신 버전 기준도 자동 | 같은 목록에 최신 버전(예: Apache 2.4.69, WildFly 42.0.0.Final, Tomcat 브랜치별)을 넣어 보내, 스크립트의 "최신 미만" 판정도 대시보드 기준을 따릅니다 |
| 서버 배치도 | 같은 서버(호스트+IP)의 인스턴스는 제품이 달라도 한 상자에 층으로 쌓입니다(예: `web02` = Apache 1 · Tomcat 1) |

## 서버 현황판 (개요 화면 맨 위) — 서버 수백 대용

서버가 많아도 한눈에 보이도록 **칸 하나 = 서버 1대**인 타일 현황판이 기본입니다(서버 24대 이하일 때는 처음에 입체 배치도로 열림, 오른쪽 위 **타일 / 입체 배치도** 로 전환, 선택은 브라우저에 기억).

**입체 배치도**도 서버 수 제한 없이 **전체 서버**를 그립니다(이전에는 위험 순 24대까지만). 300대면 처음에는 작게 보이므로 확대해서 봅니다.
- 마우스 휠 = 확대/축소(커서 위치 기준), 끌기 = 이동, 휴대폰은 두 손가락으로 확대, 오른쪽 위 **+ / − / 맞춤** 버튼
- 서버 칸이 충분히 커질 때만 이름표(호스트·IP·버전)가 보입니다. 멀리서는 색으로 판정 분포만 봅니다.
- 위험한 서버일수록 위쪽(뒤)부터 놓입니다. 서버가 40대를 넘으면 대시보드 연결선은 생략합니다.
- 30초 자동 갱신 때도 보던 확대 위치를 유지합니다.
- 한계: 이름으로 찾기·묶기·판정 숨기기는 타일 보기에만 있습니다. 휴대폰에서는 처음 화면이 매우 작습니다.

| 읽는 법 | 뜻 |
|---|---|
| 칸 색 + 기호 | 그 서버에서 **가장 나쁜 판정** — ✖ 침해 의심(붉은 테두리) / ▲ 위험 / ◆ 주의 / ✔ 양호. 색을 구분하기 어려운 사람도 기호로 구분 가능 |
| 칸 아래 작은 띠 | 한 서버에 인스턴스가 여러 개(예: Apache + Tomcat)일 때 인스턴스별 판정 |
| 빗금 | **3일 넘게 점검되지 않은 서버** (에이전트 중단·서버 꺼짐 의심) |
| 마우스 올림 / 누름 | 호스트·IP·인스턴스별 제품·버전·판정 / 인스턴스 1개면 바로 상세, 여러 개면 인스턴스 목록 창 |

- **묶기**: 판정별(기본) · 제품별(Apache / WildFly / Tomcat / Apache + Tomcat …) · 에이전트별 · IP 대역별(/24) · 묶지 않음
- **판정 칩**(침해 의심 38 · 위험 31 …)을 누르면 그 판정의 서버를 숨기거나 다시 보입니다.
- **찾기**: 호스트·IP·버전 일부를 입력하면 일치하는 칸만 밝게 표시하고 나머지는 흐리게(위치를 잃지 않도록 숨기지 않음). 한 대만 일치하면 Enter 로 바로 열림.
- 양호 서버가 60대를 넘으면 **양호 묶음은 처음에 접혀** 있어 조치가 필요한 서버가 먼저 보입니다(제목을 누르면 펼침).
- 키보드: Tab 으로 현황판에 들어간 뒤 화살표 키로 칸 이동, Enter 로 열기.
- 같은 이유로 "침해 상태" 목록은 4대, "에이전트 서버" 목록은 15대까지만 보여 주고 나머지는 서버 목록/에이전트 화면으로 연결합니다.
- 화면 시험: `python3 tools/gen_demo_reports.py /tmp/demo-data/reports` 로 서버 300대 분량 가짜 리포트를 만들어 볼 수 있습니다(운영 폴더에 넣지 마세요).

## 점검 사각지대 · 에이전트 버전 확인 (2026-11-10)

- **개요 → 점검 사각지대**: 리포트 문구로 "실제로는 검사하지 못한 항목"을 인스턴스별로 셉니다. 누르면 서버 목록에서 해당 서버만 걸러 봅니다(위쪽 칩의 ✕ 로 해제).

| 항목 | 판단 기준(리포트 문구) | 메우는 방법 |
|---|---|---|
| 접근 로그 없음 | "접근 로그 … 찾지 못했습니다" | 접근 로그 켜기, 또는 에이전트 설정 `*_LOG_PATHS`(-l) |
| 서버 로그 못 찾음 | "server.log 를 찾지 못했습니다" / "catalina 로그를 찾지 못했습니다" | `WILDFLY_SERVER_LOG_PATHS`·`TOMCAT_SERVER_LOG_PATHS`(-s) |
| 웹 파일 위치 못 찾음 | "DocumentRoot 를 찾지 못했습니다" / "배포 폴더를 찾지 못했습니다" | 설정·폴더 확인 |
| OS 로그인 기록 못 읽음 | "OS 로그인 기록(…)을 읽지 못해" | root 로 실행, 로그 위치 확인 |
| 이전 스크립트 결과 | 끝까지 실행됐는데 4-5 OS 로그인 기록 점검이 없음 | 에이전트 재설치 후 다시 점검 |
| root 권한 없이 실행 / 점검 중단 | 데이터 품질 경고와 같은 기준 | 에이전트로 점검(root) / 오류 확인 |

- **에이전트 관리 → 스크립트 칸**: 점검 스크립트 비교에 더해 **에이전트 본체 버전**(WAR 안 `webwas-precheck-agent.sh` 의 `AGENT_VERSION`)과 비교해 낮으면 "재설치 필요"를 표시합니다. 개요의 "스크립트 최신" 타일도 둘 다 최신일 때만 셉니다.

## 지난 점검 대비 · 재설치 안내 (2026-11-10)

- **서버 상세 → [지난 점검 대비] 탭**: 같은 서버(인스턴스)의 바로 전 점검과 비교해 새로 생긴 [위험]·[주의], 해결된 것, 등급이 바뀐 것(주의→위험 등),
  새로 해당하는 미조치 CVE·해결(또는 백포트)된 CVE 를 보여 줍니다. 탭 이름에 `(+새로 생긴 수 / −해결된 수)` 가 표시되고, [이전 점검 열기]로 비교 대상을 엽니다.
  같은 항목인지는 "섹션 + 문구"로 보며 **문구 안의 숫자(건수 등)는 무시**합니다(예: "경로 탐색 시도 3건" → "5건" 은 같은 항목). 문구 자체가 바뀌면(스크립트 업데이트로 표현이 달라진 경우 등) 새로 생김 + 해결됨으로 나올 수 있습니다.
- **에이전트 관리 → 재설치가 필요한 에이전트**: 점검 스크립트가 대시보드와 다르거나 에이전트 본체가 옛 버전인 서버만 모아, 이유와 함께 보여 주고 서버에 붙여 넣을 **재설치 명령(복사 버튼)** 을 함께 표시합니다. 모두 최신이면 카드가 보이지 않습니다.

### 원격 스크립트 업데이트 (버튼, 2026-11-12, 에이전트 2.4.0)

서버에 들어가 명령을 입력하지 않고, 대시보드에서 **버튼 한 번**으로 에이전트의 점검 스크립트를 갱신할 수 있습니다.

- **버튼**: 에이전트 관리 각 행의 **[스크립트 업데이트]**, 또는 "재설치가 필요한 에이전트" 카드의 **[스크립트 업데이트 요청(전체)]**.
- **동작**: 요청하면 그 에이전트가 **다음 heartbeat(1분 이내)** 에 자기 대시보드(`DASHBOARD_URL`)에서 점검 스크립트 4개 + 에이전트 본체를 다시 받아 교체합니다. 받은 파일이 `#!` 로 시작하고 `bash -n`(문법검사)를 통과할 때만 원자적으로 바꿉니다(아니면 기존 유지). 교체 뒤 새 스크립트 해시를 보고해, 화면이 "대시보드와 같음"으로 바뀝니다.
- **버전 조건**: **에이전트 2.4.0 이상**만 지원합니다. 그 이하(기존 설치분)는 이 기능이 없어서, 처음 한 번은 **수동 재설치**로 2.4.0을 올려야 합니다. 이후부터는 버튼으로 됩니다. (버튼은 2.4.0 이상 에이전트에만 보이고, 그 이하는 카드에 "원격 업데이트 미지원 — 수동 재설치 필요"로 표시)
- **보안 주의**: 이 기능은 대시보드가 에이전트에 스크립트(실행 코드)를 내려 보내 교체하게 합니다. 에이전트는 **자기 설정의 대시보드 주소에서만** 받고 문법검사 후 교체하지만, 결국 대시보드가 에이전트의 점검 스크립트를 바꿀 수 있다는 뜻입니다. **대시보드의 관리자 접근을 엄격히 관리하고(HTTPS 권장), 아무나 관리자가 되지 않도록** 하세요.

## 점검 기록 초기화 (관리자, 2026-11-10)

| 위치 | 버튼 | 지우는 범위 |
|---|---|---|
| 서버 상세 창 | 이 점검 삭제 / **이 서버 이력 삭제** | 보고 있는 1건 / 그 서버(인스턴스)의 모든 점검 이력 |
| 에이전트 관리 각 행 | **기록 초기화** | 그 에이전트가 보낸 기록 전체 + 에이전트 상태(마지막 점검·버전·메시지). **등록·토큰·주기는 유지** → 자동 점검 주기가 있으면 1분 안에 다시 점검 |
| 설정 → 점검 기록 초기화 | 범위 선택 후 [초기화…] | 오래된 이력 정리(서버마다 최근 N개만 남김) / 에이전트별 / 제품별 / 전체 |

- 누르면 먼저 지워질 건수·서버 수·앞의 5건을 보여 주고, **`초기화` 를 직접 입력해야** 실행됩니다(서버도 같은 문구를 확인).
- 지운 리포트는 바로 없어지지 않고 `<데이터폴더>/reports-trash/<시각>_<범위>/` 로 옮겨져 **30일** 보관 후 자동으로 비워집니다(`-Dwebwas.precheck.trash.days`, 0 이면 다음 정리 때 바로 비움).
- **되살리기**: 그 휴지통 폴더의 `.txt` 파일을 `<데이터폴더>/reports/` 로 다시 옮기면 화면에 다시 나타납니다. (에이전트 상태는 되살리지 않음 — 다음 점검 때 다시 채워짐)
- 사용자·에이전트 등록·최신 버전 설정·CVE 목록은 지우지 않습니다. 누가 무엇을 지웠는지 서버 로그에 `점검 기록 초기화(...) ... by 아이디` 로 남습니다.
- API: `POST /api/reset` scope=instance|agent|product|old|all, value, dryRun=true(미리보기), confirm=초기화, agentState=true

## 예외(위험 수용) · 서버 목록 CSV 내보내기 (2026-11-10)

**예외(위험 수용)** — 확인을 마치고 "이 항목은 그대로 둔다"고 결정한 [위험]·[주의] 항목을 판정에서 빼는 기능입니다.

1. 서버 상세 창 → 점검 결과의 [위험]·[주의] 항목 아래 **예외 처리** (관리자만 보임)
2. 범위(이 서버만 / 같은 제품 전체), 기간(30·90·180·365일), **사유(필수, 4자 이상)** 입력 → [예외 등록]
3. 그 항목은 서버 판정·위험/주의 건수·설정 취약 항목·CVE 집계에서 빠지고, 점검 결과에는 회색 **예외** 표시와 사유·만료일·등록자로 계속 보입니다. KPI 아래에 "예외 N건 제외"가 표시됩니다.
4. 다음 점검에서 같은 항목이 다시 나와도 예외로 인식합니다(섹션 + 문구로 찾으며, 문구 속 숫자는 무시). **만료일이 지나면 자동으로 다시 경고**합니다.
5. 설정 → **예외(위험 수용) 목록**에서 전체를 보고 [해제]할 수 있습니다. 상세 창의 [예외 해제]도 같습니다.

- **[4] 침해 흔적의 [위험]도 예외 처리할 수 있습니다** (2026-11-11 추가). 단 예외 창에 빨간 경고가 뜨며, 오탐임을 직접 확인한 경우에만 쓰세요. [4] 위험을 모두 예외 처리하면 그 서버는 '침해 의심'에서 빠지고, 항목은 '예외'로 계속 보입니다. 기간이 지나면 다시 '침해 의심'으로 돌아옵니다.
- 예외 처리한 CVE 번호도 서버 목록 검색에서는 찾힙니다.
- 저장: `<데이터폴더>/exceptions.properties`. 등록·해제는 서버 로그에 `예외(위험 수용) 등록/해제 ... by 아이디` 로 남습니다. 점검 기록 초기화로는 지워지지 않습니다.
- 주의: "같은 제품 전체" 범위는 앞으로 새로 붙는 서버에도 적용됩니다. 넓은 범위는 꼭 필요할 때만 쓰세요.
- API: `GET /api/exceptions`, `POST /api/exceptions` (report, section, text, scope=instance|product, days, reason, 관리자), `DELETE /api/exceptions/{id}` (관리자)

**CSV 내보내기** — 서버 목록 화면의 [CSV 내보내기]. 에이전트 관리 화면에도 [CSV 내보내기]가 있어 **등록된 에이전트(서버) 목록**(상태·그룹·호스트·IP·마지막 점검·점검 제품·버전·주기·스크립트 일치·에이전트 버전 등)을 엑셀로 받을 수 있습니다. 서버 목록 CSV는 지금 걸러진 목록(검색·판정·제품·필터·정렬 그대로)을 엑셀에서 바로 열리는 CSV(UTF-8 BOM)로 저장합니다. 항목: 판정, 제품, 호스트, IP, 바이너리, 버전·버전 상태, 점검 시각, 위험/주의/양호(예외 뺀 값), 예외 건수, 미반영 CVE 등급별 건수, 점검 사각지대, 데이터 경고, 수집 방식, 리포트 이름. 브라우저에서 만들어지므로 서버에 따로 기록되지 않습니다.

## 개요 화면을 왼쪽 바 메뉴로 세분화 (2026-11-11)

왼쪽 바에 개요용 메뉴 4개를 두었습니다(서버·에이전트·설정과 같은 방식). **요약은 예전 개요 화면 그대로 모든 카드를 다 보여주고**, 나머지 3개는 그 중 일부만 골라 집중해서 봅니다.

- **요약**: 예전 개요 화면 전체(핵심 지표·서버 현황판·일자별 건수·최신 버전 적용률·설정 취약·에이전트 상태·판정 분포·에이전트 서버·침해 상태·사각지대·CVE)
- **침해**: 침해 상태 · 점검 사각지대
- **취약점**: CVE별 해당 서버 · 설정 취약 항목
- **현황**: 최신 버전 적용률 · 일자별 점검 건수 · 에이전트 상태 · 에이전트 서버·다음 점검

같은 카드를 메뉴에 따라 보여주거나 숨기는 방식이라(요약=전부, 나머지=일부), 데이터·판정은 그대로입니다. 모바일에서는 아래 탭바에 같은 메뉴가 나오며 가로로 넘기면 됩니다. 화면 구성만 바뀐 것이라 에이전트 재설치는 필요 없습니다.

- **왼쪽 바 메뉴 순서 바꾸기**: 왼쪽 바의 메뉴를 **마우스로 위아래로 끌어** 순서를 바꿀 수 있습니다. 바뀐 순서는 브라우저에 저장되어 다음에도 유지되고, 모바일 아래 탭바에도 같은 순서로 반영됩니다.
- **침해·취약점·현황 화면**: 카드를 2열로 **꽉 채우고 박스 높이를 같게 맞춰**(아래 선 정렬) 보기 좋게 정리했습니다. 좁은 화면에서는 1열로 바뀝니다.

## 서버 그룹(에이전트 라벨) (2026-11-11)

에이전트마다 **그룹 이름**을 달아 서버를 묶어 볼 수 있습니다(예: `HAPPY`, `SAMPLE`). 대시보드 전용 기능이라 **에이전트 재설치는 필요 없습니다.**

- **지정**: [에이전트 추가] 때 "그룹(선택)" 칸에 입력하거나, 에이전트 관리 각 행의 **[그룹]** 버튼으로 나중에 바꿉니다. 비우면 그룹에서 빠집니다. 한글·영문·숫자 모두 쓸 수 있고 30자까지입니다.
- **보기**: 서버 목록 화면에 **그룹 드롭다운**이 생겨 그 그룹의 서버만 모아 봅니다. 각 행 호스트 옆과 에이전트 목록에 그룹 라벨이 표시됩니다. 검색창에서도 그룹 이름으로 찾힙니다. **CSV 내보내기**에 "그룹" 칸이 추가됩니다.
- 저장: 그룹은 에이전트 정보(`<데이터폴더>/agents.properties`)에 저장됩니다. 리포트가 아니라 **에이전트(서버)에 붙는 꼬리표**라, 같은 에이전트가 보낸 과거 리포트도 모두 그 그룹으로 묶입니다.
- API: `POST /api/agents/{name}/group` (group=, 관리자), 에이전트 등록 시 `group=` 파라미터.

### IP 자동 그룹 규칙 (2026-11-11)

IP 대역으로 그룹을 **자동 지정**할 수도 있습니다. 설정 → **IP 자동 그룹 규칙**(관리자)에서 패턴과 그룹 이름을 넣습니다.

- 패턴: `10.10.10.0/24`(CIDR) · `10.10.*`(= `10.10.*.*`) · `10.10.10.10`(정확한 IP). **IPv4 전용**입니다.
- **우선순위**: ① 에이전트에 직접 지정한 그룹(수동 라벨)이 있으면 그것, ② 없으면 IP 규칙 중 **위에서부터 먼저 맞는** 규칙, ③ 둘 다 없으면 그룹 없음.
- 판정 IP: 리포트에 기록된 서버 IP(없으면 에이전트 접속 IP). 규칙에 맞으면 **새로 등록하는 서버도 자동으로** 묶입니다.
- 저장: `<데이터폴더>/ipgroups.properties`. 규칙을 바꾸면 서버 목록·필터·CSV에 바로 반영됩니다.
- 한계: IPv6은 지원하지 않습니다. NAT·프록시 뒤라 접속 IP가 실제 서버 IP와 다르면 규칙이 안 맞을 수 있으니, 그런 서버는 수동 라벨을 쓰세요.
- API: `GET /api/ip-groups`, `POST /api/ip-groups`(pattern=, group=, 관리자), `DELETE /api/ip-groups/{순서번호}`(관리자)

> 에이전트 이름에 **밑줄(`_`)**을 쓸 수 있습니다(예: `web_01`). 단 리포트 파일명 구분자(`__`)와 겹치는 **연속 밑줄(`__`)**은 쓸 수 없습니다.

## [4] 실행계정 크론 판정 세분화 (2026-11-11)

예전에는 실행계정(web/was 등)에 등록된 크론이 **하나라도 있으면 무조건 [위험]**("지속성 확보 의심")이었습니다. 로그 압축·백업 같은 정상 운영 작업까지 [위험]으로 떠서 오탐이 잦았습니다. 이제 크론 **명령 내용**을 보고 나눕니다(4개 스크립트 공통).

- **[위험]**: 공격자 지속성 전형 패턴 — 파이프로 셸 실행(`… | sh`/`| bash`), 리버스쉘(`/dev/tcp/`, `ncat`/`netcat`, `nc -…`, `bash -i`, `mkfifo`), 인코딩 실행(`base64 -d`), 인터프리터 인라인 코드(`python -c`, `perl -e`, `php -r`, `ruby -e`), 임시폴더 실행(`/tmp`·`/var/tmp`·`/dev/shm`의 스크립트). 해당 줄을 따로 보여 줍니다.
- **[주의]**: 위 패턴이 아닌 그 밖의 크론 → "정상 운영 작업(로그 압축·백업·정리 등)인지 명령 내용 확인 필요". 숨기지 않고 등록된 줄을 모두 보여 주므로 관리자가 직접 확인합니다.
- 실행계정이 root면 예전처럼 계정 기준 크론 점검은 생략합니다(의미가 없어서).
- 주의: 패턴 기반이라 **우회 가능**합니다. 평범해 보이는 스크립트 경로(`/home/was/shell/x.sh`) 뒤에 악성 코드가 들어갈 수 있으므로, [주의]로 나온 크론도 내용은 꼭 확인하세요. 이 변경은 점검 스크립트 수정이므로 **에이전트 재설치가 필요**합니다.

## 서버 수백 대 운영 시 동작 (2026-11-05 개선)

에이전트 1대당 리포트를 최근 30개까지 보관하므로 서버 300대면 리포트가 약 9,000개 쌓입니다. 이 규모에서 측정해 고쳤습니다.

| 항목 (리포트 9,000개 = 300대 × 25일) | 이전 | 지금 |
|---|---|---|
| 화면이 30초마다 받는 데이터 | 31.7MB (전체 이력) | 약 0.1MB (인스턴스별 최신만, gzip 압축). 바뀐 것이 없으면 0바이트(304) |
| 응답 시간 | 1.3~6.1초 | 약 0.13초 |
| 대시보드 메모리(GC 후) | 약 249MB | 약 160MB (리포트 원문은 메모리에 두지 않고 상세·PDF 때 파일에서 읽음) |
| 첫 화면 | 2.0초 | 0.5~0.9초 |
| 서버 목록 "인스턴스별 최신만" 끄기 | 9,000줄 10.9초, 검색 3.4초 | 500줄씩 표시 + "더 보기", 2.4초, 검색 0.4초 |

- 점검 이력(상세 → 점검 이력)과 전체 이력은 **필요할 때만** 따로 받습니다.
- 일자별 차트(점검 건수, 침해 의심 추이)는 대시보드가 날짜별 숫자만 계산해 보냅니다.
- 측정값은 이 저장소 작업 환경(대시보드와 브라우저가 같은 PC)에서 잰 것입니다. 사내망에서는 받는 시간이 더 걸립니다.

## CVE 목록 자동 업데이트 — 어떻게 동작하나

| 제품 | 출처 (대시보드가 받는 곳) | 변환 규칙 |
|---|---|---|
| Apache | `https://httpd.apache.org/security/vulnerabilities-httpd.json` (Apache 보안팀이 공개하는 전체 CVE JSON) | 2.4.x 에 영향이 있는 CVE 만. **스크립트에 들어 있는 사람이 정리한 목록(한글 설명·필요 모듈)은 그대로 두고, 새 CVE 만 추가**. 새 CVE 의 필요 모듈은 제목·설명의 `mod_xxx` 로 추정하고, 못 찾으면 `core`(항상 해당)로 보수적으로 판정 |
| WildFly | `https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip` (OSV, 약 10MB) | 기존 `tools/gen_cve_table.py` 와 **같은 규칙**을 Java 로 옮김 (시험: 같은 데이터로 두 결과 149줄이 완전히 일치) |
| Tomcat | 위와 같은 OSV 파일 (`org.apache.tomcat*` 패키지) | Tomcat 본체는 항상 해당, 선택 구성요소(jasper·websocket·tribes·jmx-remote·coyote-ffm)는 `lib/` 에 jar 가 있을 때만 해당 |

- **Apache 대체 경로**: `httpd.apache.org` 에 접속하지 못하면 Apache 웹사이트 원본 저장소(github.com/apache/httpd-site, `api.github.com` 폴더 목록 + `raw.githubusercontent.com` 파일)에서 같은 CVE JSON 을 받아 씁니다. 설정 화면에 "github.com/apache/httpd-site (대체 경로)" 로 표시. 끄려면 `-Dwebwas.precheck.cve.apache.fallback=off`.
- **실제 데이터 검증 (2026-11-05)**: Apache 웹사이트 원본의 CVE JSON 288건(2026-10-29 기준)으로 변환해 보니 2.4.x 영향 CVE 180건, 스크립트에 사람이 정리해 둔 38건은 **영향 버전·등급이 모두 일치**(다름 0, 빠짐 0), 새로 추가되는 CVE 142건. 이 데이터는 테스트 자료로 넣어 두어 `mvn test` 때마다 다시 확인합니다.
- 받은 데이터가 이상하면(0건, 형식 오류, 접속 실패) **이전 목록을 그대로 쓰고** 설정 화면에 "최근 갱신 실패"로 표시합니다. 이전 목록도 없으면 스크립트 내장 목록을 씁니다.
- 에이전트가 목록을 못 받으면 **지난번에 받은 목록 → 스크립트 내장 목록** 순서로 씁니다. 리포트 상세 화면에 어떤 목록으로 판정했는지(`CVE 목록: 대시보드 자동 업데이트본 (생성 …)`) 나옵니다.
- 스크립트는 받은 목록에서 **정해진 형식에 맞는 줄만** 읽습니다(명령으로 실행하지 않음, 데이터로만 사용).
- **인터넷이 막힌 대시보드**: 관리자가 위 두 파일을 받아 대시보드 서버에 두고 주소를 `file:` 로 지정합니다.
  ```bash
  -Dwebwas.precheck.cve.apache.url=file:/data/cve-src/vulnerabilities-httpd.json
  -Dwebwas.precheck.cve.osv.url=file:/data/cve-src/all.zip
  ```
  (자동 업데이트를 아예 끄려면 `-Dwebwas.precheck.cve.auto=false`)
- 설정 화면 **CVE 목록 자동 업데이트** 카드: 제품별로 지금 쓰는 목록(자동 업데이트본/내장본), CVE 수, 내장 목록 대비 추가 건수, 마지막 확인 시각, **지금 받기**·**받기(파일)** 버튼.
  받은 파일은 에이전트 없이 직접 점검할 때 `sudo bash tomcat_precheck.sh -C tomcat_cve.txt` 처럼 쓸 수 있습니다.

**한계 (꼭 읽어 주세요)**
- 자동 목록의 설명은 원문(영문)입니다. Apache 새 CVE 의 "필요 모듈"은 추정이라 틀릴 수 있습니다(틀리면 대개 "해당"으로 더 많이 잡힘).
- OSV/Apache 데이터에 아직 올라오지 않은 취약점은 판정되지 않습니다. 버전 비교 기준이므로 **패키지(RPM/DEB) 설치본의 배포판 백포트**는 Apache 만 changelog 로 추정하고, Tomcat·WildFly 패키지는 배포판 보안 공지로 확인해야 합니다.

## Nginx 점검 항목 (nginx_precheck.sh, 2026-11-10 추가)

| 구분 | 내용 |
|---|---|
| [1] 버전 | `nginx -v`(OpenResty 등은 앞 세 자리), 설치 방식(RPM·DEB·소스), **stable 기준 판정**: stable 최신(예: 1.30.6)과 같은 브랜치면 그 최신과 비교, stable 보다 새 mainline(1.31.x)은 최신으로 봄(mainline 최신 여부는 따로 확인), 그 밖의 브랜치(예: 1.24·1.28, 지난 mainline 1.29)는 "지원 종료(EOL)" — 소스 설치는 [위험], 배포판 패키지는 [주의](배포판 백포트 가능) |
| [2] CVE | nginx.org 보안 공지의 영향 버전·수정 버전으로 판정하고, 설정에서 그 기능(HTTP/3·HTTP/2·mp4·mail·resolver·SSI 등)을 쓰지 않으면 [미해당]. 패키지 설치본은 changelog 에 CVE 번호가 있으면 "백포트 추정" |
| [3] 설정 | `nginx -T`(실제로 읽는 설정 전체, 실패 시 include 직접 추적) 기준: server_tokens(버전 노출), autoindex, SSLv3·TLSv1.0/1.1, 약한 암호, **alias 경로 탐색(off-by-slash)**, 접근 제한 없는 stub_status, PHP location 의 try_files 누락, WebDAV 쓰기 메서드, proxy_pass 에 $host 등 요청 값(SSRF), 워커 root 실행, 설정 파일·개인키 권한 |
| [4] 침해 흔적 | access_log(이 인스턴스가 연 파일·회전 파일 포함)의 경로 탐색·명령 실행·JNDI 요청, root·alias 폴더의 웹쉘 의심 파일·최근 변경 파일, 웹 실행계정의 의심 프로세스·크론·임시 파일·외부 연결, OS 로그인 기록 |

옵션: `-b nginx경로` `-c 설정파일` `-d 일수` `-l '접근로그경로'` `-C CVE목록파일`. 옵션 없이 실행하면 실행 중인 nginx 마스터를 찾고, 여러 개(-c 가 다른 인스턴스)면 각각 점검합니다.
에이전트 설정: `NGINX_LOG_PATHS`(-l). 에이전트는 `nginx: master process` 가 실행 중이면 자동으로 Nginx 를 점검합니다(에이전트 2.3.0 이상).

- **CVE 출처**: https://nginx.org/en/security_advisories.html 의 원본 XML(`raw.githubusercontent.com/nginx/nginx.org/main/xml/en/security_advisories.xml`). 대시보드가 12시간마다 받아 `/agent-api/cve/nginx` 로 내려 주며, 주소는 `-Dwebwas.precheck.cve.nginx.url` 로 바꿀 수 있습니다. `<item>` 68개 중 CVE 번호가 없는 Windows 전용 1건과 등급 none(취약점 아님) 1건을 뺀 66건(2026-11-10).
- **최신 버전 출처**: nginx.org 다운로드 페이지의 원본 XML(`xml/versions.xml`)의 **stable 첫 항목만**(2026-11-10: 1.30.6). 화면·판정 모두 stable 기준이며, 수동 지정이나 예전에 저장된 값에 mainline(두 번째 숫자가 홀수)이 섞여 있어도 stable 만 씁니다. `-Dwebwas.precheck.latest.nginx.url` 로 변경 가능.
- **필요 기능은 공지 제목으로 정한 추정**입니다(`tools/gen_nginx_cve.py` 와 `CveFeed.nginxFeature` 가 같은 규칙, 테스트로 일치 확인). 예: 제목에 HTTP/3 → `listen ... quic` 또는 `http3 on` 을 쓸 때만 해당.
- 시험: Ubuntu 24.04 nginx 1.24.0(DEB)에 위험 설정·웹쉘·공격 로그를 넣어 실행 → alias 경로 탐색 [위험], 웹쉘·공격 성공 로그 [위험](침해 의심), 해당 CVE 5건 모두 Ubuntu changelog 기준 백포트 추정, 두 인스턴스 각각 점검 확인.

## Tomcat 점검 항목 (tomcat_precheck.sh)

| 구분 | 내용 |
|---|---|
| [1] 버전 | `lib/catalina.jar` 의 ServerInfo(server.info 를 숨겼으면 server.number) → RELEASE-NOTES 순서로 버전 확인. **브랜치별 최신**(11.0/10.1/9.0)과 비교하고, 지원 목록에 없는 브랜치(8.5, 10.0 등)는 "지원 종료(EOL)" [위험] |
| [2] CVE | 위 "CVE 목록" 기준. 예: 9.0.80 → CVE-2025-24813(partial PUT RCE) 등 45건 |
| [3] 설정 | 셧다운 포트(기본 명령어 SHUTDOWN), **AJP 커넥터 secret 미설정(Ghostcat 류)**, 관리자 앱(manager/host-manager) IP 제한 없음, `tomcat-users.xml` 의 쉬운 비밀번호·평문 저장, 예제/문서 앱·기본 ROOT 페이지, DefaultServlet `readonly=false`(PUT 업로드)·`listings=true`, CGI 서블릿, 오류 페이지 버전 노출(ErrorReportValve), HTTP 헤더 버전 노출, 원격 디버그(JDWP)·JMX 무인증, root 실행, 파일 권한 |
| [4] 침해 흔적 | 접근 로그(AccessLogValve)의 경로 탐색·명령 실행·JNDI 주입·**관리자 앱 WAR 배포/PUT JSP 업로드 성공**, webapps(및 conf/Catalina/*/*.xml 이 가리키는 폴더)의 웹쉘 의심 JSP(war 안 포함), 최근 변경 파일, catalina 로그의 역직렬화·JNDI 흔적, 실행 계정의 의심 프로세스·크론·임시 파일·외부 연결, **OS 로그인 기록**(아래) |

옵션: `-H 설치폴더`(CATALINA_HOME) `-B 인스턴스폴더`(CATALINA_BASE) `-d 일수` `-l '접근로그경로'` `-s '서버로그경로'` `-C CVE목록파일`. 옵션 없이 실행하면 실행 중인 Tomcat 을 자동으로 찾고, 여러 개면 각각 점검합니다.

### 서버 로그 위치 지정 (-s, WildFly·Tomcat) · OS 로그인 기록 점검 (Apache·WildFly·Tomcat, 2026-11-10)

- **`-s '경로'`**: server.log(WildFly)·catalina.out 등(Tomcat)이 표준 위치가 아닐 때 지정합니다. 자동으로 찾는 곳에 **더해서** 읽습니다(와일드카드 가능, 작은따옴표로 감쌀 것).
  에이전트는 설정 파일의 `WILDFLY_SERVER_LOG_PATHS`·`TOMCAT_SERVER_LOG_PATHS` 값을 넘깁니다(에이전트 2.2.0 이상).
- **4-5 OS 로그인 기록**: `/var/log/secure*`(RHEL/Rocky) 또는 `/var/log/auth.log*`(Debian/Ubuntu) 중 최근 `-d`일 안에 바뀐 파일, 없으면 journal 의 auth/authpriv 기록을 읽습니다. root 권한이 필요합니다.

| 판정 | 내용 |
|---|---|
| [위험] | 같은 IP 에서 **1시간 안에 SSH 로그인 실패 10회 이상 → 그 IP 로 로그인 성공** (비밀번호 맞히기 공격 성공 의심) |
| [주의] | 실패가 많았던 IP 에서 로그인 성공(1시간 밖) / 실행 계정으로 SSH 직접 로그인 / 실행 계정의 sudo 사용·시도 / 계정 생성·변경·비밀번호 변경 |
| [정보] | su 로 실행 계정에 전환한 기록, 로그인 실패가 많은 IP 상위 5개 |

같은 서버에 제품이 여러 개(예: Apache + WildFly)면 로그인 기록 점검 결과가 제품별 리포트마다 똑같이 나옵니다(서버 단위 기록이므로).
한계: SSH(sshd) 로그인만 봅니다(콘솔·FTP 등 제외). 로그 형식이 표준(OpenSSH)과 다르거나 로그가 원격 서버로만 가면 탐지하지 못합니다. 실행 계정이 root 이면 계정 기준 항목(직접 로그인·sudo·su)은 생략합니다.
Apache 스크립트에는 `-C` 옵션·대시보드 CVE 목록 받기·위의 OS 로그인 기록 점검이, WildFly 스크립트에는 그에 더해 `-s` 옵션이 추가되었습니다.

## 1. 준비물

| 항목 | 확인 방법 | 비고 |
|---|---|---|
| Java 17 이상 | `java -version` | 빌드·실행용 (시험은 Java 21) |
| Maven 3.8 이상 | `mvn -v` | 빌드할 PC에만 필요 |
| WildFly | 대시보드를 올릴 WildFly | 기존과 같음 (jakarta Servlet 6 지원 버전) |
| 점검 대상 서버 | bash, curl, flock, (권장) unzip 또는 python3, ss | unzip/python3 이 없으면 Tomcat 버전(catalina.jar)을 RELEASE-NOTES 로 대신 읽고, war 안 JSP 점검은 생략(데이터 경고 표시) |
| 대시보드 서버의 인터넷(또는 사내 미러) | 아래 주소로 접속 가능 | `httpd.apache.org`, `osv-vulnerabilities.storage.googleapis.com`, `downloads.apache.org`, `repo1.maven.org` — 안 되면 "file:" 주소 또는 직접 지정 |

## 2. 빌드

```bash
cd webwas-precheck-dashboard
mvn package
```

`BUILD SUCCESS` 가 보이면 `target/webwas-precheck.war` 가 생깁니다.

## 3. 배포

기존 대시보드와 같은 방법이고, **이름만 바뀌었습니다.**

| 항목 | 기존 Apache / WildFly | 통합본 |
|---|---|---|
| WAR / 접속 주소 | `precheck.war` / `wfprecheck.war` | `webwas-precheck.war` → `http://<서버>:8080/webwas-precheck/` |
| 데이터 폴더 설정 | `-Dprecheck.data.dir` / `-Dwfprecheck.data.dir` | `-Dwebwas.precheck.data.dir=/data/webwas-precheck` (환경변수 `WEBWAS_PRECHECK_DATA_DIR`) |
| 기본 데이터 폴더 | `~/precheck-dashboard` 등 | 실행 계정 홈의 `webwas-precheck` |
| 초기 관리자 비밀번호 환경변수 | `PRECHECK_ADMIN_PASSWORD` 등 | `WEBWAS_PRECHECK_ADMIN_PASSWORD` |

1. WildFly 실행 계정 확인: `ps -eo user,args | grep '[j]boss-modules' | awk '{print $1}'` (예: `was`)
2. 데이터 폴더 만들기
   ```bash
   sudo mkdir -p /data/webwas-precheck
   sudo chown was: /data/webwas-precheck
   sudo chmod 700 /data/webwas-precheck
   ```
3. WildFly 에 데이터 폴더 알려 주기 (관리 CLI, WildFly 켜진 상태에서 한 번)
   ```bash
   <WildFly설치경로>/bin/jboss-cli.sh --connect --controller=127.0.0.1:9990 \
     --command='/system-property=webwas.precheck.data.dir:add(value=/data/webwas-precheck)'
   ```
4. WildFly 재시작 후 배포: `cp target/webwas-precheck.war <WildFly설치경로>/standalone/deployments/`
5. 확인: `sudo grep "데이터 폴더" <server.log 경로> | tail -1` → `데이터 폴더: /data/webwas-precheck` 가 나와야 합니다.
6. 첫 로그인: `sudo cat /data/webwas-precheck/initial-admin-password.txt` 의 `admin` 비밀번호로 로그인 → 비밀번호 변경 화면이 먼저 나옵니다.

**기존 대시보드의 리포트 옮기기**: 기존 데이터 폴더의 `reports/*.txt` 를 새 데이터 폴더의 `reports/` 에 복사하면 됩니다(형식이 같아 그대로 읽힘).
계정·에이전트 정보는 옮기지 않으므로 에이전트는 새로 등록해야 합니다(아래 4번).

## 4. 에이전트 설치 (점검할 서버마다 한 번, 제품이 여러 개여도 한 번)

0. (필요할 때) **에이전트 접속 주소** 지정: 설치 명령의 주소는 기본으로 브라우저 주소창의 주소를 씁니다. 관리자는 `https://...` 로 접속하지만 점검 서버는 `http://대시보드IP:8580/webwas-precheck` 로 붙어야 하는 경우처럼 다르면,
   에이전트 화면 위쪽 **에이전트 접속 주소** 칸에 적고 [저장]합니다(데이터 폴더의 `settings.properties` 에 저장, 관리자 전원에게 같게 적용). [비우기]를 누르면 다시 브라우저 주소를 씁니다.
   카드에 나오는 `curl ... -w "%{http_code}"` 명령을 점검 서버에서 먼저 실행해 `200` 이 나오는지 확인하세요. 셸 명령에 그대로 들어가므로 공백·따옴표·`;` `$` 등이 든 주소는 거부합니다.
   이미 설치된 에이전트의 주소는 바뀌지 않습니다(각 서버의 `/etc/webwas-precheck-agent.conf` 의 `DASHBOARD_URL`).
1. 대시보드 → **에이전트** → **에이전트 추가** → 이름(예: `web02`) 입력 → **등록**
2. 화면의 명령 한 줄을 점검할 서버에서 실행(복사 버튼 사용), 토큰을 물으면 화면의 토큰을 입력하고 Enter
   - **토큰은 입력하기 쉬운 20자**(예: `2B377-LHNSU-EQTLA-AUMSR`)입니다. 헷갈리는 `0·1·I·O` 를 뺐고, **대소문자·하이픈(-)은 구분하지 않습니다.** 폐쇄망이라 붙여넣기가 안 되면 화면 보고 그대로 입력하면 됩니다.
   - (참고) 기존에 발급한 긴 토큰도 그대로 동작합니다. 짧은 토큰은 새로 등록하거나 [토큰 재발급]한 에이전트부터 적용됩니다.
   ```bash
   D=$(mktemp -d) && curl -fsSo "$D/install.sh" http://<대시보드주소>/webwas-precheck/agent-api/files/install.sh && sudo bash "$D/install.sh" http://<대시보드주소>/webwas-precheck web02
   ```
   설치 파일은 **빈 폴더**(`mktemp -d`)에 받습니다. install.sh 는 같은 폴더에 점검 스크립트가 있으면 그것을 먼저 쓰므로, `/tmp` 에 예전 스크립트가 남아 있으면 옛 버전이 설치됩니다.
   HTTPS 를 켠 대시보드면 `https://…` 주소와 `--ca-cert CA파일`(curl 은 `--cacert`)을 쓰는 것이 안전합니다(HTTP 는 토큰이 암호화되지 않음).
3. `설치 완료` 후 1~2분 안에 **온라인**이 되고 첫 점검이 시작됩니다.

| 설치되는 것 | 내용 |
|---|---|
| `/opt/webwas-precheck-agent/` | 에이전트, 점검 스크립트 3개, 받은 CVE 목록(`cve/`), 보낸 리포트(`sent/`), 전송 대기(`outbox/`) |
| `/etc/webwas-precheck-agent.conf` | 주소·이름·토큰(권한 600), `PRODUCTS`, `RECENT_DAYS`, `RUN_TIMEOUT`, `APACHE_LOG_PATHS`·`WILDFLY_LOG_PATHS`·`TOMCAT_LOG_PATHS`(접근 로그, -l), `WILDFLY_SERVER_LOG_PATHS`·`TOMCAT_SERVER_LOG_PATHS`(서버 로그, -s) |
| systemd 타이머 `webwas-precheck-agent.timer` | 1분마다 실행 (없으면 `/etc/cron.d/webwas-precheck-agent`) |

```bash
sudo /opt/webwas-precheck-agent/webwas-precheck-agent.sh detect   # 이 서버에서 점검할 제품 확인
sudo /opt/webwas-precheck-agent/webwas-precheck-agent.sh test     # 대시보드 연결 확인
sudo /opt/webwas-precheck-agent/webwas-precheck-agent.sh run      # 지금 바로 점검
sudo bash /tmp/webwas-precheck-install.sh --uninstall             # 에이전트 삭제
```

- 제품이 꺼져 있어도 점검하려면 설정 파일의 `PRODUCTS=auto` 를 `PRODUCTS="apache tomcat"` 처럼 바꿉니다.
- **에이전트 재설치(업데이트)** — 대시보드에 새 WAR 를 먼저 배포한 뒤, 점검 서버에서 `sudo -i` 로 root 가 되어 아래를 붙여 넣습니다.
  기존 설정 파일에서 주소·이름·토큰을 읽으므로 토큰을 새로 발급할 필요가 없고, PRODUCTS·로그 경로 같은 설정도 유지됩니다.
  ```bash
  F=/etc/webwas-precheck-agent.conf
  U=$(sed -n "s/^DASHBOARD_URL='\(.*\)'$/\1/p" $F)
  N=$(sed -n "s/^AGENT_NAME='\(.*\)'$/\1/p" $F)
  T=$(sed -n "s/^AGENT_TOKEN='\(.*\)'$/\1/p" $F)
  C=$(sed -n "s/^CA_CERT='\(.*\)'$/\1/p" $F)
  D=$(mktemp -d)
  echo "대시보드: $U / 에이전트: $N / 받는 폴더: $D"
  curl -fsSo "$D/install.sh" ${C:+--cacert "$C"} "$U/agent-api/files/install.sh" && PRECHECK_AGENT_TOKEN="$T" bash "$D/install.sh" "$U" "$N" ${C:+--ca-cert "$C"}
  ```
  빈 폴더(`mktemp -d`)에 받는 이유: install.sh 는 **같은 폴더에 점검 스크립트가 있으면 그 파일을 먼저 씁니다.** `/tmp` 에 옛 스크립트가 남아 있으면 옛 버전이 설치됩니다.
  출력에 `wildfly_precheck.sh : 대시보드에서 받음` 이 보여야 합니다.
  확인: `grep '^AGENT_VERSION' /opt/webwas-precheck-agent/webwas-precheck-agent.sh` → `2.2.0` 이상.
  HTTPS 로 바꿀 때는 `U=` 줄 대신 `U=https://<대시보드주소>:8443/webwas-precheck`, `C=` 줄 대신 `C=/경로/dashboard-ca.pem` 처럼 직접 넣습니다.
- 기존 Apache/WildFly 에이전트(`/opt/precheck-agent`, `/opt/wfprecheck-agent`)는 각 설치 파일의 `--uninstall` 로 지운 뒤 새 에이전트를 설치하세요(같이 두면 이중 점검됩니다).
- "점검한 제품이 모두 최신인 서버는 자동 점검 제외"는 **그 서버의 모든 제품·인스턴스가 최신**일 때만 적용됩니다.

## 5. 리포트 직접 넣기 (에이전트를 쓸 수 없는 서버)

```bash
sudo bash apache_precheck.sh
sudo bash wildfly_precheck.sh            # 꺼져 있으면 -H /opt/wildfly
sudo bash tomcat_precheck.sh             # 꺼져 있으면 -H /opt/tomcat
sudo bash tomcat_precheck.sh -C tomcat_cve.txt   # 대시보드에서 받은 최신 CVE 목록으로 점검
```
만들어진 `/tmp/<제품>_precheck_*.txt` 를 대시보드 **리포트 업로드**로 올립니다(관리자만, 파일당 5MB 이하).

## 6. 최신 버전 자동 확인 (설정 → 제품별 최신 버전)

| 제품 | 자동 확인 주소 (12시간마다) | 주소 바꾸기 |
|---|---|---|
| Apache | `https://downloads.apache.org/httpd/` 의 `httpd-2.4.N.tar.gz` | `-Dwebwas.precheck.latest.apache.url=` |
| WildFly | Maven Central `org/wildfly/wildfly-dist/maven-metadata.xml` 의 `N.N.N.Final` | `-Dwebwas.precheck.latest.wildfly.url=` |
| Tomcat | `https://downloads.apache.org/tomcat/` 의 `tomcat-N/vX.Y.Z/` (브랜치별) | `-Dwebwas.precheck.latest.tomcat.url=` (`.xml` 로 끝나면 Maven 목록으로 읽고 높은 메이저 3개를 지원 중으로 봄) |

자동 확인이 안 되면 스크립트 기준값을 쓰며, 내부망이면 **직접 지정**으로 넣습니다(Tomcat 은 `11.0.27, 10.1.61, 9.0.123` 처럼).

## 7. 운영 시 주의

- **HTTPS 로 운영하세요.** 리포트에 서버 경로·설정·공격 IP 가 들어 있고, 설치 파일·CVE 목록은 로그인 없이 받을 수 있어 HTTP 면 바꿔치기될 수 있습니다. 아래 "HTTPS 적용" 참고. 관리자가 HTTP 로 접속하면 화면 위에 경고가 나옵니다.
- **"지금 점검"을 눌러도 오프라인 그대로일 때**: 대시보드는 에이전트에게 명령을 보내지 않고, 에이전트가 1분마다 접속할 때 "차례"를 알려 주는 방식입니다. 그래서 오프라인 에이전트는 요청이 저장만 되고("점검 요청됨 · 접속 대기"), 에이전트가 다시 접속해야 시작됩니다. 상태 칸에 "토큰 인증 실패 중"이 보이면 접속은 되는데 토큰이 틀린 것이니 **토큰 재발급**, 아무 표시가 없으면 그 서버에서 타이머·연결을 확인합니다(`sudo systemctl status webwas-precheck-agent.timer`, `sudo /opt/webwas-precheck-agent/webwas-precheck-agent.sh test`).
- **오프라인 에이전트 알림**: 3분 넘게 접속하지 않은 에이전트가 있으면 모든 화면 위에 이름·마지막 접속 시각과 함께 알림이 나옵니다(오래 끊긴 순).
- **직접 업로드한 리포트 보관 개수**: 인스턴스(호스트·제품·설치 폴더)마다 최근 30개만 남기고 오래된 것은 업로드할 때 자동 삭제합니다(에이전트 리포트와 같은 기준). `-Dwebwas.precheck.keep.uploads=개수`(0 = 제한 없음). 에이전트가 보낸 리포트는 이 설정과 관계없이 에이전트마다 30개.

## 8. HTTPS 적용 (단계별)

> ⚠️ 아래 WildFly 명령은 WildFly 27 이상의 기본 설정(standalone.xml, Elytron)을 기준으로 작성했고, **이 저장소 작업 환경에서는 WildFly 를 실행할 수 없어 직접 시험하지 못했습니다.** 운영 서버에 바로 적용하기 전에 시험 서버에서 먼저 해 보세요.
> 대시보드 앞에 Apache/Nginx/L4 같은 장비가 있고 거기서 HTTPS 를 처리한다면 1~3단계 대신 그 장비에 인증서를 넣고, 장비가 `X-Forwarded-Proto: https` 헤더를 보내게 한 뒤 4단계만 하면 됩니다.

**1. 인증서 준비** — 회사 인증서(.p12/.pfx)가 있으면 그것을 쓰고, 없으면 시험용 자체 서명 인증서를 만듭니다. (`dashboard.example.com`, `10.0.0.5` 는 실제 대시보드 주소로 바꾸기)
```bash
sudo mkdir -p /data/webwas-precheck-tls && sudo chown was: /data/webwas-precheck-tls && sudo chmod 700 /data/webwas-precheck-tls
```
```bash
sudo -u was keytool -genkeypair -alias dashboard -keyalg RSA -keysize 2048 -validity 825 -storetype PKCS12 \
  -keystore /data/webwas-precheck-tls/dashboard.p12 -storepass '강한비밀번호' \
  -dname "CN=dashboard.example.com" -ext "SAN=dns:dashboard.example.com,ip:10.0.0.5"
```

**2. WildFly 에 인증서 등록** (WildFly 가 켜진 상태에서, 관리 CLI 접속)
```bash
<WildFly설치경로>/bin/jboss-cli.sh --connect --controller=127.0.0.1:9990
```
CLI 안에서 한 줄씩 입력합니다.
```
/subsystem=elytron/key-store=dashKS:add(path=/data/webwas-precheck-tls/dashboard.p12, type=PKCS12, credential-reference={clear-text="강한비밀번호"})
/subsystem=elytron/key-manager=dashKM:add(key-store=dashKS, credential-reference={clear-text="강한비밀번호"})
/subsystem=elytron/server-ssl-context=dashSSC:add(key-manager=dashKM, protocols=["TLSv1.3","TLSv1.2"])
/subsystem=undertow/server=default-server/https-listener=https:write-attribute(name=ssl-context, value=dashSSC)
reload
```
**3. 확인** — 브라우저에서 `https://<대시보드주소>:8443/webwas-precheck/` 가 열리면 성공 (자체 서명 인증서면 브라우저 경고가 나오는 것이 정상)

**4. 대시보드를 HTTPS 전용으로** — HTTP 로 들어오면 HTTPS 로 이동, 로그인 쿠키 Secure, HSTS. (HTTPS 포트가 8443 이 아니면 `webwas.precheck.https.port` 도 지정)
```bash
<WildFly설치경로>/bin/jboss-cli.sh --connect --controller=127.0.0.1:9990 --command='/system-property=webwas.precheck.https:add(value=true)'
```
WildFly 재시작 후 server.log 에 `HTTPS 전용 모드` 가 나오면 적용된 것입니다.
- 에이전트 API(`/agent-api`)는 HTTP 로 설치된 에이전트가 끊기지 않도록 이동시키지 않습니다. **에이전트는 https 주소로 다시 설치**하세요.
  자체 서명/사설 인증서면 인증서를 파일로 꺼내 각 서버에 두고 `--ca-cert` 로 지정합니다.
  ```bash
  sudo -u was keytool -exportcert -rfc -alias dashboard -keystore /data/webwas-precheck-tls/dashboard.p12 -storepass '강한비밀번호' -file /data/webwas-precheck-tls/dashboard-ca.pem
  ```
  (재설치 명령은 위 "에이전트 재설치"와 같고, 주소만 `https://...:8443/webwas-precheck`, 끝에 `--ca-cert /경로/dashboard-ca.pem`)
- 되돌리기: `/system-property=webwas.precheck.https:remove` 후 재시작.
- 주의: 앞단 장비 없이 직접 HTTPS 를 쓰는 경우, 대시보드는 `X-Forwarded-Proto` 헤더를 그대로 믿습니다. HTTP 포트를 외부에 열어 두지 않는 것이 안전합니다.
- 결과는 '알려진 패턴' 기준이며 안전을 보증하지 않습니다. 침해 의심 서버는 설정 보완보다 침해사고 대응이 우선입니다.
- 사내망 전용 전제입니다. 인터넷에 직접 노출하지 마세요.

## 구버전 ps 호환 수정 (RHEL/CentOS 7 등, 2026-11-11, 에이전트 2.3.1)

RHEL/CentOS 7 계열의 `ps`는 한 `-eo`에 여러 칸을 `comm=,args=`처럼 묶는 형식에서 **빈 결과**를 냅니다. 이 때문에 에이전트가 실행 중인 Apache/WildFly/Tomcat/Nginx 프로세스를 못 찾아 **"점검할 제품을 찾지 못함(exit 3)"**으로 실패했습니다. 모든 스크립트의 해당 호출을 칸마다 `-o`를 분리한 형식(`ps -e -o comm= -o args=`)으로 바꿔 해결했습니다(출력은 동일, 구·신 버전 ps 모두 동작). 에이전트 버전을 2.3.1로 올렸으니, **대시보드에 새 WAR를 올린 뒤 에이전트를 재설치**해야 적용됩니다.

## 시험 결과 (2026-11-03, 이 저장소 작업 환경)

| 시험 | 결과 |
|---|---|
| `mvn test` | 53개 통과 (기존 Apache·WildFly 리포트 해석 테스트 포함) |
| Tomcat 9.0.80 / 11.0.27 공식 배포본(설치 폴더만, 실행은 안 함)을 `-H` 로 점검 | 9.0.80: CVE 45건, 일부러 심은 AJP 무인증·관리자 비번 admin·웹쉘 JSP·공격 로그를 모두 탐지 / 11.0.27: CVE 0건 |
| CVE 자동 생성 (실제 OSV 2026-11-02 데이터) | WildFly 89건(기존 Python 생성기와 149줄 동일), Tomcat 230건 |
| 대시보드 실행(Jetty) + 에이전트 `run` 실제 흐름 | CVE 목록 받기 → Tomcat 점검 → 리포트 전송 → 화면 표시, "스크립트: 대시보드와 같음" 확인 |
| WildFly 최신 버전 자동 확인 | Maven Central 에서 42.0.0.Final 확인, 에이전트가 받은 목록으로 스크립트 기준도 42.0.0.Final 로 바뀜 |

**확인하지 못한 것**: 작업 환경 네트워크 정책 때문에 `httpd.apache.org` 에 직접 접속하는 것은 시험하지 못했습니다.
대신 2026-11-05 에 같은 데이터의 원본(github.com/apache/httpd-site 의 CVE JSON 288건)으로 변환을 검증했습니다(내장 38건 모두 일치, 위 "CVE 목록 자동 업데이트" 참고).
운영 대시보드에서 설정 화면의 Apache 행이 "자동 업데이트본"이 되는지 확인하세요. GitHub 대체 경로(api.github.com 폴더 목록)는 실제 GitHub 에서 시험하지 못했고, 같은 형식의 파일로만 시험했습니다.
HTTPS 적용(8장)의 WildFly CLI 명령도 이 환경에서 WildFly 를 실행할 수 없어 시험하지 못했습니다. 대시보드의 HTTPS 전용 모드(이동·쿠키·HSTS)는 Jetty 로 확인했습니다.
또 Tomcat 은 실행 중인 프로세스 탐지·열린 포트(ss) 확인 부분을 실제 실행 상태에서 시험하지 못했습니다(이 환경에서 Tomcat 실행이 허용되지 않음).

## 개발자용 메모

```
scripts/apache_precheck.sh  wildfly_precheck.sh  tomcat_precheck.sh   점검 스크립트 (CVE 표는 "# --- CVE_DB 시작/끝 ---" 사이)
scripts/webwas-precheck-agent.sh, install.sh   → 빌드 시 WAR 의 WEB-INF/classes/agent/
tools/gen_cve_table.py     (참고) WildFly CVE 표 생성기. 같은 규칙이 CveFeed.java 에 들어 있음
src/main/java/com/webwas/precheck/
  Product.java        제품 구분 (리포트 머리글·파일명)
  ReportParser.java   네 스크립트 리포트 해석 (CVE 등급 important → high 로 통일)
  LatestVersion(s).java 제품별 최신 버전 (Tomcat 브랜치별)
  CveFeed.java        CVE 목록 자동 생성·보관 (/agent-api/cve/{제품})
  JsonParser.java, Fetch.java  외부 라이브러리 없는 JSON 읽기 / http·file 받기
API (화면용): GET /api/reports(인스턴스별 최신, ETag·gzip) · ?scope=all(전체 이력) · ?instance=키(한 인스턴스 이력)
              GET /api/daily?days=14 (일자·제품·에이전트별 점검/침해 의심 건수)
src/test/resources/  실제 Apache·WildFly·Tomcat·Nginx 점검 리포트, Apache CVE JSON 샘플
```
