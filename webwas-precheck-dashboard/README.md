# Web·WAS 사전점검 통합 대시보드 (webwas-precheck-dashboard)

기존 **Apache 사전점검 대시보드(precheck-dashboard)** 와 **WildFly 사전점검 대시보드(wildfly-precheck-dashboard)** 를
하나로 합치고, **Tomcat 점검**을 새로 넣은 대시보드입니다. WildFly(자바 WAS)에 배포하는 `.war` 파일 하나로 만들어집니다.

```
 [서버 A: Apache]          에이전트 ─┐  1분마다 "점검할 차례인가요?"  (서버 → 대시보드 방향 연결만 사용)
 [서버 B: Apache+Tomcat]   에이전트 ─┼─────────────────────────────▶ [대시보드] ◀── 브라우저(로그인)
 [서버 C: WildFly]         에이전트 ─┘  차례면: 최신 CVE 목록 받기 →        │
                                        실행 중인 제품의 점검 스크립트 실행 → 리포트 전송
                                                                            │ 12시간마다
                                                     Apache 보안팀 공식 CVE JSON · OSV 취약점 DB · 공식 배포 목록
```

## 무엇이 바뀌었나 (기존 두 대시보드 대비)

| 항목 | 내용 |
|---|---|
| 하나의 화면 | Apache · WildFly · Tomcat 결과를 한 화면에서 봅니다. 화면 위 **제품 탭(전체/Apache/WildFly/Tomcat)** 으로 거를 수 있고, 표·차트·PDF 에 제품이 표시됩니다 |
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

## Tomcat 점검 항목 (tomcat_precheck.sh)

| 구분 | 내용 |
|---|---|
| [1] 버전 | `lib/catalina.jar` 의 ServerInfo(server.info 를 숨겼으면 server.number) → RELEASE-NOTES 순서로 버전 확인. **브랜치별 최신**(11.0/10.1/9.0)과 비교하고, 지원 목록에 없는 브랜치(8.5, 10.0 등)는 "지원 종료(EOL)" [위험] |
| [2] CVE | 위 "CVE 목록" 기준. 예: 9.0.80 → CVE-2025-24813(partial PUT RCE) 등 45건 |
| [3] 설정 | 셧다운 포트(기본 명령어 SHUTDOWN), **AJP 커넥터 secret 미설정(Ghostcat 류)**, 관리자 앱(manager/host-manager) IP 제한 없음, `tomcat-users.xml` 의 쉬운 비밀번호·평문 저장, 예제/문서 앱·기본 ROOT 페이지, DefaultServlet `readonly=false`(PUT 업로드)·`listings=true`, CGI 서블릿, 오류 페이지 버전 노출(ErrorReportValve), HTTP 헤더 버전 노출, 원격 디버그(JDWP)·JMX 무인증, root 실행, 파일 권한 |
| [4] 침해 흔적 | 접근 로그(AccessLogValve)의 경로 탐색·명령 실행·JNDI 주입·**관리자 앱 WAR 배포/PUT JSP 업로드 성공**, webapps(및 conf/Catalina/*/*.xml 이 가리키는 폴더)의 웹쉘 의심 JSP(war 안 포함), 최근 변경 파일, catalina 로그의 역직렬화·JNDI 흔적, 실행 계정의 의심 프로세스·크론·임시 파일·외부 연결 |

옵션: `-H 설치폴더`(CATALINA_HOME) `-B 인스턴스폴더`(CATALINA_BASE) `-d 일수` `-l '접근로그경로'` `-C CVE목록파일`. 옵션 없이 실행하면 실행 중인 Tomcat 을 자동으로 찾고, 여러 개면 각각 점검합니다.
Apache·WildFly 스크립트의 점검 내용은 기존과 같고, `-C` 옵션과 대시보드 CVE 목록 받기만 추가되었습니다.

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

1. 대시보드 → **에이전트** → **에이전트 추가** → 이름(예: `web02`) 입력 → **등록**
2. 화면의 명령 2줄을 점검할 서버에서 실행(복사 버튼 사용), 토큰을 물으면 화면의 토큰을 붙여 넣고 Enter
   ```bash
   curl -fsSo /tmp/webwas-precheck-install.sh http://<대시보드주소>/webwas-precheck/agent-api/files/install.sh
   sudo bash /tmp/webwas-precheck-install.sh http://<대시보드주소>/webwas-precheck web02
   ```
3. `설치 완료` 후 1~2분 안에 **온라인**이 되고 첫 점검이 시작됩니다.

| 설치되는 것 | 내용 |
|---|---|
| `/opt/webwas-precheck-agent/` | 에이전트, 점검 스크립트 3개, 받은 CVE 목록(`cve/`), 보낸 리포트(`sent/`), 전송 대기(`outbox/`) |
| `/etc/webwas-precheck-agent.conf` | 주소·이름·토큰(권한 600), `PRODUCTS`, `RECENT_DAYS`, `RUN_TIMEOUT`, `APACHE_LOG_PATHS`·`WILDFLY_LOG_PATHS`·`TOMCAT_LOG_PATHS` |
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
  echo "대시보드: $U / 에이전트: $N"
  curl -fsSo /tmp/webwas-precheck-install.sh ${C:+--cacert "$C"} "$U/agent-api/files/install.sh" && PRECHECK_AGENT_TOKEN="$T" bash /tmp/webwas-precheck-install.sh "$U" "$N" ${C:+--ca-cert "$C"}
  ```
  확인: `grep '^AGENT_VERSION' /opt/webwas-precheck-agent/webwas-precheck-agent.sh` → `2.1.0` 이상.
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
  ReportParser.java   세 스크립트 리포트 해석 (CVE 등급 important → high 로 통일)
  LatestVersion(s).java 제품별 최신 버전 (Tomcat 브랜치별)
  CveFeed.java        CVE 목록 자동 생성·보관 (/agent-api/cve/{제품})
  JsonParser.java, Fetch.java  외부 라이브러리 없는 JSON 읽기 / http·file 받기
API (화면용): GET /api/reports(인스턴스별 최신, ETag·gzip) · ?scope=all(전체 이력) · ?instance=키(한 인스턴스 이력)
              GET /api/daily?days=14 (일자·제품·에이전트별 점검/침해 의심 건수)
src/test/resources/  실제 Apache·WildFly·Tomcat 점검 리포트, Apache CVE JSON 샘플
```
