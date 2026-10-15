# Apache 사전점검 대시보드 (precheck-dashboard)

각 웹서버에 설치한 **에이전트**가 `apache_precheck.sh`를 실행하고 결과를 자동으로 보내면,
**로그인한 사용자에게만** 한 화면으로 보여 주는 웹 대시보드입니다. WildFly(자바 WAS)에 배포하는 `.war` 파일로 만들어집니다.
(에이전트를 설치할 수 없는 서버는 결과 파일을 직접 업로드할 수도 있습니다)

```
 [웹서버 A] 에이전트 ─┐   1분마다 "점검할 차례인가요?"  (웹서버 → 대시보드 방향 연결만 사용)
 [웹서버 B] 에이전트 ─┼─────────────────────────────▶ [WildFly: 대시보드] ◀── 브라우저(로그인)
 [웹서버 C] 에이전트 ─┘   차례면 apache_precheck.sh 실행 → 리포트 전송
```

## 화면 구성

| 영역 | 내용 |
|---|---|
| 점검 에이전트 | 웹서버별 에이전트 상태(온라인/오프라인/점검 중), 마지막 점검 결과, 다음 자동 점검, 주기 설정, **지금 점검** 버튼 |
| 핵심 지표 | 점검 인스턴스 수, **침해 의심**, 위험, 2.4.69 미만(EOL 포함), 미조치 CVE 보유, 데이터 경고 |
| 서버별 점검 결과 표 | 판정 · 호스트 · 버전 · 설치방식 · 점검일시 · 위험/주의/양호 건수 · 미조치 CVE(등급별) · 데이터 경고 |
| 차트 3종 | 서버별 위험/주의/양호 건수, CVE별 해당 서버 수(백포트 추정은 빗금), 설정 취약 항목별 서버 수 |
| 상세 화면(행 클릭) | 점검 결과(침해 흔적 → 위험 설정 → 버전 → CVE 순), CVE 판정 표, 같은 인스턴스의 점검 이력, 원본 리포트 |

판정 규칙(스크립트 결과를 그대로 따름):

- **침해 의심**: `[4] 침해 흔적` 섹션에 `[위험]`이 하나라도 있음 → 패치보다 사고 대응이 우선
- **위험** / **주의** / **양호**: 리포트의 `[위험]`/`[주의]` 건수 기준
- **미조치 CVE**: `[2]`에서 "해당"이고, 패키지 changelog 백포트 기록이 **없는** CVE
- **데이터 경고**: 모듈 수 0, 접근 로그 미발견, root 권한 아님, 점검 요약 없음(중간 종료) 등 → 결과를 그대로 믿으면 안 되는 경우

## 1. 준비물

| 항목 | 확인 방법 | 비고 |
|---|---|---|
| Java 17 이상 | `java -version` | 코드는 Java 17 기준으로 컴파일, 테스트는 Java 21 에서 함 |
| Maven 3.8 이상 | `mvn -v` | 빌드할 PC에만 필요 |
| WildFly | 이미 운영 중인 WildFly 가 있으면 그대로 사용 | 테스트는 WildFly 40.0.1.Final 에서 했음 |

## 2. 빌드 (war 파일 만들기)

```bash
cd precheck-dashboard
mvn package
```

끝나면 `target/precheck.war` 파일이 생깁니다. (`BUILD SUCCESS`가 보이면 성공)

## 3. 배포

### 방법 A. 이미 있는 WildFly 에 올리기 (권장)

1. 리포트와 계정을 저장할 폴더를 정합니다. 예: `/data/precheck`
2. WildFly 를 시작할 때 이 폴더를 알려 줍니다. 아래 둘 중 하나:
   - 시작 옵션: `./standalone.sh -Dprecheck.data.dir=/data/precheck`
   - 또는 환경변수: `export PRECHECK_DATA_DIR=/data/precheck`
   - (아무것도 안 하면 WildFly 실행 계정의 홈 폴더 아래 `precheck-dashboard` 를 씁니다)
3. war 파일을 배포 폴더에 복사합니다.
   ```bash
   cp target/precheck.war <WildFly설치경로>/standalone/deployments/
   ```
4. 브라우저에서 `http://<서버주소>:8080/precheck/` 접속

### 방법 B. WildFly 가 없을 때 (최소 구성 서버 자동 생성)

```bash
mvn -Pprovision package
./target/server/bin/standalone.sh -Dprecheck.data.dir=/data/precheck
```

→ `http://<서버주소>:8080/` 로 접속합니다.
※ 이 방법은 빌드 PC가 `repository.jboss.org` 에 접속할 수 있어야 합니다. (사내망에서 막혀 있으면 실패하며, 이 경우 방법 A를 쓰세요)

## 4. 첫 로그인

1. 처음 시작하면 관리자 계정 `admin` 이 자동으로 만들어집니다.
2. 초기 비밀번호는 데이터 폴더의 `initial-admin-password.txt` 파일에 있습니다.
   ```bash
   sudo cat /data/precheck/initial-admin-password.txt
   ```
   (초기 비밀번호를 직접 정하려면 첫 시작 전에 환경변수 `PRECHECK_ADMIN_PASSWORD` 를 설정)
3. 로그인하면 **비밀번호 변경 화면이 먼저 나옵니다.** 바꾸기 전에는 대시보드를 볼 수 없습니다.
4. 비밀번호를 바꾸면 `initial-admin-password.txt` 는 자동으로 삭제됩니다.

비밀번호 규칙: 10자 이상, 영문·숫자·특수문자 중 2가지 이상, 아이디 포함 불가.
5번 연속으로 틀리면 해당 아이디+IP 는 5분간 로그인이 차단됩니다. 30분 동안 아무것도 안 하면 자동 로그아웃됩니다.

## 5. 에이전트 설치 (웹서버마다 한 번)

### 에이전트가 하는 일과 하지 않는 일

- 1분마다 대시보드에 "점검할 차례인지"만 묻습니다. **웹서버에 포트를 열지 않습니다** (웹서버 → 대시보드 방향 연결만 사용).
- 차례가 되면(자동 주기 또는 대시보드의 **지금 점검**) 웹서버에 설치된 `apache_precheck.sh`(수정본)를 root 로 실행하고 결과를 보냅니다.
- 대시보드는 "실행해/말아"만 알려 줄 수 있습니다. **명령어나 스크립트를 원격으로 받아 실행하지 않습니다.**
  대시보드가 해킹되더라도 웹서버에서 임의 명령이 실행되지 않게 하기 위한 설계입니다.
- 대시보드가 꺼져 있으면 결과를 웹서버의 `/opt/precheck-agent/outbox`에 보관했다가 다음에 다시 보냅니다.
- 점검 결과는 에이전트마다 최근 30개만 대시보드에 보관합니다(오래된 것은 자동 삭제).

### 설치 순서

1. 대시보드에 관리자로 로그인 → **점검 에이전트** 영역의 **에이전트 추가**
2. 에이전트 이름(예: `web01`)과 자동 점검 주기(기본 24시간)를 넣고 **등록**
3. 화면에 나오는 명령 2줄을 점검할 웹서버에서 실행합니다. (각 명령 옆 **복사** 버튼 사용)
   ```bash
   curl -fsSo /tmp/precheck-install.sh http://<대시보드주소>/precheck/agent-api/files/install.sh
   sudo bash /tmp/precheck-install.sh http://<대시보드주소>/precheck web01
   ```
4. 토큰을 물어보면 화면의 **에이전트 토큰**을 붙여 넣고 Enter (입력해도 화면에 보이지 않는 것이 정상)
5. `설치 완료`가 나오면 1~2분 안에 대시보드에서 상태가 **온라인**이 되고 첫 점검이 자동으로 시작됩니다.

인터넷/대시보드에서 파일을 받을 수 없는 서버는 `scripts/` 의 `install.sh`, `precheck-agent.sh`, `apache_precheck.sh` 세 파일을
같은 폴더에 복사한 뒤 그 폴더에서 `sudo bash install.sh <대시보드주소> <이름>` 을 실행하면 됩니다.

설치되는 것:

| 위치 | 내용 |
|---|---|
| `/opt/precheck-agent/` | 에이전트·점검 스크립트, 보낸 리포트(`sent/`, 최근 20개), 전송 대기(`outbox/`) |
| `/etc/precheck-agent.conf` | 대시보드 주소·이름·토큰 (권한 600). `LOG_PATHS`, `RECENT_DAYS`, `RUN_TIMEOUT` 도 여기서 변경 |
| systemd 타이머 `precheck-agent.timer` | 1분마다 실행 (systemd 가 없는 서버는 `/etc/cron.d/precheck-agent`) |

필요 조건: bash, curl, flock(util-linux). 웹서버에서 대시보드 주소·포트로 나가는 방화벽이 열려 있어야 합니다.

### 자주 쓰는 명령 (웹서버에서)

```bash
sudo /opt/precheck-agent/precheck-agent.sh test   # 대시보드 연결 확인
sudo /opt/precheck-agent/precheck-agent.sh run    # 지금 바로 점검
journalctl -u precheck-agent -n 50                # 최근 동작 기록 (cron 이면 /var/log/precheck-agent.log)
sudo bash /tmp/precheck-install.sh --uninstall    # 에이전트 삭제
```

### 대시보드에서 보는 에이전트 상태

| 상태 | 의미 |
|---|---|
| 온라인 | 최근 3분 안에 접속함 |
| 점검 요청됨 | **지금 점검**을 눌렀고, 에이전트가 다음 접속(1분 이내) 때 시작함 |
| 점검 중 | 에이전트가 스크립트를 실행 중 (2시간 넘게 결과가 없으면 실패로 보고 다시 시도) |
| 오프라인 | 3분 넘게 접속이 없음 → 서버 다운, 방화벽, 토큰 변경 등을 확인 |
| 설치 대기 | 등록만 하고 아직 한 번도 접속하지 않음 |

"스크립트" 열이 **다름**이면 웹서버의 `apache_precheck.sh`가 대시보드에 들어 있는 버전과 다르다는 뜻입니다.
누군가 서버에서 스크립트를 바꿨을 수 있으니 확인하고, 필요하면 에이전트를 다시 설치하세요.

## 6. 리포트 직접 넣기 (에이전트를 쓸 수 없는 서버)

1. 각 Apache 서버에서 점검 스크립트를 실행합니다. **`scripts/apache_precheck.sh`(수정본) 사용을 권장합니다** (아래 "알려진 문제" 참고).
   ```bash
   sudo bash apache_precheck.sh
   ```
2. 만들어진 `/tmp/apache_precheck_*.txt` 파일을 가져와서 아래 둘 중 하나로 넣습니다.
   - 대시보드 오른쪽 위 **리포트 업로드** (관리자만, 여러 파일 동시 가능, 파일당 5MB 이하)
   - 데이터 폴더의 `reports/` 폴더에 직접 복사 (예: `scp` 로 모아 넣기). 새로고침하면 반영됩니다.
3. 리포트 형식이 아닌 파일(첫 줄에 `Apache 패치 전 보안 사전 점검` 이 없음)은 거부됩니다. UTF-8 과 EUC-KR 모두 읽습니다.

## 7. 사용자 관리 (관리자)

오른쪽 위 **사용자 관리** → 아이디와 역할(조회 전용 / 관리자)을 넣고 추가하면 임시 비밀번호가 **한 번만** 표시됩니다.
사용자는 첫 로그인 때 비밀번호를 바꿔야 합니다. 비밀번호 초기화·삭제도 여기서 합니다.

| 역할 | 할 수 있는 것 |
|---|---|
| 조회 전용 | 대시보드·상세·원본 보기, 본인 비밀번호 변경 |
| 관리자 | 위 + 리포트 업로드/삭제, 사용자 추가/초기화/삭제, 에이전트 추가/지금 점검/주기 변경/토큰 재발급/삭제 |

## 8. 운영 시 꼭 확인할 것

- **HTTPS 로 운영하세요.** 리포트에는 서버 경로·설정·공격 IP 같은 민감한 정보가 들어 있습니다. HTTPS 를 쓰면 `WEB-INF/web.xml` 의 `<secure>true</secure>` 주석을 풀어 쿠키를 HTTPS 전용으로 만드세요.
- 데이터 폴더(`users.properties`, `reports/`)는 WildFly 실행 계정만 읽을 수 있게 권한을 두세요. 비밀번호는 PBKDF2 해시로만 저장됩니다.
- **에이전트 토큰**은 해당 웹서버의 `/etc/precheck-agent.conf` 에만 저장되고, 대시보드에는 해시값만 저장됩니다. 유출이 의심되면 **토큰 재발급**을 누르세요(이전 토큰은 즉시 무효).
- 에이전트 토큰으로 할 수 있는 것은 "그 에이전트 이름으로 상태·리포트 보내기"뿐입니다. 대시보드 화면 조회나 다른 에이전트 조작은 할 수 없습니다.
- 다만 토큰을 가진 사람은 그 에이전트 이름으로 **가짜 리포트를 올릴 수는 있습니다.** 화면의 각 리포트에 "에이전트 OOO 수집"이 표시되므로, 의심스러우면 해당 서버에서 직접 `precheck-agent.sh run` 으로 재점검하세요.
- `/agent-api/files/` 의 설치 파일 3개는 로그인 없이 받을 수 있습니다(비밀 정보 없음). 대신 HTTPS 가 아니면 중간에서 바꿔치기될 수 있으므로 **HTTPS 사용을 강하게 권장합니다.**
- 이 대시보드는 사내망 전용으로 쓰는 것을 전제로 만들었습니다. 인터넷에 직접 노출하지 마세요.

## 알려진 문제: 원본 스크립트의 인스턴스 탐지 버그 (수정본 포함)

원본 `apache_precheck.sh` 는 실행 중인 Apache 에 `-f`/`-d` 인자가 **없을 때**(가장 흔한 경우) 다음과 같이 오동작합니다.
Ubuntu 24.04 + apache2 2.4.58 에서 실제로 재현했습니다.

- 원인: `IFS=$'\t' read` 는 TAB 이 연속되면 하나로 합칩니다. 인자 칸이 비어 있으면 PID 가 인자 자리로 밀려 들어갑니다.
- 결과 1: 리포트에 `인스턴스 실행 인자: 1583`(PID)이 찍히고, `apache2 1583 -M` 처럼 잘못 호출되어 **로드된 모듈 수: 0**
  → 모듈 조건이 있는 CVE 가 **모두 "미해당"으로 잘못 판정**됩니다 (실제로는 해당일 수 있음).
- 결과 2: Include 목록을 못 얻어 설정 폴더의 `*.conf` 를 전부 읽습니다. 비활성 파일(`mods-available/` 등)까지 점검해 **오탐**이 생깁니다.
  (재현 환경에서 비활성 `mods-available/userdir.conf` 때문에 AllowOverride 가 [주의]로 잘못 나왔고, 수정본에서는 [양호])

`scripts/apache_precheck.sh` 는 구분자를 TAB 대신 `\x1f` 로 바꾼 수정본입니다. 원본과의 차이는 이 부분뿐입니다.
수정 후 같은 서버에서 모듈 수가 0 → 27 로 정상 집계되는 것을 확인했습니다.
대시보드는 원본 스크립트로 만든 리포트에서 이 현상을 감지하면 **데이터 경고**로 표시합니다.

## 참고: WildFly AI 관련 프로젝트와의 관계

요청에 언급된 두 프로젝트는 이 대시보드에 **포함하지 않았습니다.** 이유:

- [wildfly-ai-feature-pack](https://github.com/wildfly/wildfly-ai-feature-pack/releases): 최신 0.20.1 릴리스 노트에
  "Make the feature pack and its subsystems experimental." 라고 적혀 있습니다(실험 단계). 쓰려면 외부 LLM(Gemini 등) 연동이 필요해
  점검 결과(서버 경로·공격 IP 등)를 외부로 보내게 됩니다.
- [wildfly-mcp](https://github.com/wildfly-extras/wildfly-mcp): README 설명은 "A WildFly MCP server to integrate with your AI chatbot in order to interact with WildFly server using natural language."
  입니다. 즉 **WildFly 서버**를 대상으로 하는 도구이며, Apache 점검 리포트를 해석하는 기능은 아닙니다.

대신 나중에 붙일 수 있도록 다음을 맞춰 두었습니다.

- WildFly 버전을 AI feature pack 0.20.1 과 같은 40.x 계열로 맞춤 (릴리스 노트: "Upgrade WildFly to 40.0.0.Final")
- 모든 결과를 JSON API(`/api/reports`, `/api/reports/{파일명}`)로 제공 → MCP 서버나 챗봇이 이 API 를 읽도록 확장 가능 (로그인 세션 필요)

## 개발자용 메모

```
src/main/java/com/webwas/precheck/
  ReportParser.java   리포트 텍스트 → Report (스크립트 출력 형식에 맞춘 정규식)
  ReportStore.java    reports/ 폴더 스캔·캐시·업로드·삭제
  UserStore.java      users.properties (PBKDF2-HMAC-SHA256, 210,000회)
  AuthFilter.java     로그인 확인, 첫 로그인 비번 변경 강제, CSRF, 보안 헤더(CSP 등)
  AgentStore.java     에이전트 목록·토큰 해시·점검 지시 판단 (agents.properties)
  AgentApiServlet.java  에이전트용 API (/agent-api/heartbeat, report, result, files)
  LoginServlet / PasswordServlet / LogoutServlet / ApiServlet
src/main/webapp/      index.html, static/app.js, static/app.css (외부 CDN 없음)
src/test/             실제 Ubuntu apache2 2.4.58 에서 얻은 리포트로 해석기 테스트
scripts/              apache_precheck.sh 수정본, precheck-agent.sh(에이전트), install.sh(설치)
                      → 빌드 시 WAR 의 WEB-INF/classes/agent/ 에 함께 들어감
```

테스트: `mvn test`
