# WildFly IP 추적기

WildFly 로그에서 **특정 IP가 언제, 무엇을 했는지** 뽑아 보여주고, 위험도와 차단 방법(WildFly CLI 명령)을 알려주는 도구입니다.
같은 분석을 세 가지 방법으로 쓸 수 있습니다.

| 방법 | 파일 | 이런 분께 |
|---|---|---|
| ① 웹 화면 | `web/index.html` | 로그 파일을 끌어다 놓고 바로 보고 싶을 때 (설치 없음) |
| ② 명령어 | `ip_tracker.py` | 서버에서 직접 돌리거나, 큰 로그를 처리할 때 |
| ③ AI 채팅 연동 (MCP) | `mcp_server.py` | Claude Desktop 등에서 "203.0.113.45 이력 보여줘"처럼 말로 물을 때 |

---

## 1. 이 도구가 읽는 로그

| 로그 | 기본 위치 | 형식 (WildFly 기본값) |
|---|---|---|
| 액세스 로그 | `standalone/log/access_log.YYYY-MM-DD.log` | `%h %l %u %t "%r" %s %b` ("common" 패턴) |
| 서버 로그 | `standalone/log/server.log` | `%d{yyyy-MM-dd HH:mm:ss,SSS} %-5p [%c] (%t) %s%e%n` |

- 액세스 로그는 WildFly에서 **기본으로 꺼져 있을 수 있습니다.** 파일이 없다면 아래 "부록 A"로 켜세요.
- "combined" 패턴(Referer, User-Agent 포함)도 자동 인식합니다.
- server.log는 **IP 주소가 적힌 줄만** 사용합니다 (로그인 실패 메시지 등). IP가 안 찍히는 앱이라면 액세스 로그가 주 자료가 됩니다.
- 형식이 달라서 못 읽은 줄은 "형식 인식 못한 줄 N줄"로 알려줍니다. 이 숫자가 크면 로그 패턴이 다른 것이니, 로그 몇 줄을 보여주시면 맞춰 드릴 수 있습니다.

## 2. 무엇을 "의심"으로 판단하나

| 태그 | 기준 | 점수 |
|---|---|---|
| 인젝션시도 | 요청 주소에 `union select`, `<script`, `${jndi:` 등 | +50 |
| 스캔 | `/.env`, `/.git`, `/manager/html`, `/console`, `../` 등 민감 경로 3건 이상 | +30 (1~2건은 +10) |
| 인증실패 | 401/403 응답, server.log의 "Login failed" 등 10건 이상 | +30 (3~9건은 +10) |
| 과도한 요청 | 1분에 120회 이상 | +30 (60회 이상은 +10) |
| 경로 탐색 | 요청의 절반 이상이 404 | +10 |
| 비정상메서드 | GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH 외 | +10 |

**50점 이상 = 높음, 20점 이상 = 중간, 그 외 = 낮음.**
이 기준은 제가 정한 단순 규칙입니다. 업계 표준이 아니므로 운영 환경에 맞게 `ip_tracker.py`의 `analyze()` 숫자를 조정하세요. 정상 사용자가 "중간"으로 나오거나 공격이 "낮음"으로 나올 수 있습니다.

## 3. 조치 방법 (IP 차단)

도구가 만들어 주는 명령은 WildFly의 Undertow `expression-filter`와 `ip-access-control` 기능을 씁니다. 차단된 IP는 **403** 응답을 받습니다.

```
/subsystem=undertow/configuration=filter/expression-filter=block-203_0_113_45:add(expression="ip-access-control(default-allow=true, acl={'203.0.113.45 deny'})")
/subsystem=undertow/server=default-server/host=default-host/filter-ref=block-203_0_113_45:add
:reload
```

**입력 순서 (아주 자세히)**
1. WildFly가 설치된 서버에 접속합니다.
2. WildFly 설치 폴더로 이동합니다. 예: `cd /opt/wildfly`
3. `bin/jboss-cli.sh --connect` 를 입력하고 Enter. (윈도우: `bin\jboss-cli.bat --connect`)
4. `[standalone@localhost:9990 /]` 같은 글자가 나오면 위 명령을 **한 줄씩** 붙여넣고 Enter.
5. 각 줄 뒤에 `"outcome" => "success"` 가 나오면 성공입니다.
6. 마지막 `:reload`는 설정을 다시 읽는 명령입니다. **잠깐 서비스가 끊길 수 있으니** 사용량이 적은 시간에 하세요.

**주의할 점**
- 서버 앞에 로드밸런서·프록시(L4, nginx, Apache 등)가 있으면 로그에 찍힌 IP가 **프록시 IP**일 수 있습니다. 그 IP를 차단하면 **모든 사용자가 막힙니다.** 먼저 로그의 IP가 실제 사용자 IP인지 확인하세요. 이런 구조라면 앞단 장비나 방화벽에서 차단하는 편이 안전합니다.
- 공격 IP는 자주 바뀝니다. IP 차단은 임시 조치이고, 근본 대책은 취약점 패치·관리 콘솔 외부 노출 차단·WAF 등입니다.
- 이 명령은 제가 실제 WildFly 서버에서 실행해 보지 않았습니다. 명령 형식은 WildFly·Undertow 소스 코드에서 확인했습니다(출처 아래). **운영 서버 전에 개발 서버에서 먼저 시험하세요.**

---

## 4. 사용법 ① 웹 화면 (가장 쉬움)

1. `web/index.html` 파일을 크롬이나 엣지로 엽니다 (더블클릭).
2. 처음에는 **예시 데이터**가 보입니다 (주황색 "예시 데이터" 표시).
3. 서버에서 받은 `access_log...log`, `server.log` 파일을 화면 위쪽 점선 상자에 **끌어다 놓습니다.** 여러 개를 한꺼번에 놓아도 됩니다. `.gz` 압축 파일도 됩니다.
4. 왼쪽 **IP 목록**에서 IP를 누릅니다. 빨간 점 = 위험도 높음.
5. 오른쪽에서 확인:
   - **위험도와 판단 근거**
   - **타임테이블**: 세로 = 날짜, 가로 = 0~23시. 숫자 = 요청 건수. 빨간 테두리 = 의심 행동이 있었던 시간.
   - 타임테이블 칸을 누르면 아래 **상세 이력**이 그 시간만 보입니다.
   - **권장 조치**의 [복사] 버튼으로 차단 명령을 복사합니다.
   - **CSV 복사** 후 엑셀에 붙여넣으면 표로 볼 수 있습니다.
6. 대역 조회: 왼쪽 검색칸에 `203.0.113.0/24` 를 입력하고 Enter.

파일은 브라우저 안에서만 읽고 어디로도 전송하지 않습니다. 매우 큰 로그(수백 MB)는 브라우저가 느려질 수 있으니 그때는 ②번 방법을 쓰세요.

## 5. 사용법 ② 명령어

준비: Python 3.8 이상 (추가 설치 없음). 확인: `python3 --version`

```bash
# 1) 요청이 많은 IP 상위 10개
python3 ip_tracker.py --logs /opt/wildfly/standalone/log --top 10

# 2) 특정 IP 상세 + 타임테이블 HTML + 엑셀용 CSV
python3 ip_tracker.py --logs /opt/wildfly/standalone/log --ip 203.0.113.45 --html report.html --csv report.csv

# 3) 기간 지정
python3 ip_tracker.py --logs ./logs --ip 203.0.113.45 --since 2026-10-20 --until 2026-10-21T23:59

# 4) 대역 전체
python3 ip_tracker.py --logs ./logs --ip 203.0.113.0/24
```

예시 데이터로 바로 시험: `python3 ip_tracker.py --logs samples --ip 203.0.113.45`

## 6. 사용법 ③ AI 채팅 연동 (MCP)

[wildfly-mcp](https://github.com/wildfly-extras/wildfly-mcp)는 WildFly를 AI 채팅에서 말로 다루게 해주는 MCP 서버이고, `getWildFlyLogFileContent`(기본 마지막 200줄) 같은 도구를 제공합니다. 다만 IP별 이력 분석이나 타임테이블 기능은 그 README에 없습니다. 그래서 이 저장소의 `mcp_server.py`를 **wildfly-mcp와 나란히** 등록해서 함께 쓰는 구성을 권장합니다.

이 MCP 서버가 제공하는 도구:

| 도구 | 하는 일 |
|---|---|
| `listTopIps` | 요청 많은 IP 상위 N개 + 의심 요청 수 |
| `getIpHistory` | 특정 IP/대역 이력, 위험도, 근거, 차단 명령 |
| `createIpTimetable` | 타임테이블 HTML + CSV 파일 생성 |

Claude Desktop 설정 파일(`claude_desktop_config.json`)에 추가하는 예:

```json
{
  "mcpServers": {
    "wildfly": {
      "command": "java",
      "args": ["-Dorg.wildfly.user.name=chatbot-user", "-Dorg.wildfly.user.password=비밀번호",
               "-jar", "/경로/wildfly-mcp-server-stdio-runner.jar"]
    },
    "wildfly-ip-tracker": {
      "command": "python3",
      "args": ["/경로/wildfly-ip-tracker/mcp_server.py"],
      "env": { "WILDFLY_LOG_DIR": "/opt/wildfly/standalone/log", "REPORT_DIR": "/tmp/ip-reports" }
    }
  }
}
```

- `mcp_server.py`는 로그 **파일**을 직접 읽으므로, AI 채팅 앱이 WildFly 로그 폴더에 접근할 수 있는 PC/서버에서 실행해야 합니다.
- wildfly-mcp 쪽은 RBAC `Monitor` 역할 계정을 권장한다고 그 README에 적혀 있습니다. 이 역할로는 쓰기 작업(차단 명령 실행)이 실패하므로, 차단은 사람이 직접 CLI로 하는 구성이 됩니다. 저는 이것이 더 안전하다고 봅니다.

### wildfly-ai-feature-pack 으로 서버 안에 넣는 방법은?

[wildfly-ai-feature-pack](https://github.com/wildfly/wildfly-ai-feature-pack)의 `mcp-server` 레이어를 쓰면 WildFly 안에 배포한 Java 코드를 MCP 도구로 노출할 수 있습니다. 이번에는 이 방식을 **만들지 않았습니다.** 이유:
- 최신 릴리스(0.20.1) 노트에 "Make the feature pack and its subsystems experimental" 이라고 되어 있어 아직 실험 단계입니다.
- MCP 어노테이션 패키지 이름이 자료마다 다릅니다 (예제 `org.wildfly.mcp.api.Tool`, 현재 README `org.mcp_java.server.*`, 어노테이션 저장소 `org.mcpjava.server.tools.Tool`). 버전을 고정하지 않으면 빌드가 깨질 가능성이 큽니다.
- 운영 WildFly에 실험 기능을 넣는 것보다 로그 파일을 밖에서 읽는 편이 위험이 적습니다.
필요하시면 사용하는 WildFly 버전을 알려주세요. 그 버전에 맞춰 시험해 보겠습니다.

---

## 부록 A. 액세스 로그 켜기

```
/subsystem=undertow/server=default-server/host=default-host/setting=access-log:add
:reload
```
기본값: 패턴 `common`, 파일 이름 `access_log.` + 날짜 + `log`, 위치 `${jboss.server.log.dir}`, 매일 교체.
User-Agent까지 남기려면 `add(pattern=combined)`로 추가하세요.

## 부록 B. 테스트

```bash
python3 -m unittest discover -s tests -v
python3 web/build.py   # samples/ 를 바꾼 뒤 web/index.html 다시 만들기
```

## 출처

- WildFly 액세스 로그 기본값(`common`, `access_log.`, `log`, `${jboss.server.log.dir}`, rotate=true): `wildfly/wildfly` 저장소 `undertow/src/main/java/org/wildfly/extension/undertow/AccessLogDefinition.java`
- `common`/`combined` 패턴 정의: `undertow-io/undertow` 저장소 `core/.../accesslog/AccessLogHandler.java`
- `ip-access-control(default-allow=..., acl={'... deny'}, failure-status=...)` 문법, 기본 403: `undertow-io/undertow` 저장소 `core/.../IPAddressAccessControlHandler.java`
- `configuration=filter/expression-filter`, `filter-ref` 경로: `wildfly/wildfly` 저장소 `undertow/.../filters/FilterDefinitions.java`, `ExpressionFilterDefinition.java`
- server.log 패턴: `wildfly/wildfly` 저장소 `ee-feature-pack/galleon-shared/.../appclient.xml`의 `pattern-formatter`
- wildfly-mcp 도구 목록·설정: https://github.com/wildfly-extras/wildfly-mcp (`wildfly-mcp-server/README.md`)
- wildfly-ai-feature-pack 릴리스·레이어: https://github.com/wildfly/wildfly-ai-feature-pack/releases , README
