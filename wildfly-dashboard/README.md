# WildFly Dashboard

WildFly 서버 모니터링 대시보드입니다. 로그인한 사용자만 사용할 수 있으며 다음 기능을 제공합니다.

| 메뉴 | 내용 |
|---|---|
| **대시보드** | KPI(서버 상태·Heap·Metaspace·쓰레드), Heap 추이·GC 활동·Heap 구성 차트, 자원 사용률 게이지, 데이터소스·메모리 풀 추이, 서버 상태(running / reload-required 등), 제품/Core 버전, 설정 파일, 가동 시간, JVM·OS 정보, 배포 애플리케이션 목록, JVM 실행 옵션 |
| **XLog (트랜잭션)** | Scouter XLog 처럼 요청 하나하나를 점으로 표시 (가로: 종료 시각, 세로: 처리시간, 색: 정상/4xx/5xx). 드래그로 영역을 선택하면 해당 트랜잭션 목록(서비스, 처리시간, 상태, 클라이언트, 쓰레드), TPS·평균 응답시간·오류율·느린 요청 수, 서비스별 통계(건수, TPS, 평균, 95%, 최대, 오류, 처리시간 비중) |
| **메모리** | Heap 사용량/Committed/최대(Xmx) 실시간 추이 차트, **Metaspace** 사용량·peak·MaxMetaspaceSize 추이, Compressed Class Space, 메모리 풀별 사용률, GC 횟수/시간, 클래스 로딩 수 |
| **DB 데이터소스** | 데이터소스/XA 데이터소스의 JNDI, URL, 드라이버, 풀 설정, 풀 통계(사용 중/Active/가용/대기/타임아웃/평균 대기 시간 등), 연결 테스트, JDBC 드라이버 목록 (비밀번호는 마스킹) |
| **쓰레드 덤프** | 전체 쓰레드 덤프 수집, 상태 분포, 쓰레드 풀별 사용 현황(유휴/작업 중), 데드락 체인, 락 경합(소유자/대기자), 동일 스택 그룹(Hot Stack), DB 커넥션 대기 감지, 이름/클래스 검색, **jstack 형식 텍스트 다운로드** |
| **힙 덤프 분석** | `.hprof` / `.hprof.gz` 업로드 또는 서버에서 바로 생성(`jcmd GC.heap_dump`) → 백그라운드 분석: 클래스 히스토그램(인스턴스 수, Shallow 크기), 가장 큰 객체, 클래스로더별 클래스 수(Metaspace 누수 점검), 누수 의심 항목. `jmap -histo` / `jcmd GC.class_histogram` 텍스트도 분석 가능 |
| **사용자 관리** | 대시보드 사용자 추가/삭제 (admin 전용) |

## 구조

```
브라우저 ──(로그인 세션)──▶ WildFly Dashboard (Node.js) ──HTTP Digest──▶ WildFly 관리 API :9990/management
                                   │                                     (/core-service=platform-mbean,
                                   └─ jcmd GC.heap_dump (같은 호스트일 때)   /subsystem=datasources ...)
```

- 모든 데이터는 WildFly **HTTP 관리 API**(jboss-cli, HAL 콘솔과 동일한 DMR JSON API)에서 읽습니다.
  [wildfly-mcp](https://github.com/wildfly-extras/wildfly-mcp) 서버의 `getWildFlyStatus`, `getJVMInfo`,
  `getWildFlyServerConfiguration` 도구가 사용하는 것과 같은 관리 API·관리 사용자 계정을 사용하므로,
  WildFly 쪽에 별도 에이전트나 배포가 필요 없습니다.
- JVM 정보(Heap, Metaspace, GC, 쓰레드)는 `/core-service=platform-mbean` 리소스, DB 정보는 `/subsystem=datasources` 에서 가져옵니다.
- WildFly 관리 모델에는 힙 덤프 생성 작업이 없으므로, 힙 덤프는 WildFly 와 **같은 호스트**에서는 `jcmd` 로 생성하고,
  원격 서버는 생성한 파일을 업로드해 분석합니다.
- WildFly 37 (WildFly Core 29) 로 실제 동작을 검증했습니다.

## 빠른 시작

요구사항: Node.js 18 이상

```bash
cd wildfly-dashboard
npm install

# 1) WildFly 없이 화면 확인 (시뮬레이션 데이터)
npm run mock

# 2) 실제 WildFly 연결
WILDFLY_URL=http://127.0.0.1:9990/management \
WILDFLY_USER=monitor WILDFLY_PASSWORD='관리자비밀번호' \
WILDFLY_LOCAL_HEAPDUMP=true \
npm start
```

브라우저에서 `http://<서버>:9080` 에 접속하면 로그인 화면이 나옵니다.

### 최초 로그인

처음 실행하면 `admin` 계정이 자동 생성되고 **비밀번호가 콘솔에 출력**됩니다.

```
================================================================
 초기 관리자 계정이 생성되었습니다.  ID: admin   PW: S2VUyIZyzhKy
 첫 로그인 시 비밀번호를 변경해야 합니다.
================================================================
```

- 첫 로그인 후에는 비밀번호를 변경해야 다른 화면을 사용할 수 있습니다 (8자 이상, 영문+숫자).
- 초기 비밀번호를 직접 지정하려면 `DASHBOARD_ADMIN_PASSWORD` 환경 변수를 설정합니다.
- 사용자 추가/비밀번호 초기화: 화면의 **사용자 관리** 메뉴 또는 `node scripts/add-user.js <아이디> [admin|viewer]`
  (서버 실행 중에도 바로 반영됩니다).

| 역할 | 권한 |
|---|---|
| `admin` | 전체 조회 + 힙 덤프 생성/업로드/다운로드/삭제, 데이터소스 연결 테스트, 사용자 관리 |
| `viewer` | 조회 전용 (쓰레드 덤프 수집, 힙 덤프 분석 결과 조회 포함) |

## WildFly 준비

1. 관리 사용자 생성 (모니터링 전용 계정 권장):
   ```bash
   $JBOSS_HOME/bin/add-user.sh -u monitor -p '비밀번호' -s
   ```
   RBAC 를 사용 중이라면 `Monitor` 역할로 조회가 가능하며, 데이터소스 연결 테스트(`test-connection-in-pool`)에는 `Operator` 이상이 필요합니다.
2. 원격에서 접속한다면 관리 인터페이스 바인딩을 확인합니다 (`-bmanagement=0.0.0.0` 또는 특정 IP). 운영 환경에서는 방화벽으로 대시보드 서버에서만 9990 포트에 접근하도록 제한하세요.
3. DB 풀 통계를 보려면 데이터소스 통계를 활성화합니다:
   ```
   /subsystem=datasources/data-source=MyDS:write-attribute(name=statistics-enabled,value=true)
   ```

## 설정

환경 변수 또는 `config/config.json` (`config/config.example.json` 참고). 여러 인스턴스는 아래 [여러 인스턴스 모니터링](#여러-인스턴스-모니터링) 을 참고하세요.

| 환경 변수 | 설명 | 기본값 |
|---|---|---|
| `WILDFLY_URL` | 관리 API URL | - |
| `WILDFLY_HOST` / `WILDFLY_PORT` / `WILDFLY_HTTPS` | URL 대신 개별 지정 | `9990` |
| `WILDFLY_USER` / `WILDFLY_PASSWORD` | 관리 사용자 (wildfly-mcp 의 `WILDFLY_MCP_SERVER_USER_NAME` / `..._PASSWORD` 도 인식) | - |
| `WILDFLY_LOCAL_HEAPDUMP` | 같은 호스트에서 `jcmd` 로 힙 덤프 생성 허용 | `false` |
| `DASHBOARD_PORT` / `DASHBOARD_HOST` | 대시보드 리슨 주소 | `9080` / `0.0.0.0` |
| `DASHBOARD_DATA_DIR` | 사용자 파일, 힙 덤프 저장 위치 | `./data` |
| `DASHBOARD_ADMIN_PASSWORD` | 최초 admin 비밀번호 | 랜덤 생성 |
| `DASHBOARD_SESSION_TIMEOUT` | 세션 유휴 만료(분) | `30` |
| `DASHBOARD_SECURE_COOKIE` | HTTPS 리버스 프록시 뒤에서 `true` | `false` |
| `DASHBOARD_MAX_UPLOAD_MB` | 업로드 최대 크기 | `8192` |
| `DASHBOARD_JCMD` | jcmd 경로 | `jcmd` |
| `DASHBOARD_DISCOVERY` | 로컬 WildFly 프로세스 자동 탐지 | Linux 에서 `true` |
| `DASHBOARD_DISCOVERY_USER` / `DASHBOARD_DISCOVERY_PASSWORD` | 자동 탐지한 인스턴스에 사용할 관리 계정 | - |
| `DASHBOARD_MOCK` | 시뮬레이션 모드 (인스턴스 4개 시뮬레이션) | `false` |

## 여러 인스턴스 모니터링

**전체 인스턴스** 메뉴에서 모든 WildFly 인스턴스의 상태를 카드로 한눈에 보고, 카드를 누르면 해당 인스턴스의 상세 대시보드로 이동합니다.
상단 드롭다운에서도 인스턴스를 바꿀 수 있습니다. 인스턴스가 2개 이상이면 로그인 후 첫 화면이 전체 인스턴스 화면입니다.

인스턴스 목록은 두 곳에서 만들어집니다.

1. **자동 탐지 (Linux, 기본 켜짐):** 대시보드가 있는 서버에서 실행 중인 WildFly **standalone** 프로세스를 `discovery.intervalSeconds`(기본 30초)마다 찾습니다.
   - 각 프로세스의 관리 주소와 포트를 계산합니다. 먼저 그 인스턴스가 쓰는 설정 파일(`-c standalone-xxx.xml`)의 `port-offset`, `management-http` 포트, management 인터페이스 주소를 읽습니다. 그다음 실행 옵션(`-bmanagement`, `-Djboss.socket.binding.port-offset` 등)을 반영합니다.
     그래서 여러 인스턴스가 **같은 standalone 폴더를 공유하고 설정 파일만 다른 구성**(포트 오프셋이 설정 파일 안에만 있는 경우)도 포트를 정확히 찾습니다.
   - 새로 뜬 인스턴스는 자동으로 추가되고, 종료된 인스턴스는 다음 탐지 때 빠집니다.
   - 관리 API 가 알려 주는 PID 와 실제 프로세스 PID 를 비교합니다. 다르면 카드에 경고가 표시됩니다. 포트 오프셋을 `standalone.xml` 에만 설정한 경우가 그렇습니다.
   - 탐지한 인스턴스에는 `discovery.username` / `password` 관리 계정을 사용합니다. 비어 있으면 `servers` 에 등록한 로컬 서버의 계정을 씁니다.
     관리 계정은 인스턴스 폴더(base dir)의 `configuration/mgmt-users.properties` 에 저장됩니다.
     폴더가 인스턴스마다 다르면 폴더마다 `add-user.sh -sc <base dir>/configuration -u monitor -p '...'` 를 실행하고, 같은 폴더를 공유하면 한 번만 실행하면 됩니다.
   - domain 모드 서버는 자동 탐지하지 않습니다.
2. **`servers` 설정:** 원격 서버나 자동 탐지가 안 되는 인스턴스를 직접 등록합니다. 자동 탐지된 인스턴스와 주소가 같으면 설정한 쪽이 우선이고, 중복으로 표시되지 않습니다.

**인스턴스 이름**은 다음 순서로 정해집니다.
1. `servers` 항목의 `name` (직접 적은 경우)
2. `-Djboss.node.name` / `-Djboss.server.name`
3. 인스턴스 폴더(base dir) 이름 (공용 `standalone` 폴더는 제외)
4. 설정 파일 이름에서 `standalone-` 과 `.xml` 을 뺀 이름 (`standalone-claude-test.xml` → `claude-test`)

`servers` 에 등록한 로컬 서버도 `name` 을 비워 두면 같은 규칙으로 인스턴스 이름이 붙습니다.

```json
"discovery": { "enabled": true, "intervalSeconds": 30, "username": "monitor", "password": "change-me" }
```
자동 탐지를 끄려면 `"enabled": false` 또는 `DASHBOARD_DISCOVERY=false` 를 설정합니다.

## DB 데이터소스 경고 기준

| 표시 | 조건 | 의미 |
|---|---|---|
| ● 획득 실패 +N | `BlockingFailureCount` 가 최근 5분 안에 늘어남 | `blocking-timeout-wait-millis` 안에 커넥션을 얻지 못해 요청이 실패함 (`IJ000453: Unable to get managed connection`) |
| ▲ 풀 포화 N% | 사용 중(`InUseCount`) / `max-pool-size` ≥ 90% | 커넥션이 거의 다 쓰이는 중. 곧 대기·획득 실패가 생길 수 있음 |
| 획득 실패 누적 N (회색) | 누적값만 있고 최근 5분간 늘지 않음 | 예전에 실패가 있었음. 지금 문제는 아님 |

`TimedOut`(유휴 정리)은 `idle-timeout-minutes` 동안 쓰이지 않아 닫힌 커넥션 수로, 정상 동작이라 경고에 쓰지 않습니다.
대기 발생·획득 실패·유휴 정리는 서버 시작(또는 통계 초기화) 이후 누적값입니다.

## XLog (트랜잭션)

XLog 는 WildFly(Undertow) **access log** 에 기록된 요청별 처리시간으로 그립니다. 대시보드가 같은 서버에 있는 access log 파일을 실시간으로 읽습니다(2초마다, 로그 rotate 자동 처리).
WildFly 에 에이전트를 설치하지 않아도 되고, 그 대신 요청 안의 SQL·메서드 단위 프로파일은 볼 수 없습니다.

**설정 (인스턴스마다 한 번):** XLog 화면에서 관리자가 **XLog 수집 설정** 버튼을 누르면 다음을 적용합니다.
1. access log 활성화
   - 패턴: `%h %{time,yyyy-MM-dd'T'HH:mm:ss.SSSZ} "%r" %s %b %D "%I"`
   - 파일: `access_log_<인스턴스명>.log`. 이름을 인스턴스마다 다르게 해서, 같은 폴더를 공유하는 인스턴스끼리 섞이지 않게 합니다.
   - 재기동이 필요 없습니다.
2. HTTP/HTTPS/AJP 리스너의 `record-request-start-time=true` 설정
   - 처리시간(`%D`) 기록에 필요합니다.
   - **WildFly reload 후 적용**됩니다. reload 는 자동으로 하지 않으니 점검 시간에 `jboss-cli.sh -c --controller=127.0.0.1:<관리포트> ':reload'` 를 실행하세요.

이미 access log 를 쓰고 있다면 패턴에 `%D`(또는 `%T`)와 시각(`%t` 또는 `%{time,...}`)이 있으면 그대로 읽습니다. 없으면 버튼을 누를 때 패턴 변경 여부를 묻습니다.
직접 설정하려면 화면의 "직접 설정하려면 (jboss-cli)" 안내를 참고하세요. 원격 서버(대시보드와 다른 호스트)의 인스턴스는 로그 파일을 읽을 수 없어 XLog 를 지원하지 않습니다.

## 힙 덤프 분석

- **생성**: `WILDFLY_LOCAL_HEAPDUMP=true`(또는 서버 설정 `allowLocalHeapDump: true`)이면 대시보드가 WildFly 의 PID 를
  관리 API 로 조회한 뒤 `jcmd <pid> GC.heap_dump <data>/heapdumps/<id>.hprof` 를 실행합니다.
  대시보드는 **WildFly 와 같은 OS 사용자**로 실행해야 하며, 데이터 디렉터리에 WildFly 프로세스가 쓸 수 있어야 합니다.
  덤프 중에는 JVM 이 멈추므로(Stop-The-World) 운영 중인 서버에서는 주의하세요.
- **업로드**: 원격 서버는 `jcmd <pid> GC.heap_dump /tmp/wildfly.hprof` 로 만든 파일(또는 `-XX:+HeapDumpOnOutOfMemoryError` 로 생긴 파일)을 업로드합니다. `.gz` 압축 파일도 됩니다.
  덤프가 너무 크면 `jcmd <pid> GC.class_histogram > histo.txt` 결과만 올려도 히스토그램 분석이 가능합니다.
- **분석 방식**: HPROF 파일을 한 번 순차적으로 읽는 스트리밍 파서(별도 worker thread)로, 수 GB 덤프도 적은 메모리로 분석합니다
  (실측: 77MB 덤프 약 0.4초). 크기는 객체 헤더+필드 기준의 **추정 Shallow 크기**입니다.
  Retained size / dominator tree 가 필요하면 다운로드 받아 Eclipse MAT 으로 상세 분석하세요.
- **누수 의심 판단**: 애플리케이션 클래스가 힙의 10% 이상, 단일 객체가 힙의 10% 이상, 다량의 Finalizer/Thread/세션 객체,
  과도한 클래스 수(Metaspace) 등을 표시합니다.

## 보안

- 모든 화면과 API 는 로그인 세션이 필요합니다 (HttpOnly + SameSite=Strict 쿠키, 유휴 30분 만료).
- 비밀번호는 scrypt 해시로 `data/users.json` 에 저장되며, 같은 IP 에서 5회 실패 시 5분간 잠깁니다.
- 상태 변경 API 는 `X-Requested-With` 헤더를 요구하고, CSP/X-Frame-Options 등 보안 헤더를 설정합니다.
- 데이터소스 비밀번호 등 credential 속성은 브라우저로 보내기 전에 마스킹합니다.
- 운영 환경에서는 HTTPS 리버스 프록시(nginx 등) 뒤에 두고 `DASHBOARD_SECURE_COOKIE=true` 로 설정하세요.

## Docker

```bash
docker build -t wildfly-dashboard .
docker run -d -p 9080:9080 -v wfdash-data:/data \
  -e WILDFLY_URL=http://wildfly-host:9990/management \
  -e WILDFLY_USER=monitor -e WILDFLY_PASSWORD='비밀번호' \
  wildfly-dashboard
docker logs <컨테이너>   # 최초 admin 비밀번호 확인
```

컨테이너에서는 WildFly 프로세스에 `jcmd` 로 접근할 수 없으므로 힙 덤프는 업로드 방식으로 사용합니다.

## AI 연동 (선택)

이 대시보드는 사람이 보는 화면을 제공하고, 같은 관리 API 를 자연어로 다루려면 다음을 함께 사용할 수 있습니다.

- [wildfly-mcp](https://github.com/wildfly-extras/wildfly-mcp): WildFly MCP 서버 + Chat Bot. 이 대시보드와 같은 관리 사용자 계정으로 연결해
  "힙 사용량이 왜 높지?", "최근 로그에서 에러를 찾아줘" 같은 질의를 할 수 있습니다.
- [wildfly-ai-feature-pack](https://github.com/wildfly/wildfly-ai-feature-pack): WildFly 에 LangChain4j / MCP 서버 기능을 추가하는 Galleon feature pack (애플리케이션에서 AI 기능을 쓸 때).

## 개발

```bash
npm test          # 단위 테스트 (HPROF 파서, Digest 인증, 쓰레드 분석, 사용자 저장소)
npm run mock      # 시뮬레이션 모드 실행
```

```
server.js                 Express 앱 (라우팅, 세션, 권한)
src/wildfly-client.js     WildFly 관리 API 클라이언트 (HTTP Digest, composite 요청)
src/collectors.js         서버/메모리/데이터소스/쓰레드 정보 수집, 인스턴스 요약
src/discovery.js          로컬 WildFly 프로세스 자동 탐지 (/proc)
src/xlog.js               access log 패턴 해석, 파일 tail, XLog 수집 설정
src/thread-analyzer.js    쓰레드 덤프 분석, jstack 형식 출력
src/hprof/parser.js       HPROF 스트리밍 파서, 클래스 히스토그램 파서
src/heapdump.js           힙 덤프 저장/생성(jcmd)/분석 작업 관리
src/auth.js               사용자 저장소 (scrypt), 로그인 잠금
src/mock.js               시뮬레이션용 관리 API
public/                   로그인 화면, 대시보드 화면
```
