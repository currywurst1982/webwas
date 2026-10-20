# nGrinder 부하테스트 대시보드

nGrinder 컨트롤러의 REST API(`/perftest/api`, `/agent/api`)에서 데이터를 받아
한 화면에 보여주는 대시보드입니다.

| 화면 구역 | 내용 |
|---|---|
| ① 합격 기준(SLA) | 목표 TPS / 최대 평균응답시간(MTT) / 최대 에러율 입력 → 합격·불합격 자동 표시 |
| ② 테스트 모니터 | 선택한 테스트의 TPS, Peak TPS, MTT, 에러율, Vuser, 경과시간 + TPS·MTT 그래프. 실행 중이면 실시간 갱신. **중지**, **같은 설정으로 재실행** 버튼 |
| ③ 최근 테스트 목록 | 테스트별 결과 요약과 판정 |
| ④ 포화점 분석 | 같은 이름의 완료된 테스트를 Vuser 순으로 놓고 TPS·MTT 변화 비교 |
| ⑤ 에이전트 현황 | 에이전트 상태(READY/BUSY/INACTIVE), 승인 여부 |

파일 구성
- `index.html` : 대시보드 화면 (외부 라이브러리 없이 동작 → 인터넷이 막힌 사내망에서도 사용 가능)
- `server.py` : 화면을 띄우고, 화면의 요청을 nGrinder로 대신 전달하는 작은 서버 (Python 3.8+ 만 있으면 됨, 추가 설치 없음)

---

## 처음 사용하는 분을 위한 단계별 안내

### 0단계. 준비물 확인
1. nGrinder 컨트롤러 주소 (예: `http://10.0.0.5:8080`) — 평소 브라우저로 nGrinder에 접속하는 주소입니다.
2. nGrinder 로그인 아이디 / 비밀번호
3. 이 폴더(`ngrinder-dashboard`)를 받은 PC에 **Python 3** 설치 여부
   - 터미널(Windows는 "명령 프롬프트" 또는 "PowerShell", Mac은 "터미널" 앱)을 열고 아래를 입력 후 Enter:
     ```
     python3 --version
     ```
     (Windows에서 안 되면 `python --version` 또는 `py --version`)
   - `Python 3.x.x` 처럼 나오면 OK. 안 나오면 https://www.python.org/downloads/ 에서 설치합니다.

### 1단계. nGrinder 없이 화면부터 보기 (데모 모드)
1. 터미널에서 이 폴더로 이동합니다. 예:
   ```
   cd 내려받은경로/webwas/ngrinder-dashboard
   ```
2. 서버 실행:
   ```
   python3 server.py
   ```
3. 브라우저에서 `http://localhost:8000` 접속.
4. 계정을 넣지 않았으므로 자동으로 **데모(가짜 데이터)** 모드가 됩니다. 화면 구성을 확인하세요.
5. 끄려면 터미널에서 `Ctrl` + `C`.

### 2단계. 실제 nGrinder에 연결하기
**Mac / Linux**
```
NGRINDER_URL=http://10.0.0.5:8080 NGRINDER_USER=아이디 NGRINDER_PASSWORD=비밀번호 python3 server.py
```

**Windows (PowerShell)**
```
$env:NGRINDER_URL="http://10.0.0.5:8080"; $env:NGRINDER_USER="아이디"; $env:NGRINDER_PASSWORD="비밀번호"; python server.py
```

**Windows (명령 프롬프트 cmd)**
```
set NGRINDER_URL=http://10.0.0.5:8080
set NGRINDER_USER=아이디
set NGRINDER_PASSWORD=비밀번호
python server.py
```

그다음 브라우저에서 `http://localhost:8000` 접속 → 오른쪽 위 "데이터 모드"가 **실제 nGrinder 연결**인지 확인합니다.
상단에 초록색 `연결됨` 표시가 보이면 성공입니다.

### 3단계. 사용 순서 (권장)
1. ① 합격 기준에 목표값을 입력합니다 (예: TPS 500 이상, MTT 300ms 이하, 에러율 1% 이하).
2. nGrinder 원래 화면에서 테스트를 만들고 시작합니다 (스크립트 작성·테스트 생성은 nGrinder 화면에서 합니다).
3. 대시보드 ②에서 실시간 TPS·응답시간을 봅니다. 실행 중인 테스트가 있으면 자동 선택됩니다.
4. 문제가 보이면 **테스트 중지** 버튼으로 멈춥니다.
5. 같은 스크립트로 에이전트 수만 바꿔 **같은 설정으로 재실행**을 여러 번 하면, ④ 그래프에 Vuser별 결과가 쌓여 포화점을 찾을 수 있습니다.

---

## 문제 해결

| 증상 | 원인 / 해결 |
|---|---|
| 상단에 `연결 실패`, "nGrinder 연결 실패: URLError" | `NGRINDER_URL` 주소가 틀렸거나, 이 PC에서 nGrinder 서버에 접근할 수 없음. 브라우저로 그 주소가 열리는지 먼저 확인 |
| "JSON 대신 HTML이 돌아왔습니다" | 아이디/비밀번호가 틀려 로그인 페이지가 돌아온 경우가 대부분 |
| HTTP 403 | 해당 계정에 권한이 없음. 에이전트 목록 일부 기능은 관리자 권한이 필요할 수 있음 |
| 재실행 시 "test agent should be equal to or less than N" | 사용 가능한 에이전트 수(N)보다 많이 입력함. ⑤에서 READY+승인 에이전트 수 확인 |
| `Address already in use` | 8000번 포트를 다른 프로그램이 사용 중. `DASHBOARD_PORT=8010` 처럼 다른 번호로 실행 |

---

## 한계와 주의사항 (반드시 읽어 주세요)
- **실제 nGrinder 서버에서는 아직 검증하지 않았습니다.** API 경로와 필드명은 nGrinder 공식 소스코드
  (github.com/naver/ngrinder, 2024-10 기준 master)를 읽고 맞췄고, 같은 형식으로 응답하는 가짜 서버로만 테스트했습니다.
  nGrinder 버전이 많이 다르면(특히 3.4 이하) 일부 값이 안 나올 수 있습니다.
- **재실행 버튼은 대상 서버에 실제 부하를 겁니다.** 운영 서버를 대상으로 한 테스트라면 누르기 전에 반드시 확인하세요.
- 서버는 기본적으로 **이 PC에서만 접속 가능**(127.0.0.1)하게 열립니다. 다른 사람과 같이 보려고 `DASHBOARD_HOST=0.0.0.0` 으로 열면,
  주소를 아는 누구나 여러분의 nGrinder 계정 권한으로 테스트를 중지/재실행할 수 있게 됩니다. 사내 보안 정책을 먼저 확인하세요.
- 비밀번호는 화면(HTML)에 들어가지 않고 `server.py` 실행 시 환경변수로만 전달됩니다.
- ④ 포화점 그래프는 "테스트 이름이 같다 = 같은 시나리오"라고 가정합니다. 이름만 같고 스크립트가 다르면 비교가 무의미합니다.
- 실시간 그래프는 대시보드를 켜 둔 동안 받은 샘플만 그립니다(새로고침하면 처음부터). 완료된 테스트는 전체 구간을 nGrinder에서 받아 그립니다.
- 대상 서버의 CPU·메모리, DB, WAS(WildFly 등) 내부 지표는 이 대시보드에 없습니다. 병목 원인 분석에는 별도 모니터링(APM, Grafana 등)이 필요합니다.

## 사용한 nGrinder API
| 용도 | 요청 |
|---|---|
| 테스트 목록 | `GET /perftest/api?page=0&size=20` |
| 실행 중 샘플 | `GET /perftest/api/{id}/sample` |
| 완료 테스트 그래프 | `GET /perftest/api/{id}/perf?dataType=TPS,Mean_Test_Time_(ms),Errors,Vuser&onlyTotal=true&imgWidth=800` |
| 중지 | `PUT /perftest/api/{id}?action=stop` |
| 같은 설정으로 재실행 | `POST /perftest/api/{id}/clone_and_start` (본문 `{"agentCount": N}`) |
| 에이전트 목록 | `GET /agent/api/list` |

인증은 HTTP Basic 방식(`Authorization: Basic ...`)으로 `server.py`가 붙입니다.
