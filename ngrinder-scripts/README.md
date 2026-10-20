# 로그인이 필요한 nGrinder 테스트 스크립트

| 파일 | 언제 쓰나 |
|---|---|
| `login_session_cookie.groovy` | 로그인 **화면(폼)**에서 로그인하고, 서버가 준 **쿠키(예: JSESSIONID)**로 로그인 상태가 유지되는 웹사이트 |
| `login_token_api.groovy` | 로그인 **API**가 `{"accessToken":"..."}` 같은 **토큰**을 돌려주고, 이후 요청에 `Authorization: Bearer 토큰`을 붙이는 서비스 |
| `simple_get.groovy` | 로그인 없이 페이지·API를 반복 조회 (가장 기본) |
| `login_csrf.groovy` | 로그인할 때 아이디·비밀번호 말고 **CSRF 토큰**(`_csrf` 등)도 함께 보내야 하는 웹사이트 (Spring Security 등) |
| `resources/users.csv` | 테스트용 계정 목록 (한 줄에 `아이디,비밀번호`) |

nGrinder **3.5.x** 기준입니다 (`org.ngrinder.http.HTTPRequest` 사용). 3.4 이하 버전이면 문법이 달라 그대로는 동작하지 않습니다.

---

## 스크립트가 하는 일 (공통 흐름)

```
[@BeforeProcess]  프로세스당 1번 : users.csv 읽기, 측정 항목 이름 정하기
[@BeforeThread]   가상 사용자당 1번 : 내 계정으로 로그인 → 쿠키/토큰 저장
[@Before]         매 반복 직전   : (쿠키 방식) 저장한 쿠키 다시 넣기
[@Test]           반복 측정      : 로그인해야 볼 수 있는 페이지/API 호출 → 성공 확인
```

- **로그인은 가상 사용자당 1번만** 합니다. 측정하고 싶은 것은 보통 "로그인한 사용자가 페이지를 쓰는 속도"이기 때문입니다.
  로그인 자체의 부하를 재고 싶다면 로그인 코드를 `@Test` 쪽으로 옮기면 됩니다.
- **쿠키를 매번 다시 넣는 이유**: nGrinder는 반복(run)이 시작될 때마다 쿠키를 지웁니다
  (소스: `HTTPPluginThreadState.beginRun()` 안의 `CookieManager.reset()`, 이것을 `GrinderThread`가 반복마다 호출).
- **가상 사용자마다 다른 계정**: `GrinderUtils.getThreadUniqId()`(전체 가상 사용자 중 몇 번째인지)로 users.csv의 줄을 골라 씁니다.
  계정 수보다 가상 사용자가 많으면 계정을 돌려 씁니다(같은 계정 동시 로그인). 서비스가 동시 로그인을 막는다면 **가상 사용자 수 이상으로 계정을 준비**하세요.

---

## 사용 순서 (비개발자용 단계별)

### 1단계. 내 서비스의 로그인 방식 알아내기 (브라우저 개발자 도구)
1. Chrome으로 테스트할 사이트의 로그인 화면을 엽니다.
2. `F12` 키(Mac은 `Cmd + Option + I`)를 눌러 개발자 도구를 엽니다 → 위쪽 탭에서 **Network(네트워크)** 를 누릅니다.
3. **Preserve log(로그 보존)** 체크박스를 켭니다. (로그인 후 화면이 바뀌어도 기록이 남게)
4. 실제로 아이디/비밀번호를 넣고 로그인합니다.
5. 목록에서 **Method가 POST** 이고 이름에 `login`, `signin`, `auth` 같은 단어가 들어간 줄을 클릭합니다.
6. 아래 내용을 메모합니다.

| 메모할 것 | 어디서 보나 | 스크립트의 어느 칸 |
|---|---|---|
| 로그인 주소 | Headers 탭 → Request URL | `LOGIN_PATH` (주소 중 도메인 뒷부분, 예: `/login`) |
| 보내는 형식 | Headers 탭 → Request Headers → `Content-Type` | `application/x-www-form-urlencoded` 면 **예제 1**, `application/json` 이면 **예제 2** |
| 아이디·비밀번호 항목 이름 | Payload 탭 (예: `username`, `password` 또는 `userId`, `pw`) | `ID_FIELD`, `PW_FIELD` |
| (예제 1) 로그인 후 쿠키 | Headers 탭 → Response Headers → `Set-Cookie` 가 있는지 | 있으면 예제 1이 맞음 |
| (예제 2) 토큰 항목 이름 | Response(응답) 탭의 JSON에서 토큰이 들어있는 이름 (예: `accessToken`, `token`) | `TOKEN_FIELD` |

7. 로그인 후 테스트하고 싶은 페이지/API 주소도 같은 방법으로 메모합니다 → `TARGET_PATH` 또는 `API1_PATH`, `API2_PATH`.
8. (예제 1) 그 페이지에 **로그인했을 때만 보이는 글자**(예: "홍길동님 환영합니다"의 "님 환영합니다")를 정해 `SUCCESS_TEXT` 에 넣습니다.

> 로그인 요청에 아이디·비밀번호 말고 `_csrf`, `csrf_token` 같은 **알 수 없는 긴 값이 함께 가면** CSRF 토큰입니다 → 아래 "CSRF 토큰이 필요한 경우" 참고.

### 2단계. nGrinder에 스크립트 올리기
1. nGrinder에 로그인 → 위 메뉴 **Script(스크립트)**.
2. **스크립트 만들기** → 이름 입력, 종류 **Groovy** 선택 → 만들기.
   (이때 "라이브러리/리소스 폴더 생성" 옵션이 보이면 체크하세요. nGrinder 설명: "resources 폴더에는 어떤 파일이든 올릴 수 있습니다.")
3. 열린 편집기의 내용을 **모두 지우고**, 이 폴더의 `.groovy` 파일 내용을 통째로 붙여 넣습니다.
4. 맨 위 **★ 설정** 부분을 1단계에서 메모한 값으로 바꿉니다. `BASE_URL` 은 `http://대상서버주소:포트` 입니다.
5. 저장합니다.

### 3단계. 계정 파일 올리기
1. 스크립트 목록에서 스크립트와 **같은 위치에 `resources` 폴더**가 있는지 확인합니다. 없으면 **폴더 만들기**로 `resources` 를 만듭니다.
   (nGrinder 위키: "you can create resources folder at the same location with the script.")
2. `resources` 폴더로 들어가 **업로드** 로 `users.csv` 를 올립니다.
   파일 내용은 **테스트용 계정**으로 바꾸세요. 운영 중인 실제 고객 계정은 절대 쓰지 마세요.

### 4단계. 검증 → 실행
1. 스크립트 편집 화면에서 **검증** 버튼을 누릅니다. 에이전트 1 × 프로세스 1 × 스레드 1(가상 사용자 1명)로 시험 실행하는 기능입니다
   (소스 `LocalScriptTestDriveService`). 검증은 **컨트롤러 서버에서** 실행되므로, 컨트롤러에서 대상 서버로 접속이 가능해야 합니다.
2. 아래 로그에 `로그인 성공` / `받은 쿠키 1개` 같은 메시지가 보이고 에러가 없으면 성공입니다.
3. 성공하면 테스트를 만들어 실행합니다. 처음엔 **가상 사용자 10명, 1분**처럼 작게 시작하세요.

---

## CSRF 토큰이 필요한 경우 (`login_csrf.groovy`)

### CSRF 토큰이란
로그인 화면을 열 때 서버가 **일회성 비밀값(토큰)**을 같이 주고, 로그인할 때 그 값을 돌려받아 "진짜 우리 화면에서 온 요청인지" 확인하는 장치입니다.
그래서 스크립트도 브라우저처럼 **① 로그인 화면을 먼저 열고 → ② 토큰을 읽고 → ③ 토큰과 함께 로그인**해야 합니다.

### 토큰이 어디에 있는지 확인하기 (개발자 도구)
1. 1단계처럼 Network 탭을 열고 로그인합니다.
2. 로그인 요청(POST)의 **Payload** 탭에서 아이디·비밀번호 외의 항목 이름을 봅니다 (예: `_csrf`). → `CSRF_NAME`
3. Payload에 없다면 **Headers → Request Headers** 에서 `X-CSRF-TOKEN`, `X-XSRF-TOKEN` 같은 헤더를 찾습니다.
4. 로그인 화면에서 `Ctrl + U`(페이지 소스 보기) → `Ctrl + F` 로 2번에서 본 이름을 검색합니다.

| 찾은 위치 | 예시 | 스크립트 동작 |
|---|---|---|
| ① 폼 안의 숨은 입력칸 | `<input type="hidden" name="_csrf" value="...">` | 값을 읽어 로그인 폼에 같은 이름으로 넣음 |
| ② 화면 머리의 meta 태그 | `<meta name="_csrf" content="...">` `<meta name="_csrf_header" content="X-CSRF-TOKEN">` | 값을 읽어 지정된 헤더로 보냄 (+폼에도 넣음) |
| ③ 쿠키 | 응답 헤더 `Set-Cookie: XSRF-TOKEN=...` | 쿠키 값을 읽어 `X-XSRF-TOKEN` 헤더로 보냄 |

스크립트는 ① → ② → ③ 순서로 **자동으로** 찾습니다. 이름이 기본값과 다르면 ★ 설정의 `CSRF_NAME`, `CSRF_COOKIE`, `CSRF_COOKIE_HEADER` 만 바꾸면 됩니다.

기본값의 근거 (Spring Security 소스, 2026-10 기준 main 브랜치):
- `HttpSessionCsrfTokenRepository`: `DEFAULT_CSRF_PARAMETER_NAME = "_csrf"`, `DEFAULT_CSRF_HEADER_NAME = "X-CSRF-TOKEN"`
- `CookieCsrfTokenRepository`: `DEFAULT_CSRF_COOKIE_NAME = "XSRF-TOKEN"`, `DEFAULT_CSRF_HEADER_NAME = "X-XSRF-TOKEN"`
- 공식 문서(csrf.adoc): "The `CookieCsrfTokenRepository` writes to a cookie named `XSRF-TOKEN` and reads it from an HTTP request header named `X-XSRF-TOKEN` or the request parameter `_csrf` by default."

### 로그인 후에 저장/주문 같은 POST도 측정하려면
★ 설정의 `ACTION_PAGE_PATH`(그 기능이 있는 화면), `ACTION_PATH`(POST 주소), `ACTION_PARAMS`(보낼 값)를 채우세요.
**로그인하면 토큰이 바뀌는 경우가 많아서**, 스크립트는 POST 직전마다 화면을 다시 열어 새 토큰을 읽습니다.
근거: Spring 문서 "the `CsrfAuthenticationStrategy` and `CsrfLogoutHandler` will clear the previous token." /
Spring Security 6부터는 "The `CsrfToken` now includes randomness on every request by default" (BREACH 공격 방지).
그래서 **토큰 값을 한 번 복사해 고정값으로 넣는 방식은 동작하지 않습니다.**

### CSRF 관련 오류
| 로그 메시지 | 원인 / 해결 |
|---|---|
| `로그인 화면에서 CSRF 토큰을 찾지 못했습니다` (아래에 화면 앞부분이 찍힘) | `CSRF_NAME` 이 틀렸거나, 토큰이 화면이 아니라 JavaScript로 나중에 만들어지는 경우. 찍힌 화면 내용과 개발자 도구 내용을 알려주시면 맞춰 드립니다 |
| `로그인 요청이 거부됐습니다 ... 403` | 토큰을 보내는 이름/헤더가 서버 기대와 다름. 개발자 도구에서 로그인 요청이 토큰을 Payload로 보내는지, 어떤 헤더로 보내는지 다시 확인 |
| `POST 실패 ... 403` | `ACTION_PAGE_PATH` 화면에 토큰이 없음 → 토큰이 있는 화면 주소로 바꾸기 |

## 오류 코드 (에이전트 로그에서 한글이 깨져도 이 코드는 보임)
| 코드 | 의미 |
|---|---|
| `[LOGIN_FAILED]` | 로그인 요청이 실패 (주소·입력칸 이름·계정 확인, CSRF면 403 여부) |
| `[NO_LOGIN_COOKIE]` | 로그인했는데 쿠키를 못 받음 |
| `[NOT_LOGGED_IN]` | 로그인 후 페이지에 "성공 글자"가 없음 (글자 오타, 동시 로그인 제한 등) |
| `[NO_TOKEN]` | 로그인 API 응답에서 토큰 항목을 못 찾음 |
| `[LOGIN_PAGE_FAILED]` / `[NO_CSRF_TOKEN]` | 로그인 화면을 못 열었거나 CSRF 토큰을 못 찾음 |
| `[POST_FAILED]` | 로그인 후 POST 실패 (403이면 CSRF 토큰 문제) |
| `[BAD_STATUS]` / `[TEXT_NOT_FOUND]` / `[NO_PATHS]` | 단순 조회: 응답코드 이상 / 기대 글자 없음 / 주소 목록 비어 있음 |

## 자주 나는 오류

| 로그 메시지 | 원인 / 해결 |
|---|---|
| `로그인 쿠키를 받지 못했습니다` | 아이디·비밀번호 항목 이름(`ID_FIELD`, `PW_FIELD`)이나 `LOGIN_PATH` 가 틀렸을 가능성. 또는 계정/비밀번호가 틀림 |
| `로그인이 풀린 것 같습니다` | `SUCCESS_TEXT` 가 실제 페이지에 없는 글자이거나, 서비스가 동시 로그인을 막아 먼저 로그인한 세션이 끊김 |
| `로그인 API 실패 ... 400` | 서버가 JSON이 아닌 다른 형식을 기대함 → 1단계의 Content-Type 다시 확인 |
| `응답에서 토큰(accessToken)을 찾지 못했습니다` | `TOKEN_FIELD` 이름이 다름. 로그에 찍힌 응답 내용에서 실제 이름 확인. 토큰이 `{"data":{"token":"..."}}` 처럼 한 단계 안쪽에 있으면 스크립트 수정 필요 |
| `FileNotFoundException ... users.csv` | 3단계: `resources` 폴더 위치나 파일 이름 확인 |

---

## 꼭 알아야 할 함정 (검증하며 발견)

- **응답 본문은 `res.bodyText` 대신 스크립트 안의 `text(res)` 로 읽습니다.**
  nGrinder의 `getBodyText()` 는 `getBodyText(Charset.defaultCharset())`, 즉 **에이전트 PC의 기본 문자셋**으로 글자를 만듭니다.
  실제 nGrinder 에이전트(Java 11, 로캘 미설정 리눅스)에서 돌렸을 때 응답의 "님 환영합니다"가 깨져 **로그인 성공인데도 실패로 처리**됐습니다.
  한국어 Windows(MS949) 에이전트에서도 같은 일이 생길 수 있습니다. `text(res)` 는 서버가 알려준 문자셋(없으면 UTF-8)을 씁니다.
- **에이전트 로그의 한글이 `????` 로 깨질 수 있습니다.** 그래서 오류 메시지 앞에 영문 코드(`[NOT_LOGGED_IN]` 등)를 붙였습니다. 아래 표로 의미를 찾으세요.

- **폼 로그인에는 `Content-Type: application/x-www-form-urlencoded` 를 반드시 직접 지정해야 합니다.**
  nGrinder 3.5.x는 `request.POST(주소, [항목:값])` 처럼 헤더 없이 부르면 **JSON으로 보냅니다**
  (소스 `ContentTypeUtils.getContentType()` 의 기본값이 `ContentType.APPLICATION_JSON`).
  실제로 헤더 없이 돌렸을 때 테스트 서버에 `{"username":"loadtest01",...}` JSON이 도착해 로그인에 실패했습니다.
- nGrinder는 폼 본문을 **chunked 방식**(Content-Length 없이 나눠 보내기)으로 보냈습니다. 일반적인 웹서버는 문제없지만,
  아주 오래된 서버나 일부 보안장비가 거부하면 로그인이 실패할 수 있습니다.

## 어떻게 검증했나 (한계 포함)
- **실제 nGrinder 3.5.9-p1 컨트롤러 + 에이전트(Java 11)** 에서 4개 스크립트를 모두 1분씩 실행해 완료 확인
  (대상: `loadtest-app` 예제 기능, Tomcat 10.1 / WildFly 39). 결과는 `../loadtest-app/README.md` 참고.
- CSRF 예제: Spring Security처럼 동작하는 가짜 서버(토큰 없으면 403, 로그인하면 세션·토큰 교체)를 ①숨은 입력칸 ②meta+헤더 ③쿠키+헤더 세 방식으로 만들어
  각각 로그인 1번 → 로그인 후 페이지 3번 + 로그인 후 POST 3번이 모두 성공함을 확인. `CSRF_NAME` 을 틀리게 넣으면 위 오류 메시지가 나오는 것도 확인.
- Maven 중앙 저장소의 **nGrinder 3.5.9-p1 실행 라이브러리**로 두 스크립트를 컴파일·실행하고, 가짜 로그인 서버(쿠키 방식 + 토큰 방식)에 붙여 확인했습니다.
  - 쿠키 방식: 로그인 1번 → 마이페이지 3번 반복, 3번 모두 로그인 상태로 응답
  - 토큰 방식: 로그인 1번 → API 2개를 3번씩 반복, 모두 200 응답
- **실제 nGrinder 컨트롤러/에이전트 화면에서는 돌려보지 못했습니다.** 또한 검증 환경의 Java가 21이라,
  nGrinder 기본 Groovy(3.0.5) 대신 같은 3.0 계열 Groovy 3.0.22로 실행했습니다. 스크립트 문법과 nGrinder 함수는 같습니다.
- 로컬(JUnit) 실행에서는 반복 사이에 쿠키가 지워지지 않아 "쿠키 다시 넣기"의 필요성 자체는 재현되지 않았고, 이 부분은 소스 코드 근거입니다. 다시 넣는 코드는 있어도 해가 없습니다.
