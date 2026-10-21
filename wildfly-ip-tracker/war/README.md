# 사내망 전용 WAR 배포 안내

`dist/ip-tracker.war` 를 WildFly에 배포하면 사내 PC에서 `http://서버주소:8080/ip-tracker/` 로 IP 추적기를 쓸 수 있습니다.

## 이 WAR에 들어 있는 보호 장치

| 장치 | 내용 | 설정 위치 |
|---|---|---|
| 사내 IP만 허용 | 허용 목록 밖의 IP는 비밀번호가 맞아도 **403** 거부 | `WEB-INF/undertow-handlers.conf` (build_war.py가 생성) |
| 로그인 필수 | `ip-tracker-user` 역할이 있는 계정만 접속 (BASIC 인증) | `WEB-INF/web.xml` |
| 읽기 전용 | GET/HEAD 외 메서드(PUT, DELETE 등) 거부 | `WEB-INF/web.xml` |
| 외부 접속 없음 | Google 글꼴 제거, CSP로 외부 리소스·통신 차단 | build_war.py |
| 화면 끼워넣기 금지 | `X-Frame-Options: DENY` | `undertow-handlers.conf` |

로그 파일은 이 WAR가 들어 있는 서버로 **올라가지 않습니다.** 접속한 PC의 브라우저 안에서만 읽습니다.

기본 허용 IP: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (사설 IP 대역 전체), 서버 자신(`127.0.0.1`).
**사설 대역 전체는 넓은 범위입니다.** 회사 대역이 정해져 있다면 3단계처럼 좁혀서 다시 만드는 것을 권장합니다.

## 시험 결과 (WildFly 37.0.1.Final, 2026-10-21)

| 시험 | 결과 |
|---|---|
| 비밀번호 없이 접속 | 401 (로그인 창) |
| 틀린 비밀번호 | 401 |
| 맞는 비밀번호 | 200, 화면 정상 표시 |
| PUT 요청 | 403 |
| `WEB-INF/web.xml` 직접 요청 | 404 |
| 허용 목록 밖 IP (맞는 비밀번호) | 403 |

다른 WildFly 버전에서는 시험하지 않았습니다. Jakarta EE 10 이상(WildFly 27 이상)을 대상으로 작성했습니다. WildFly 26 이하에서는 `web.xml` 형식 때문에 실패할 수 있습니다.

---

## 설치 순서 (처음부터 끝까지)

### 1단계. WAR 파일 받기
GitHub 저장소의 `wildfly-ip-tracker/war/dist/ip-tracker.war` 파일을 내려받습니다.
허용 IP를 바꾸려면 3단계로 직접 만드세요.

### 2단계. 로그인 계정 만들기 (서버에서)
WildFly 설치 폴더로 이동한 뒤 실행합니다.

```bash
cd /opt/wildfly                 # 실제 설치 경로로 바꾸세요
bin/add-user.sh -a -u 홍길동 -p '긴비밀번호를여기에' -g ip-tracker-user
```
- `-a` : 관리자 계정이 아니라 **애플리케이션 사용자**로 만든다는 뜻입니다. 빠뜨리면 관리 콘솔 계정이 만들어지니 꼭 넣으세요.
- `-g ip-tracker-user` : 이 도구를 쓸 수 있는 역할입니다. 이름을 바꾸면 안 됩니다.
- 윈도우 서버는 `bin\add-user.bat` 입니다.
- 사람마다 따로 만드세요. 계정을 함께 쓰면 누가 접속했는지 알 수 없습니다.

### 3단계. (선택) 우리 회사 IP 대역만 허용하도록 다시 만들기
Python 3가 있는 PC에서 실행합니다.

```bash
python3 war/build_war.py --allow 10.20.0.0/16 192.168.5.* 127.0.0.1
```
- `10.20.0.0/16` 은 10.20.x.x 전체, `192.168.5.*` 는 192.168.5.x 전체를 뜻합니다.
- 회사 IP 대역은 네트워크 담당자에게 확인하세요.
- 결과물: `war/dist/ip-tracker.war`

### 4단계. 배포
```bash
cp ip-tracker.war /opt/wildfly/standalone/deployments/
```
몇 초 뒤 같은 폴더에 `ip-tracker.war.deployed` 파일이 생기면 성공입니다.
`ip-tracker.war.failed` 가 생기면 실패입니다. 그 파일을 열면 이유가 적혀 있습니다.

### 5단계. 접속
사내 PC 브라우저에서 `http://서버주소:8080/ip-tracker/` 로 접속합니다. 로그인 창에 2단계 계정을 입력합니다.

### 삭제
```bash
rm /opt/wildfly/standalone/deployments/ip-tracker.war
```

---

## 반드시 확인할 점

1. **HTTP로 접속하면 비밀번호가 사실상 평문으로 전송됩니다.** BASIC 인증은 암호화가 아닙니다. 사내망이라도 `https://서버주소:8443/ip-tracker/` 로 쓰는 것을 권장합니다. HTTPS 인증서 설정은 서버 담당자와 상의하세요.
2. **서버 앞에 로드밸런서·프록시가 있으면 IP 제한이 동작하지 않을 수 있습니다.** WildFly에는 모든 요청이 프록시 IP로 보입니다. 프록시가 사설 IP라면 **외부 접속까지 모두 허용됩니다.** 이 경우 프록시에서 접근을 제한하거나, 서버 담당자에게 WildFly의 `proxy-address-forwarding` 설정을 확인받으세요. 이 구성은 제가 시험하지 않았습니다.
3. **운영 중인 WildFly에 배포해도 되는지 먼저 확인하세요.** 이 WAR에는 Java 코드가 없고 화면 파일 하나뿐이라 서버 부하는 거의 없습니다. 그래도 회사의 배포 절차와 보안 심사를 따라야 합니다.
4. `undertow-handlers.conf` 에는 **주석(#)을 쓸 수 없습니다.** 넣으면 배포가 실패합니다(WildFly 37에서 확인).
