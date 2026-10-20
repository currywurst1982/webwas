# webwas — nGrinder 부하테스트 도구 모음

| 폴더 | 무엇인가 | 언제 쓰나 |
|---|---|---|
| [`loadtest-app/`](loadtest-app/README.md) | **WAS에 올리는 WAR** (시나리오 대시보드 + 성능테스트 개론 + 실시간 모니터 + 테스트 대상 예제) | 화면에서 시나리오를 고르고 단위·통합·성능·임계 테스트를 버튼으로 실행할 때 (**추천 시작점**) |
| [`ngrinder-scripts/`](ngrinder-scripts/README.md) | nGrinder Groovy 스크립트 (단순 조회, 폼 로그인, 토큰 로그인, CSRF 로그인) | 스크립트를 nGrinder에 직접 붙여 넣어 쓰거나 고칠 때. 대시보드도 이 파일들을 템플릿으로 씀 |
| [`ngrinder-dashboard/`](ngrinder-dashboard/README.md) | 실시간 모니터 화면 + Python 중계 서버(`server.py`) | WAS 없이 PC에서 모니터 화면만 띄울 때 |

## 처음이라면
1. nGrinder 컨트롤러와 에이전트를 설치합니다 (에이전트는 테스트 대상 서버와 **다른** 서버 권장).
2. `loadtest-app` 을 빌드(`mvn package`)해서 테스트용 WAS에 배포합니다 → `http://WAS주소:포트/loadtest/`
3. 화면의 **성능테스트 개론**을 한 번 읽고, ④에서 **단위 → 통합 → 성능 → 임계** 순서로 실행합니다.

자세한 설치·사용법과 검증 내용은 각 폴더의 README에 있습니다.
