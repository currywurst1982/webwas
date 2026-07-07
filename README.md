# ScouterAPM 모니터링 알리미

`183.111.151.101` 에서 운영중인 ScouterAPM 서버 데이터를 주기적으로 조회하여
**OOM 위험**, **서비스 응답 지연/행(hang)**, **에러율 급증**, **오브젝트 다운**,
**Scouter 자체 알럿** 등 즉시 확인이 필요한 이상 징후를 콘솔(및 선택적으로 Slack)에
알려주는 경량 모니터링 도구입니다.

## 중요: 접속 포트 안내

`6100` 포트는 Scouter **에이전트/collector용 원시 TCP 포트**입니다 (agent → server 데이터 수집,
구버전 Scouter Client의 TCP 프로토콜용). 이 도구는 안정성과 유지보수를 위해 Scouter가
공식 제공하는 **HTTP Web API(v1)** 를 사용합니다. 이 API는 보통 별도 포트
(내장형 6180 / standalone 6188, `net_http_port` 설정값)로 서비스됩니다.

서버 관리자에게 아래 사항을 확인해 주세요.

1. `net_http_port` 값 (기본 6180/6188) 및 방화벽에서 해당 포트 접근 허용 여부
2. `net_http_api_allow_ips` 에 이 도구를 실행할 서버의 IP를 등록 (가장 간단한 인증 방식, 기본값으로 사용)
   - 세션/토큰 로그인 방식을 쓰려면 `config.yaml` 의 `auth.mode` 를 `session` 또는 `bearer` 로 변경

## 설치

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml
# config.yaml 에서 host/http_port/auth/threshold 값을 환경에 맞게 수정
```

## 실행

```bash
# 데모: 실제 서버 없이 샘플 데이터로 동작/화면 확인
python3 run.py --demo

# 1회 점검 후 종료
python3 run.py --config config.yaml --once

# 상주 모니터링 (poll_interval_sec 주기로 반복)
python3 run.py --config config.yaml
```

## 감지 항목

| 카테고리 | 판단 기준 (config.yaml `thresholds`) |
|---|---|
| `OOM_RISK` | `HeapTotUsage`(힙 사용률 %), `PermPercent`, `GcTime`(GC 누적시간) 이 임계값 초과 |
| `SLOW_RESPONSE` | `ElapsedTime`(평균 응답시간), `Elapsed90%`(90퍼센타일), `ActiveService`(동시 실행 수)가 임계값 초과 |
| `HANG_SERVICE` | 개별 실행중 트랜잭션(`activeService`)이 임계값 이상 오래 실행중 (요청 행/무한대기 의심) |
| `HIGH_ERROR_RATE` | `ErrorRate`(%) 초과 |
| `OBJECT_DOWN` | Scouter에 등록된 오브젝트(WAS 인스턴스)가 비활성(다운) 상태 |
| `NATIVE_ALERT` | Scouter 서버 자체 alert 스크립트(`ext_alert_*`)가 발생시킨 알럿을 그대로 전달 |

같은 (오브젝트, 카테고리) 조합은 `notify.cooldown_sec` 동안 재알림을 억제합니다.

## 구조

```
run.py                     CLI 진입점
scouter_monitor/
  config.py                config.yaml 로딩
  client.py                Scouter HTTP Web API 클라이언트
  mock_client.py            --demo 용 샘플 데이터 클라이언트
  rules.py                  임계값 기반 이상 감지 규칙
  notifier.py               콘솔/Slack 알림 및 요약 테이블 출력
  monitor.py                폴링 루프 오케스트레이션
tests/test_rules.py         감지 규칙 단위 테스트
```

## 참고

- 카운터 키(`HeapTotUsage`, `GcTime`, `ElapsedTime`, `ActiveService` 등)와 임계값은
  운영 환경의 WAS 특성에 맞춰 `config.yaml` 에서 조정하세요.
- 실제 서버의 HTTP Web API 응답 스키마가 일부 다를 경우 `scouter_monitor/monitor.py`
  의 `normalize_counters` / `normalize_active_services` 에서 매핑을 보정하면 됩니다.
- Scouter Web API 공식 문서: `scouter-project/scouter` 저장소의
  `scouter.document/tech/Web-API-Guide.md`
