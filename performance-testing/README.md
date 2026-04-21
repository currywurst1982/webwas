# WildFly 26 성능테스트 프레임워크

Linux 환경의 WildFly 26 WAS를 대상으로 한 실무 수준의 부하테스트 및 성능 분석 도구 모음입니다.

## 디렉토리 구조

```
performance-testing/
├── gatling/
│   ├── simulations/                  # Gatling 시뮬레이션 (Scala)
│   │   ├── ReadApiSimulation.scala   # 읽기 중심 API (GET 70%)
│   │   ├── WriteApiSimulation.scala  # 쓰기 중심 API (POST/PUT/DELETE)
│   │   ├── MixedLoadSimulation.scala # 혼합 부하 / 스트레스 / 스파이크
│   │   └── EnduranceSimulation.scala # 장기 내구성 테스트 (8~24h)
│   └── resources/
│       └── gatling.conf              # Gatling 설정 (백분위 버킷, 타임아웃)
├── jmeter/
│   └── wildfly-load-test.jmx         # JMeter 테스트 플랜 (커맨드라인 실행용)
├── monitoring/
│   ├── collect-wildfly-stats.sh      # WildFly CLI 통계 수집 (DS 풀/Undertow)
│   ├── collect-jvm-metrics.sh        # jstat/jstack 기반 JVM 메트릭 수집
│   ├── collect-os-metrics.sh         # CPU/Memory/Disk/Network/TCP 수집
│   └── thread-dump.sh                # Thread Dump 수집 및 BLOCKED 분석
├── wildfly-config/
│   ├── undertow-tuning.cli           # Undertow worker/IO thread 튜닝
│   ├── datasource-tuning.cli         # 커넥션 풀 튜닝 (pool-size/timeout)
│   ├── jvm-options.conf              # G1GC/ZGC JVM 옵션 템플릿
│   └── os-kernel-tuning.sh           # Linux 커널 파라미터 튜닝 (apply/check/revert)
├── scripts/
│   ├── run-load-test.sh              # 통합 실행 (점검→모니터링→부하→분석)
│   ├── pre-test-check.sh             # 테스트 시작 전 환경 점검
│   ├── post-test-analysis.sh         # 수집 데이터 분석 및 병목 탐지
│   └── generate-test-data.sh         # CSV 피더 파일 생성
└── analysis/
    ├── analyze-gc-log.sh             # GC 로그 분석 (Pause/오버헤드/백분위)
    ├── generate-report.sh            # 최종 HTML+텍스트 보고서 생성
    └── sla.conf                      # SLA 기준값 설정
```

## 빠른 시작

### 1. 사전 준비

```bash
# 테스트 데이터 피더 파일 생성
bash scripts/generate-test-data.sh --count 300

# 운영 DB에서 실제 데이터 추출 (권장)
DB_HOST=db.internal DB_NAME=mydb bash scripts/generate-test-data.sh --db-extract

# WildFly 튜닝 적용 (선택)
$JBOSS_HOME/bin/jboss-cli.sh --connect --file=wildfly-config/undertow-tuning.cli
$JBOSS_HOME/bin/jboss-cli.sh --connect --file=wildfly-config/datasource-tuning.cli

# OS 커널 파라미터 점검 및 적용
sudo bash wildfly-config/os-kernel-tuning.sh check
sudo bash wildfly-config/os-kernel-tuning.sh apply
```

### 2. 통합 실행 (권장)

```bash
# 혼합 부하, 100 사용자, 5분, 3회 반복
bash scripts/run-load-test.sh -t mixed -u 100 -d 300 -r 60 -n 3

# 스트레스 테스트 (한계점 탐색)
BASE_URL=http://was.internal:8080 \
  bash scripts/run-load-test.sh -t mixed -u 500 -d 600

# 읽기 API 전용, JMeter 사용
bash scripts/run-load-test.sh -t read -u 200 -s jmeter
```

### 3. 개별 실행

#### Gatling

```bash
# 읽기 부하
$GATLING_HOME/bin/gatling.sh -s wildfly.ReadApiSimulation \
  -DbaseUrl=http://localhost:8080 -DappContext=/myapp \
  -DtargetUsers=100 -DrampDuration=60 -DholdDuration=300

# 스파이크 테스트
$GATLING_HOME/bin/gatling.sh -s wildfly.MixedLoadSimulation \
  -DbaseUrl=http://localhost:8080 -DtestType=spike -DbaseUsers=50 -DmaxUsers=500

# 내구성 테스트 (8시간)
$GATLING_HOME/bin/gatling.sh -s wildfly.EnduranceSimulation \
  -DbaseUrl=http://localhost:8080 -DholdHours=8 -Dusers=30
```

#### JMeter (CLI)

```bash
$JMETER_HOME/bin/jmeter -n \
  -t jmeter/wildfly-load-test.jmx \
  -Jhost=localhost -Jport=8080 -Jctx=/myapp \
  -Jusers=100 -Jramp=60 -Jduration=300 \
  -l results/result_$(date +%Y%m%d_%H%M%S).jtl \
  -e -o results/report/
```

### 4. 모니터링 (별도 터미널)

```bash
# WildFly DS 풀 / Undertow 통계 (10초 간격)
WILDFLY_DS_NAMES="ExampleDS,SecondDS" \
  bash monitoring/collect-wildfly-stats.sh 10 /tmp/perf-results

# JVM GC / Thread 모니터링
WF_PID=$(pgrep -f jboss-modules)
bash monitoring/collect-jvm-metrics.sh $WF_PID 5 /tmp/perf-results

# OS CPU/Memory/Network
bash monitoring/collect-os-metrics.sh 5 /tmp/perf-results

# Thread Dump 5회 수집 (10초 간격)
bash monitoring/thread-dump.sh $WF_PID 5 10 /tmp/perf-results
```

### 5. 분석 및 보고서

```bash
# GC 로그 분석
bash analysis/analyze-gc-log.sh /var/log/wildfly/gc/gc_2024.log

# 결과 분석 (병목 탐지)
bash scripts/post-test-analysis.sh results/run_20240115_103000/

# 최종 HTML 보고서 생성
bash analysis/generate-report.sh results/
# → results/final_report_YYYYMMDD_HHMMSS/performance_report.html
```

## 측정 지표 체계

| 카테고리 | 지표 | 경보 기준 |
|---------|------|----------|
| 응답시간 | p50/p95/p99/최대 | p95 > SLA 값 |
| 처리량 | TPS, 에러율 | 에러율 > 0.1% |
| JVM | Young/Full GC 횟수, GC 오버헤드 | Full GC > 0, 오버헤드 > 5% |
| WildFly DS | in-use-count, wait-count, blocking-failure | wait > 0, failure > 0 |
| CPU | user%, sys%, iowait% | iowait > 10% |
| 메모리 | Heap 사용률, Swap | Swap > 100MB |
| TCP | TIME_WAIT, CLOSE_WAIT | TIME_WAIT > 3000 |

## SLA 기준 수정

`analysis/sla.conf` 파일에서 프로젝트 SLA에 맞게 값을 수정합니다:

```bash
SLA_P95=300          # 목표 p95 응답시간 (ms)
SLA_ERROR_RATE=0.1   # 허용 에러율 (%)
SLA_TPS=500          # 목표 TPS
```

## 환경 변수

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `BASE_URL` | `http://localhost:8080` | 대상 서버 URL |
| `APP_CONTEXT` | `/myapp` | 애플리케이션 컨텍스트 |
| `JBOSS_HOME` | `/opt/wildfly` | WildFly 설치 경로 |
| `GATLING_HOME` | `/opt/gatling` | Gatling 설치 경로 |
| `JMETER_HOME` | `/opt/jmeter` | JMeter 설치 경로 |
| `JAVA_HOME` | `/usr/lib/jvm/java-11-openjdk` | JDK 경로 |
| `WILDFLY_MGMT_HOST` | `127.0.0.1` | WildFly Management Host |
| `WILDFLY_MGMT_PORT` | `9990` | WildFly Management Port |
| `WILDFLY_DS_NAMES` | `ExampleDS` | 모니터링 대상 DS 이름(쉼표 구분) |
| `NET_IFACE` | `eth0` | 네트워크 인터페이스 |
| `DISK_DEV` | `sda` | 디스크 장치 |
