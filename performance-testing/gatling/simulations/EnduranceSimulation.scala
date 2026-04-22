package wildfly

import io.gatling.core.Predef._
import io.gatling.http.Predef._
import scala.concurrent.duration._

/**
 * 내구성(Endurance) 테스트 — 장시간 안정성 검증
 *
 * 목적:
 *   - 메모리 누수 탐지 (힙 사용량이 시간이 지나도 안정적인지)
 *   - 커넥션 풀 고갈 탐지 (BlockingFailure 발생 여부)
 *   - Thread 누수 탐지 (Thread 수가 계속 증가하지 않는지)
 *   - 응답시간 저하 탐지 (초반 p95 vs 후반 p95 비교)
 *
 * 시나리오 구성 (낮은 일정 부하 — 안정성 집중):
 *   40%  DB Ping     — 커넥션 풀 생존 확인
 *   40%  DB SELECT   — perf_test_log COUNT 조회
 *   20%  DB INSERT   — perf_test_log 실제 쓰기
 *
 * 주요 시스템 프로퍼티 (-D):
 *   baseUrl      기본값: http://localhost:8080
 *   holdHours    실행 시간(시간)  기본값: 8
 *   holdMinutes  실행 시간(분)    기본값: 0  (테스트용 단시간 실행 시 사용)
 *   users        동시 사용자 수   기본값: 20 (내구성 테스트는 낮은 부하)
 *   dbDelayMs    DB 커넥션 보유(ms) 기본값: 300
 */
class EnduranceSimulation extends Simulation {

  val baseUrl     = System.getProperty("baseUrl",     "http://localhost:8080")
  val appContext  = System.getProperty("appContext",   "")
  val holdHours   = System.getProperty("holdHours",   "8").toInt
  val holdMinutes = System.getProperty("holdMinutes", "0").toInt
  val users       = System.getProperty("users",       "20").toInt
  val dbDelayMs   = System.getProperty("dbDelayMs",   "300").toInt

  // holdMinutes 우선 (0이면 holdHours 사용)
  val holdDuration: FiniteDuration =
    if (holdMinutes > 0) holdMinutes.minutes else holdHours.hours

  val pingPath   = s"${appContext}/db-perf-test/db-ping.jsp"
  val selectPath = s"${appContext}/db-perf-test/db-query.jsp?type=select&delay=${dbDelayMs}"
  val insertPath = s"${appContext}/db-perf-test/db-query.jsp?type=insert&delay=${dbDelayMs}"

  val httpProtocol = http
    .baseUrl(baseUrl)
    .acceptHeader("application/json")
    .acceptEncodingHeader("gzip, deflate")
    .userAgentHeader("Gatling/WildFly-Endurance")
    .connectionHeader("keep-alive")
    .disableCaching
    .maxConnectionsPerHost(50)

  // ── 시나리오 1: DB Ping 반복 (40%) — 커넥션 풀 생존 확인 ──────────────────
  val pingScenario = scenario("DB Ping (생존 확인)")
    .during(holdDuration) {
      exec(
        http("DB Ping")
          .get(pingPath)
          .check(status.is(200))
          .check(responseTimeInMillis.lte(3000))
      )
      .pause(3.seconds, 7.seconds)
    }

  // ── 시나리오 2: DB SELECT 반복 (40%) — 응답시간 저하 감지 ─────────────────
  val selectScenario = scenario("DB SELECT (응답시간 모니터링)")
    .during(holdDuration) {
      exec(
        http("DB SELECT")
          .get(selectPath)
          .check(status.in(200, 503))
          .check(responseTimeInMillis.lte(dbDelayMs + 5000))
      )
      .pause(2.seconds, 5.seconds)
    }

  // ── 시나리오 3: DB INSERT 반복 (20%) — 쓰기 누수 감지 ────────────────────
  val insertScenario = scenario("DB INSERT (쓰기 안정성)")
    .during(holdDuration) {
      exec(
        http("DB INSERT")
          .post(insertPath)
          .header("Content-Type", "application/json")
          .body(StringBody(session => {
            val rand = scala.util.Random.nextInt(999999)
            s"""{"name":"endurance-$rand","category":"END","price":9900}"""
          }))
          .check(status.in(200, 201))
          .check(responseTimeInMillis.lte(dbDelayMs + 5000))
      )
      .pause(5.seconds, 10.seconds)
    }

  setUp(
    // DB Ping: 40%
    pingScenario.inject(
      rampUsers((users * 0.4).toInt).during(2.minutes)
    ),
    // DB SELECT: 40%
    selectScenario.inject(
      nothingFor(30.seconds),
      rampUsers((users * 0.4).toInt).during(2.minutes)
    ),
    // DB INSERT: 20%
    insertScenario.inject(
      nothingFor(60.seconds),
      rampUsers((users * 0.2).toInt).during(2.minutes)
    )
  ).protocols(httpProtocol)
    .assertions(
      // 장기 테스트 — 에러율과 p99 안정성에 집중
      global.responseTime.percentile(99).lte(dbDelayMs + 5000),
      global.failedRequests.percent.lte(1.0),
      // 응답시간 표준편차 — 값이 클수록 불안정 (메모리 누수 등)
      global.responseTime.stdDev.lte(2000)
    )
}
