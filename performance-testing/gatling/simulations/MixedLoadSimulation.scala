package wildfly

import io.gatling.core.Predef._
import io.gatling.http.Predef._
import scala.concurrent.duration._

/**
 * 혼합 부하 시뮬레이션 — DB 연동 포함
 *
 * 시나리오 구성:
 *   20%  페이지 조회  — GET /                           (DS 미사용)
 *   50%  DB 읽기      — GET /db-perf-test/db-query.jsp  (DS SELECT + pg_sleep)
 *   30%  DB 쓰기      — POST db-query.jsp?type=insert   (DS INSERT + pg_sleep)
 *
 * 주요 시스템 프로퍼티 (-D):
 *   baseUrl      기본값: http://localhost:8080
 *   appContext    기본값: (없음)
 *   targetUsers  기본값: 50
 *   rampDuration 기본값: 60  (초)
 *   holdDuration 기본값: 300 (초)
 *   testType     load(기본) | stress | spike
 *   dbDelayMs    DB 커넥션 보유 시간(ms)  기본값: 500
 *                InUse 가시화 목적 — 값이 클수록 InUse↑, 처리량↓
 */
class MixedLoadSimulation extends Simulation {

  // ── 기본 설정 ─────────────────────────────────────────────────────────────
  val baseUrl      = System.getProperty("baseUrl",      "http://localhost:8080")
  val appContext   = System.getProperty("appContext",    "")
  val targetUsers  = System.getProperty("targetUsers",  "50").toInt
  val maxUsers     = System.getProperty("maxUsers",     "500").toInt
  val testType     = System.getProperty("testType",     "load")
  val rampDuration = System.getProperty("rampDuration", "60").toInt
  val holdDuration = System.getProperty("holdDuration", "300").toInt

  // ── DB 지연 설정 ──────────────────────────────────────────────────────────
  // pg_sleep(N)으로 커넥션을 N ms 동안 점유 → Prometheus 스크래핑(5s)에 InUse 포착
  // 예상 InUse = (동시 DB 사용자) × (dbDelayMs / 1000) / (think_time 평균)
  val dbDelayMs = System.getProperty("dbDelayMs", "500").toInt

  // ── DB 엔드포인트 설정 ────────────────────────────────────────────────────
  val dbPingPath  = System.getProperty("dbPingPath",  "/db-perf-test/db-ping.jsp")
  val dbReadPath  = System.getProperty("dbReadPath",  s"/db-perf-test/db-query.jsp?type=select&delay=$dbDelayMs")
  val dbWritePath = System.getProperty("dbWritePath", s"/db-perf-test/db-query.jsp?type=insert&delay=$dbDelayMs")

  // ── HTTP 프로토콜 ─────────────────────────────────────────────────────────
  val httpProtocol = http
    .baseUrl(baseUrl)
    .acceptHeader("text/html,application/xhtml+xml,application/json,*/*;q=0.8")
    .acceptLanguageHeader("ko-KR,ko;q=0.9,en;q=0.8")
    .acceptEncodingHeader("gzip, deflate")
    .userAgentHeader("Gatling/WildFly-PerfTest")
    .connectionHeader("keep-alive")
    .disableCaching
    .maxConnectionsPerHost(50)

  // ── 시나리오 1: 정적 페이지 조회 (20%) — DS 미사용 ───────────────────────
  val browseScenario = scenario("페이지 조회")
    .exec(
      http("GET /")
        .get(appContext + "/")
        .check(status.is(200))
        .check(responseTimeInMillis.lte(3000))
    )
    .pause(2.seconds, 5.seconds)

  // ── 시나리오 2: DB 읽기 (50%) — DS SELECT + pg_sleep ─────────────────────
  val dbReadScenario = scenario("DB 읽기")
    .exec(
      http("DB SELECT (db-ping)")
        .get(appContext + dbPingPath)
        .check(status.in(200, 503))
        .check(responseTimeInMillis.lte(5000))
    )
    .pause(200.milliseconds, 500.milliseconds)
    .exec(
      http("DB SELECT (db-query)")
        .get(appContext + dbReadPath)
        .check(status.in(200, 503))
        // dbDelayMs + 네트워크 여유분
        .check(responseTimeInMillis.lte(dbDelayMs + 3000))
    )
    .pause(500.milliseconds, 1.second)

  // ── 시나리오 3: DB 쓰기 (30%) — DS INSERT + pg_sleep ─────────────────────
  val dbWriteScenario = scenario("DB 쓰기")
    .exec(
      http("POST 등록 (DB INSERT)")
        .post(appContext + dbWritePath)
        .header("Content-Type", "application/json")
        .body(StringBody(session => {
          val rand = scala.util.Random.nextInt(999999)
          s"""{"name":"perf-test-$rand","category":"PERF","price":9900}"""
        }))
        .check(status.in(200, 201, 400, 404, 503))
        .check(responseTimeInMillis.lte(dbDelayMs + 3000))
    )
    .pause(1.second, 2.seconds)

  // ── 부하 주입 패턴 ────────────────────────────────────────────────────────
  private def browseInject = testType match {
    case "stress" =>
      browseScenario.inject(
        incrementUsersPerSec(2).times(10).eachLevelLasting(30.seconds).startingFrom(2)
      )
    case "spike" =>
      browseScenario.inject(atOnceUsers((maxUsers * 0.2).toInt))
    case _ =>
      browseScenario.inject(
        rampUsers((targetUsers * 0.2).toInt).during(rampDuration.seconds),
        constantUsersPerSec(targetUsers * 0.02).during(holdDuration.seconds)
      )
  }

  private def dbReadInject = testType match {
    case "stress" =>
      dbReadScenario.inject(
        nothingFor(5.seconds),
        incrementUsersPerSec(5).times(10).eachLevelLasting(30.seconds).startingFrom(5)
      )
    case "spike" =>
      dbReadScenario.inject(atOnceUsers((maxUsers * 0.5).toInt))
    case _ =>
      dbReadScenario.inject(
        nothingFor(5.seconds),
        rampUsers((targetUsers * 0.5).toInt).during(rampDuration.seconds),
        constantUsersPerSec(targetUsers * 0.05).during(holdDuration.seconds)
      )
  }

  private def dbWriteInject = testType match {
    case "stress" =>
      dbWriteScenario.inject(
        nothingFor(10.seconds),
        incrementUsersPerSec(3).times(8).eachLevelLasting(30.seconds).startingFrom(3)
      )
    case "spike" =>
      dbWriteScenario.inject(atOnceUsers((maxUsers * 0.3).toInt))
    case _ =>
      dbWriteScenario.inject(
        nothingFor(10.seconds),
        rampUsers((targetUsers * 0.3).toInt).during(rampDuration.seconds),
        constantUsersPerSec(targetUsers * 0.03).during(holdDuration.seconds)
      )
  }

  setUp(
    browseInject,
    dbReadInject,
    dbWriteInject
  ).protocols(httpProtocol)
    .assertions(
      global.responseTime.percentile(95).lte(dbDelayMs + 2000),
      global.responseTime.percentile(99).lte(dbDelayMs + 5000),
      global.failedRequests.percent.lte(5.0)
    )
}
