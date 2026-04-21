package wildfly

import io.gatling.core.Predef._
import io.gatling.http.Predef._
import scala.concurrent.duration._

/**
 * 혼합 부하 시뮬레이션 — 실제 배포된 앱 기준
 * 대상: GET /  (WildFly 26 보안 점검 앱)
 *
 * 실행 모드 (-DtestType=):
 *   load   → 목표 동시 사용자 유지 (기본값)
 *   stress → 단계적 증가로 Breaking Point 탐색
 *   spike  → 순간 최대 부하 주입
 */
class MixedLoadSimulation extends Simulation {

  val baseUrl      = System.getProperty("baseUrl",      "http://localhost:8080")
  val appContext   = System.getProperty("appContext",    "")
  val targetUsers  = System.getProperty("targetUsers",  "50").toInt
  val maxUsers     = System.getProperty("maxUsers",     "500").toInt
  val testType     = System.getProperty("testType",     "load")
  val rampDuration = System.getProperty("rampDuration", "60").toInt
  val holdDuration = System.getProperty("holdDuration", "300").toInt

  val httpProtocol = http
    .baseUrl(baseUrl)
    .acceptHeader("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    .acceptLanguageHeader("ko-KR,ko;q=0.9,en;q=0.8")
    .acceptEncodingHeader("gzip, deflate")
    .userAgentHeader("Gatling/WildFly-PerfTest")
    .connectionHeader("keep-alive")
    .disableCaching
    .maxConnectionsPerHost(50)

  // ── 시나리오 1: 단순 페이지 조회 (70%) ──────────────────────────────────────
  val browseScenario = scenario("페이지 조회")
    .exec(
      http("GET /")
        .get(appContext + "/")
        .check(status.is(200))
        .check(responseTimeInMillis.lte(3000))
    )
    .pause(2.seconds, 5.seconds)

  // ── 시나리오 2: 반복 브라우징 (20%) — 사용자가 새로고침하는 패턴 ────────────
  val repeatBrowseScenario = scenario("반복 브라우징")
    .repeat(3) {
      exec(
        http("GET / (반복)")
          .get(appContext + "/")
          .check(status.is(200))
      )
      .pause(1.second, 3.seconds)
    }
    .pause(5.seconds, 10.seconds)

  // ── 시나리오 3: 빠른 연속 요청 (10%) — 자동화 클라이언트 패턴 ───────────────
  val burstScenario = scenario("연속 요청")
    .repeat(5) {
      exec(
        http("GET / (burst)")
          .get(appContext + "/")
          .check(status.in(200, 304))
      )
      .pause(200.milliseconds, 500.milliseconds)
    }
    .pause(10.seconds, 20.seconds)

  val browseInjection = testType match {
    case "stress" =>
      browseScenario.inject(
        incrementUsersPerSec(5).times(10).eachLevelLasting(30.seconds).startingFrom(5)
      )
    case "spike" =>
      browseScenario.inject(atOnceUsers(maxUsers))
    case _ =>
      browseScenario.inject(
        rampUsers((targetUsers * 0.7).toInt).during(rampDuration.seconds),
        constantUsersPerSec(targetUsers * 0.07).during(holdDuration.seconds)
      )
  }

  setUp(
    browseInjection,
    repeatBrowseScenario.inject(
      nothingFor(10.seconds),
      rampUsers((targetUsers * 0.2).toInt).during(rampDuration.seconds),
      constantUsersPerSec(targetUsers * 0.02).during(holdDuration.seconds)
    ),
    burstScenario.inject(
      nothingFor(20.seconds),
      rampUsers((targetUsers * 0.1).toInt).during(rampDuration.seconds),
      constantUsersPerSec(targetUsers * 0.01).during(holdDuration.seconds)
    )
  ).protocols(httpProtocol)
    .assertions(
      global.responseTime.percentile(95).lte(500),
      global.responseTime.percentile(99).lte(2000),
      global.failedRequests.percent.lte(1.0)
    )
}
