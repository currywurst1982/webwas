package wildfly

import io.gatling.core.Predef._
import io.gatling.http.Predef._
import scala.concurrent.duration._

/**
 * 읽기 중심 부하테스트 — 실제 배포된 앱 기준
 * 대상: GET /  (WildFly 26 보안 점검 앱)
 * 측정 목표: p95 < 300ms, 에러율 < 0.1%
 */
class ReadApiSimulation extends Simulation {

  val baseUrl      = System.getProperty("baseUrl",      "http://localhost:8080")
  val appContext   = System.getProperty("appContext",    "")
  val targetUsers  = System.getProperty("targetUsers",  "100").toInt
  val rampDuration = System.getProperty("rampDuration", "60").toInt
  val holdDuration = System.getProperty("holdDuration", "300").toInt

  val httpProtocol = http
    .baseUrl(baseUrl)
    .acceptHeader("text/html,application/xhtml+xml,*/*;q=0.8")
    .acceptEncodingHeader("gzip, deflate")
    .userAgentHeader("Gatling/WildFly-PerfTest")
    .connectionHeader("keep-alive")
    .disableCaching
    .maxConnectionsPerHost(50)

  val mainPageScenario = scenario("메인 페이지 조회")
    .exec(
      http("GET /")
        .get(appContext + "/")
        .check(status.is(200))
        .check(responseTimeInMillis.lte(1000))
    )
    .pause(2.seconds, 5.seconds)

  val multiLoadScenario = scenario("연속 페이지 로드")
    .exec(
      http("GET / (1차)")
        .get(appContext + "/")
        .check(status.is(200))
    )
    .pause(1.second)
    .exec(
      http("GET / (2차)")
        .get(appContext + "/")
        .check(status.is(200))
    )
    .pause(3.seconds, 7.seconds)

  setUp(
    mainPageScenario.inject(
      rampUsers(targetUsers).during(rampDuration.seconds),
      constantUsersPerSec(targetUsers / 10.0).during(holdDuration.seconds)
    ),
    multiLoadScenario.inject(
      nothingFor(10.seconds),
      rampUsers(targetUsers / 2).during(rampDuration.seconds),
      constantUsersPerSec(targetUsers / 20.0).during(holdDuration.seconds)
    )
  ).protocols(httpProtocol)
    .assertions(
      global.responseTime.percentile(95).lte(300),
      global.responseTime.percentile(99).lte(1000),
      global.failedRequests.percent.lte(0.1)
    )
}
