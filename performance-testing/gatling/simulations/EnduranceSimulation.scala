package wildfly

import io.gatling.core.Predef._
import io.gatling.http.Predef._
import scala.concurrent.duration._

/**
 * 내구성(Endurance) 테스트 - 장시간 안정성 검증
 * - 메모리 누수, 커넥션 풀 고갈, Thread 누수 탐지
 * - 기본 8시간 실행 (운영 시 24시간으로 조정)
 * - 실행: gatling.sh -s wildfly.EnduranceSimulation -DholdHours=8
 */
class EnduranceSimulation extends Simulation {

  val baseUrl    = System.getProperty("baseUrl",    "http://localhost:8080")
  val appContext = System.getProperty("appContext",  "")
  val holdHours  = System.getProperty("holdHours",  "8").toInt
  val users      = System.getProperty("users",      "30").toInt  // 평균 부하 수준

  val httpProtocol = http
    .baseUrl(baseUrl)
    .acceptHeader("application/json")
    .contentTypeHeader("application/json")
    .connectionHeader("keep-alive")
    .disableCaching

  val itemIdFeeder = csv("item_ids.csv").circular
  val userFeeder   = csv("users_with_auth.csv").circular

  // ── 지속 실행 시나리오: 조회+쓰기 반복 ──────────────────────────────────
  val enduranceScenario = scenario("Endurance - 반복 CRUD")
    .feed(userFeeder)
    .exec(
      http("POST /auth/login")
        .post(appContext + "/api/auth/login")
        .body(StringBody("""{"userId":"${userId}","password":"${password}"}"""))
        .check(status.is(200))
        .check(jsonPath("$.token").saveAs("token"))
    )
    .during(holdHours.hours) {
      feed(itemIdFeeder)
        .exec(
          http("GET /items/{id}")
            .get(appContext + "/api/items/${itemId}")
            .check(status.is(200))
        )
        .pause(1.second, 3.seconds)
        .exec(
          http("POST /items")
            .post(appContext + "/api/items")
            .header("Authorization", "Bearer ${token}")
            .body(StringBody("""{"name":"endurance-item","category":"TEST","price":999}"""))
            .check(status.in(200, 201))
            .check(jsonPath("$.id").saveAs("endId"))
        )
        .exec(
          http("DELETE /items/{id}")
            .delete(appContext + "/api/items/${endId}")
            .header("Authorization", "Bearer ${token}")
            .check(status.in(200, 204))
        )
        .pause(3.seconds, 8.seconds)
    }

  // ── 주기적 헬스체크: 응답시간 저하 감지 ─────────────────────────────────
  val healthCheckScenario = scenario("Health Check")
    .during(holdHours.hours) {
      exec(
        http("GET /health")
          .get(appContext + "/actuator/health")
          .check(status.is(200))
          .check(responseTimeInMillis.lte(1000))
      )
      .pause(30.seconds)
    }

  setUp(
    enduranceScenario.inject(
      rampUsers(users).during(120.seconds),      // 2분 램프업
      constantUsersPerSec(users / 10.0) during (holdHours.hours)
    ),
    healthCheckScenario.inject(
      nothingFor(120.seconds),
      atOnceUsers(1)
    )
  ).protocols(httpProtocol)
    .assertions(
      // 장기 테스트는 에러율과 p99에 집중
      global.responseTime.percentile(99).lte(3000),
      global.failedRequests.percent.lte(0.5),
      // 응답시간 편차(표준편차)가 평균의 50% 이하 - 안정성 지표
      global.responseTime.stdDev.lte(500)
    )
}
