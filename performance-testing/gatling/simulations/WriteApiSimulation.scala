package wildfly

import io.gatling.core.Predef._
import io.gatling.http.Predef._
import scala.concurrent.duration._

/**
 * 쓰기 중심 API 부하테스트
 * - 대상: 등록/수정/삭제 API (POST/PUT/DELETE)
 * - 측정 목표: p95 < 500ms, 에러율 < 0.1%
 * - 실행: gatling.sh -s wildfly.WriteApiSimulation
 */
class WriteApiSimulation extends Simulation {

  val baseUrl      = System.getProperty("baseUrl",      "http://localhost:8080")
  val appContext   = System.getProperty("appContext",    "")
  val targetUsers  = System.getProperty("targetUsers",  "50").toInt
  val rampDuration = System.getProperty("rampDuration", "60").toInt
  val holdDuration = System.getProperty("holdDuration", "300").toInt

  val httpProtocol = http
    .baseUrl(baseUrl)
    .acceptHeader("application/json")
    .contentTypeHeader("application/json")
    .connectionHeader("keep-alive")
    .disableCaching

  val userFeeder = csv("users_with_auth.csv").circular

  // ── 시나리오 1: 등록 → 수정 → 삭제 복합 흐름 ───────────────────────────
  val crudScenario = scenario("CRUD 전체 흐름")
    .feed(userFeeder)
    // 1. 로그인
    .exec(
      http("POST /auth/login")
        .post(appContext + "/api/auth/login")
        .body(StringBody("""{"userId":"${userId}","password":"${password}"}"""))
        .check(status.is(200))
        .check(jsonPath("$.token").saveAs("token"))
    )
    .pause(500.milliseconds)

    // 2. 등록
    .exec(
      http("POST /items (등록)")
        .post(appContext + "/api/items")
        .header("Authorization", "Bearer ${token}")
        .body(StringBody(
          """{
            |  "name": "perf-test-item-${userId}",
            |  "category": "TEST",
            |  "price": 9900,
            |  "description": "성능테스트용 데이터"
            |}""".stripMargin
        ))
        .check(status.is(201))
        .check(jsonPath("$.id").saveAs("createdId"))
    )
    .pause(1.second)

    // 3. 수정
    .exec(
      http("PUT /items/{id} (수정)")
        .put(appContext + "/api/items/${createdId}")
        .header("Authorization", "Bearer ${token}")
        .body(StringBody(
          """{
            |  "name": "perf-test-item-updated-${userId}",
            |  "price": 19900
            |}""".stripMargin
        ))
        .check(status.is(200))
    )
    .pause(1.second)

    // 4. 삭제 (테스트 데이터 정리)
    .exec(
      http("DELETE /items/{id} (삭제)")
        .delete(appContext + "/api/items/${createdId}")
        .header("Authorization", "Bearer ${token}")
        .check(status.is(204))
    )
    .pause(3.seconds, 6.seconds)

  // ── 시나리오 2: 대량 등록 (Bulk Insert 성능) ────────────────────────────
  val bulkInsertScenario = scenario("대량 등록")
    .feed(userFeeder)
    .exec(
      http("POST /auth/login")
        .post(appContext + "/api/auth/login")
        .body(StringBody("""{"userId":"${userId}","password":"${password}"}"""))
        .check(status.is(200))
        .check(jsonPath("$.token").saveAs("token"))
    )
    .pause(500.milliseconds)
    .repeat(10) {
      exec(
        http("POST /items/bulk (대량등록)")
          .post(appContext + "/api/items/bulk")
          .header("Authorization", "Bearer ${token}")
          .body(StringBody(
            """[
              |  {"name":"bulk-item-1","category":"TEST","price":1000},
              |  {"name":"bulk-item-2","category":"TEST","price":2000},
              |  {"name":"bulk-item-3","category":"TEST","price":3000},
              |  {"name":"bulk-item-4","category":"TEST","price":4000},
              |  {"name":"bulk-item-5","category":"TEST","price":5000}
              |]""".stripMargin
          ))
          .check(status.is(201))
          .check(responseTimeInMillis.lte(2000))
      )
      .pause(500.milliseconds)
    }
    .pause(5.seconds, 10.seconds)

  setUp(
    crudScenario.inject(
      nothingFor(5.seconds),
      rampUsers(targetUsers)      over (rampDuration.seconds),
      constantUsersPerSec(targetUsers / 10.0) during (holdDuration.seconds)
    ),
    bulkInsertScenario.inject(
      nothingFor(10.seconds),
      rampUsers(targetUsers / 5)  over (rampDuration.seconds),
      constantUsersPerSec(targetUsers / 50.0) during (holdDuration.seconds)
    )
  ).protocols(httpProtocol)
    .assertions(
      global.responseTime.percentile(95).lte(500),
      global.responseTime.percentile(99).lte(2000),
      global.failedRequests.percent.lte(0.1)
    )
}
