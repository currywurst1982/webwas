package wildfly

import io.gatling.core.Predef._
import io.gatling.http.Predef._
import scala.concurrent.duration._

/**
 * 혼합 부하 시뮬레이션 (스트레스/스파이크 테스트)
 * - 읽기 70% / 쓰기 20% / 복합 트랜잭션 10% 혼합
 * - 한계점(Breaking Point) 탐색: 단계적 부하 증가
 * - 실행: gatling.sh -s wildfly.MixedLoadSimulation
 *
 * 실행 모드 선택 (시스템 프로퍼티):
 *   -DtestType=stress  → 부하를 계속 증가 (Breaking Point 탐색)
 *   -DtestType=spike   → 순간 10배 스파이크 주입
 *   -DtestType=load    → 목표 TPS 유지 (기본값)
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
    .acceptHeader("application/json")
    .contentTypeHeader("application/json")
    .connectionHeader("keep-alive")
    .disableCaching
    .maxConnectionsPerHost(100)

  val itemIdFeeder  = csv("item_ids.csv").circular
  val userFeeder    = csv("users_with_auth.csv").circular
  val searchFeeder  = csv("search_keywords.csv").circular

  // ── 읽기 시나리오 (70%) ──────────────────────────────────────────────────
  val readScenario = scenario("혼합-읽기")
    .feed(itemIdFeeder)
    .exec(
      http("GET /items/{id}")
        .get(appContext + "/api/items/${itemId}")
        .check(status.is(200))
    )
    .pause(1.second, 3.seconds)

  // ── 쓰기 시나리오 (20%) ──────────────────────────────────────────────────
  val writeScenario = scenario("혼합-쓰기")
    .feed(userFeeder)
    .exec(
      http("POST /auth/login")
        .post(appContext + "/api/auth/login")
        .body(StringBody("""{"userId":"${userId}","password":"${password}"}"""))
        .check(status.is(200))
        .check(jsonPath("$.token").saveAs("token"))
    )
    .exec(
      http("POST /items")
        .post(appContext + "/api/items")
        .header("Authorization", "Bearer ${token}")
        .body(StringBody("""{"name":"mixed-test","category":"TEST","price":1000}"""))
        .check(status.in(200, 201))
        .check(jsonPath("$.id").saveAs("newId"))
    )
    .exec(
      http("DELETE /items/{id}")
        .delete(appContext + "/api/items/${newId}")
        .header("Authorization", "Bearer ${token}")
        .check(status.in(200, 204))
    )
    .pause(2.seconds, 5.seconds)

  // ── 복합 트랜잭션 (10%): 주문 플로우 ────────────────────────────────────
  val transactionScenario = scenario("복합 트랜잭션")
    .feed(userFeeder)
    .exec(
      http("POST /auth/login")
        .post(appContext + "/api/auth/login")
        .body(StringBody("""{"userId":"${userId}","password":"${password}"}"""))
        .check(status.is(200))
        .check(jsonPath("$.token").saveAs("token"))
    )
    .pause(500.milliseconds)
    .exec(
      http("POST /orders (주문 생성)")
        .post(appContext + "/api/orders")
        .header("Authorization", "Bearer ${token}")
        .body(StringBody(
          """{
            |  "items": [{"itemId": 1, "qty": 2}, {"itemId": 2, "qty": 1}],
            |  "paymentMethod": "CARD",
            |  "deliveryAddr": "서울시 테스트구"
            |}""".stripMargin
        ))
        .check(status.in(200, 201))
        .check(jsonPath("$.orderId").saveAs("orderId"))
        .check(responseTimeInMillis.lte(3000))
    )
    .pause(1.second)
    .exec(
      http("GET /orders/{id} (주문 확인)")
        .get(appContext + "/api/orders/${orderId}")
        .header("Authorization", "Bearer ${token}")
        .check(status.is(200))
        .check(jsonPath("$.status").is("CONFIRMED"))
    )
    .pause(5.seconds, 10.seconds)

  // ── 부하 프로파일 선택 ────────────────────────────────────────────────────
  val readInjection = testType match {
    case "stress" =>
      // 단계적 증가: Breaking Point 탐색
      List(
        incrementUsersPerSec(10).times(10).eachLevelLasting(30.seconds).startingFrom(10)
      )
    case "spike" =>
      // 기본 부하 → 스파이크 → 기본 복귀
      List(
        constantUsersPerSec(targetUsers * 0.7)  during (60.seconds),
        atOnceUsers(maxUsers),
        constantUsersPerSec(targetUsers * 0.7)  during (120.seconds)
      )
    case _ =>
      // 기본 Load Test
      List(
        rampUsers((targetUsers * 0.7).toInt).during(rampDuration.seconds),
        constantUsersPerSec(targetUsers * 0.07) during (holdDuration.seconds)
      )
  }

  setUp(
    readScenario.inject(
      rampUsers((targetUsers * 0.7).toInt).during(rampDuration.seconds),
      constantUsersPerSec(targetUsers * 0.07) during (holdDuration.seconds)
    ),
    writeScenario.inject(
      nothingFor(15.seconds),
      rampUsers((targetUsers * 0.2).toInt).during(rampDuration.seconds),
      constantUsersPerSec(targetUsers * 0.02) during (holdDuration.seconds)
    ),
    transactionScenario.inject(
      nothingFor(30.seconds),
      rampUsers((targetUsers * 0.1).toInt).during(rampDuration.seconds),
      constantUsersPerSec(targetUsers * 0.01) during (holdDuration.seconds)
    )
  ).protocols(httpProtocol)
    .assertions(
      global.responseTime.percentile(95).lte(500),
      global.responseTime.percentile(99).lte(2000),
      global.failedRequests.percent.lte(0.5)
    )
}
