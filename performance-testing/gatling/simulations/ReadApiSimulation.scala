package wildfly

import io.gatling.core.Predef._
import io.gatling.http.Predef._
import scala.concurrent.duration._

/**
 * 읽기 중심 API 부하테스트
 * - 대상: 조회/검색 API (GET)
 * - 측정 목표: p95 < 300ms, 에러율 < 0.1%
 * - 실행: gatling.sh -s wildfly.ReadApiSimulation
 */
class ReadApiSimulation extends Simulation {

  // ── 환경 변수로 오버라이드 가능 ──────────────────────────────────────────
  val baseUrl        = System.getProperty("baseUrl",        "http://localhost:8080")
  val appContext     = System.getProperty("appContext",      "/myapp")
  val targetUsers    = System.getProperty("targetUsers",    "100").toInt
  val rampDuration   = System.getProperty("rampDuration",   "60").toInt    // 초
  val holdDuration   = System.getProperty("holdDuration",   "300").toInt   // 초 (5분)

  // ── HTTP 프로토콜 설정 ───────────────────────────────────────────────────
  val httpProtocol = http
    .baseUrl(baseUrl)
    .acceptHeader("application/json")
    .acceptEncodingHeader("gzip, deflate")
    .userAgentHeader("Gatling/WildFly-PerfTest")
    .connectionHeader("keep-alive")
    .disableCaching                       // 브라우저 캐시 배제, WAS 레벨만 측정
    .maxConnectionsPerHost(50)

  // ── 피더(Feeder): 다양한 파라미터로 DB 캐시 편향 방지 ──────────────────
  val itemIdFeeder    = csv("item_ids.csv").circular
  val searchFeeder    = csv("search_keywords.csv").circular
  val userIdFeeder    = csv("user_ids.csv").random

  // ── 시나리오 1: 단건 조회 ────────────────────────────────────────────────
  val itemDetailScenario = scenario("단건 조회")
    .feed(itemIdFeeder)
    .exec(
      http("GET /items/{id}")
        .get(appContext + "/api/items/${itemId}")
        .check(status.is(200))
        .check(jsonPath("$.id").exists)
        .check(responseTimeInMillis.lte(1000))
    )
    .pause(2.seconds, 5.seconds)  // Think time

  // ── 시나리오 2: 목록 조회 (페이지네이션) ────────────────────────────────
  val itemListScenario = scenario("목록 조회")
    .exec(
      http("GET /items?page=1")
        .get(appContext + "/api/items")
        .queryParam("page", "#{page}")
        .queryParam("size", "20")
        .queryParam("sort", "createdAt,desc")
        .check(status.is(200))
        .check(jsonPath("$.content").exists)
    )
    .pause(3.seconds, 8.seconds)

  // ── 시나리오 3: 검색 (인덱스 활용 여부 측정) ────────────────────────────
  val searchScenario = scenario("검색")
    .feed(searchFeeder)
    .exec(
      http("GET /items/search")
        .get(appContext + "/api/items/search")
        .queryParam("keyword", "${keyword}")
        .queryParam("page", "0")
        .queryParam("size", "20")
        .check(status.is(200))
        .check(responseTimeInMillis.lte(2000))
    )
    .pause(5.seconds, 10.seconds)

  // ── 시나리오 4: 사용자별 이력 조회 ──────────────────────────────────────
  val userHistoryScenario = scenario("사용자 이력 조회")
    .feed(userIdFeeder)
    .exec(
      http("POST /auth/login")
        .post(appContext + "/api/auth/login")
        .header("Content-Type", "application/json")
        .body(StringBody("""{"userId":"${userId}","password":"Test1234!"}"""))
        .check(status.is(200))
        .check(jsonPath("$.token").saveAs("authToken"))
    )
    .pause(1.second)
    .exec(
      http("GET /users/{id}/history")
        .get(appContext + "/api/users/${userId}/history")
        .header("Authorization", "Bearer ${authToken}")
        .check(status.is(200))
    )
    .pause(3.seconds, 7.seconds)

  // ── 부하 프로파일: 점진적 램프업 후 유지 ────────────────────────────────
  setUp(
    itemDetailScenario.inject(
      rampUsers(targetUsers)       over (rampDuration.seconds),
      constantUsersPerSec(targetUsers / 10.0) during (holdDuration.seconds)
    ),
    itemListScenario.inject(
      rampUsers(targetUsers / 2)   over (rampDuration.seconds),
      constantUsersPerSec(targetUsers / 20.0) during (holdDuration.seconds)
    ),
    searchScenario.inject(
      rampUsers(targetUsers / 4)   over (rampDuration.seconds),
      constantUsersPerSec(targetUsers / 40.0) during (holdDuration.seconds)
    ),
    userHistoryScenario.inject(
      rampUsers(targetUsers / 4)   over (rampDuration.seconds),
      constantUsersPerSec(targetUsers / 40.0) during (holdDuration.seconds)
    )
  ).protocols(httpProtocol)
    .assertions(
      global.responseTime.percentile(95).lte(300),   // p95 < 300ms
      global.responseTime.percentile(99).lte(1000),  // p99 < 1s
      global.failedRequests.percent.lte(0.1),        // 에러율 < 0.1%
      global.requestsPerSec.gte(targetUsers.toDouble / 2)
    )
}
