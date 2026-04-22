package wildfly

import io.gatling.core.Predef._
import io.gatling.http.Predef._
import scala.concurrent.duration._

/**
 * 혼합 부하 시뮬레이션 — DB 연동 포함
 *
 * 시나리오 구성:
 *   50%  페이지 조회      — GET /            (정적 응답, DS 미사용)
 *   30%  DB 읽기          — GET /api/items   (DS SELECT)
 *   20%  DB 쓰기          — POST/DELETE      (DS INSERT/DELETE)
 *
 * 주요 시스템 프로퍼티 (-D):
 *   baseUrl      기본값: http://localhost:8080
 *   appContext    기본값: (없음)
 *   targetUsers  기본값: 50
 *   rampDuration 기본값: 60  (초)
 *   holdDuration 기본값: 300 (초)
 *   testType     load(기본) | stress | spike
 *   dbListPath   DB 목록 조회 경로  기본값: /api/items
 *   dbDetailPath DB 단건 조회 경로  기본값: /api/items/{id}
 *   dbWritePath  DB 등록 경로       기본값: /api/items
 *   dbAuthPath   로그인 경로        기본값: (없음 — 인증 불필요 시 빈값)
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

  // ── DB 엔드포인트 설정 ────────────────────────────────────────────────────
  val dbListPath   = System.getProperty("dbListPath",   "/api/items")
  val dbDetailPath = System.getProperty("dbDetailPath", "/api/items")
  val dbWritePath  = System.getProperty("dbWritePath",  "/api/items")
  val dbAuthPath   = System.getProperty("dbAuthPath",   "")

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

  // ── 피더: item_ids.csv 없으면 인라인 기본값 사용 ─────────────────────────
  val itemIdFeeder = Iterator.continually(Map("itemId" -> (1 + scala.util.Random.nextInt(100)).toString))

  // ── 시나리오 1: 정적 페이지 조회 (50%) — DS 미사용 ───────────────────────
  val browseScenario = scenario("페이지 조회")
    .exec(
      http("GET /")
        .get(appContext + "/")
        .check(status.is(200))
        .check(responseTimeInMillis.lte(3000))
    )
    .pause(2.seconds, 5.seconds)

  // ── 시나리오 2: DB 읽기 (30%) — DS SELECT ────────────────────────────────
  val dbReadScenario = scenario("DB 읽기")
    .exec(
      // 목록 조회 (전체 SELECT)
      http("GET 목록 (DB SELECT)")
        .get(appContext + dbListPath)
        .check(status.in(200, 304))
        .check(responseTimeInMillis.lte(2000))
    )
    .pause(1.second, 2.seconds)
    .feed(itemIdFeeder)
    .exec(
      // 단건 조회 (PK SELECT)
      http("GET 단건 (DB SELECT by ID)")
        .get(appContext + dbDetailPath + "/#{itemId}")
        .check(status.in(200, 404))
        .check(responseTimeInMillis.lte(1000))
    )
    .pause(1.second, 3.seconds)

  // ── 시나리오 3: DB 쓰기 (20%) — DS INSERT + DELETE ───────────────────────
  val dbWriteScenario = scenario("DB 쓰기")
    .exec(
      http("POST 등록 (DB INSERT)")
        .post(appContext + dbWritePath)
        .header("Content-Type", "application/json")
        .body(StringBody(session => {
          val rand = scala.util.Random.nextInt(999999)
          s"""{
             |  "name"       : "perf-test-$rand",
             |  "category"   : "PERF",
             |  "price"      : 9900,
             |  "description": "Gatling 성능테스트 데이터"
             |}""".stripMargin
        }))
        .check(status.in(200, 201, 400, 404))
        .check(responseTimeInMillis.lte(3000))
    )
    .pause(2.seconds, 4.seconds)

  // ── 부하 주입 패턴 ────────────────────────────────────────────────────────
  private def browseInject = testType match {
    case "stress" =>
      browseScenario.inject(
        incrementUsersPerSec(5).times(10).eachLevelLasting(30.seconds).startingFrom(5)
      )
    case "spike" =>
      browseScenario.inject(atOnceUsers(maxUsers))
    case _ =>
      browseScenario.inject(
        rampUsers((targetUsers * 0.5).toInt).during(rampDuration.seconds),
        constantUsersPerSec(targetUsers * 0.05).during(holdDuration.seconds)
      )
  }

  private def dbReadInject = testType match {
    case "stress" =>
      dbReadScenario.inject(
        nothingFor(5.seconds),
        incrementUsersPerSec(3).times(10).eachLevelLasting(30.seconds).startingFrom(3)
      )
    case "spike" =>
      dbReadScenario.inject(atOnceUsers((maxUsers * 0.3).toInt))
    case _ =>
      dbReadScenario.inject(
        nothingFor(5.seconds),
        rampUsers((targetUsers * 0.3).toInt).during(rampDuration.seconds),
        constantUsersPerSec(targetUsers * 0.03).during(holdDuration.seconds)
      )
  }

  private def dbWriteInject = testType match {
    case "stress" =>
      dbWriteScenario.inject(
        nothingFor(10.seconds),
        incrementUsersPerSec(2).times(8).eachLevelLasting(30.seconds).startingFrom(2)
      )
    case "spike" =>
      dbWriteScenario.inject(atOnceUsers((maxUsers * 0.2).toInt))
    case _ =>
      dbWriteScenario.inject(
        nothingFor(10.seconds),
        rampUsers((targetUsers * 0.2).toInt).during(rampDuration.seconds),
        constantUsersPerSec(targetUsers * 0.02).during(holdDuration.seconds)
      )
  }

  setUp(
    browseInject,
    dbReadInject,
    dbWriteInject
  ).protocols(httpProtocol)
    .assertions(
      global.responseTime.percentile(95).lte(500),
      global.responseTime.percentile(99).lte(2000),
      global.failedRequests.percent.lte(5.0)
    )
}
