package wildfly

import io.gatling.core.Predef._
import io.gatling.http.Predef._
import scala.concurrent.duration._

/**
 * 쓰기 중심 부하테스트 — perf_test_log 테이블 INSERT
 *
 * 시나리오 구성:
 *   70%  단건 INSERT  — POST /db-perf-test/db-query.jsp?type=insert
 *   30%  연속 INSERT  — 1명이 5건 연속 INSERT (Bulk 시뮬레이션)
 *
 * 주요 시스템 프로퍼티 (-D):
 *   baseUrl      기본값: http://localhost:8080
 *   targetUsers  기본값: 50
 *   rampDuration 기본값: 60  (초)
 *   holdDuration 기본값: 300 (초)
 *   testType     load(기본) | stress | spike
 *   dbDelayMs    INSERT 당 커넥션 보유 시간(ms)  기본값: 500
 */
class WriteApiSimulation extends Simulation {

  val baseUrl      = System.getProperty("baseUrl",      "http://localhost:8080")
  val appContext   = System.getProperty("appContext",    "")
  val targetUsers  = System.getProperty("targetUsers",  "50").toInt
  val maxUsers     = System.getProperty("maxUsers",     "500").toInt
  val testType     = System.getProperty("testType",     "load")
  val rampDuration = System.getProperty("rampDuration", "60").toInt
  val holdDuration = System.getProperty("holdDuration", "300").toInt
  val dbDelayMs    = System.getProperty("dbDelayMs",    "500").toInt

  val insertPath = s"${appContext}/db-perf-test/db-query.jsp?type=insert&delay=${dbDelayMs}"

  val httpProtocol = http
    .baseUrl(baseUrl)
    .acceptHeader("application/json")
    .acceptEncodingHeader("gzip, deflate")
    .userAgentHeader("Gatling/WildFly-WriteTest")
    .connectionHeader("keep-alive")
    .disableCaching
    .maxConnectionsPerHost(50)

  // ── 시나리오 1: 단건 INSERT (70%) ────────────────────────────────────────
  val singleInsertScenario = scenario("단건 INSERT")
    .exec(
      http("POST perf_test_log (단건)")
        .post(insertPath)
        .header("Content-Type", "application/json")
        .body(StringBody(session => {
          val rand = scala.util.Random.nextInt(999999)
          s"""{"name":"perf-single-$rand","category":"WRITE","price":9900}"""
        }))
        .check(status.in(200, 201))
        .check(responseTimeInMillis.lte(dbDelayMs + 3000))
    )
    .pause(500.milliseconds, 1500.milliseconds)

  // ── 시나리오 2: 연속 INSERT 5건 (30%) — Bulk 쓰기 부하 시뮬레이션 ────────
  val bulkInsertScenario = scenario("연속 INSERT (5건)")
    .repeat(5) {
      exec(
        http("POST perf_test_log (연속)")
          .post(insertPath)
          .header("Content-Type", "application/json")
          .body(StringBody(session => {
            val rand = scala.util.Random.nextInt(999999)
            s"""{"name":"perf-bulk-$rand","category":"BULK","price":${rand % 100000}}"""
          }))
          .check(status.in(200, 201))
          .check(responseTimeInMillis.lte(dbDelayMs + 3000))
      )
      .pause(200.milliseconds, 500.milliseconds)
    }
    .pause(2.seconds, 4.seconds)

  // ── 부하 주입 패턴 ────────────────────────────────────────────────────────
  private def singleInject = testType match {
    case "stress" =>
      singleInsertScenario.inject(
        incrementUsersPerSec(5).times(10).eachLevelLasting(30.seconds).startingFrom(5)
      )
    case "spike" =>
      singleInsertScenario.inject(atOnceUsers((maxUsers * 0.7).toInt))
    case _ =>
      singleInsertScenario.inject(
        rampUsers((targetUsers * 0.7).toInt).during(rampDuration.seconds),
        constantUsersPerSec(targetUsers * 0.07).during(holdDuration.seconds)
      )
  }

  private def bulkInject = testType match {
    case "stress" =>
      bulkInsertScenario.inject(
        nothingFor(10.seconds),
        incrementUsersPerSec(2).times(8).eachLevelLasting(30.seconds).startingFrom(2)
      )
    case "spike" =>
      bulkInsertScenario.inject(atOnceUsers((maxUsers * 0.3).toInt))
    case _ =>
      bulkInsertScenario.inject(
        nothingFor(10.seconds),
        rampUsers((targetUsers * 0.3).toInt).during(rampDuration.seconds),
        constantUsersPerSec(targetUsers * 0.03).during(holdDuration.seconds)
      )
  }

  setUp(
    singleInject,
    bulkInject
  ).protocols(httpProtocol)
    .assertions(
      global.responseTime.percentile(95).lte(dbDelayMs + 2000),
      global.responseTime.percentile(99).lte(dbDelayMs + 5000),
      global.failedRequests.percent.lte(1.0)
    )
}
