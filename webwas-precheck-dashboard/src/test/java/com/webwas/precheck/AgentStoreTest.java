package com.webwas.precheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AgentStoreTest {
    private static final long H = 3_600_000L;

    @TempDir
    Path dir;

    @Test
    void tokenAuthAndPersistence() throws Exception {
        AgentStore s = new AgentStore(dir.resolve("agents.properties"));
        String token = s.create("web01", 24);
        // 입력하기 쉬운 토큰: 20자 + 하이픈, 헷갈리는 0·1·I·O 없음
        assertTrue(token.matches("[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}"), token);
        assertTrue(s.authenticate("web01", token));
        // 대소문자·하이픈·공백은 무시 (타이핑 실수 허용)
        assertTrue(s.authenticate("web01", token.toLowerCase()));
        assertTrue(s.authenticate("web01", token.replace("-", "")));
        assertTrue(s.authenticate("web01", "  " + token.toLowerCase() + " "));
        assertFalse(s.authenticate("web01", token + "X"));
        assertFalse(s.authenticate("nobody", token));
        assertFalse(s.authenticate("web01", null));
        // 파일에는 토큰 원문이 없어야 함
        assertFalse(Files.readString(dir.resolve("agents.properties"), StandardCharsets.UTF_8).contains(token));
        // 다시 읽어도 인증 유지
        AgentStore again = new AgentStore(dir.resolve("agents.properties"));
        assertTrue(again.authenticate("web01", token));
        // 재발급하면 이전 토큰 무효
        String t2 = again.rotateToken("web01");
        assertFalse(again.authenticate("web01", token));
        assertTrue(again.authenticate("web01", t2));
    }

    @Test
    void rejectsBadNames() throws Exception {
        AgentStore s = new AgentStore(dir.resolve("a.properties"));
        s.create("web_01", 24);                                                     // 밑줄 1개는 허용
        assertThrows(IllegalArgumentException.class, () -> s.create("web__01", 24)); // 연속 밑줄은 파일명 구분자라 금지
        assertThrows(IllegalArgumentException.class, () -> s.create("_web", 24));    // 영문·숫자로 시작해야 함
        assertThrows(IllegalArgumentException.class, () -> s.create("../x", 24));
        assertThrows(IllegalArgumentException.class, () -> s.create("w", 24));
        s.create("web-01.prod", 24);
        assertThrows(IllegalArgumentException.class, () -> s.create("web-01.prod", 24));
    }

    @Test
    void schedulesFirstRunThenWaitsForInterval() throws Exception {
        AgentStore s = new AgentStore(dir.resolve("a.properties"));
        s.create("web01", 24);
        long t = 1_000_000_000_000L;
        // 처음 접속: 리포트가 없으므로 바로 점검
        assertEquals("schedule", s.heartbeat("web01", t, "h", "1.1.1.1", "1.0.0", "abc", false));
        // 점검 중에는 다시 지시하지 않음
        assertNull(s.heartbeat("web01", t + 60_000, "h", "1.1.1.1", "1.0.0", "abc", false));
        assertEquals("running", s.get("web01").state(t + 60_000));
        s.reportReceived("web01", t + 120_000);
        s.runFinished("web01", t + 120_000, 0, 1, "ok");
        // 주기(24h) 전에는 실행 안 함
        assertNull(s.heartbeat("web01", t + 23 * H, "h", "1.1.1.1", "1.0.0", "abc", false));
        assertEquals("schedule", s.heartbeat("web01", t + 25 * H, "h", "1.1.1.1", "1.0.0", "abc", false));
    }

    @Test
    void probeNeverTriggersRun() throws Exception {
        AgentStore s = new AgentStore(dir.resolve("a.properties"));
        s.create("web01", 24);
        long t = 1_000_000_000_000L;
        assertNull(s.heartbeat("web01", t, "h", null, null, null, false, true));
        assertEquals("online", s.get("web01").state(t));
        // 연결 확인 직후의 첫 정식 heartbeat 에서 점검 지시
        assertEquals("schedule", s.heartbeat("web01", t + 60_000, "h", null, null, null, false));
    }

    /** 제품별 최신 버전 (테스트용: 인터넷 확인 없이 스크립트 기준값만) */
    static LatestVersions latest(Path dir, String wildfly) throws Exception {
        Path d = Files.createDirectories(dir.resolve("lv-" + wildfly));
        return new LatestVersions(d, java.util.Map.of(Product.APACHE, "2.4.69", Product.WILDFLY, wildfly,
                Product.TOMCAT, "11.0.27 10.1.61 9.0.123"));
    }

    @Test
    void upToDateServersSkipScheduleButManualStillRuns() throws Exception {
        AgentStore s = new AgentStore(dir.resolve("a.properties"));
        s.create("web01", 24);
        long t = 1_000_000_000_000L;
        LatestVersions v41 = latest(dir, "41.0.1.Final"), v42 = latest(dir, "42.0.0.Final");
        // 버전을 모르면(첫 점검 전) 점검해서 버전을 알아냄
        assertEquals("schedule", s.heartbeat("web01", t, "h", null, null, null, false, false, v41));
        s.reportReceived("web01", t + 1000, Product.WILDFLY, "41.0.1.Final");
        s.runFinished("web01", t + 1000, 0, 1, "ok");
        // 최신(41.0.1.Final) 이상이면 주기가 지나도 자동 점검 안 함
        assertNull(s.heartbeat("web01", t + 48 * H, "h", null, null, null, false, false, v41));
        // 새 버전(42.0.0.Final)이 나오면 다시 점검 대상
        assertEquals("schedule", s.heartbeat("web01", t + 49 * H, "h", null, null, null, false, false, v42));
        s.runFinished("web01", t + 49 * H, 0, 1, "ok");
        s.reportReceived("web01", t + 49 * H, Product.WILDFLY, "42.0.0.Final");
        // 지금 점검은 최신이어도 실행
        s.requestRun("web01");
        assertEquals("manual", s.heartbeat("web01", t + 50 * H, "h", null, null, null, false, false, v42));
    }

    /** 한 서버에 Apache(최신) + Tomcat(최신 미만)이 같이 있으면 자동 점검에서 빠지지 않아야 함 */
    @Test
    void mixedProductsAllMustBeLatest() throws Exception {
        AgentStore s = new AgentStore(dir.resolve("a.properties"));
        s.create("web02", 24);
        long t = 1_000_000_000_000L;
        LatestVersions lv = latest(dir, "41.0.1.Final");
        s.reportReceived("web02", t, Product.APACHE, "2.4.69");
        s.reportReceived("web02", t + 2000, Product.TOMCAT, "9.0.100");
        s.runFinished("web02", t + 3000, 0, 2, "ok");
        assertFalse(AgentStore.upToDate(s.get("web02"), lv));
        assertEquals("schedule", s.heartbeat("web02", t + 48 * H, "h", null, null, null, false, false, lv));
        s.runFinished("web02", t + 48 * H, 0, 2, "ok");
        // 둘 다 최신으로 올리면 제외
        s.reportReceived("web02", t + 49 * H, Product.APACHE, "2.4.69");
        s.reportReceived("web02", t + 49 * H + 1000, Product.TOMCAT, "9.0.123");
        assertTrue(AgentStore.upToDate(s.get("web02"), lv));
        // 지원 종료 브랜치(8.5)는 최신이 아님
        s.reportReceived("web02", t + 80 * H, Product.TOMCAT, "8.5.100");
        assertFalse(AgentStore.upToDate(s.get("web02"), lv));
        // 저장 후 다시 읽어도 제품별 버전 유지
        assertEquals("8.5.100", new AgentStore(dir.resolve("a.properties")).get("web02").versions.get(Product.TOMCAT));
    }

    @Test
    void manualRunAndManualOnlyMode() throws Exception {
        AgentStore s = new AgentStore(dir.resolve("a.properties"));
        s.create("web01", 0);
        long t = 1_000_000_000_000L;
        assertNull(s.heartbeat("web01", t, "h", null, null, null, false)); // 수동 모드: 자동 실행 없음
        s.requestRun("web01");
        assertEquals("requested", s.get("web01").state(t + 1000));
        assertEquals("manual", s.heartbeat("web01", t + 1000, "h", null, null, null, false));
        assertFalse(s.get("web01").pendingRun);
        // 에이전트가 이미 실행 중(busy)이면 지시하지 않고 대기
        s.runFinished("web01", t + 2000, 0, 1, "ok");
        s.requestRun("web01");
        assertNull(s.heartbeat("web01", t + 3000, "h", null, null, null, true));
        assertTrue(s.get("web01").pendingRun);
    }

    @Test
    void failedRunRetriesAfter30MinutesAndStaleRunExpires() throws Exception {
        AgentStore s = new AgentStore(dir.resolve("a.properties"));
        s.create("web01", 24);
        long t = 1_000_000_000_000L;
        assertEquals("schedule", s.heartbeat("web01", t, "h", null, null, null, false));
        s.runFinished("web01", t + 60_000, 1, 0, "리포트가 만들어지지 않음");
        assertNull(s.heartbeat("web01", t + 10 * 60_000, "h", null, null, null, false));
        assertEquals("schedule", s.heartbeat("web01", t + 31 * 60_000, "h", null, null, null, false));
        // 결과가 2시간 넘게 오지 않으면 실행 중 상태 해제 후 다시 지시
        long later = t + 31 * 60_000 + AgentStore.RUN_TIMEOUT_MILLIS + 1;
        assertEquals("schedule", s.heartbeat("web01", later, "h", null, null, null, false));
    }

    @Test
    void offlineAfterThreeMinutes() throws Exception {
        AgentStore s = new AgentStore(dir.resolve("a.properties"));
        s.create("web01", 0);
        long t = 1_000_000_000_000L;
        assertEquals("never", s.get("web01").state(t));
        s.heartbeat("web01", t, "h", null, null, null, false);
        assertEquals("online", s.get("web01").state(t + 60_000));
        assertEquals("offline", s.get("web01").state(t + AgentStore.OFFLINE_MILLIS + 1));
    }

    @Test
    void agentReportsArePrefixedAndPruned() throws Exception {
        Path reports = Files.createDirectories(dir.resolve("reports"));
        ReportStore store = new ReportStore(reports);
        String header = "WildFly 패치 전 보안 사전 점검  |  호스트: web01  |  일시: 2026-10-15 01:00:00\n";
        String saved = store.saveAgentReport("web01", "wildfly_precheck_web01_20261015_010000.txt", header.getBytes(StandardCharsets.UTF_8));
        assertEquals("agent-web01__wildfly_precheck_web01_20261015_010000.txt", saved);
        Report r = store.get(saved);
        assertEquals("web01", r.source);
        assertEquals("web01", r.host);
        // 파일명 조작 거부
        assertThrows(IllegalArgumentException.class, () -> store.saveAgentReport("web01", "../users.properties", header.getBytes(StandardCharsets.UTF_8)));
        assertThrows(IllegalArgumentException.class, () -> store.saveAgentReport("web01", "wildfly_precheck_x.txt", "not a report".getBytes(StandardCharsets.UTF_8)));
        // 에이전트당 최근 KEEP_PER_AGENT 개만 보관
        for (int i = 0; i < ReportStore.KEEP_PER_AGENT + 5; i++) {
            Path p = reports.resolve(String.format("agent-web01__wildfly_precheck_web01_20261016_%06d.txt", i));
            Files.writeString(p, header, StandardCharsets.UTF_8);
            Files.setLastModifiedTime(p, java.nio.file.attribute.FileTime.fromMillis(1_000_000L + i));
        }
        store.saveAgentReport("web01", "wildfly_precheck_web01_20261017_000000.txt", header.getBytes(StandardCharsets.UTF_8));
        long left;
        try (var ds = Files.list(reports)) {
            left = ds.filter(p -> p.getFileName().toString().startsWith("agent-web01__")).count();
        }
        assertEquals(ReportStore.KEEP_PER_AGENT, left);
        assertTrue(Files.exists(reports.resolve("agent-web01__wildfly_precheck_web01_20261017_000000.txt")));
    }

    /** 한 서버의 WildFly 여러 개(26·41)를 한 번에 점검하면 낮은 버전 기준 → 최신 버전 제외 규칙에 걸리지 않아야 함 */
    @Test
    void multiInstanceRunKeepsLowestVersion(@TempDir Path dir) throws Exception {
        AgentStore s = new AgentStore(dir.resolve("agents.properties"));
        s.create("was01", 24);
        long t = 1_800_000_000_000L;
        s.reportReceived("was01", t, Product.WILDFLY, "26.1.3.Final");
        s.reportReceived("was01", t + 5_000, Product.WILDFLY, "41.0.1.Final");
        AgentStore.Agent a = s.get("was01");
        assertEquals("26.1.3.Final", a.versions.get(Product.WILDFLY));
        assertFalse(AgentStore.upToDate(a, latest(dir, "41.0.1.Final")));
        // 다음 점검(하루 뒤)에서 모두 올렸으면 새 값으로 바뀜
        s.reportReceived("was01", t + 24 * 3_600_000L, Product.WILDFLY, "41.0.1.Final");
        a = s.get("was01");
        assertEquals("41.0.1.Final", a.versions.get(Product.WILDFLY));
    }

    /** 점검이 3분 넘게 걸려도 오프라인으로 보이면 안 됨: 옛 에이전트는 점검 중이면 "점검 중", 새 에이전트는 신호로 판단 */
    @Test
    void longRunIsNotOffline(@TempDir Path dir) throws Exception {
        AgentStore s = new AgentStore(dir.resolve("agents.properties"));
        s.create("old01", 24);
        s.create("new01", 24);
        long t = 1_800_000_000_000L;
        assertEquals("schedule", s.heartbeat("old01", t, "h", null, "2.0.0", null, false));
        assertEquals("schedule", s.heartbeat("new01", t, "h", null, "2.1.0", null, false));
        long later = t + 10 * 60_000L;   // 10분 동안 점검 중
        assertEquals("running", s.get("old01").state(later));     // 옛 에이전트: 신호가 없어도 점검 중
        assertEquals("offline", s.get("new01").state(later));     // 새 에이전트: 신호가 끊기면 오프라인 (정말 멈춘 것)
        s.heartbeat("new01", later - 30_000L, "h", null, "2.1.0", null, true);  // 점검 중 신호(busy=1)
        assertEquals("running", s.get("new01").state(later));
        // 점검이 끝나면 둘 다 평소 규칙
        s.runFinished("old01", later, 0, 1, "ok");
        assertEquals("online", s.get("old01").state(later + 60_000L));
        assertEquals("offline", s.get("old01").state(later + 4 * 60_000L));
        // 점검 제한 시간(2시간)이 지나면 옛 에이전트도 오프라인
        s.heartbeat("old01", later + 5 * 60_000L, "h", null, "2.0.0", null, true);
        assertEquals("offline", s.get("old01").state(later + 5 * 60_000L + AgentStore.RUN_TIMEOUT_MILLIS + 1));
    }

    /** 토큰이 틀린 에이전트: 인증 실패를 기록해 화면에 원인 표시. 정상 접속하면 사라짐 */
    @Test
    void authFailureIsShownUntilNextSuccess(@TempDir Path dir) throws Exception {
        AgentStore s = new AgentStore(dir.resolve("agents.properties"));
        s.create("web09", 24);
        long t = 1_800_000_000_000L;
        s.heartbeat("web09", t, "h", "10.0.0.9", "2.1.0", null, false, true);
        s.authFailed("web09", "10.0.0.9", t + 60_000, false);
        s.authFailed("nobody", "10.0.0.1", t, false);           // 없는 이름은 무시
        java.util.Map<String, Object> m = s.get("web09").toMap(t + 70_000, null);
        assertEquals(t + 60_000, m.get("authFailAt"));
        assertEquals("10.0.0.9", m.get("authFailIp"));
        s.authFailed("web09", "10.0.0.9", t + 120_000, true);
        assertEquals(true, s.get("web09").toMap(t + 130_000, null).get("authLocked"));
        s.heartbeat("web09", t + 200_000, "h", "10.0.0.9", "2.1.0", null, false, true); // 토큰 고친 뒤 정상 접속
        assertEquals(0L, s.get("web09").toMap(t + 210_000, null).get("authFailAt"));
    }

    @Test
    void scriptUpdateRequest() throws Exception {
        java.nio.file.Path f = dir.resolve("agents.properties");
        AgentStore s = new AgentStore(f);
        s.create("web01", 24);
        s.create("web02", 24);
        // 업데이트 요청 → heartbeat 때 한 번만 지시하고 꺼짐
        assertEquals(1, s.requestUpdate("web01"));
        assertTrue(s.takePendingUpdate("web01"));
        assertFalse(s.takePendingUpdate("web01"), "두 번째 heartbeat 에는 지시 안 함");
        assertFalse(s.takePendingUpdate("web02"), "요청 안 한 에이전트는 false");
        // 저장/로드 유지 (요청 후 heartbeat 전)
        s.requestUpdate("web02");
        assertTrue(new AgentStore(f).takePendingUpdate("web02"));
        // 여러 대 한 번에
        assertEquals(2, s.requestUpdate(java.util.List.of("web01", "web02")));
        assertEquals(0, s.requestUpdate(java.util.List.of("nope")));
        // 없는 에이전트 단건은 예외
        assertThrows(IllegalArgumentException.class, () -> s.requestUpdate("nope"));
    }

    @Test
    void groupLabel() throws Exception {
        Path f = dir.resolve("agents.properties");
        AgentStore s = new AgentStore(f);
        s.create("web01", 24, "HAPPY");
        s.create("web02", 24, "  HAPPY  ");          // 공백은 정리
        s.create("web03", 24, null);                 // 그룹 없음
        assertEquals("HAPPY", group(s, "web01"));
        assertEquals("HAPPY", group(s, "web02"));
        assertEquals("", group(s, "web03"));
        // 변경·해제
        assertEquals("SAMPLE 운영", s.setGroup("web03", "SAMPLE 운영"));   // 한글·공백 허용
        assertEquals("", s.setGroup("web01", "  "));                      // 공백만이면 해제
        // 제어문자 제거, 30자 제한
        assertEquals("a b", AgentStore.normGroup("a\t\n b"));
        assertEquals(30, AgentStore.normGroup("x".repeat(50)).length());
        // 다시 읽어도 유지
        AgentStore s2 = new AgentStore(f);
        assertEquals("HAPPY", group(s2, "web02"));
        assertEquals("SAMPLE 운영", group(s2, "web03"));
        assertEquals("", group(s2, "web01"));
        // 없는 에이전트
        assertThrows(IllegalArgumentException.class, () -> s.setGroup("nope", "X"));
    }

    private static String group(AgentStore s, String name) {
        return s.list().stream().filter(a -> a.name.equals(name)).findFirst().orElseThrow().group;
    }

}
