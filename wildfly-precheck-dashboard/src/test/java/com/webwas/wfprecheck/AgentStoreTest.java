package com.webwas.wfprecheck;

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
        assertTrue(s.authenticate("web01", token));
        assertFalse(s.authenticate("web01", token + "x"));
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
        assertThrows(IllegalArgumentException.class, () -> s.create("web_01", 24)); // 밑줄은 파일명 구분자라 금지
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

    @Test
    void upToDateServersSkipScheduleButManualStillRuns() throws Exception {
        AgentStore s = new AgentStore(dir.resolve("a.properties"));
        s.create("web01", 24);
        long t = 1_000_000_000_000L;
        // 버전을 모르면(첫 점검 전) 점검해서 버전을 알아냄
        assertEquals("schedule", s.heartbeat("web01", t, "h", null, null, null, false, false, "41.0.1.Final"));
        s.reportReceived("web01", t + 1000, "41.0.1.Final");
        s.runFinished("web01", t + 1000, 0, 1, "ok");
        // 최신(41.0.1.Final) 이상이면 주기가 지나도 자동 점검 안 함
        assertNull(s.heartbeat("web01", t + 48 * H, "h", null, null, null, false, false, "41.0.1.Final"));
        // 새 버전(42.0.0.Final)이 나오면 다시 점검 대상
        assertEquals("schedule", s.heartbeat("web01", t + 49 * H, "h", null, null, null, false, false, "42.0.0.Final"));
        s.runFinished("web01", t + 49 * H, 0, 1, "ok");
        s.reportReceived("web01", t + 49 * H, "42.0.0.Final");
        // 지금 점검은 최신이어도 실행
        s.requestRun("web01");
        assertEquals("manual", s.heartbeat("web01", t + 50 * H, "h", null, null, null, false, false, "42.0.0.Final"));
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
        s.reportReceived("was01", t, "26.1.3.Final");
        s.reportReceived("was01", t + 5_000, "41.0.1.Final");
        AgentStore.Agent a = s.get("was01");
        assertEquals("26.1.3.Final", a.wildflyVersion);
        assertFalse(AgentStore.upToDate(a, "41.0.1.Final"));
        // 다음 점검(하루 뒤)에서 모두 올렸으면 새 값으로 바뀜
        s.reportReceived("was01", t + 24 * 3_600_000L, "41.0.1.Final");
        a = s.get("was01");
        assertEquals("41.0.1.Final", a.wildflyVersion);
    }
}
