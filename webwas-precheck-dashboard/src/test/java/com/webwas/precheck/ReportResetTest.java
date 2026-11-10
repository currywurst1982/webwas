package com.webwas.precheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** 점검 기록 초기화: 범위별 선택, 휴지통 이동·보관 기간 정리, 에이전트 상태 초기화 */
class ReportResetTest {

    private static Report r(String id, String source, Product p, String host, String binary, String at) {
        Report x = new Report();
        x.id = id;
        x.source = source;
        x.product = p;
        x.host = host;
        x.binary = binary;
        x.checkedAt = at;
        return x;
    }

    /** 최신순 (ReportStore.all() 과 같은 순서) */
    private static final List<Report> ALL = List.of(
            r("a3", "web01", Product.WILDFLY, "h1", "/opt/wf", "2026-11-10 03:00:00"),
            r("b1", "web02", Product.NGINX, "h2", "/usr/sbin/nginx", "2026-11-09 03:00:00"),
            r("a2", "web01", Product.WILDFLY, "h1", "/opt/wf", "2026-11-08 03:00:00"),
            r("c1", null, Product.APACHE, "h3", "/usr/sbin/httpd", "2026-11-07 03:00:00"),
            r("a1", "web01", Product.WILDFLY, "h1", "/opt/wf", "2026-11-06 03:00:00"));

    private static List<String> ids(List<Report> l) {
        return l.stream().map(x -> x.id).toList();
    }

    @Test
    void selectsByScope() {
        assertEquals(List.of("a3", "a2", "a1"), ids(ReportReset.select(ALL, "instance", ALL.get(0).instanceKey())));
        assertEquals(List.of("a3", "a2", "a1"), ids(ReportReset.select(ALL, "agent", "web01")));
        assertEquals(List.of("b1"), ids(ReportReset.select(ALL, "product", "nginx")));
        assertEquals(List.of("a1"), ids(ReportReset.select(ALL, "old", "2")), "서버마다 최근 2개 남김 → h1 의 가장 오래된 것만");
        assertEquals(List.of(), ids(ReportReset.select(ALL, "old", "5")));
        assertEquals(5, ReportReset.select(ALL, "all", null).size());
        assertThrows(IllegalArgumentException.class, () -> ReportReset.select(ALL, "old", "0"));
        assertThrows(IllegalArgumentException.class, () -> ReportReset.select(ALL, "agent", "../x"));
        assertThrows(IllegalArgumentException.class, () -> ReportReset.select(ALL, "product", "iis"));
        assertThrows(IllegalArgumentException.class, () -> ReportReset.select(ALL, "everything", null));
        assertEquals(3, ReportReset.preview(ReportReset.select(ALL, "agent", "web01")).get("count"));
        assertEquals(1L, ReportReset.preview(ReportReset.select(ALL, "agent", "web01")).get("instances"));
    }

    @Test
    void trashMovesFilesAndPurgesOldTrash(@TempDir Path data) throws Exception {
        Path reports = data.resolve("reports");
        Files.createDirectories(reports);
        String a = "wildfly_precheck_vm_20261016_050340_pid4068.txt", b = "tomcat_precheck_vm_20261103_074010.txt";
        Files.writeString(reports.resolve(a), ReportParserTest.resource("wildfly_precheck_vm_20261016_050340_pid4068.txt"));
        Files.writeString(reports.resolve(b), ReportParserTest.resource("tomcat_precheck_vm_20261103_074010.txt"));
        ReportStore store = new ReportStore(reports);
        assertEquals(2, store.all().size());
        assertEquals(1, store.trash(List.of(a, "../etc/passwd", "없는파일.txt"), "agent"));
        assertEquals(1, store.all().size());
        Path moved = store.lastTrash();
        assertTrue(Files.isRegularFile(moved.resolve(a)), "휴지통에 보관");
        assertEquals(data.resolve("reports-trash"), moved.getParent());
        // 보관 기간(기본 30일)이 지난 휴지통 폴더는 다음 정리 때 지워짐
        Files.setLastModifiedTime(moved, FileTime.fromMillis(System.currentTimeMillis() - 31L * 86_400_000L));
        assertTrue(store.delete(b));
        assertFalse(Files.exists(moved), "31일 지난 휴지통 비움");
        assertTrue(Files.isRegularFile(store.lastTrash().resolve(b)), "방금 지운 것은 남음");
        assertEquals(0, store.all().size());
    }

    @Test
    void agentHistoryResetKeepsRegistration(@TempDir Path dir) throws Exception {
        AgentStore s = new AgentStore(dir.resolve("agents.properties"));
        String token = s.create("web09", 24);
        long t = 1_800_000_000_000L;
        s.heartbeat("web09", t, "h", "10.0.0.9", "2.3.0", null, false, true);
        s.reportReceived("web09", t, Product.NGINX, "1.24.0");
        s.runFinished("web09", t, 0, 1, "리포트 1개 전송 완료");
        assertTrue(s.resetHistory("web09"));
        AgentStore.Agent a = new AgentStore(dir.resolve("agents.properties")).get("web09");   // 파일에도 저장됐는지
        assertEquals(0, a.lastReportAt);
        assertEquals(0, a.lastRunAt);
        assertTrue(a.versions.isEmpty());
        assertEquals("", a.lastMessage);
        assertEquals("10.0.0.9", a.ip, "접속 정보는 유지");
        assertTrue(s.authenticate("web09", token), "토큰 유지");
        assertFalse(s.resetHistory("nobody"));
    }
}
