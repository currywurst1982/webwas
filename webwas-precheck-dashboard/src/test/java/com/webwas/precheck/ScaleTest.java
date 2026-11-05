package com.webwas.precheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** 서버 수백 대 규모 대비: 캐시에 원문을 두지 않음, 폴더 상태 버전, 일자별 집계 */
class ScaleTest {

    @Test
    void cacheDropsRawButFullHasIt(@TempDir Path dir) throws Exception {
        String text = ReportParserTest.resource(TomcatAndCveFeedTest.TC9);
        Files.writeString(dir.resolve(TomcatAndCveFeedTest.TC9), text, StandardCharsets.UTF_8);
        ReportStore store = new ReportStore(dir);
        Report light = store.all().get(0);
        assertNull(light.raw);                         // 메모리 절약
        assertTrue(light.section4Raw.isEmpty());
        assertFalse(light.findings.isEmpty());         // 화면·설정 PDF 에 필요한 정보는 유지
        assertEquals("compromise", light.intrusionStatus());
        Report full = store.full(light.id);
        assertNotNull(full);
        assertEquals(text, full.raw);                  // 상세·원본·침해 PDF 는 파일에서 다시 읽음
        assertFalse(full.section4Raw.isEmpty());
        assertNull(store.full("../etc/passwd"));
        assertNull(store.full("nope.txt"));
    }

    @Test
    void versionChangesOnlyWhenFolderChanges(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve(TomcatAndCveFeedTest.TC9), ReportParserTest.resource(TomcatAndCveFeedTest.TC9), StandardCharsets.UTF_8);
        ReportStore store = new ReportStore(dir);
        store.all();
        long v1 = store.version();
        store.all();
        assertEquals(v1, store.version());             // 그대로면 같은 값 → 화면에 304
        Files.writeString(dir.resolve(TomcatAndCveFeedTest.TC11), ReportParserTest.resource(TomcatAndCveFeedTest.TC11), StandardCharsets.UTF_8);
        store.all();
        assertNotEquals(v1, store.version());          // 리포트가 늘면 달라짐
    }

    @Test
    void dailyCountsByDayProductSource() throws Exception {
        String today = LocalDate.now().toString();
        String old = LocalDate.now().minusDays(30).toString();
        Report a = ReportParserTest.load(TomcatAndCveFeedTest.TC9);   // 침해 의심
        a.checkedAt = today + " 01:00:00";
        a.source = "web01";
        Report b = ReportParserTest.load(TomcatAndCveFeedTest.TC11);
        b.checkedAt = today + " 02:00:00";
        b.source = "web01";
        Report c = ReportParserTest.load(TomcatAndCveFeedTest.TC11);
        c.checkedAt = old + " 02:00:00";                              // 14일 밖 → 제외
        Map<String, Object> d = ApiServlet.daily(List.of(a, b, c), 14);
        @SuppressWarnings("unchecked")
        List<List<Object>> rows = (List<List<Object>>) d.get("rows");
        assertEquals(1, rows.size(), rows.toString());
        assertEquals(List.of(today, "tomcat", "web01", 2, 1), rows.get(0));
        assertEquals(3, d.get("totalReports"));
    }
}
