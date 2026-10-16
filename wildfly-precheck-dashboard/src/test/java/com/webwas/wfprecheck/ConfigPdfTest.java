package com.webwas.wfprecheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.Test;

class ConfigPdfTest {

    @Test
    void groupsIssuesByItemWithTargetServers() throws Exception {
        Report wf40 = ReportParserTest.load(ReportParserTest.WF40);
        Report wf41 = ReportParserTest.load(ReportParserTest.WF41);
        Report wf34 = ReportParserTest.load(ReportParserTest.WF34);
        List<ConfigIssues.Item> items = ConfigIssues.group(List.of(wf40, wf41, wf34));

        // 기본 환영 페이지는 세 서버 모두 [주의] → 서버 수가 많아 맨 앞
        ConfigIssues.Item welcome = items.get(0);
        assertTrue(welcome.key.startsWith("기본 환영 페이지(welcome-content)가 / 에 연결됨"), welcome.key);
        assertEquals(3, welcome.targets.size());
        assertEquals("warn", welcome.level);

        ConfigIssues.Item weak = items.stream().filter(i -> i.key.equals("관리 계정에 추측하기 쉬운 비밀번호 사용")).findFirst().orElseThrow();
        assertEquals("risk", weak.level);
        assertEquals(1, weak.targets.size());
        assertEquals("40.0.1.Final", weak.targets.get(0).report().version);

        ConfigIssues.Item mgmt = items.stream().filter(i -> i.key.startsWith("관리 인터페이스 바인드 주소가 0.0.0.0")).findFirst().orElseThrow();
        assertEquals("34.0.1.Final", mgmt.targets.get(0).report().version);
        // [4] 침해 흔적 항목은 설정 취약에 들어가면 안 됨
        assertFalse(items.stream().anyMatch(i -> i.key.startsWith("접근 로그")));
    }

    @Test
    void pdfListsItemsAndTargets() throws Exception {
        Report wf40 = ReportParserTest.load(ReportParserTest.WF40);
        Report wf41 = ReportParserTest.load(ReportParserTest.WF41);
        byte[] pdf = ConfigPdf.build(ConfigIssues.group(List.of(wf40, wf41)), 2, "41.0.1.Final", "전체 서버", "admin");
        String t;
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            t = new PDFTextStripper().getText(doc);
        }
        assertTrue(t.contains("설정 취약 항목별 대상 서버"), t);
        assertTrue(t.contains("점검 서버 2대 중 2대"), t);
        assertTrue(t.contains("관리 계정에 추측하기 쉬운 비밀번호 사용"));
        assertTrue(t.contains("실행 계정이 root"));
        assertTrue(t.contains("vm (192.0.2.2) [wildfly-40.0.1.Final]"), t);
        assertTrue(t.contains("-agentlib:jdwp=transport=dt_socket,address=127.0.0.1:8787"), t);
        // 침해 흔적·CVE 내용은 들어가지 않음
        assertFalse(t.contains("CVE-2026-3260"));
    }

    @Test
    void emptyListStillProducesPdf() throws Exception {
        byte[] pdf = ConfigPdf.build(List.of(), 0, "41.0.1.Final", "전체 서버", "admin");
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            assertTrue(new PDFTextStripper().getText(doc).contains("설정 취약 항목이 없습니다"));
        }
    }
}
