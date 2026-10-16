package com.webwas.precheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.util.List;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.Test;

class CvePdfTest {

    private static Report load(String resource, String fileName) throws Exception {
        try (InputStream in = CvePdfTest.class.getResourceAsStream("/" + resource)) {
            assertNotNull(in, resource);
            return ReportParser.parse(fileName, ReportParser.decode(in.readAllBytes()));
        }
    }

    private static List<Report> sample() throws Exception {
        // web01: 테스트용 가상 리포트(소스 설치, 백포트 없음), vm: 실제 Ubuntu DEB 리포트(백포트 추정 3건)
        return List.of(load("sample_compromise_web01.txt", "apache_precheck_web01_20261014_100000_pid321.txt"),
                load("apache_precheck_vm_fixed.txt", "agent-vm-test__apache_precheck_vm_20261015_080000.txt"));
    }

    @Test
    void groupsByCveWithOpenAndBackportedTargets() throws Exception {
        List<CveIssues.Item> items = CveIssues.group(sample());
        // 같은 정렬 규칙: 미조치 수 → 등급(critical 먼저)
        assertEquals("critical", items.get(0).severity);

        CveIssues.Item c = items.stream().filter(i -> i.id.equals("CVE-2024-38476")).findFirst().orElseThrow();
        assertEquals(2, c.targets.size());
        assertEquals(1, c.openCount());
        assertEquals(1, c.backportCount());
        assertEquals("2.4.0~2.4.59", c.affected);
        assertEquals("core", c.condition);
        // 미조치 서버가 먼저
        assertEquals("web01", c.targets.get(0).report().host);
        assertFalse(c.targets.get(0).backported());

        // 모듈 미사용으로 미해당인 CVE 는 포함하지 않음
        assertFalse(items.stream().anyMatch(i -> i.id.equals("CVE-2021-44790")));
    }

    @Test
    void pdfListsCvesAndTargets() throws Exception {
        List<Report> reports = sample();
        byte[] pdf = CvePdf.build(CveIssues.group(reports), reports.size(), "2.4.69", "전체 서버", "admin");
        String t;
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            t = new PDFTextStripper().getText(doc);
        }
        assertTrue(t.contains("CVE별 대상 서버"), t);
        assertTrue(t.contains("점검 서버 2대 중 2대"), t);
        assertTrue(t.contains("CVE-2021-41773"));
        assertTrue(t.contains("경로 탐색/파일 노출"));
        assertTrue(t.contains("영향 버전: 2.4.49~2.4.49"));
        assertTrue(t.contains("web01 (PID 321)"));
        assertTrue(t.contains("백포트 추정 (changelog 에 수정 기록)"));
        assertTrue(t.contains("에이전트 vm-test"));
        assertTrue(t.contains("https://www.cve.org/CVERecord?id=CVE-2024-38476"));
        // 미해당 CVE, 설정·침해 내용은 들어가지 않음
        assertFalse(t.contains("CVE-2021-44790"));
        assertFalse(t.contains("ProxyRequests"));
        assertFalse(t.contains("203.0.113.7"));
    }

    @Test
    void emptyListStillProducesPdf() throws Exception {
        byte[] pdf = CvePdf.build(List.of(), 0, "2.4.69", "전체 서버", "admin");
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            assertTrue(new PDFTextStripper().getText(doc).contains("해당 CVE 가 없습니다"));
        }
    }
}
