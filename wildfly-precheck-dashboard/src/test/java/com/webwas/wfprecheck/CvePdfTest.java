package com.webwas.wfprecheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.Test;

class CvePdfTest {

    /** 실제 리포트: WildFly 26.1.3 / 31.0.1 / 41.0.1 */
    private static List<Report> sample() throws Exception {
        return List.of(ReportParserTest.load(ReportParserTest.WF26), ReportParserTest.load(ReportParserTest.WF31),
                ReportParserTest.load(ReportParserTest.WF41));
    }

    @Test
    void groupsByCveWithTargets() throws Exception {
        List<CveIssues.Item> items = CveIssues.group(sample());
        // 정렬: 대상 서버 수 → 등급. 세 버전 모두에 해당하는 것은 수정 버전이 없는 CVE-2026-3260 뿐
        assertEquals("CVE-2026-3260", items.get(0).id);
        assertEquals(3, items.get(0).targets.size());

        CveIssues.Item c = items.stream().filter(i -> i.id.equals("CVE-2025-12543")).findFirst().orElseThrow();
        assertEquals("critical", c.severity);
        assertEquals(2, c.targets.size()); // 26.1.3(undertow 2.2.19), 31.0.1(undertow 2.3.12)
        assertTrue(c.advisory.startsWith("GHSA-"));
        // 같은 CVE 라도 서버마다 해당 구간·설치 버전이 다를 수 있으므로 서버별 리포트에 그대로 남아 있음
        assertTrue(c.targets.stream().anyMatch(t -> t.report().version.equals("31.0.1.Final")));

        // 구성요소가 없거나 다른 프로젝트라 미해당인 CVE 는 포함하지 않음
        assertFalse(items.stream().anyMatch(i -> i.id.equals("CVE-2019-10184")));
        assertFalse(items.stream().anyMatch(i -> i.id.equals("CVE-2014-7839")));
    }

    @Test
    void pdfListsCvesAndTargets() throws Exception {
        List<Report> reports = sample();
        byte[] pdf = CvePdf.build(CveIssues.group(reports), reports.size(), "41.0.1.Final", "전체 서버", "admin");
        String t;
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            t = new PDFTextStripper().getText(doc);
        }
        assertTrue(t.contains("CVE별 대상 서버"), t);
        assertTrue(t.contains("점검 서버 3대 중 3대"), t);
        assertTrue(t.contains("WildFly 최신 41.0.1.Final"), t);
        assertTrue(t.contains("CVE-2022-1278"));
        assertTrue(t.contains("WildFly vulnerable to Insecure Default Initialization of Resource"));
        assertTrue(t.contains("영향 구간: WildFly 0~27.0.0.Beta1 미만"), t);
        assertTrue(t.contains("vm (192.0.2.2) [wildfly-26.1.3.Final]"), t);
        assertTrue(t.contains("undertow-core 2.3.12.Final 설치됨"), t);
        assertTrue(t.contains("https://osv.dev/vulnerability/GHSA-fmq7-gh8v-mjvc"), t);
        assertTrue(t.contains("https://www.cve.org/CVERecord?id=CVE-2022-1278"));
        assertFalse(t.contains("백포트"));
        // 미해당 CVE, 설정·침해 내용은 들어가지 않음
        assertFalse(t.contains("CVE-2019-10184"));
        assertFalse(t.contains("welcome-content"));
        assertFalse(t.contains("upload.jsp"));
    }

    @Test
    void emptyListStillProducesPdf() throws Exception {
        byte[] pdf = CvePdf.build(List.of(), 0, "41.0.1.Final", "전체 서버", "admin");
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            assertTrue(new PDFTextStripper().getText(doc).contains("해당 CVE 가 없습니다"));
        }
    }
}
