package com.webwas.precheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.file.Path;
import java.util.List;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class IntrusionPdfTest {

    private static Report load(String resource, String fileName) throws Exception {
        try (InputStream in = IntrusionPdfTest.class.getResourceAsStream("/" + resource)) {
            assertNotNull(in, resource);
            return ReportParser.parse(fileName, ReportParser.decode(in.readAllBytes()));
        }
    }

    private static String text(byte[] pdf) throws Exception {
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            return new PDFTextStripper().getText(doc);
        }
    }

    /** 침해 의심 리포트(테스트용 가상 데이터): PDF 에 [4] 섹션만 들어가고 [3] 위험 설정 내용은 빠져야 함 */
    @Test
    void containsOnlyIntrusionSection() throws Exception {
        Report r = load("sample_compromise_web01.txt", "apache_precheck_web01_20261014_100000_pid321.txt");
        assertEquals("compromise", r.intrusionStatus());
        assertFalse(r.section4Raw.isEmpty());

        String t = text(IntrusionPdf.single(r, "2.4.69", "admin"));
        assertTrue(t.contains("판정: 침해 의심"), t);
        assertTrue(t.contains("경로 탐색 시도 중 200(성공) 응답 3건"));
        assertTrue(t.contains("203.0.113.7"));
        assertTrue(t.contains("최신 2.4.69 미만"));
        assertTrue(t.contains("192.0.2.11, 2001:db8::11"), t);
        assertFalse(t.contains("PID"), t);
        assertTrue(t.contains(IntrusionPdf.sha256(r.raw)));
        // [3] 위험 설정, [2] CVE 내용은 들어가면 안 됨
        assertFalse(t.contains("ProxyRequests"), t);
        assertFalse(t.contains("CVE-2021-41773"), t);
    }

    /** 실제 Ubuntu 리포트(침해 흔적 없음)도 오류 없이 만들어지고 "흔적 없음"으로 표시 */
    @Test
    void cleanRealReport() throws Exception {
        Report r = load("apache_precheck_vm_fixed.txt", "apache_precheck_vm_20261015_080000.txt");
        assertEquals("clean", r.intrusionStatus());
        String t = text(IntrusionPdf.single(r, "2.4.69", "viewer1"));
        assertTrue(t.contains("알려진 침해 흔적 없음"), t);
        assertTrue(t.contains("웹쉘 의심 코드 패턴 파일 없음"));
        assertFalse(t.contains("ServerTokens"));
    }

    @Test
    void combinedHasCoverAndEveryServer() throws Exception {
        Report a = load("sample_compromise_web01.txt", "apache_precheck_web01_20261014_100000_pid321.txt");
        Report b = load("sample_compromise_web01.txt", "apache_precheck_web09_20261014_100000_pid9.txt");
        b.host = "web09";
        byte[] pdf = IntrusionPdf.combined(List.of(a, b), "2.4.69", "admin");
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            assertTrue(doc.getNumberOfPages() >= 3);
        }
        String t = text(pdf);
        assertTrue(t.contains("침해 의심 서버 점검 결과"));
        assertTrue(t.contains("web01") && t.contains("web09"));
    }

    @Test
    void suspectsUseLatestReportPerInstance() throws Exception {
        Report old = load("sample_compromise_web01.txt", "apache_precheck_web01_20261014_100000_pid321.txt");
        Report fixedLater = load("apache_precheck_vm_fixed.txt", "apache_precheck_vm_20261015_080000.txt");
        // 같은 인스턴스로 만들어, 나중 점검에서 흔적이 없으면 의심 목록에서 빠지는지 확인
        fixedLater.host = old.host;
        fixedLater.binary = old.binary;
        fixedLater.pid = old.pid;
        assertTrue(ApiServlet.suspects(List.of(fixedLater, old)).isEmpty());
        assertEquals(1, ApiServlet.suspects(List.of(old)).size());
    }

    @Test
    void parsesOfficialListing(@TempDir Path dir) throws Exception {
        // https://downloads.apache.org/httpd/ 실제 목록의 한 줄 형식
        String html = "<a href=\"httpd-2.4.68.tar.gz\">httpd-2.4.68.tar.gz</a>\n"
                + "<img src=\"/icons/compressed.gif\" alt=\"[TGZ]\"> <a href=\"httpd-2.4.69.tar.gz\">httpd-2.4.69.tar.gz</a>         2026-10-01 12:55   10M  HTTP Server project\n"
                + "<a href=\"httpd-2.4.9.tar.bz2\">httpd-2.4.9.tar.bz2</a>";
        assertEquals("2.4.69", LatestVersion.parseListing(html));
        assertNull(LatestVersion.parseListing("<html>nothing</html>"));

        LatestVersion lv = new LatestVersion(dir.resolve("lv.properties"), "http://127.0.0.1:9/none", "2.4.69");
        assertEquals("2.4.69", lv.current());           // 확인 전: 스크립트 기준
        assertEquals("baseline", lv.origin());
        lv.setManual("2.4.70");
        assertEquals("2.4.70", lv.current());
        assertTrue(lv.isUpToDate("2.4.70"));
        assertFalse(lv.isUpToDate("2.4.69"));
        // 다시 읽어도 유지
        assertEquals("2.4.70", new LatestVersion(dir.resolve("lv.properties"), null, "2.4.69").current());
        lv.setAuto();
        lv.refresh(); // 접속 불가 주소 → 실패 기록, 기준값 유지
        assertEquals("2.4.69", lv.current());
        assertNotNull(lv.toMap().get("autoError"));
    }
}
