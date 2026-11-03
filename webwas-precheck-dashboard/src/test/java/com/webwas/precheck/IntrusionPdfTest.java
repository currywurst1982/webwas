package com.webwas.precheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
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

    /** 침해 흔적 시험 인스턴스(WildFly 31.0.1): PDF 에 [4] 섹션만 들어가고 [2]·[3] 내용은 빠져야 함 */
    @Test
    void containsOnlyIntrusionSection() throws Exception {
        Report r = ReportParserTest.load(ReportParserTest.WF31);
        assertEquals("compromise", r.intrusionStatus());
        assertFalse(r.section4Raw.isEmpty());

        String t = text(IntrusionPdf.single(r, lv(), "admin"));
        assertTrue(t.contains("판정: 침해 의심"), t);
        assertTrue(t.contains("웹쉘 의심 코드 패턴(명령 실행·클래스 주입)을 포함한 JSP 2개"), t);
        assertTrue(t.contains("shop.war!/upload.jsp"), t);
        assertTrue(t.contains("최신 41.0.1.Final 미만"), t);
        assertTrue(t.contains("WildFly 버전"), t);
        assertTrue(t.contains("/opt/wf-test/wildfly-31.0.1.Final"), t);
        assertTrue(t.contains(IntrusionPdf.sha256(r.raw)));
        // [3] 위험 설정, [2] CVE 내용은 들어가면 안 됨
        assertFalse(t.contains("CVE-2024-3884"), t);
        assertFalse(t.contains("AJP 리스너"), t);
    }

    /** 침해 흔적이 없는 실제 리포트(WildFly 40.0.1)도 오류 없이 만들어지고 "흔적 없음"으로 표시 */
    @Test
    void cleanRealReport() throws Exception {
        Report r = ReportParserTest.load(ReportParserTest.WF40);
        assertEquals("clean", r.intrusionStatus());
        String t = text(IntrusionPdf.single(r, lv(), "viewer1"));
        assertTrue(t.contains("알려진 침해 흔적 없음"), t);
        assertTrue(t.contains("최신 41.0.1.Final 미만"), t);
        assertTrue(t.contains("접근 로그가 없어"), t); // 데이터 품질 경고
        assertFalse(t.contains("welcome-content"));
    }

    @Test
    void combinedHasCoverAndEveryServer() throws Exception {
        Report a = ReportParserTest.load(ReportParserTest.WF31);
        Report b = ReportParser.parse("wildfly_precheck_was09_20261016_050344_pid9.txt", ReportParserTest.resource(ReportParserTest.WF31));
        b.host = "was09";
        byte[] pdf = IntrusionPdf.combined(List.of(a, b), lv(), "admin");
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            assertTrue(doc.getNumberOfPages() >= 3);
        }
        String t = text(pdf);
        assertTrue(t.contains("침해 의심 서버 점검 결과"));
        assertTrue(t.contains("vm") && t.contains("was09"));
    }

    @Test
    void suspectsUseLatestReportPerInstance() throws Exception {
        Report old = ReportParserTest.load(ReportParserTest.WF31);
        Report fixedLater = ReportParserTest.load(ReportParserTest.WF41);
        // 같은 인스턴스로 만들어, 나중 점검에서 흔적이 없으면 의심 목록에서 빠지는지 확인
        fixedLater.host = old.host;
        fixedLater.binary = old.binary;
        assertTrue(ApiServlet.suspects(List.of(fixedLater, old)).isEmpty());
        assertEquals(1, ApiServlet.suspects(List.of(old)).size());
    }

    @TempDir
    Path tmp;

    private LatestVersions lv() throws Exception {
        return AgentStoreTest.latest(tmp, "41.0.1.Final");
    }

    @Test
    void parsesMavenMetadata(@TempDir Path dir) throws Exception {
        // Maven Central maven-metadata.xml 형식 (org.wildfly:wildfly-dist). Beta/CR 은 제외하고 가장 높은 Final
        String xml = "<metadata><groupId>org.wildfly</groupId><artifactId>wildfly-dist</artifactId><versioning>"
                + "<latest>42.0.0.Beta1</latest><release>42.0.0.Beta1</release><versions>"
                + "<version>9.0.2.Final</version><version>40.0.1.Final</version><version>41.0.0.Final</version>"
                + "<version>41.0.1.Final</version><version>42.0.0.Beta1</version>"
                + "</versions></versioning></metadata>";
        assertEquals("41.0.1.Final", LatestVersion.parseListing(Product.WILDFLY, xml));
        assertNull(LatestVersion.parseListing(Product.WILDFLY, "<html>nothing</html>"));
        assertTrue(LatestVersion.validVersion(Product.WILDFLY, "41.0.1.Final"));
        assertFalse(LatestVersion.validVersion(Product.WILDFLY, "42.0.0.Beta1"));
        assertFalse(LatestVersion.validVersion(Product.WILDFLY, "2.4.69"));

        LatestVersion lv = new LatestVersion(Product.WILDFLY, dir.resolve("lv.properties"), "http://127.0.0.1:9/none", "41.0.1.Final");
        assertEquals("41.0.1.Final", lv.current());           // 확인 전: 스크립트 기준
        assertEquals("baseline", lv.origin());
        lv.setManual("42.0.0.Final");
        assertEquals("42.0.0.Final", lv.current());
        assertTrue(lv.isUpToDate("42.0.0.Final"));
        assertFalse(lv.isUpToDate("41.0.1.Final"));
        // 다시 읽어도 유지
        assertEquals("42.0.0.Final", new LatestVersion(Product.WILDFLY, dir.resolve("lv.properties"), null, "41.0.1.Final").current());
        lv.setAuto();
        lv.refresh(); // 접속 불가 주소 → 실패 기록, 기준값 유지
        assertEquals("41.0.1.Final", lv.current());
        assertNotNull(lv.toMap().get("autoError"));
    }

    @Test
    void apacheListing() {
        String html = "<a href=\"httpd-2.4.68.tar.gz\">x</a><a href=\"httpd-2.4.69.tar.bz2\">y</a><a href=\"httpd-2.2.34.tar.gz\">";
        assertEquals("2.4.69", LatestVersion.parseListing(Product.APACHE, html));
        assertTrue(LatestVersion.validVersion(Product.APACHE, "2.4.70"));
        assertFalse(LatestVersion.validVersion(Product.APACHE, "41.0.1.Final"));
    }

    /** Tomcat 은 브랜치(9.0 / 10.1 / 11.0)마다 최신 버전이 따로 있음 */
    @Test
    void tomcatBranches(@TempDir Path dir) throws Exception {
        assertEquals("11.0.27,10.1.61,9.0.123",
                LatestVersion.bestPerBranch(List.of("9.0.122", "9.0.123", "10.0.27", "10.1.61", "11.0.27", "11.0.26", "10.1.60"), 0));
        LatestVersion lv = new LatestVersion(Product.TOMCAT, dir.resolve("t.properties"), "http://127.0.0.1:9/none", "11.0.27 10.1.61 9.0.123");
        assertEquals("11.0.27 / 10.1.61 / 9.0.123", lv.display());
        assertEquals("9.0.123", lv.latestFor("9.0.85"));
        assertTrue(lv.below("9.0.85"));
        assertFalse(lv.below("10.1.61"));
        assertNull(lv.latestFor("8.5.100"));
        assertTrue(lv.below("8.5.100"));          // 지원 종료 브랜치
        assertTrue(lv.unsupportedBranch("10.0.27"));
        assertTrue(lv.below("11.0.0-M20"));       // 마일스톤은 정식보다 낮음
        lv.setManual("11.0.28, 10.1.62, 9.0.124");
        assertEquals("11.0.28,10.1.62,9.0.124", lv.current());
        assertThrows(IllegalArgumentException.class, () -> lv.setManual("41.0.1.Final"));
    }
}
