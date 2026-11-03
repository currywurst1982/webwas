package com.webwas.precheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tomcat 리포트 해석 + CVE 목록 자동 생성(CveFeed) */
class TomcatAndCveFeedTest {
    static final String TC9 = "tomcat_precheck_vm_20261103_074010.txt";
    static final String TC11 = "tomcat_precheck_vm_20261103_074324.txt";

    @TempDir
    Path dir;

    /** 실제 Tomcat 9.0.80 설치 폴더를 tomcat_precheck.sh 로 점검한 리포트 (AJP·약한 비번·웹쉘을 일부러 심어 둠) */
    @Test
    void parsesTomcat9Report() throws Exception {
        Report r = ReportParserTest.load(TC9);
        assertEquals(Product.TOMCAT, r.product);
        assertEquals("9.0.80", r.version);
        assertEquals("/opt/tomcat9", r.binary);
        assertEquals("ZIP", r.installType);
        assertEquals("/opt/tomcat9/conf/server.xml", r.mainConfig);
        assertTrue(r.summaryFound);
        assertEquals("compromise", r.intrusionStatus());   // 웹쉘 JSP + 200 응답
        assertTrue(r.cveDbInfo.startsWith("스크립트 내장본"), r.cveDbInfo);

        Report.Cve c = r.cves.stream().filter(x -> x.id.equals("CVE-2025-24813")).findFirst().orElseThrow();
        assertTrue(c.applicable);
        assertEquals("critical", c.severity);
        assertEquals("GHSA-83qj-6fr2-vhqg", c.advisory);
        assertEquals("Tomcat 9.0.0.M1~9.0.99 미만", c.affected);
        // lib 에 jar 가 없는 선택 구성요소(jmx-remote 등)는 미해당
        assertTrue(r.cves.stream().anyMatch(x -> !x.applicable));
        assertTrue(r.findings.stream().anyMatch(f -> "3".equals(f.section) && "risk".equals(f.level) && f.text.startsWith("AJP 커넥터")));
        // 설정 항목 묶음 이름: "관리 계정에 추측하기 쉬운 비밀번호 사용: admin → ..." → 계정명 앞까지
        List<ConfigIssues.Item> items = ConfigIssues.group(List.of(r));
        assertTrue(items.stream().anyMatch(i -> i.title().equals("[Tomcat] 관리 계정에 추측하기 쉬운 비밀번호 사용")),
                items.stream().map(ConfigIssues.Item::title).toList().toString());
    }

    @Test
    void latestBranchDecidesBelowLatest() throws Exception {
        LatestVersions lv = AgentStoreTest.latest(dir, "41.0.1.Final");
        Report r9 = ReportParserTest.load(TC9);
        Report r11 = ReportParserTest.load(TC11);
        assertTrue(r9.belowLatest(lv));
        assertEquals("9.0.123", r9.toSummary(lv).get("latestForVersion"));
        assertFalse(r11.belowLatest(lv));
        assertEquals("ok".equals(r11.status()) || "warn".equals(r11.status()), true);
        assertEquals("tomcat", r11.toSummary(lv).get("product"));
        // 같은 호스트의 Apache/Tomcat 은 다른 인스턴스
        assertFalse(r9.instanceKey().equals(r11.instanceKey()));
        assertTrue(r9.instanceKey().startsWith("tomcat|"));
    }

    @Test
    void productDetection() throws Exception {
        assertEquals(Product.APACHE, Product.fromText("Apache 패치 전 보안 사전 점검  |  호스트: a"));
        assertEquals(Product.WILDFLY, Product.fromText("WildFly 패치 전 보안 사전 점검  |  호스트: a"));
        assertEquals(Product.TOMCAT, Product.fromText("Tomcat 패치 전 보안 사전 점검  |  호스트: a"));
        assertNull(Product.fromText("nginx"));
        assertEquals(Product.TOMCAT, Product.fromFileName("agent-was01__tomcat_precheck_was01_20261103_000000.txt"));
        assertTrue(ReportParser.looksLikeReport("Tomcat 패치 전 보안 사전 점검 | 호스트: x"));
    }

    // ------------------------------------------------------------ CveFeed

    private static String script(Product p) throws Exception {
        return Files.readString(Path.of("scripts", p.script), StandardCharsets.UTF_8);
    }

    @Test
    void embeddedRowsAreReadFromScripts() throws Exception {
        assertTrue(CveFeed.rowsOf(script(Product.APACHE), Product.APACHE).size() >= 38);
        assertTrue(CveFeed.rowsOf(script(Product.WILDFLY), Product.WILDFLY).size() >= 149);
        assertTrue(CveFeed.rowsOf(script(Product.TOMCAT), Product.TOMCAT).size() >= 600);
    }

    /** Apache 공식 JSON (5.x 형식 3건 + 4.0 형식 1건 + 사람이 정리한 목록에 있는 1건) */
    @Test
    void apacheJsonToRows() throws Exception {
        String json = Files.readString(Path.of("src/test/resources/cve/vulnerabilities-httpd-sample.json"));
        List<String> rows = CveFeed.apacheRows(JsonParser.parse(json));
        Map<String, String> byId = new java.util.HashMap<>();
        rows.forEach(r -> byId.put(r.substring(0, r.indexOf('|')), r));
        // 5.x: version 2.4.0 + lessThanOrEqual 2.4.59, 제목의 mod_rewrite 없음 → "backreferences"... 모듈 추정
        assertTrue(byId.get("CVE-2024-38474").startsWith("CVE-2024-38474|2.4.0|2.4.59|important|"), byId.get("CVE-2024-38474"));
        // 5.x 단일 버전
        assertTrue(byId.get("CVE-2026-23918").startsWith("CVE-2026-23918|2.4.66|2.4.66|important|http2_module|"), byId.get("CVE-2026-23918"));
        // 4.0: "=" 로 나열된 버전 → 최소~최대
        assertTrue(byId.get("CVE-2021-41773").startsWith("CVE-2021-41773|2.4.49|2.4.49|critical|core|"), byId.get("CVE-2021-41773"));
        String opt = byId.get("CVE-2017-9798");
        assertNotNull(opt);
        assertTrue(opt.matches("CVE-2017-9798\\|2\\.4\\.\\d+\\|2\\.4\\.27\\|\\w+\\|[a-z0-9_&,]+\\|.*"), opt);
        assertTrue(byId.get("CVE-2023-31122").contains("|macro_module|"), byId.get("CVE-2023-31122"));
        rows.forEach(r -> assertTrue(CveFeed.APACHE_ROW.matcher(r).matches(), r));

        // 사람이 정리한 내장 목록이 우선 (한글 설명 유지), 새 CVE 만 추가
        List<String> curated = CveFeed.rowsOf(script(Product.APACHE), Product.APACHE);
        List<String> merged = CveFeed.mergeApache(curated, rows);
        assertEquals(curated.size() + 2, merged.size()); // CVE-2017-9798, CVE-2023-31122 만 새로 추가
        assertTrue(merged.stream().anyMatch(r -> r.startsWith("CVE-2026-23918|") && r.contains("HTTP/2 double free")));
    }

    @Test
    void moduleConditionGuess() {
        assertEquals("proxy_ajp_module", CveFeed.moduleCondition("Heap overflow in mod_proxy_ajp"));
        assertEquals("ssl_module,http2_module", CveFeed.moduleCondition("mod_ssl and mod_http2 issue"));
        assertEquals("http2_module", CveFeed.moduleCondition("HTTP/2 DoS"));
        assertEquals("core", CveFeed.moduleCondition("Path traversal in core"));
        assertEquals("2.4.59", CveFeed.prev("2.4.60"));
        assertNull(CveFeed.prev("2.4.0"));
    }

    private static byte[] zip(Map<String, String> files) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(b)) {
            for (Map.Entry<String, String> e : files.entrySet()) {
                z.putNextEntry(new ZipEntry(e.getKey()));
                z.write(e.getValue().getBytes(StandardCharsets.UTF_8));
                z.closeEntry();
            }
        }
        return b.toByteArray();
    }

    /** OSV 권고(JSON) → WildFly / Tomcat 줄. 관계없는 패키지·철회된 권고는 제외 */
    @Test
    void osvZipToRows() throws Exception {
        String tomcat = "{\"id\":\"GHSA-83qj-6fr2-vhqg\",\"aliases\":[\"CVE-2025-24813\"],\"summary\":\"Apache Tomcat: Potential RCE | partial PUT\","
                + "\"database_specific\":{\"severity\":\"CRITICAL\"},\"affected\":["
                + "{\"package\":{\"ecosystem\":\"Maven\",\"name\":\"org.apache.tomcat:tomcat-catalina\"},\"ranges\":[{\"type\":\"ECOSYSTEM\",\"events\":"
                + "[{\"introduced\":\"9.0.0.M1\"},{\"fixed\":\"9.0.99\"},{\"introduced\":\"10.1.0-M1\"},{\"fixed\":\"10.1.35\"}]}]},"
                + "{\"package\":{\"ecosystem\":\"Maven\",\"name\":\"org.apache.tomcat.embed:tomcat-embed-websocket\"},\"ranges\":[{\"type\":\"ECOSYSTEM\",\"events\":"
                + "[{\"introduced\":\"11.0.0-M1\"},{\"last_affected\":\"11.0.2\"}]}]}]}";
        String wildfly = "{\"id\":\"GHSA-fmq7-gh8v-mjvc\",\"aliases\":[\"CVE-2022-1278\"],\"summary\":\"WildFly vulnerable\","
                + "\"database_specific\":{\"severity\":\"HIGH\"},\"affected\":[{\"package\":{\"name\":\"org.wildfly:wildfly-dist\"},"
                + "\"ranges\":[{\"type\":\"ECOSYSTEM\",\"events\":[{\"introduced\":\"0\"},{\"fixed\":\"27.0.0.Beta1\"}]}]},"
                + "{\"package\":{\"name\":\"io.undertow:undertow-core\"},\"ranges\":[{\"type\":\"ECOSYSTEM\",\"events\":[{\"introduced\":\"2.3.0\"}]}]}]}";
        String withdrawn = "{\"id\":\"GHSA-xxxx-yyyy-zzzz\",\"withdrawn\":\"2025-01-01T00:00:00Z\",\"aliases\":[\"CVE-2024-0001\"],"
                + "\"affected\":[{\"package\":{\"name\":\"org.apache.tomcat:tomcat\"},\"ranges\":[{\"type\":\"ECOSYSTEM\",\"events\":[{\"introduced\":\"0\"}]}]}]}";
        String other = "{\"id\":\"GHSA-aaaa-bbbb-cccc\",\"aliases\":[\"CVE-2024-0002\"],\"affected\":[{\"package\":{\"name\":\"org.springframework:spring-web\"}}]}";
        Map<Product, List<String>> rows = CveFeed.osvRows(zip(Map.of("a.json", tomcat, "b.json", wildfly, "c.json", withdrawn, "d.json", other)));

        List<String> t = rows.get(Product.TOMCAT);
        assertEquals(3, t.size(), t.toString());
        assertTrue(t.contains("CVE-2025-24813|GHSA-83qj-6fr2-vhqg|critical|tomcat||9.0.0.M1|9.0.99||Apache Tomcat: Potential RCE / partial PUT"), t.toString());
        assertTrue(t.contains("CVE-2025-24813|GHSA-83qj-6fr2-vhqg|critical|tomcat-websocket||11.0.0-M1||11.0.2|Apache Tomcat: Potential RCE / partial PUT"), t.toString());
        List<String> w = rows.get(Product.WILDFLY);
        assertTrue(w.contains("CVE-2022-1278|GHSA-fmq7-gh8v-mjvc|high|WILDFLY||0|27.0.0.Beta1||WildFly vulnerable"), w.toString());
        assertTrue(w.contains("CVE-2022-1278|GHSA-fmq7-gh8v-mjvc|high|undertow-core|io.undertow|2.3.0|||WildFly vulnerable"), w.toString());
        t.forEach(r -> assertTrue(CveFeed.OSV_ROW.matcher(r).matches(), r));

        // 자동 목록 우선 + 자동 목록에 없는 내장 CVE 는 유지
        List<String> merged = CveFeed.mergeOsv(List.of("CVE-2000-0001|GHSA-old|low|tomcat||0|1.0||old", "CVE-2025-24813|GHSA-83qj-6fr2-vhqg|critical|tomcat||9.0.0|9.0.50||stale"), t);
        assertTrue(merged.contains("CVE-2000-0001|GHSA-old|low|tomcat||0|1.0||old"));
        assertFalse(merged.stream().anyMatch(r -> r.endsWith("|stale")));
    }

    /** 대시보드가 실제로 받아 쓰는 흐름: 자동 갱신(file: 주소) → 에이전트에 내려 줄 목록 → 다시 시작해도 유지 */
    @Test
    void feedStoresAndServes() throws Exception {
        Map<Product, String> scripts = new java.util.EnumMap<>(Product.class);
        for (Product p : Product.values()) scripts.put(p, script(p));
        Path json = dir.resolve("httpd.json");
        Files.copy(Path.of("src/test/resources/cve/vulnerabilities-httpd-sample.json"), json);
        Path osv = dir.resolve("all.zip");
        Files.write(osv, zip(Map.of("x.json", "{\"id\":\"GHSA-new1-new1-new1\",\"aliases\":[\"CVE-2099-1111\"],\"summary\":\"future\","
                + "\"database_specific\":{\"severity\":\"HIGH\"},\"affected\":[{\"package\":{\"name\":\"org.apache.tomcat:tomcat\"},"
                + "\"ranges\":[{\"type\":\"ECOSYSTEM\",\"events\":[{\"introduced\":\"11.0.0\"},{\"fixed\":\"11.0.99\"}]}]}]}")));
        System.setProperty("webwas.precheck.cve.apache.url", json.toUri().toString());
        System.setProperty("webwas.precheck.cve.osv.url", osv.toUri().toString());
        try {
            CveFeed feed = new CveFeed(dir.resolve("cve"), scripts);
            String before = feed.dbText(Product.TOMCAT, "11.0.27,10.1.61,9.0.123");
            assertTrue(before.contains("# GENERATED=스크립트 내장본"), before.substring(0, 200));
            feed.refreshAll();
            Map<String, Object> st = feed.toMap();
            @SuppressWarnings("unchecked")
            Map<String, Map<String, Object>> ps = (Map<String, Map<String, Object>>) st.get("products");
            assertEquals("generated", ps.get("tomcat").get("using"));
            assertEquals(1, ps.get("tomcat").get("addedCves"));
            assertEquals(2, ps.get("apache").get("addedCves"));
            assertNull(ps.get("apache").get("error"));
            String tc = feed.dbText(Product.TOMCAT, "11.0.28,10.1.62,9.0.124");
            assertTrue(tc.contains("# LATEST=11.0.28,10.1.62,9.0.124"));
            assertTrue(tc.contains("CVE-2099-1111|GHSA-new1-new1-new1|high|tomcat||11.0.0|11.0.99||future"));
            assertTrue(tc.contains("CVE-2025-24813|"));           // 내장 목록 유지
            assertTrue(tc.contains(CveFeed.START) && tc.contains(CveFeed.END));
            // 다시 시작해도 생성 목록 유지
            CveFeed again = new CveFeed(dir.resolve("cve"), scripts);
            assertTrue(again.dbText(Product.APACHE, "2.4.69").contains("CVE-2023-31122|"));
            // 받은 데이터가 비정상이면 이전 목록 유지 + 오류 기록
            Files.writeString(json, "[]");
            again.refreshApache();
            @SuppressWarnings("unchecked")
            Map<String, Map<String, Object>> ps2 = (Map<String, Map<String, Object>>) again.toMap().get("products");
            assertNotNull(ps2.get("apache").get("error"));
            assertTrue(again.dbText(Product.APACHE, "2.4.69").contains("CVE-2023-31122|"));
        } finally {
            System.clearProperty("webwas.precheck.cve.apache.url");
            System.clearProperty("webwas.precheck.cve.osv.url");
        }
    }
}
