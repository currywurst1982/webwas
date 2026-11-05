package com.webwas.precheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** 2026-11-05 개선: Apache CVE 실제 데이터 검증·대체 경로, 직접 업로드 보관 개수 */
class ImprovementsTest {

    @AfterEach
    void clear() {
        System.clearProperty("webwas.precheck.keep.uploads");
    }

    private static String realApacheJson() throws Exception {
        try (InputStream in = new GZIPInputStream(Files.newInputStream(Path.of("src/test/resources/cve/vulnerabilities-httpd-20261029.json.gz")))) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /** 실제 Apache 보안팀 데이터(288건): 사람이 정리한 스크립트 내장 38건의 영향 버전·등급이 자동 변환과 모두 같아야 함 */
    @Test
    void realApacheDataMatchesCuratedList() throws Exception {
        List<String> feed = CveFeed.apacheRows(JsonParser.parse(realApacheJson()));
        assertEquals(180, feed.size());                       // 2.4.x 에 영향이 있는 CVE
        Map<String, String[]> byId = new HashMap<>();
        feed.forEach(r -> byId.put(r.split("\\|")[0], r.split("\\|")));
        List<String> curated = CveFeed.rowsOf(Files.readString(Path.of("scripts/apache_precheck.sh")), Product.APACHE);
        assertEquals(38, curated.size());
        for (String c : curated) {
            String[] x = c.split("\\|");
            String[] y = byId.get(x[0]);
            assertNotNull(y, "자동 목록에 없음: " + x[0]);
            assertEquals(x[1] + "~" + x[2] + " " + x[3], y[1] + "~" + y[2] + " " + y[3], x[0]);
        }
        // 알려진 예: mod_status 버퍼 오버플로는 2.4.10 에서 수정
        assertEquals("CVE-2014-0226|2.4.1|2.4.9|moderate|status_module|mod_status buffer overflow",
                feed.stream().filter(r -> r.startsWith("CVE-2014-0226|")).findFirst().orElseThrow());
        assertEquals(180, CveFeed.mergeApache(curated, feed).size());
    }

    /** httpd.apache.org 에 못 갈 때: GitHub 폴더 목록 → 파일별 JSON (여기서는 file: 주소로 흉내) */
    @Test
    void apacheFolderFallback(@TempDir Path dir) throws Exception {
        Object all = JsonParser.parse(Files.readString(Path.of("src/test/resources/cve/vulnerabilities-httpd-sample.json")));
        StringBuilder list = new StringBuilder("[");
        int i = 0;
        for (Object o : (List<?>) all) {
            String id = JsonParser.str(JsonParser.obj(o, "CVE_data_meta"), "ID");
            if (id == null) id = JsonParser.str(JsonParser.obj(o, "cveMetadata"), "cveId");
            Path f = dir.resolve(id + ".json");
            Files.writeString(f, Json.write(o));
            list.append(i++ > 0 ? "," : "").append("{\"name\":\"").append(id).append(".json\",\"download_url\":\"").append(f.toUri()).append("\"}");
        }
        // 엉뚱한 파일·다른 호스트는 무시
        list.append(",{\"name\":\"README.md\",\"download_url\":\"").append(dir.resolve("x").toUri()).append("\"}");
        list.append(",{\"name\":\"CVE-2099-0001.json\",\"download_url\":\"https://evil.example/x.json\"}]");
        Path listing = dir.resolve("listing.json");
        Files.writeString(listing, list.toString());
        List<Object> got = CveFeed.fetchApacheFolder(listing.toUri().toString());
        assertEquals(5, got.size());
        List<String> rows = CveFeed.apacheRows(got);
        assertTrue(rows.stream().anyMatch(r -> r.startsWith("CVE-2021-41773|2.4.49|2.4.49|critical|")), rows.toString());
    }

    /** 직접 업로드분은 인스턴스마다 최근 N개만 보관 (에이전트 리포트·다른 인스턴스는 건드리지 않음) */
    @Test
    void uploadsAreCappedPerInstance(@TempDir Path dir) throws Exception {
        System.setProperty("webwas.precheck.keep.uploads", "3");
        ReportStore store = new ReportStore(dir);
        String tmpl = ReportParserTest.resource(TomcatAndCveFeedTest.TC11);
        // 에이전트가 보낸 것 1개 (보관 개수와 무관해야 함)
        Files.writeString(dir.resolve("agent-web01__tomcat_precheck_vm_20261101_000000.txt"), tmpl);
        for (int d = 1; d <= 5; d++) {
            String t = tmpl.replaceFirst("일시: \\S+", "일시: 2026-11-0" + d);
            store.saveUpload("tomcat_precheck_vm_2026110" + d + "_000000.txt", t.getBytes(StandardCharsets.UTF_8));
        }
        // 다른 인스턴스(호스트가 다름)
        store.saveUpload("tomcat_precheck_other_20261101_000000.txt",
                tmpl.replaceFirst("호스트: vm ", "호스트: other ").getBytes(StandardCharsets.UTF_8));
        List<String> names = store.all().stream().map(r -> r.id).sorted().toList();
        assertEquals(List.of(
                "agent-web01__tomcat_precheck_vm_20261101_000000.txt",
                "tomcat_precheck_other_20261101_000000.txt",
                "tomcat_precheck_vm_20261103_000000.txt",
                "tomcat_precheck_vm_20261104_000000.txt",
                "tomcat_precheck_vm_20261105_000000.txt"), names);
        // 0 = 제한 없음
        System.setProperty("webwas.precheck.keep.uploads", "0");
        store.saveUpload("tomcat_precheck_vm_20261102_000000.txt", tmpl.replaceFirst("일시: \\S+", "일시: 2026-11-02").getBytes(StandardCharsets.UTF_8));
        assertTrue(store.all().stream().anyMatch(r -> r.id.equals("tomcat_precheck_vm_20261102_000000.txt")));
        assertFalse(ReportStore.keepUploads() > 0);
    }
}
