package com.webwas.precheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.Charset;
import org.junit.jupiter.api.Test;

class ReportParserTest {

    private static String resource(String name) throws Exception {
        try (InputStream in = ReportParserTest.class.getResourceAsStream("/" + name)) {
            assertNotNull(in, name);
            return ReportParser.decode(in.readAllBytes());
        }
    }

    /** Ubuntu 24.04 apache2 2.4.58 에서 원본 스크립트를 실제로 실행해 얻은 리포트. */
    @Test
    void parsesRealUbuntuReport() throws Exception {
        String name = "apache_precheck_vm_20261015_073443.txt";
        Report r = ReportParser.parse(name, resource(name));

        assertEquals("vm", r.host);
        assertEquals("2026-10-15 07:34:43", r.checkedAt);
        assertEquals("2.4.58", r.version);
        assertEquals("/usr/sbin/apache2", r.binary);
        assertEquals("DEB", r.installType);
        assertEquals("www-data", r.runUser);
        assertTrue(r.below2469);
        assertFalse(r.eol);
        assertTrue(r.summaryFound);
        assertEquals(1, r.risk);
        assertEquals(5, r.warn);
        assertEquals(15, r.ok);
        assertEquals(11, r.info);

        long applicable = r.cves.stream().filter(c -> c.applicable).count();
        long skipped = r.cves.stream().filter(c -> !c.applicable).count();
        assertEquals(3, applicable);
        assertEquals(22, skipped);
        assertTrue(r.cves.stream().filter(c -> c.applicable).allMatch(c -> c.backported));

        Report.Cve c = r.cves.stream().filter(x -> x.id.equals("CVE-2024-38476")).findFirst().orElseThrow();
        assertEquals("important", c.severity);
        assertEquals("2.4.0~2.4.59", c.affected);
        assertEquals("core", c.condition);

        Report.Finding idx = r.findings.stream().filter(f -> f.text.startsWith("Options Indexes")).findFirst().orElseThrow();
        assertEquals("3", idx.section);
        assertEquals(2, idx.details.size());

        // 원본 스크립트 버그(PID 가 실행 인자로 들어감, 모듈 0개)를 데이터 품질 경고로 표시
        assertEquals("1583", r.pid);
        assertEquals(0, r.moduleCount);
        assertEquals(3, r.dataQuality.size()); // 모듈 0개, PID 인자 버그, Include 안 된 파일(mods-available) 점검
        assertTrue(r.dataQuality.get(2).contains("/etc/apache2/mods-available/userdir.conf"), r.dataQuality.toString());
        assertFalse(r.compromiseSuspected());
        assertEquals("risk", r.status());
    }

    @Test
    void detectsCompromiseAndUnpatchedCves() {
        String text = String.join("\n",
                "Apache 패치 전 보안 사전 점검  |  호스트: web01  |  일시: 2026-10-14 10:00:00",
                "",
                "==================================================================",
                " [1] 버전 및 설치 방식 확인",
                "==================================================================",
                "[정보] 실행파일: /usr/local/apache2/bin/httpd",
                "[정보] 버전 정보: Server version: Apache/2.4.49 (Unix)",
                "[위험] Apache 2.4.49 : 2.4.69 미만입니다. 아래 [2]에서 해당 CVE를 확인하세요.",
                "[정보] 설치 방식: 소스 설치(또는 패키지 정보 없음) → 버전 숫자 기준으로 판정합니다.",
                "[정보] 로드된 모듈 수: 40",
                "        core_module so_module",
                "==================================================================",
                " [2] 버전 구간별 해당 CVE 판정 (2.4.x)",
                "==================================================================",
                "[위험] CVE-2021-41773 [critical] 경로 탐색/파일 노출, CGI 켜져 있으면 원격코드실행 (실제 공격 확인) (영향: 2.4.49~2.4.49, 조건: core)",
                "[미해당] CVE-2022-23943 (important) - 필요 모듈(sed_module) 미사용",
                "==================================================================",
                " [4] 침해 흔적 점검 (이미 해킹당했는지)",
                "==================================================================",
                "[위험] 경로 탐색 시도 중 200(성공) 응답 3건 → 침해 가능성. 즉시 상세 분석 필요",
                "        1.2.3.4 - - [14/Oct/2026] \"GET /cgi-bin/.%2e/.%2e/etc/passwd HTTP/1.1\" 200 100");
        Report r = ReportParser.parse("apache_precheck_web01_20261014_100000_pid321.txt", text);
        assertEquals("web01", r.host);
        assertEquals("321", r.pid);
        assertEquals("소스", r.installType);
        assertTrue(r.compromiseSuspected());
        assertEquals("compromise", r.status());
        Report.Cve c = r.cves.stream().filter(x -> x.applicable).findFirst().orElseThrow();
        assertEquals("critical", c.severity);
        assertFalse(c.backported);
        assertFalse(r.summaryFound);
        assertEquals(3, r.risk);
        assertEquals(1, r.findings.stream().filter(f -> "4".equals(f.section)).findFirst().orElseThrow().details.size());
    }

    /** 수정본 스크립트(scripts/apache_precheck.sh)로 같은 서버를 재점검한 리포트: 데이터 품질 경고가 없어야 함. */
    @Test
    void fixedScriptReportHasNoDataQualityWarnings() throws Exception {
        Report r = ReportParser.parse("apache_precheck_vm_20261015_080000.txt", resource("apache_precheck_vm_fixed.txt"));
        assertEquals("1583", r.pid);
        assertEquals(27, r.moduleCount);
        assertTrue(r.dataQuality.isEmpty(), r.dataQuality.toString());
        assertTrue(r.findings.stream().anyMatch(f -> f.text.startsWith("AllowOverride 는 모두 None")));
    }

    /** 로그를 못 찾은 것은 침해 흔적이 아니라 점검 누락 → "확인 필요"가 아니라 데이터 경고 */
    @Test
    void missingLogsIsCoverageGapNotIntrusion() {
        String text = String.join("\n",
                "Apache 패치 전 보안 사전 점검  |  호스트: legacy01  |  일시: 2026-10-13 14:00:00",
                "==================================================================",
                " [4] 침해 흔적 점검 (이미 해킹당했는지)",
                "==================================================================",
                "[주의] 접근 로그 파일을 찾지 못했습니다. 로그 기반 점검을 건너뜁니다.",
                "[양호] 웹쉘 의심 코드 패턴 파일 없음 (패턴 우회형 웹쉘은 탐지 못함 → KISA 휘슬 병행 권장)");
        Report r = ReportParser.parse("apache_precheck_legacy01_20261013_140000.txt", text);
        assertEquals("clean", r.intrusionStatus());
        assertTrue(r.dataQuality.stream().anyMatch(d -> d.contains("접근 로그")));
        assertEquals(2, r.section4Raw.size());

        String scan = text.replace("[주의] 접근 로그 파일을 찾지 못했습니다. 로그 기반 점검을 건너뜁니다.", "[주의] 경로 탐색 시도 12건 (성공 응답 없음) → 스캔 대상이 되고 있음");
        assertEquals("check", ReportParser.parse("apache_precheck_legacy01_20261013_140000.txt", scan).intrusionStatus());
    }

    /** 원본 스크립트(PID 버그 → 폴더 전체 검색)로 만든 실제 리포트: Include 안 된 파일 점검 경고 */
    @Test
    void legacyReportWarnsAboutUnincludedFiles() throws Exception {
        Report r = ReportParser.parse("apache_precheck_vm_20261016_012910.txt", resource("legacy_unincluded_debian.txt"));
        assertEquals(null, r.confMethod);
        assertEquals("확인 안 됨(이전 스크립트)", r.confMethodShort());
        assertTrue(r.dataQuality.stream().anyMatch(d -> d.contains("Include 되지 않은 설정 파일") && d.contains("available")), r.dataQuality.toString());
    }

    /** 수정본 스크립트의 Include 추적 결과(소스 설치 구조): 주석 처리된 conf/extra 파일은 대상 아님 */
    @Test
    void includeTraceReportListsOnlyIncludedFiles() throws Exception {
        Report r = ReportParser.parse("apache_precheck_vm_20261016_013039_pid938.txt", resource("srcstyle_include_trace.txt"));
        assertTrue(r.confMethod.startsWith("메인 설정("), r.confMethod);
        assertEquals("httpd.conf Include 추적", r.confMethodShort());
        assertEquals(3, r.confFiles.size());
        assertTrue(r.confFiles.stream().noneMatch(f -> f.contains("httpd-autoindex") || f.contains("httpd-manual")
                || f.contains("httpd-userdir") || f.contains("httpd-ssl")), r.confFiles.toString());
        assertTrue(r.dataQuality.stream().noneMatch(d -> d.contains("Include 되지 않은")));
        // Options Indexes 는 실제로 Include 된 conf.d/site.conf 에서만 나와야 함
        Report.Finding idx = r.findings.stream().filter(f -> f.text.startsWith("Options Indexes")).findFirst().orElseThrow();
        assertEquals(1, idx.details.size());
        assertTrue(idx.details.get(0).contains("/conf.d/site.conf:"));
    }

    @Test
    void decodesEucKr() {
        String s = "Apache 패치 전 보안 사전 점검  |  호스트: h  |  일시: 2026-01-01 00:00:00";
        assertEquals(s, ReportParser.decode(s.getBytes(Charset.forName("MS949"))));
    }

    @Test
    void comparesVersionsNumerically() {
        assertTrue(ReportParser.compareVersions("2.4.9", "2.4.10") < 0);
        assertTrue(ReportParser.compareVersions("2.4.69", "2.4.69") == 0);
        assertTrue(ReportParser.compareVersions("2.4.70", "2.4.69") > 0);
    }

    @Test
    void jsonEscapesHtml() {
        assertEquals("\"\\u003cscript\\u003e\\\"\"", Json.write("<script>\""));
    }
}
