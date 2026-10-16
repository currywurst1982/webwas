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

class ConfigPdfTest {

    private static Report load(String resource, String fileName) throws Exception {
        try (InputStream in = ConfigPdfTest.class.getResourceAsStream("/" + resource)) {
            assertNotNull(in, resource);
            return ReportParser.parse(fileName, ReportParser.decode(in.readAllBytes()));
        }
    }

    @Test
    void groupsIssuesByItemWithTargetServers() throws Exception {
        // web01: 테스트용 가상 리포트, vm: 실제 Ubuntu 리포트 (둘 다 ServerTokens [주의])
        Report web01 = load("sample_compromise_web01.txt", "apache_precheck_web01_20261014_100000_pid321.txt");
        Report vm = load("apache_precheck_vm_fixed.txt", "agent-vm-test__apache_precheck_vm_20261015_080000.txt");
        List<ConfigIssues.Item> items = ConfigIssues.group(List.of(web01, vm));

        ConfigIssues.Item tokens = items.stream().filter(i -> i.key.startsWith("ServerTokens 가 Prod 가 아님")).findFirst().orElseThrow();
        assertEquals(2, tokens.targets.size());
        assertEquals("warn", tokens.level);
        // 서버 수 많은 항목이 먼저
        assertEquals(tokens, items.get(0));

        ConfigIssues.Item dir = items.stream().filter(i -> i.key.startsWith("<Directory />")).findFirst().orElseThrow();
        assertEquals("risk", dir.level);
        assertEquals(1, dir.targets.size());
        assertEquals("web01", dir.targets.get(0).report().host);
        assertEquals(List.of("/usr/local/apache2/conf/httpd.conf:210:Require all granted"), dir.targets.get(0).details());
        // [4] 침해 흔적 항목은 설정 취약에 들어가면 안 됨
        assertFalse(items.stream().anyMatch(i -> i.key.startsWith("경로 탐색")));
    }

    @Test
    void pdfListsItemsTargetsAndConfigLocations() throws Exception {
        Report web01 = load("sample_compromise_web01.txt", "apache_precheck_web01_20261014_100000_pid321.txt");
        Report vm = load("apache_precheck_vm_fixed.txt", "agent-vm-test__apache_precheck_vm_20261015_080000.txt");
        byte[] pdf = ConfigPdf.build(ConfigIssues.group(List.of(web01, vm)), 2, "2.4.69", "전체 서버", "admin");
        String t;
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            t = new PDFTextStripper().getText(doc);
        }
        assertTrue(t.contains("설정 취약 항목별 대상 서버"), t);
        assertTrue(t.contains("점검 서버 2대 중 2대"), t);
        assertTrue(t.contains("ServerTokens 가 Prod 가 아님"));
        assertTrue(t.contains("ProxyRequests On"));
        assertTrue(t.contains("web01 (PID 321)"));
        assertTrue(t.contains("에이전트 vm-test"));
        // 서버별 설정 위치(파일:줄)
        assertTrue(t.contains("/etc/apache2/conf-enabled/security.conf:12:ServerTokens OS"), t);
        assertTrue(t.contains("/usr/local/apache2/conf/extra/proxy.conf:3:ProxyRequests On"));
        // 침해 흔적 내용은 들어가지 않음
        assertFalse(t.contains("203.0.113.7"));
    }

    @Test
    void emptyListStillProducesPdf() throws Exception {
        byte[] pdf = ConfigPdf.build(List.of(), 0, "2.4.69", "전체 서버", "admin");
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            assertTrue(new PDFTextStripper().getText(doc).contains("설정 취약 항목이 없습니다"));
        }
    }
}
