package com.webwas.precheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Nginx 추가 (2026-11-10).
 * 리소스: nginx_precheck.sh 를 Ubuntu nginx 1.24.0(DEB)에 실제로 실행한 리포트 (위험 설정·웹쉘·공격 로그를 일부러 넣은 시험 서버),
 *        nginx.org 원본 XML(security_advisories.xml, versions.xml, 2026-11-10 내려받음).
 */
class NginxTest {

    private static String res(String name) throws Exception {
        return ReportParserTest.resource(name);
    }

    @Test
    void parsesRealReport() throws Exception {
        Report r = ReportParserTest.load("nginx_precheck_vm_20261110_050306_pid845.txt");
        assertEquals(Product.NGINX, r.product);
        assertEquals("1.24.0", r.version);
        assertEquals("DEB", r.installType);
        assertEquals("www-data", r.runUser);
        assertEquals("/usr/sbin/nginx", r.binary);
        assertTrue(r.eol, "1.24 는 지원 종료 브랜치");
        assertEquals(5, r.confFiles.size(), r.confFiles.toString());
        assertEquals("nginx -T(실제로 읽는 설정)", r.confMethodShort());
        // CVE: 설정에서 쓰는 기능(SSL·mp4)에 해당하는 5건, 모두 Ubuntu changelog 에 수정 기록 → 백포트 추정
        long applicable = r.cves.stream().filter(c -> c.applicable).count();
        assertEquals(5, applicable);
        assertTrue(r.cves.stream().filter(c -> c.applicable).allMatch(c -> c.backported));
        assertEquals(17, r.cves.stream().filter(c -> !c.applicable).count());
        Report.Cve mp4 = r.cves.stream().filter(c -> c.id.equals("CVE-2026-27784")).findFirst().orElseThrow();
        assertEquals("mp4 모듈 사용", mp4.condition);
        assertEquals("1.1.19~1.29.6", mp4.affected);
        // 위험 설정·침해 흔적
        assertEquals("risk", find(r, "3", "alias 경로 탐색").level);
        assertEquals("warn", find(r, "3", "autoindex on").level);
        assertEquals("risk", find(r, "4", "경로 탐색 시도 중 200").level);
        assertEquals("risk", find(r, "4", "웹쉘 의심 코드").level);
        assertEquals("compromise", r.intrusionStatus());
        assertEquals(List.of("authLog"), r.gaps());
        assertEquals("nginx", r.toSummary().get("product"));
    }

    @Test
    void cveFeedMatchesScriptTable() throws Exception {
        // 대시보드가 공식 XML 로 만든 목록 = 스크립트 내장 목록 (같은 규칙인지 확인)
        List<String> feed = CveFeed.nginxRows(res("nginx/security_advisories.xml"));
        String script = Files.readString(Path.of("scripts/nginx_precheck.sh"), StandardCharsets.UTF_8);
        assertEquals(CveFeed.rowsOf(script, Product.NGINX), feed);
        assertEquals(66, feed.size()); // <item> 68개 중 CVE 없음(Windows)·등급 none 2개 제외
        assertTrue(feed.contains("CVE-2024-32760|medium|http3|1.25.0-1.25.5;1.26.0|1.27.0+;1.26.1+|Buffer overwrite in HTTP/3"), feed.toString());
        assertEquals("proxy", CveFeed.nginxFeature("HTTP/2 request injection in the ngx_http_proxy_module"));
        assertEquals("core", CveFeed.nginxFeature("Integer overflow in the range filter"));
    }

    @Test
    void latestVersionPerBranch(@TempDir Path dir) throws Exception {
        assertEquals("1.31.8,1.30.6", LatestVersion.parseNginxVersions(res("nginx/versions.xml")));
        LatestVersion lv = new LatestVersion(Product.NGINX, dir.resolve("lv.properties"), "file:/none", "1.31.8 1.30.6");
        assertEquals("1.31.8 / 1.30.6", lv.display());
        assertTrue(lv.below("1.24.0"), "지원 종료 브랜치");
        assertTrue(lv.unsupportedBranch("1.28.2"));
        assertTrue(lv.below("1.30.5"));
        assertFalse(lv.below("1.30.6"));
        assertFalse(lv.below("1.31.8"));
        assertTrue(LatestVersion.validVersion(Product.NGINX, "1.31.9, 1.30.7"));
        assertFalse(LatestVersion.validVersion(Product.NGINX, "nginx"));
    }

    /** 에이전트의 스크립트 순서(SHA-256 계산 순서) = 대시보드 Product 순서 */
    @Test
    void agentProductOrderMatchesDashboard() throws Exception {
        String agent = Files.readString(Path.of("scripts/webwas-precheck-agent.sh"), StandardCharsets.UTF_8);
        Matcher m = Pattern.compile("(?m)^ALL_PRODUCTS=\"([a-z ]+)\"").matcher(agent);
        assertTrue(m.find());
        assertEquals(Arrays.stream(Product.values()).map(p -> p.id).toList(), List.of(m.group(1).split(" ")));
    }

    private static Report.Finding find(Report r, String sec, String text) {
        return r.findings.stream().filter(f -> sec.equals(f.section) && f.text.contains(text)).findFirst()
                .orElseThrow(() -> new AssertionError("없음: " + text));
    }
}
