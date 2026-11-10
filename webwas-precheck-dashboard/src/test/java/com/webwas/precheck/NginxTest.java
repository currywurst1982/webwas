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

    /** Nginx 최신 버전 기준 = stable 만 (2026-11-10 사용자 요청). stable 보다 새 mainline 은 최신으로 봄 */
    @Test
    void latestVersionStableOnly(@TempDir Path dir) throws Exception {
        assertEquals("1.30.6", LatestVersion.parseNginxVersions(res("nginx/versions.xml")));
        LatestVersion lv = new LatestVersion(Product.NGINX, dir.resolve("lv.properties"), "file:/none", "1.30.6");
        assertEquals("1.30.6", lv.display());
        assertTrue(lv.below("1.24.0"), "지원 종료 브랜치");
        assertTrue(lv.unsupportedBranch("1.28.2"));
        assertTrue(lv.unsupportedBranch("1.29.8"), "지난 mainline");
        assertTrue(lv.below("1.30.5"));
        assertFalse(lv.below("1.30.6"));
        assertFalse(lv.below("1.31.8"), "stable 보다 새 mainline");
        assertFalse(lv.unsupportedBranch("1.31.2"));
        // 수동 지정·예전 값에 mainline 이 섞여 있어도 stable 만
        lv.setManual("1.31.8, 1.30.6");
        assertEquals("1.30.6", lv.current());
        assertTrue(LatestVersion.validVersion(Product.NGINX, "1.30.7"));
        assertFalse(LatestVersion.validVersion(Product.NGINX, "nginx"));
    }

    /** 예전 대시보드가 저장한 자동 확인 값("1.31.8,1.30.6")이 남아 있어도 stable 만 씀 */
    @Test
    void oldStoredValueBecomesStable(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("latest-version-nginx.properties");
        Files.writeString(f, "mode=auto\nautoVersion=1.31.8,1.30.6\nautoSuccessAt=1\n", StandardCharsets.UTF_8);
        LatestVersion lv = new LatestVersion(Product.NGINX, f, "file:/none", "1.30.6");
        assertEquals("1.30.6", lv.current());
    }

    /** 프록시 전용 서버: [정보] 로 나오고 점검 사각지대(웹 파일 위치 못 찾음)로 세지 않음. 폴더를 못 찾은 경우는 그대로 사각지대 */
    @Test
    void proxyOnlyIsNotAGap() throws Exception {
        String text = res("nginx_precheck_vm_20261110_050306_pid845.txt");
        int i = text.indexOf("[정보] 점검 대상 웹 루트:");
        int j = text.indexOf("\n[", text.indexOf("\n", i) + 1);
        String proxy = text.substring(0, i)
                + "[정보] 프록시 전용 서버 — root·alias 설정 없이 요청을 뒤쪽 서버로 넘기기만 하므로 이 서버에는 웹 파일 점검 대상이 없습니다. (웹쉘 점검은 뒤쪽 WAS 서버 결과에서 확인)\n"
                + "        /etc/nginx/conf.d/app.conf:5:proxy_pass http://127.0.0.1:8080;\n" + text.substring(j + 1);
        Report p = ReportParser.parse("nginx_precheck_vm_20261110_050306_pid845.txt", proxy);
        assertEquals("info", find(p, "4", "프록시 전용 서버").level);
        assertFalse(p.gaps().contains("webFiles"), p.gaps().toString());
        String missing = text.substring(0, i) + "[주의] 웹 루트(root·alias) 폴더를 찾지 못했습니다. 파일 기반 점검을 건너뜁니다.\n" + text.substring(j + 1);
        assertTrue(ReportParser.parse("nginx_precheck_vm_20261110_050306_pid845.txt", missing).gaps().contains("webFiles"));
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
