package com.webwas.wfprecheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.Charset;
import org.junit.jupiter.api.Test;

/**
 * 테스트 리포트는 모두 공식 배포본(GitHub 릴리스 zip)을 실제로 띄우고 scripts/wildfly_precheck.sh 를 실행해 얻은 것:
 *   WF26 = 26.1.3.Final (wildfly 계정, 기본 설정)
 *   WF31 = 31.0.1.Final (wildfly 계정, 접근 로그 켬 + 시험용 공격 요청 + 웹쉘 패턴 문자열만 든 시험용 JSP 배포)
 *   WF34 = 34.0.1.Final (꺼진 상태에서 -H 로 점검, 관리 인터페이스를 설정 파일에서 0.0.0.0 으로 바꿈)
 *   WF40 = 40.0.1.Final (root 실행, admin/admin 관리 계정, --debug 127.0.0.1:8787)
 *   WF41 = 41.0.1.Final (wildfly 계정, 기본 설정)
 */
class ReportParserTest {
    static final String WF26 = "wildfly_precheck_vm_20261016_050340_pid4068.txt";
    static final String WF41 = "wildfly_precheck_vm_20261016_050342_pid4072.txt";
    static final String WF31 = "wildfly_precheck_vm_20261016_050344_pid4154.txt";
    static final String WF40 = "wildfly_precheck_vm_20261016_050346_pid8481.txt";
    static final String WF34 = "wildfly_precheck_vm_20261016_050357.txt";

    static String resource(String name) throws Exception {
        try (InputStream in = ReportParserTest.class.getResourceAsStream("/" + name)) {
            assertNotNull(in, name);
            return ReportParser.decode(in.readAllBytes());
        }
    }

    static Report load(String name) throws Exception {
        return ReportParser.parse(name, resource(name));
    }

    @Test
    void parsesLatestFinalReport() throws Exception {
        Report r = load(WF41);
        assertEquals("vm", r.host);
        assertEquals("2026-10-16 05:03:42", r.checkedAt);
        assertEquals("4072", r.pid);
        assertEquals("41.0.1.Final", r.version);
        assertEquals("/opt/wf-test/wildfly-41.0.1.Final", r.binary);
        assertEquals("ZIP", r.installType);
        assertEquals("standalone", r.runMode);
        assertEquals("wildfly", r.runUser);
        assertEquals(777, r.moduleCount);
        assertEquals(java.util.List.of("192.0.2.2"), r.ips);
        assertEquals("/opt/wf-test/wildfly-41.0.1.Final/standalone/configuration/standalone.xml", r.mainConfig);
        assertEquals("standalone.xml", r.confMethodShort());
        assertFalse(r.eol);
        assertTrue(r.summaryFound);
        assertEquals(0, r.risk);
        assertEquals(6, r.warn);

        // OSV 에 수정 버전이 없는 Undertow CVE 1건만 해당 (moderate → [주의])
        assertEquals(1, r.cves.stream().filter(c -> c.applicable).count());
        Report.Cve c = r.cves.stream().filter(x -> x.applicable).findFirst().orElseThrow();
        assertEquals("CVE-2026-3260", c.id);
        assertEquals("moderate", c.severity);
        assertEquals("undertow-core 0~수정 버전 없음", c.affected);
        assertEquals("undertow-core 2.4.3.Final 설치됨", c.condition);
        assertEquals("GHSA-3x3v-w654-m28m", c.advisory);
        // WildFly 40 이상의 undertow-servlet 은 다른 프로젝트(io.undertow.ee) → 옛 CVE 미해당
        Report.Cve na = r.cves.stream().filter(x -> x.id.equals("CVE-2019-10184")).findFirst().orElseThrow();
        assertFalse(na.applicable);
        assertEquals("io.undertow:undertow-servlet", na.condition);

        // 이전에 배포했던 앱의 남은 파일(data/content)·임시 폴더 파일은 [주의] → "확인 필요"
        assertEquals("check", r.intrusionStatus());
        // 접근 로그가 없는 것은 침해 흔적이 아니라 점검 누락 (기본값) → 데이터 경고
        assertTrue(r.dataQuality.stream().anyMatch(d -> d.contains("접근 로그")), r.dataQuality.toString());
        assertEquals("warn", r.status());
    }

    @Test
    void oldJavaxVersionHasManyCves() throws Exception {
        Report r = load(WF26);
        assertEquals("26.1.3.Final", r.version);
        assertTrue(r.eol, "WildFly 26 은 javax(Java EE 8) 계열");
        assertEquals(27, r.cves.stream().filter(c -> c.applicable).count());
        Report.Cve wf = r.cves.stream().filter(x -> x.id.equals("CVE-2022-1278")).findFirst().orElseThrow();
        assertEquals("high", wf.severity);
        assertEquals("WildFly 0~27.0.0.Beta1 미만", wf.affected);
        assertEquals("WildFly 26.1.3.Final 설치됨", wf.condition);
        assertEquals("risk", r.status());
        assertTrue(ReportParser.compareVersions(r.version, "41.0.1.Final") < 0);
    }

    @Test
    void detectsWeakAdminPasswordAndRoot() throws Exception {
        Report r = load(WF40);
        assertEquals("40.0.1.Final", r.version);
        assertEquals("root", r.runUser);
        assertTrue(r.findings.stream().anyMatch(f -> "3".equals(f.section) && "risk".equals(f.level)
                && f.text.startsWith("관리 계정에 추측하기 쉬운 비밀번호 사용: admin")));
        assertTrue(r.findings.stream().anyMatch(f -> "3".equals(f.section) && "warn".equals(f.level)
                && f.text.startsWith("원격 디버그(JDWP) 옵션이 켜져 있음")));
        assertEquals(2, r.risk);
    }

    @Test
    void detectsCompromiseTracesInDemoInstance() throws Exception {
        Report r = load(WF31);
        assertTrue(r.compromiseSuspected());
        assertEquals("compromise", r.status());
        Report.Finding ws = r.findings.stream().filter(f -> f.text.startsWith("웹쉘 의심 코드 패턴")).findFirst().orElseThrow();
        assertEquals("4", ws.section);
        assertTrue(ws.details.get(0).endsWith("shop.war!/upload.jsp"), ws.details.toString());
        Report.Finding req = r.findings.stream().filter(f -> f.text.startsWith("명령실행/웹쉘/JNDI 주입 의심 요청 중 200")).findFirst().orElseThrow();
        assertEquals(2, req.details.size());
        assertTrue(r.section4Raw.stream().anyMatch(l -> l.contains("access_log.log")));
        assertTrue(r.dataQuality.isEmpty(), r.dataQuality.toString());
    }

    @Test
    void stoppedServerUsesConfigFile() throws Exception {
        Report r = load(WF34);
        assertNull(r.pid);
        assertNull(r.runUser);
        assertTrue(r.findings.stream().anyMatch(f -> "risk".equals(f.level)
                && f.text.startsWith("관리 인터페이스 바인드 주소가 0.0.0.0 (설정 기준)")));
        assertTrue(r.findings.stream().anyMatch(f -> "warn".equals(f.level)
                && f.text.startsWith("애플리케이션 계정에 추측하기 쉬운 비밀번호 사용: appuser")));
    }

    /** 서버 구분에 PID 를 쓰지 않음: 같은 설치 폴더면 같은 인스턴스, 인스턴스 구분(서버 폴더·설정)이 다르면 다른 인스턴스 */
    @Test
    void instanceKeyIgnoresPid() {
        String head = "WildFly 패치 전 보안 사전 점검  |  호스트: was07  |  일시: 2026-10-16 09:00:00\n"
                + "==================================================================\n"
                + " [1] 버전 및 설치 방식 확인\n"
                + "==================================================================\n";
        Report a = ReportParser.parse("wildfly_precheck_was07_20261016_090000_pid100.txt", head
                + "[정보] 실행 중인 WildFly 프로세스 자동 탐지: PID 100\n[정보] 서버 IP: 10.1.2.3 10.9.9.9\n[정보] 설치 폴더: /opt/wildfly\n");
        Report b = ReportParser.parse("wildfly_precheck_was07_20261017_090000_pid999.txt", head
                + "[정보] 실행 중인 WildFly 프로세스 자동 탐지: PID 999\n[정보] 설치 폴더: /opt/wildfly\n");
        Report c = ReportParser.parse("wildfly_precheck_was07_20261016_090000_pid200.txt", head
                + "[정보] 인스턴스 구분: base=/srv/app2 config=standalone-full.xml\n[정보] 설치 폴더: /opt/wildfly\n");
        assertEquals("100", a.pid);
        assertEquals(a.instanceKey(), b.instanceKey());
        assertFalse(a.instanceKey().equals(c.instanceKey()));
        assertEquals("base=/srv/app2 config=standalone-full.xml", c.confArg);
        assertEquals(java.util.List.of("10.1.2.3", "10.9.9.9"), a.ips);
        assertEquals("10.1.2.3", a.displayIp());
        assertNull(b.displayIp());
        b.fallbackIp = "172.16.0.5";
        assertEquals("172.16.0.5", b.displayIp());
    }

    @Test
    void missingSummaryIsDataQualityWarning() {
        String text = "WildFly 패치 전 보안 사전 점검  |  호스트: h  |  일시: 2026-10-16 09:00:00\n"
                + " [1] 버전 및 설치 방식 확인\n"
                + "[위험] WildFly 설치 폴더를 찾지 못했습니다. WildFly 를 기동한 상태에서 다시 실행하거나 -H 로 경로를 지정하세요.\n";
        Report r = ReportParser.parse("wildfly_precheck_h_20261016_090000.txt", text);
        assertFalse(r.summaryFound);
        assertEquals(1, r.risk);
        assertEquals(2, r.dataQuality.size(), r.dataQuality.toString());
    }

    @Test
    void decodesEucKr() {
        String s = "WildFly 패치 전 보안 사전 점검  |  호스트: h  |  일시: 2026-01-01 00:00:00";
        assertEquals(s, ReportParser.decode(s.getBytes(Charset.forName("MS949"))));
    }

    /** 스크립트의 vcmp 와 같은 규칙 (스크립트 쪽도 같은 사례로 확인함) */
    @Test
    void comparesMavenStyleVersions() {
        assertTrue(ReportParser.compareVersions("2.2.19.Final", "2.2.24.Final") < 0);
        assertTrue(ReportParser.compareVersions("2.4.3.Final", "2.2.39.Final") > 0);
        assertTrue(ReportParser.compareVersions("2.3.0.Alpha1", "2.3.0.Final") < 0);
        assertEquals(0, ReportParser.compareVersions("2.3.0.Final", "2.3.0"));
        assertEquals(0, ReportParser.compareVersions("2.0.19.FINAL", "2.0.19.Final"));
        assertEquals(0, ReportParser.compareVersions("17.0", "17.0.0.Final"));
        assertTrue(ReportParser.compareVersions("41.0.0.Beta1", "41.0.0.Final") < 0);
        assertEquals(0, ReportParser.compareVersions("7.2.5.GA", "7.2.5.Final"));
        assertTrue(ReportParser.compareVersions("2.2.5.SP1", "2.2.5.Final") > 0);
        assertTrue(ReportParser.compareVersions("2.3.0.CR1", "2.3.0.Beta2") > 0);
        assertTrue(ReportParser.compareVersions("4.7.8.Final", "4.7.10.Final") < 0);
        assertTrue(ReportParser.compareVersions("40.0.1.Final", "41.0.1.Final") < 0);
    }

    @Test
    void jsonEscapesHtml() {
        assertEquals("\"\\u003cscript\\u003e\\\"\"", Json.write("<script>\""));
    }
}
