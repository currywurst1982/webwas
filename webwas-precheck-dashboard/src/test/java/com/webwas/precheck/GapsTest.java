package com.webwas.precheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/** 점검 사각지대: 리포트에서 실제로 수행되지 못한 점검을 찾는지 */
class GapsTest {

    /** 새 스크립트(로그인 기록 점검 있음), Tomcat 접근 로그 없음, -s 로 서버 로그 지정 */
    @Test
    void newTomcatReport() throws Exception {
        List<String> g = ReportParserTest.load("tomcat_precheck_vm_authlog.txt").gaps();
        assertEquals(List.of("accessLog"), g);
    }

    /** 이전 스크립트(4-5 로그인 기록 점검 없음) WildFly: 접근 로그 없음 + 옛 스크립트 */
    @Test
    void oldWildflyReport() throws Exception {
        Report r = ReportParserTest.load("wildfly_precheck_vm_20261016_050340_pid4068.txt");
        List<String> g = r.gaps();
        assertTrue(g.contains("accessLog"), g.toString());
        assertTrue(g.contains("oldScript"), g.toString());
        assertFalse(g.contains("authLog"), g.toString());
        assertEquals(g, r.toSummary().get("gaps"));
    }

    /** OS 로그인 기록을 못 읽은 경우 */
    @Test
    void authLogUnreadable() throws Exception {
        String text = ReportParserTest.resource("tomcat_precheck_vm_authlog.txt");
        int i = text.indexOf("[정보] 점검 대상 OS 로그인 기록");
        int j = text.indexOf("\n==", i);
        String changed = text.substring(0, i)
                + "[정보] OS 로그인 기록(/var/log/secure, /var/log/auth.log, journal)을 읽지 못해 로그인 기록 점검을 건너뜁니다. (root 권한 필요)\n"
                + text.substring(j + 1);
        List<String> g = ReportParser.parse("tomcat_precheck_vm_authlog.txt", changed).gaps();
        assertTrue(g.contains("authLog"), g.toString());
        assertFalse(g.contains("oldScript"), g.toString());
    }
}
