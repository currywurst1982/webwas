package com.webwas.precheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * [4] 실행 계정의 다른 프로세스: 사람이 로그인한 터미널(-bash)은 [정보]라 "침해 의심"이 아니고,
 * 서버 프로세스가 띄운 것만 [위험]. (2026-11-09 개선 전에는 로그인 셸도 [위험] → 오탐)
 */
class UserProcsTest {

    /** 실제 tomcat_precheck.sh 실행 결과: 서버가 띄운 셸=위험, 백그라운드=주의, su - was 로그인=정보 */
    @Test
    void realRunClassifiesByParent() throws Exception {
        Report r = ReportParserTest.load("tomcat_precheck_vm_procs_check.txt");
        Report.Finding srv = find(r, "Tomcat 프로세스가 띄운 다른 프로세스");
        assertEquals("risk", srv.level);
        assertTrue(srv.details.get(0).contains("<- python3("), srv.details.toString());
        assertEquals("warn", find(r, "실행 중인 다른 프로세스 (백그라운드 실행").level);
        Report.Finding login = find(r, "로그인한 터미널 세션");
        assertEquals("info", login.level);
        assertTrue(login.details.stream().anyMatch(d -> d.contains("-bash") && d.contains("<- su(")), login.details.toString());
    }

    /** 침해 흔적이 로그인 세션(정보)뿐이면 침해 의심이 아님 */
    @Test
    void loginSessionAloneIsNotCompromise() throws Exception {
        String text = ReportParserTest.resource(TomcatAndCveFeedTest.TC11);
        String marker = " [4] 침해 흔적 점검";
        int i = text.indexOf(marker);
        int lineEnd = text.indexOf('\n', text.indexOf("=====", i + marker.length()));
        String injected = text.substring(0, lineEnd + 1)
                + "[정보] Tomcat 실행계정(was) 으로 로그인한 터미널 세션 (관리자 작업인지 확인: last was / /var/log/secure)\n"
                + "        785500 785499 pts/1 04:56 -bash  <- su(785499)\n"
                + text.substring(lineEnd + 1);
        Report r = ReportParser.parse(TomcatAndCveFeedTest.TC11, injected);
        assertEquals("info", find(r, "로그인한 터미널 세션").level);
        assertTrue(!"compromise".equals(r.intrusionStatus()), r.intrusionStatus());
        assertTrue(r.toSummary().get("intrusionFindings").toString().indexOf("로그인한 터미널") < 0);
    }

    private static Report.Finding find(Report r, String text) {
        return r.findings.stream().filter(f -> "4".equals(f.section) && f.text.contains(text)).findFirst()
                .orElseThrow(() -> new AssertionError("없음: " + text));
    }
}
