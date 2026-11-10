package com.webwas.precheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * [4] 4-3 서버 로그 위치 지정(-s) + 4-5 OS 로그인 기록(/var/log/secure) 점검 결과를 대시보드가 읽는지.
 * 리소스는 tomcat_precheck.sh 를 실제로 실행한 결과 (경로만 일반화).
 */
class AuthLogTest {

    @Test
    void parsesServerLogOptionAndAuthLog() throws Exception {
        Report r = ReportParserTest.load("tomcat_precheck_vm_authlog.txt");
        assertEquals(Product.TOMCAT, r.product);
        // -s 로 지정한 catalina.out 에서 JNDI 흔적
        assertEquals("info", find(r, "-s 옵션 값으로 추가").level);
        assertEquals("risk", find(r, "JNDI").level);
        // OS 로그인 기록
        assertEquals("info", find(r, "점검 대상 OS 로그인 기록").level);
        Report.Finding brute = find(r, "로그인 실패가 몰린 직후");
        assertEquals("risk", brute.level);
        assertTrue(brute.details.get(0).contains("Accepted password for root from 203.0.113.7"), brute.details.toString());
        assertEquals("warn", find(r, "로그인 실패가 많았던 IP").level);
        assertEquals("warn", find(r, "계정 생성").level);
        assertEquals("info", find(r, "로그인 실패가 많은 IP 상위").level);
        assertEquals("compromise", r.intrusionStatus());
    }

    private static Report.Finding find(Report r, String text) {
        return r.findings.stream().filter(f -> "4".equals(f.section) && f.text.contains(text)).findFirst()
                .orElseThrow(() -> new AssertionError("없음: " + text));
    }
}
