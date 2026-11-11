package com.webwas.precheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** 예외(위험 수용): 판정·건수·CVE 집계에서 빠지고, 다음 점검에도 이어지며, 만료되면 다시 경고 */
class ExceptionStoreTest {
    private static final String TOMCAT = "tomcat_precheck_vm_20261103_074010.txt";
    private static final String NGINX = "nginx_precheck_vm_20261110_050306_pid845.txt";
    private static final long DAY = 86_400_000L;

    @TempDir
    Path tmp;

    private static Report parse(String name, String file) throws Exception {
        return ReportParser.parse(name, ReportParserTest.resource(file));
    }

    private static Report.Finding find(Report r, String section, String prefix) {
        return r.findings.stream().filter(f -> f.section.equals(section) && f.text.startsWith(prefix)).findFirst().orElseThrow();
    }

    @Test
    void cveWarningExemptedAndCountsDrop() throws Exception {
        ExceptionStore ex = new ExceptionStore(tmp.resolve("exceptions.properties"));
        Report r = parse(TOMCAT, TOMCAT);
        long now = 1_800_000_000_000L;
        ex.apply(r, now);
        int warnBefore = r.effectiveWarn();
        long cvesBefore = r.cves.stream().filter(c -> c.applicable).count();
        Report.Finding f = find(r, "2", "CVE-2023-44487");

        ExceptionStore.Entry e = ex.add(r, f, "instance", "HTTP/2 미사용 확인", 90, "admin", now);
        assertEquals(now + 90 * DAY, e.expiresAt);
        ex.apply(r, now);
        assertNotNull(f.exempt);
        assertEquals(warnBefore - 1, r.effectiveWarn());
        assertEquals(1, r.exemptCount("warn"));
        Report.Cve c = r.cves.stream().filter(x -> x.id.equals("CVE-2023-44487")).findFirst().orElseThrow();
        assertNotNull(c.exempt, "CVE 표에도 예외 표시");
        @SuppressWarnings("unchecked")
        Map<String, Object> counts = (Map<String, Object>) r.toSummary().get("counts");
        assertEquals(warnBefore - 1, counts.get("warn"));
        assertEquals(cvesBefore - 1, r.cves.stream().filter(x -> x.applicable && x.exempt == null).count());

        // 만료 뒤에는 다시 경고
        ex.apply(r, now + 91 * DAY);
        assertNull(f.exempt);
        assertEquals(warnBefore, r.effectiveWarn());

        // 다른 서버에는 적용되지 않음(instance 범위), 같은 제품 범위면 적용
        Report other = parse("agent-was02__" + TOMCAT, TOMCAT);
        other.host = "was02";
        ex.apply(other, now);
        if (!other.instanceKey().equals(r.instanceKey())) {
            assertNull(find(other, "2", "CVE-2023-44487").exempt);
        }
        ex.add(r, f, "product", "전사 HTTP/2 비활성", 30, "admin", now);
        ex.apply(other, now);
        assertNotNull(find(other, "2", "CVE-2023-44487").exempt);
    }

    @Test
    void numbersInTextIgnoredAndCompromiseNotExemptable() throws Exception {
        ExceptionStore ex = new ExceptionStore(tmp.resolve("exceptions.properties"));
        Report r = parse(NGINX, NGINX);
        long now = 1_800_000_000_000L;

        Report.Finding alias = find(r, "3", "alias 경로 탐색 위험");
        assertThrows(IllegalArgumentException.class, () -> ex.add(r, alias, "instance", "짧", 90, "admin", now), "사유 4자 미만");
        assertThrows(IllegalArgumentException.class, () -> ex.add(r, alias, "instance", "충분한 사유", 7, "admin", now), "허용 기간 아님");
        assertThrows(IllegalArgumentException.class, () -> ex.add(r, alias, "all", "충분한 사유", 30, "admin", now), "범위 오류");
        ex.add(r, alias, "instance", "내부 전용 경로, 외부 차단", 30, "admin", now);
        ex.apply(r, now);
        assertEquals("compromise", r.status(), "[4] 침해 흔적 [위험]이 아직 남아 있어 침해 의심");

        // 다음 점검: 문구 속 숫자만 바뀐 항목도 같은 예외로 인식, 판정 반영
        String next = ReportParserTest.resource(NGINX).replace("[주의] 지원 종료(EOL) 브랜치 Nginx 1.24.x", "[주의] 지원 종료(EOL) 브랜치 Nginx 1.26.x");
        Report r1 = ReportParser.parse(NGINX, next);
        Report.Finding eol = find(r1, "1", "지원 종료(EOL)");
        ex.add(r, find(r, "1", "지원 종료(EOL)"), "instance", "배포판 백포트 확인", 30, "admin", now);
        ex.apply(r1, now);
        assertNotNull(eol.exempt);
        assertNotNull(find(r1, "3", "alias 경로 탐색 위험").exempt);

        // 저장 후 다시 읽어도 유지, 해제하면 서명이 바뀜(화면 캐시 갱신)
        ExceptionStore again = new ExceptionStore(tmp.resolve("exceptions.properties"));
        assertEquals(2, again.list().size());
        String sig = again.signature(now);
        assertTrue(again.remove(again.list().get(0).id));
        assertNotEquals(sig, again.signature(now));
        assertEquals(1, new ExceptionStore(tmp.resolve("exceptions.properties")).list().size());
        assertTrue(Files.readString(tmp.resolve("exceptions.properties")).contains(".reason="));
    }

    @Test
    void intrusionRiskCanBeExemptedAndClearsCompromise() throws Exception {
        ExceptionStore ex = new ExceptionStore(tmp.resolve("exceptions.properties"));
        Report r = parse(NGINX, NGINX);
        long now = 1_800_000_000_000L;
        ex.apply(r, now);
        assertEquals("compromise", r.status(), "[4] 침해 흔적 [위험]이 있어 처음엔 침해 의심");

        // [4] 침해 흔적 [위험]도 이제 예외 처리 가능 (입력 검증은 그대로)
        Report.Finding risk4 = find(r, "4", "경로 탐색 시도 중 200");
        assertNull(ExceptionStore.refuseReason(risk4));
        assertTrue(ExceptionStore.isIntrusionRisk(risk4));
        assertThrows(IllegalArgumentException.class, () -> ex.add(r, risk4, "instance", "짧", 90, "admin", now), "사유 4자 미만");
        assertThrows(IllegalArgumentException.class, () -> ex.add(r, risk4, "all", "충분한 사유", 30, "admin", now), "범위 오류");

        // [4] 위험을 전부 예외 처리하면 침해 의심에서 빠짐 (항목은 '예외'로 계속 보임)
        for (Report.Finding f : new java.util.ArrayList<>(r.findings)) {
            if (ExceptionStore.isIntrusionRisk(f)) ex.add(r, f, "instance", "오탐 확인(격리망·내부 점검 로그 대조)", 90, "admin", now);
        }
        ex.apply(r, now);
        assertFalse(r.compromiseSuspected(), "모두 예외 처리하면 침해 의심 아님");
        assertNotEquals("compromise", r.intrusionStatus());
        assertNotEquals("compromise", r.status());
        assertNotNull(find(r, "4", "경로 탐색 시도 중 200").exempt, "예외 항목은 그대로 남아 표시됨");

        // 만료되면 다시 침해 의심
        ex.apply(r, now + 91L * DAY);
        assertTrue(r.compromiseSuspected(), "예외 기간이 지나면 다시 침해 의심");
    }

    @Test
    void statusBecomesOkWhenAllExempted() throws Exception {
        ExceptionStore ex = new ExceptionStore(tmp.resolve("exceptions.properties"));
        Report r = parse(TOMCAT, TOMCAT);
        long now = 1_800_000_000_000L;
        ex.apply(r, now);
        if ("compromise".equals(r.status())) return; // 침해 의심 샘플이면 이 시나리오 대상 아님
        for (Report.Finding f : r.findings) {
            if (ExceptionStore.refuseReason(f) == null) ex.add(r, f, "instance", "테스트용 위험 수용", 365, "admin", now);
        }
        ex.apply(r, now);
        assertEquals(0, r.effectiveRisk());
        assertEquals(0, r.effectiveWarn());
        assertEquals("ok", r.status());
    }
}
