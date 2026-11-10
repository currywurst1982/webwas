package com.webwas.precheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** 지난 점검 대비: 같은 인스턴스의 바로 전 점검과 비교 */
class ReportDiffTest {
    private static final String F = "nginx_precheck_vm_20261110_050306_pid845.txt";

    @SuppressWarnings("unchecked")
    private static List<String> texts(Map<String, Object> d, String k) {
        return ((List<Map<String, Object>>) d.get(k)).stream().map(x -> (String) x.get("text")).toList();
    }

    @Test
    void comparesWithPreviousScan() throws Exception {
        String text = ReportParserTest.resource(F);
        // 이전 점검: autoindex [주의] 가 있었고, alias 는 [주의] 였으며, 경로 탐색 건수가 달랐다고 가정
        String prevText = text
                .replace("[위험] alias 경로 탐색 위험", "[주의] alias 경로 탐색 위험")
                .replace("경로 탐색 시도 중 200(성공) 응답 3건", "경로 탐색 시도 중 200(성공) 응답 1건")
                .replace("[주의] stub_status(서버 상태 페이지)", "[양호] stub_status(서버 상태 페이지)");
        // 이번 점검: autoindex 를 고쳐서 없어짐
        String curText = text.replace("[주의] autoindex on → 디렉터리 파일 목록이 웹에 노출됨. 필요한 위치가 아니면 제거",
                "[양호] 디렉터리 목록(autoindex) 노출 설정 없음");
        Report prev = ReportParser.parse("agent-web09__nginx_precheck_vm_20261109_050306_pid845.txt", prevText);
        Report cur = ReportParser.parse("agent-web09__nginx_precheck_vm_20261110_050306_pid845.txt", curText);
        prev.checkedAt = "2026-11-09 05:03:06";
        cur.checkedAt = "2026-11-10 05:03:06";
        assertEquals(prev.instanceKey(), cur.instanceKey());

        Map<String, Object> d = ReportDiff.diff(cur, prev);
        assertEquals(true, d.get("hasPrevious"));
        assertTrue(texts(d, "resolved").stream().anyMatch(t -> t.startsWith("autoindex on")), d.toString());
        assertTrue(texts(d, "added").stream().anyMatch(t -> t.startsWith("stub_status")), "양호 → 주의 = 새로 생김");
        assertTrue(texts(d, "levelChanged").stream().anyMatch(t -> t.startsWith("alias 경로 탐색")), "주의 → 위험");
        assertFalse(texts(d, "added").stream().anyMatch(t -> t.contains("경로 탐색 시도 중 200")), "건수만 바뀐 것은 같은 항목");
        assertFalse(texts(d, "resolved").stream().anyMatch(t -> t.contains("경로 탐색 시도 중 200")));
        assertEquals(List.of(), d.get("cveNew"));

        // 바로 전 점검 찾기: 최신순 목록에서 같은 인스턴스의 더 이른 것
        Report older = ReportParser.parse("agent-web09__nginx_precheck_vm_20261101_050306_pid845.txt", text);
        older.checkedAt = "2026-11-01 05:03:06";
        Report other = ReportParser.parse("tomcat_precheck_vm_20261103_074010.txt", ReportParserTest.resource("tomcat_precheck_vm_20261103_074010.txt"));
        List<Report> all = List.of(cur, other, prev, older);
        assertEquals(prev.id, ReportDiff.previous(all, cur).id);
        assertEquals(older.id, ReportDiff.previous(all, prev).id);
        assertNull(ReportDiff.previous(all, older));
        assertEquals(false, ReportDiff.diff(older, null).get("hasPrevious"));
    }
}
