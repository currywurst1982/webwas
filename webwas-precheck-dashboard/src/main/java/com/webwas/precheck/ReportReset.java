package com.webwas.precheck;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 점검 기록 초기화: 어떤 리포트를 지울지 고름. (실제 이동은 ReportStore.trash — 휴지통으로 옮기고 일정 기간 뒤 비움)
 *  instance = 서버(인스턴스) 1개의 모든 점검 이력        (value = instanceKey)
 *  agent    = 에이전트가 보낸 모든 리포트                 (value = 에이전트 이름)
 *  product  = 제품의 모든 리포트                          (value = apache|wildfly|tomcat|nginx)
 *  old      = 인스턴스마다 최근 N개만 남기고 나머지        (value = N, 1 이상)
 *  all      = 전체
 */
public final class ReportReset {
    private ReportReset() {
    }

    public static final String CONFIRM_WORD = "초기화";

    /** all 은 점검 일시 최신순 (ReportStore.all()). 잘못된 범위·값이면 IllegalArgumentException */
    public static List<Report> select(List<Report> all, String scope, String value) {
        String v = value == null ? "" : value.trim();
        List<Report> out = new ArrayList<>();
        switch (scope == null ? "" : scope) {
            case "instance" -> {
                if (v.isEmpty()) throw new IllegalArgumentException("서버(인스턴스)를 지정하세요.");
                for (Report r : all) if (r.instanceKey().equals(v)) out.add(r);
            }
            case "agent" -> {
                if (!AgentStore.validName(v)) throw new IllegalArgumentException("에이전트 이름이 올바르지 않습니다.");
                for (Report r : all) if (v.equals(r.source)) out.add(r);
            }
            case "product" -> {
                Product p = Product.byId(v);
                if (p == null) throw new IllegalArgumentException("제품을 지정하세요.");
                for (Report r : all) if (r.product == p) out.add(r);
            }
            case "old" -> {
                int keep;
                try {
                    keep = Integer.parseInt(v);
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("남길 개수를 숫자로 입력하세요.");
                }
                if (keep < 1 || keep > 1000) throw new IllegalArgumentException("남길 개수는 1~1000 입니다.");
                Map<String, Integer> seen = new HashMap<>();
                for (Report r : all) {   // 최신순이므로 인스턴스마다 앞의 keep 개가 최근 것
                    int n = seen.merge(r.instanceKey(), 1, Integer::sum);
                    if (n > keep) out.add(r);
                }
            }
            case "all" -> out.addAll(all);
            default -> throw new IllegalArgumentException("알 수 없는 초기화 범위입니다.");
        }
        return out;
    }

    /** 화면 확인용 요약: 건수, 서버(인스턴스) 수, 앞의 몇 건 */
    public static Map<String, Object> preview(List<Report> picked) {
        Map<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("count", picked.size());
        m.put("instances", picked.stream().map(Report::instanceKey).distinct().count());
        m.put("sample", picked.stream().limit(5)
                .map(r -> r.product.label + " " + r.host + (r.version == null ? "" : " " + r.version) + " · " + (r.checkedAt == null ? "?" : r.checkedAt))
                .toList());
        return m;
    }
}
