package com.webwas.precheck;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * [2] CVE 판정에서 "해당"인 CVE 를 "CVE별 → 대상 서버" 로 묶음.
 * 화면 차트(app.js renderCveChart)와 같은 정렬: 미조치 서버 수 → 등급 → 백포트 서버 수.
 */
public final class CveIssues {
    private CveIssues() {}

    private static final List<String> SEVERITY_ORDER = List.of("critical", "important", "moderate", "low");

    /** CVE 1개에 해당하는 서버 1대 (backported = 패키지 changelog 에 수정 기록 있음) */
    public record Target(Report report, boolean backported) {}

    public static final class Item {
        public final String id;
        public String severity;
        public String description;
        public String affected;
        public String condition;
        public final List<Target> targets = new ArrayList<>();

        Item(String id) {
            this.id = id;
        }

        public long openCount() {
            return targets.stream().filter(t -> !t.backported()).count();
        }

        public long backportCount() {
            return targets.size() - openCount();
        }
    }

    static int severityRank(String s) {
        int i = SEVERITY_ORDER.indexOf(s);
        return i < 0 ? SEVERITY_ORDER.size() : i;
    }

    public static List<Item> group(List<Report> reports) {
        Map<String, Item> items = new LinkedHashMap<>();
        for (Report r : reports) {
            for (Report.Cve c : r.cves) {
                if (!c.applicable) continue;
                Item it = items.computeIfAbsent(c.id, Item::new);
                if (it.severity == null) it.severity = c.severity;
                if (it.description == null) it.description = c.description;
                if (it.affected == null) it.affected = c.affected;
                if (it.condition == null) it.condition = c.condition;
                it.targets.add(new Target(r, c.backported));
            }
        }
        List<Item> out = new ArrayList<>(items.values());
        out.sort(Comparator.comparingLong((Item i) -> -i.openCount())
                .thenComparingInt(i -> severityRank(i.severity))
                .thenComparingLong(i -> -i.backportCount())
                .thenComparing(i -> i.id));
        for (Item it : out) {
            it.targets.sort(Comparator.comparing((Target t) -> t.backported() ? 1 : 0).thenComparing(t -> t.report().host));
        }
        return out;
    }
}
