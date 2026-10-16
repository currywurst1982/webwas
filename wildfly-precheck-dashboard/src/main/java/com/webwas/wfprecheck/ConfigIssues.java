package com.webwas.wfprecheck;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * [3] 위험 설정 점검의 [위험]/[주의] 항목을 "항목별 → 대상 서버" 로 묶음.
 * 화면 차트(app.js renderConfigChart)와 같은 규칙: 문구에서 " → " 또는 " (" 앞부분을 항목 이름으로 씀.
 */
public final class ConfigIssues {
    private ConfigIssues() {}

    /** 항목 1개에 해당하는 서버 1대 */
    public record Target(Report report, String level, String text, List<String> details) {}

    /** 설정 취약 항목 1개 */
    public static final class Item {
        public final String key;
        public String level = "warn";          // 대상 중 하나라도 위험이면 risk
        public String text;                    // 대표 문구 (첫 서버의 원문)
        public final List<Target> targets = new ArrayList<>();

        Item(String key) {
            this.key = key;
        }

        public long riskCount() {
            return targets.stream().filter(t -> "risk".equals(t.level())).count();
        }
    }

    public static String key(String text) {
        // "관리 계정에 추측하기 쉬운 비밀번호 사용: admin → ..." 처럼 계정명이 붙는 항목도 서버 간에 한 항목으로 묶음
        return text.split(" → | \\(|: ", 2)[0].trim();
    }

    /** 인스턴스별 최신 리포트만 (all 은 최신순으로 정렬된 목록) */
    public static List<Report> latestPerInstance(List<Report> all) {
        Set<String> seen = new HashSet<>();
        List<Report> out = new ArrayList<>();
        for (Report r : all) {
            if (seen.add(r.instanceKey())) out.add(r);
        }
        return out;
    }

    /** 항목별로 묶어 서버 수가 많은 순(같으면 위험 먼저)으로 반환 */
    public static List<Item> group(List<Report> reports) {
        Map<String, Item> items = new LinkedHashMap<>();
        for (Report r : reports) {
            Set<String> seenInReport = new HashSet<>();
            for (Report.Finding f : r.findings) {
                if (!"3".equals(f.section) || !("risk".equals(f.level) || "warn".equals(f.level))) continue;
                String k = key(f.text);
                if (!seenInReport.add(k)) continue;
                Item it = items.computeIfAbsent(k, Item::new);
                if (it.text == null) it.text = f.text;
                if ("risk".equals(f.level)) it.level = "risk";
                it.targets.add(new Target(r, f.level, f.text, f.details));
            }
        }
        List<Item> out = new ArrayList<>(items.values());
        out.sort(Comparator.comparingInt((Item i) -> -i.targets.size())
                .thenComparingLong(i -> -i.riskCount())
                .thenComparing(i -> i.key));
        for (Item it : out) {
            it.targets.sort(Comparator.comparing((Target t) -> "risk".equals(t.level()) ? 0 : 1).thenComparing(t -> t.report().host));
        }
        return out;
    }
}
