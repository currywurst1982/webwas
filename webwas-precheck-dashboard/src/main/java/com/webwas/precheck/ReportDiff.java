package com.webwas.precheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 같은 서버(인스턴스)의 바로 전 점검과 비교: 새로 생긴 [위험]·[주의], 해결된 것, 등급이 바뀐 것, 미조치 CVE 변화.
 * 항목은 "섹션 + 문구(숫자는 #로)" 로 맞춤 → "경로 탐색 시도 3건" 과 "5건" 은 같은 항목(건수만 바뀜).
 */
public final class ReportDiff {
    private ReportDiff() {
    }

    /** all = 점검 일시 최신순 (ReportStore.all()). cur 보다 앞선 같은 인스턴스의 가장 최근 점검. 없으면 null */
    public static Report previous(List<Report> all, Report cur) {
        String key = cur.instanceKey();
        String at = cur.checkedAt == null ? "" : cur.checkedAt;
        for (Report r : all) {
            if (r.id.equals(cur.id) || !r.instanceKey().equals(key)) continue;
            String t = r.checkedAt == null ? "" : r.checkedAt;
            if (t.compareTo(at) < 0 || (t.equals(at) && r.id.compareTo(cur.id) < 0)) return r;
        }
        return null;
    }

    static String key(Report.Finding f) {
        return f.section + "|" + f.text.replaceAll("\\d+", "#").replaceAll("\\s+", " ").trim();
    }

    private static Map<String, Report.Finding> issues(Report r) {
        Map<String, Report.Finding> m = new LinkedHashMap<>();
        for (Report.Finding f : r.findings) {
            if ("risk".equals(f.level) || "warn".equals(f.level)) m.putIfAbsent(key(f), f);
        }
        return m;
    }

    private static Set<String> openCves(Report r) {
        Set<String> s = new LinkedHashSet<>();
        for (Report.Cve c : r.cves) if (c.applicable && !c.backported) s.add(c.id);
        return s;
    }

    private static Map<String, Object> item(Report.Finding f) {
        return Map.of("level", f.level, "section", f.section, "text", f.text);
    }

    /** prev 가 null 이면 "비교할 이전 점검 없음" */
    public static Map<String, Object> diff(Report cur, Report prev) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (prev == null) {
            m.put("hasPrevious", false);
            return m;
        }
        m.put("hasPrevious", true);
        m.put("prevId", prev.id);
        m.put("prevCheckedAt", prev.checkedAt);
        m.put("prevVersion", prev.version);
        m.put("prevStatus", prev.status());
        m.put("versionChanged", prev.version != null && cur.version != null && !prev.version.equals(cur.version));
        Map<String, Report.Finding> a = issues(prev), b = issues(cur);
        List<Map<String, Object>> added = new ArrayList<>(), resolved = new ArrayList<>(), changed = new ArrayList<>();
        for (Map.Entry<String, Report.Finding> e : b.entrySet()) {
            Report.Finding old = a.get(e.getKey());
            if (old == null) added.add(item(e.getValue()));
            else if (!old.level.equals(e.getValue().level)) {
                Map<String, Object> c = new LinkedHashMap<>(item(e.getValue()));
                c.put("from", old.level);
                changed.add(c);
            }
        }
        for (Map.Entry<String, Report.Finding> e : a.entrySet()) {
            if (!b.containsKey(e.getKey())) resolved.add(item(e.getValue()));
        }
        // 위험 먼저, 섹션은 침해 흔적(4) → 설정(3) → 버전(1) → CVE(2) 순 (상세 화면과 같은 순서)
        java.util.Comparator<Map<String, Object>> order = java.util.Comparator
                .comparing((Map<String, Object> x) -> "risk".equals(x.get("level")) ? 0 : 1)
                .thenComparing(x -> "4312".indexOf(String.valueOf(x.get("section"))));
        added.sort(order);
        resolved.sort(order);
        m.put("added", added);
        m.put("resolved", resolved);
        m.put("levelChanged", changed);
        Set<String> ca = openCves(prev), cb = openCves(cur);
        Set<String> newCves = new LinkedHashSet<>(cb), goneCves = new LinkedHashSet<>(ca);
        newCves.removeAll(ca);
        goneCves.removeAll(cb);
        m.put("cveNew", new ArrayList<>(newCves));
        m.put("cveResolved", new ArrayList<>(goneCves));
        m.put("prevCounts", Map.of("risk", prev.risk, "warn", prev.warn, "ok", prev.ok));
        return m;
    }
}
