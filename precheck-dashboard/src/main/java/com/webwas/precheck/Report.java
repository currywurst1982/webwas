package com.webwas.precheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** apache_precheck.sh 리포트 1개를 해석한 결과. */
public class Report {

    /** 점검 결과 한 줄: [위험]/[주의]/[양호]/[정보] + 아래 들여쓰기 상세줄. */
    public static class Finding {
        public final String level;    // risk | warn | ok | info
        public final String section;  // 1 | 2 | 3 | 4
        public final String text;
        public final List<String> details = new ArrayList<>();

        Finding(String level, String section, String text) {
            this.level = level;
            this.section = section;
            this.text = text;
        }

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("level", level);
            m.put("section", section);
            m.put("text", text);
            m.put("details", details);
            return m;
        }
    }

    /** [2] 섹션의 CVE 판정 한 건. */
    public static class Cve {
        public String id;
        public String severity;      // critical | important | moderate | low
        public String description;   // 미해당 항목은 리포트에 설명이 없음
        public String affected;      // 예: 2.4.0~2.4.59
        public String condition;     // 필요 모듈 조건
        public boolean applicable;   // true=해당, false=모듈 미사용으로 미해당
        public boolean backported;   // 패키지 changelog 에 수정 기록 있음

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("severity", severity);
            m.put("description", description);
            m.put("affected", affected);
            m.put("condition", condition);
            m.put("applicable", applicable);
            m.put("backported", backported);
            return m;
        }
    }

    public String id;            // 파일명
    public String source;        // 리포트를 보낸 에이전트 이름 (수동 업로드면 null)
    public long fileSize;
    public long fileModified;
    public String host;
    public String checkedAt;     // "2026-10-15 07:34:43"
    public String pid;
    public String binary;
    public String versionLine;
    public String version;
    public String installType;
    public Integer moduleCount;
    public String runUser;
    public int risk, warn, ok, info;
    public boolean summaryFound;
    public boolean below2469;
    public boolean eol;
    public final List<Finding> findings = new ArrayList<>();
    public final List<Cve> cves = new ArrayList<>();
    public final List<String> dataQuality = new ArrayList<>();
    public String raw;

    /** 같은 서버의 같은 Apache 인스턴스를 묶는 키 (호스트 + 실행파일 + PID). */
    public String instanceKey() {
        return host + "|" + (binary == null ? "" : binary) + "|" + (pid == null ? "" : pid);
    }

    public boolean compromiseSuspected() {
        return findings.stream().anyMatch(f -> "4".equals(f.section) && "risk".equals(f.level));
    }

    /** 전체 판정: compromise > risk > warn > ok */
    public String status() {
        if (compromiseSuspected()) return "compromise";
        if (risk > 0) return "risk";
        if (warn > 0) return "warn";
        return "ok";
    }

    private Map<String, Integer> cveCounts(boolean onlyUnpatched) {
        Map<String, Integer> m = new LinkedHashMap<>();
        for (String s : new String[] {"critical", "important", "moderate", "low"}) m.put(s, 0);
        for (Cve c : cves) {
            if (!c.applicable) continue;
            if (onlyUnpatched && c.backported) continue;
            m.merge(c.severity, 1, Integer::sum);
        }
        return m;
    }

    public Map<String, Object> toSummary() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("host", host);
        m.put("source", source);
        m.put("checkedAt", checkedAt);
        m.put("pid", pid);
        m.put("binary", binary);
        m.put("version", version);
        m.put("versionLine", versionLine);
        m.put("installType", installType);
        m.put("moduleCount", moduleCount);
        m.put("runUser", runUser);
        m.put("instanceKey", instanceKey());
        m.put("status", status());
        m.put("compromise", compromiseSuspected());
        m.put("below2469", below2469);
        m.put("eol", eol);
        m.put("counts", Map.of("risk", risk, "warn", warn, "ok", ok, "info", info));
        m.put("cveApplicable", cveCounts(false));
        m.put("cveUnpatched", cveCounts(true));
        m.put("cveList", cves.stream().filter(c -> c.applicable).map(Cve::toMap).toList());
        m.put("configIssues", findings.stream()
                .filter(f -> "3".equals(f.section) && ("risk".equals(f.level) || "warn".equals(f.level)))
                .map(f -> Map.of("level", f.level, "text", f.text)).toList());
        m.put("dataQuality", dataQuality);
        m.put("fileModified", fileModified);
        return m;
    }

    public Map<String, Object> toDetail() {
        Map<String, Object> m = toSummary();
        m.put("findings", findings.stream().map(Finding::toMap).toList());
        m.put("cves", cves.stream().map(Cve::toMap).toList());
        m.put("raw", raw);
        return m;
    }
}
