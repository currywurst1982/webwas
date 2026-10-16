package com.webwas.wfprecheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** wildfly_precheck.sh 리포트 1개를 해석한 결과. */
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
        public String severity;      // critical | high | moderate | low (GitHub Advisory 등급)
        public String description;   // 미해당 항목은 리포트에 설명이 없음
        public String affected;      // 예: undertow-core 2.3.0.Alpha1~2.3.21.Final 미만
        public String condition;     // 해당: 설치된 구성요소와 버전 / 미해당: 필요한 구성요소
        public String advisory;      // OSV 권고 ID (GHSA-...)
        public boolean applicable;   // true=해당, false=구성요소가 없거나 다른 프로젝트라 미해당
        public boolean backported;   // WildFly 는 백포트 판정 없음 (항상 false, 화면 호환용)

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("severity", severity);
            m.put("description", description);
            m.put("affected", affected);
            m.put("condition", condition);
            m.put("advisory", advisory);
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
    /** 서버 IP (스크립트가 기록, 이전 스크립트 리포트는 비어 있음) */
    public final List<String> ips = new ArrayList<>();
    /** IP 기록이 없을 때 대신 보여 줄 에이전트 접속 IP (화면 표시용, 파일에는 없음) */
    public volatile String fallbackIp;
    /** 인스턴스 구분 (기본값과 다른 서버 폴더·설정 파일. 예: "base=/srv/app1 config=standalone-full.xml") */
    public String confArg;
    /** 메인 설정 파일 경로 (수정본 스크립트가 기록) */
    public String mainConfig;
    /** WildFly 설치 폴더 (JBOSS_HOME) */
    public String binary;
    public String versionLine;
    public String version;
    public String installType;   // ZIP | RPM | DEB | Galleon
    public String runMode;       // standalone | domain
    public String javaVersion;
    /** modules 폴더의 구성요소(jar) 수 */
    public Integer moduleCount;
    public String runUser;
    /** (Apache 대시보드와의 호환용, WildFly 는 항상 메인 설정 파일 1개) */
    public String confMethod;
    /** 설정 점검 대상 파일 목록 */
    public final List<String> confFiles = new ArrayList<>();
    public int risk, warn, ok, info;
    public boolean summaryFound;
    /** Java EE 8(javax) 계열 (WildFly 26 이하). 화면 호환을 위해 이름은 eol 그대로 사용 */
    public boolean eol;
    public final List<Finding> findings = new ArrayList<>();
    public final List<Cve> cves = new ArrayList<>();
    public final List<String> dataQuality = new ArrayList<>();
    /** 원본 리포트의 [4] 침해 흔적 섹션 원문 (구분선 제외) */
    public final List<String> section4Raw = new ArrayList<>();
    public String raw;

    /**
     * 같은 서버의 같은 WildFly 인스턴스를 묶는 키: 호스트 + 설치 폴더 + 인스턴스 구분(서버 폴더·설정 파일).
     * PID 는 재시작할 때마다 바뀌므로 쓰지 않음.
     */
    public String instanceKey() {
        return host + "|" + (binary == null ? "" : binary) + "|" + (confArg == null ? "" : confArg);
    }

    /** 대표 IP: 리포트에 기록된 첫 IP, 없으면 에이전트 접속 IP(fallbackIp) */
    public String displayIp() {
        return !ips.isEmpty() ? ips.get(0) : fallbackIp;
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
        for (String s : new String[] {"critical", "high", "moderate", "low"}) m.put(s, 0);
        for (Cve c : cves) {
            if (!c.applicable) continue;
            if (onlyUnpatched && c.backported) continue;
            m.merge(c.severity, 1, Integer::sum);
        }
        return m;
    }

    /**
     * [4] 섹션의 [주의] 중 "접근 로그/배포 폴더를 못 찾아 점검을 건너뜀" 같은 항목은 침해 흔적이 아니라
     * 점검 누락이므로 침해 판정에서 제외 (데이터 품질 경고로 따로 표시됨).
     */
    static boolean coverageGap(Finding f) {
        return f.text.startsWith("접근 로그 파일을 찾지 못했습니다") || f.text.startsWith("배포 폴더를 찾지 못했습니다")
                || f.text.startsWith("unzip/python3 이 없어");
    }

    /** [4] 침해 흔적의 판정: compromise(위험 있음) | check(주의 있음) | clean | none(점검 안 됨) */
    public String intrusionStatus() {
        boolean any = false, warnFound = false;
        for (Finding f : findings) {
            if (!"4".equals(f.section) || coverageGap(f)) continue;
            any = true;
            if ("risk".equals(f.level)) return "compromise";
            if ("warn".equals(f.level)) warnFound = true;
        }
        return warnFound ? "check" : any ? "clean" : "none";
    }

    public Map<String, Object> toSummary() {
        return toSummary(null);
    }

    /** latest = 지금 기준 WildFly 최신 Final 버전 (null 이면 판정 안 함) */
    public Map<String, Object> toSummary(String latest) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("host", host);
        m.put("source", source);
        m.put("checkedAt", checkedAt);
        m.put("pid", pid);
        m.put("ip", displayIp());
        m.put("ips", ips.isEmpty() && fallbackIp != null ? List.of(fallbackIp) : ips);
        m.put("ipFromAgent", ips.isEmpty() && fallbackIp != null);
        m.put("mainConfig", mainConfig);
        m.put("confArg", confArg);
        m.put("binary", binary);
        m.put("version", version);
        m.put("versionLine", versionLine);
        m.put("installType", installType);
        m.put("runMode", runMode);
        m.put("javaVersion", javaVersion);
        m.put("moduleCount", moduleCount);
        m.put("runUser", runUser);
        m.put("confMethod", confMethod);
        m.put("confMethodShort", confMethodShort());
        m.put("confFileCount", confFiles.size());
        m.put("instanceKey", instanceKey());
        m.put("status", status());
        m.put("compromise", compromiseSuspected());
        m.put("belowLatest", latest != null && version != null && ReportParser.compareVersions(version, latest) < 0);
        m.put("intrusion", intrusionStatus());
        m.put("intrusionFindings", findings.stream()
                .filter(f -> "4".equals(f.section) && !coverageGap(f) && ("risk".equals(f.level) || "warn".equals(f.level)))
                .map(f -> Map.of("level", f.level, "text", f.text)).toList());
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
        return toDetail(null);
    }

    /** 화면·PDF 표시용 짧은 이름 */
    public String confMethodShort() {
        return mainConfig == null ? "확인 안 됨" : mainConfig.substring(mainConfig.lastIndexOf('/') + 1);
    }

    public Map<String, Object> toDetail(String latest) {
        Map<String, Object> m = toSummary(latest);
        m.put("confFiles", confFiles);
        m.put("findings", findings.stream().map(Finding::toMap).toList());
        m.put("cves", cves.stream().map(Cve::toMap).toList());
        m.put("raw", raw);
        return m;
    }
}
