package com.webwas.precheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** apache_precheck.sh / wildfly_precheck.sh / tomcat_precheck.sh 리포트 1개를 해석한 결과. */
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
        public String severity;      // critical | high | moderate | low (Apache 의 important 는 high 로 통일)
        public String description;   // 미해당 항목은 리포트에 설명이 없음
        public String affected;      // 예: 2.4.0~2.4.59 / undertow-core 2.3.0.Alpha1~2.3.21.Final 미만
        public String condition;     // Apache: 필요 모듈 조건 / WildFly·Tomcat: 설치된 구성요소와 버전(미해당이면 필요한 구성요소)
        public String advisory;      // OSV 권고 ID (GHSA-..., WildFly·Tomcat)
        public boolean applicable;   // true=해당, false=모듈/구성요소가 없어 미해당
        public boolean backported;   // Apache 패키지 changelog 에 수정 기록 있음 (WildFly·Tomcat 은 항상 false)

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

    /** 점검 대상 제품 (리포트 머리글로 판별) */
    public Product product = Product.APACHE;
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
    /** 인스턴스 구분. Apache: -f 설정 파일 / WildFly: "base=... config=..." / Tomcat: "base=/srv/tomcat1" (CATALINA_BASE) */
    public String confArg;
    /** 메인 설정 파일 경로 (수정본 스크립트가 기록) */
    public String mainConfig;
    /** Apache: httpd 실행 파일 / WildFly: 설치 폴더(JBOSS_HOME) / Tomcat: 설치 폴더(CATALINA_HOME) */
    public String binary;
    public String versionLine;
    public String version;
    public String installType;   // RPM | DEB | 소스 | ZIP | Galleon
    public String runMode;       // standalone | domain
    public String javaVersion;
    /** Apache: 로드된 모듈 수 / WildFly·Tomcat: 구성요소(jar) 수 */
    public Integer moduleCount;
    public String runUser;
    /** Apache: [3] 설정 파일 목록을 얻은 방법 (WildFly·Tomcat 은 메인 설정 파일 1개라 null) */
    public String confMethod;
    /** 설정 점검 대상 파일 목록 */
    public final List<String> confFiles = new ArrayList<>();
    public int risk, warn, ok, info;
    public boolean summaryFound;
    /** 교체가 필요한 버전 계열. Apache: 2.2 이하(EOL) / WildFly: Java EE 8(javax, 26 이하) / Tomcat: 지원 종료 브랜치 */
    public boolean eol;
    /** CVE 판정에 쓴 CVE 목록 출처 (스크립트 내장본 / 대시보드 자동 업데이트본). 이전 스크립트는 null */
    public String cveDbInfo;
    public final List<Finding> findings = new ArrayList<>();
    public final List<Cve> cves = new ArrayList<>();
    public final List<String> dataQuality = new ArrayList<>();
    /** 원본 리포트의 [4] 침해 흔적 섹션 원문 (구분선 제외) */
    public final List<String> section4Raw = new ArrayList<>();
    public String raw;

    /**
     * 같은 서버의 같은 인스턴스를 묶는 키: 제품 + 호스트 + 설치 폴더(실행 파일) + 인스턴스 구분.
     * PID 는 재시작할 때마다 바뀌므로 쓰지 않음.
     */
    public String instanceKey() {
        return product.id + "|" + host + "|" + (binary == null ? "" : binary) + "|" + (confArg == null ? "" : confArg);
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
                || f.text.startsWith("unzip/python3 이 없어") || f.text.startsWith("server.log 를 찾지 못했습니다")
                || f.text.startsWith("DocumentRoot 를 찾지 못했습니다") || f.text.startsWith("catalina 로그를 찾지 못했습니다");
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

    /**
     * 점검 사각지대: 이 리포트에서 실제로 수행되지 못한 점검 (리포트 문구로 판단).
     * accessLog 접근 로그 없음 / serverLog 서버 로그 없음 / webFiles 웹 파일 위치 못 찾음 /
     * authLog OS 로그인 기록 못 읽음 / oldScript 로그인 기록 점검이 없는 이전 스크립트 /
     * noRoot root 권한 없이 실행 / incomplete 점검이 중간에 끝남
     */
    public List<String> gaps() {
        List<String> g = new ArrayList<>();
        boolean auth = false;
        for (Finding f : findings) {
            String t = f.text;
            if (t.contains("접근 로그") && t.contains("찾지 못했")) add(g, "accessLog");
            if (t.contains("server.log 를 찾지 못했") || t.contains("catalina 로그를 찾지 못했")) add(g, "serverLog");
            if (t.contains("DocumentRoot 를 찾지 못했") || t.contains("배포 폴더를 찾지 못했")) add(g, "webFiles");
            if (t.contains("OS 로그인 기록")) {
                auth = true;
                if (t.contains("읽지 못해")) add(g, "authLog");
            }
        }
        boolean incomplete = false;
        for (String d : dataQuality) {
            if (d.contains("root 권한 없이")) add(g, "noRoot");
            if (d.contains("'점검 요약'이 없습니다") || d.contains("초기 단계에서 중단")) incomplete = true;
        }
        if (incomplete) add(g, "incomplete");
        else if (!auth) add(g, "oldScript"); // 끝까지 돌았는데 4-5 로그인 기록 점검이 없음 = 2026-11-10 이전 스크립트
        return g;
    }

    private static void add(List<String> g, String code) {
        if (!g.contains(code)) g.add(code);
    }

    /** 최신 버전 미만인가 (latest 가 없거나 버전을 모르면 false) */
    public boolean belowLatest(LatestVersions latest) {
        return latest != null && latest.below(product, version);
    }

    /** eol 표시 문구 (제품마다 의미가 다름) */
    public String eolLabel() {
        return switch (product) {
            case APACHE -> "EOL";
            case WILDFLY -> "javax 계열";
            case TOMCAT -> "지원 종료";
        };
    }

    /** latest = 제품별 최신 버전 정보 (null 이면 최신 여부 판정 안 함) */
    public Map<String, Object> toSummary(LatestVersions latest) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("product", product.id);
        m.put("productLabel", product.label);
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
        m.put("belowLatest", belowLatest(latest));
        m.put("latestForVersion", latest == null ? null : latest.latestFor(product, version));
        m.put("intrusion", intrusionStatus());
        m.put("intrusionFindings", findings.stream()
                .filter(f -> "4".equals(f.section) && !coverageGap(f) && ("risk".equals(f.level) || "warn".equals(f.level)))
                .map(f -> Map.of("level", f.level, "text", f.text)).toList());
        m.put("eol", eol);
        m.put("eolLabel", eolLabel());
        m.put("cveDbInfo", cveDbInfo);
        m.put("counts", Map.of("risk", risk, "warn", warn, "ok", ok, "info", info));
        m.put("cveApplicable", cveCounts(false));
        m.put("cveUnpatched", cveCounts(true));
        m.put("cveList", cves.stream().filter(c -> c.applicable).map(Cve::toMap).toList());
        m.put("configIssues", findings.stream()
                .filter(f -> "3".equals(f.section) && ("risk".equals(f.level) || "warn".equals(f.level)))
                .map(f -> Map.of("level", f.level, "text", f.text)).toList());
        m.put("dataQuality", dataQuality);
        m.put("gaps", gaps());
        m.put("fileModified", fileModified);
        return m;
    }

    public Map<String, Object> toDetail() {
        return toDetail(null);
    }

    /** 화면·PDF 표시용 짧은 이름 */
    public String confMethodShort() {
        if (product == Product.APACHE) {
            if (confMethod == null) return "확인 안 됨(이전 스크립트)";
            if (confMethod.startsWith("httpd -t -D DUMP_INCLUDES")) return "httpd 가 읽는 파일(DUMP_INCLUDES)";
            if (confMethod.startsWith("메인 설정")) return "httpd.conf Include 추적";
            return confMethod;
        }
        return mainConfig == null ? "확인 안 됨" : mainConfig.substring(mainConfig.lastIndexOf('/') + 1);
    }

    public Map<String, Object> toDetail(LatestVersions latest) {
        Map<String, Object> m = toSummary(latest);
        m.put("confFiles", confFiles);
        m.put("findings", findings.stream().map(Finding::toMap).toList());
        m.put("cves", cves.stream().map(Cve::toMap).toList());
        m.put("raw", raw);
        return m;
    }
}
