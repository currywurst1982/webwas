package com.webwas.precheck;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 점검 스크립트 리포트 해석기. 세 스크립트 모두 같은 출력 형식(risk/warn/ok/info/detail/section 함수)을 씀.
 *  - apache_precheck.sh  → /tmp/apache_precheck_<호스트>_<시각>[_pid<PID>].txt
 *  - wildfly_precheck.sh → /tmp/wildfly_precheck_<호스트>_<시각>[_pid<PID>].txt
 *  - tomcat_precheck.sh  → /tmp/tomcat_precheck_<호스트>_<시각>[_pid<PID>].txt
 *  - nginx_precheck.sh   → /tmp/nginx_precheck_<호스트>_<시각>[_pid<PID>].txt
 * 제품은 첫 줄의 머리글("Apache 패치 전 보안 사전 점검" 등)로 구분.
 */
public final class ReportParser {
    private ReportParser() {}

    /** 업로드 오류 안내용 머리글 */
    public static final String HEADER_MARK = "Apache/WildFly/Tomcat 패치 전 보안 사전 점검";

    private static final Pattern HEADER = Pattern.compile("호스트:\\s*(.*?)\\s*\\|\\s*일시:\\s*(.+?)\\s*$");
    private static final Pattern FILE_NAME = Pattern.compile(
            "^(?:agent-([A-Za-z0-9.-]+)__)?(apache|wildfly|tomcat|nginx)_precheck_(.+)_(\\d{8})_(\\d{6})(?:_pid(\\d+))?\\.txt$");
    private static final Pattern SECTION = Pattern.compile("^ \\[(\\d)\\] ");
    private static final Pattern FINDING = Pattern.compile("^\\[(위험|주의|양호|정보)\\] (.*)$");
    private static final Pattern NOT_APPLICABLE = Pattern.compile("^\\[미해당\\] (CVE-\\d+-\\d+) \\((\\w+)\\) - 필요 모듈\\((.*)\\) 미사용");
    /** Apache 예: CVE-2024-38474 [important] 설명 (영향: 2.4.0~2.4.59, 조건: rewrite_module) - 백포트 추정(changelog ...) */
    private static final Pattern CVE_LINE_APACHE = Pattern.compile(
            "^(CVE-\\d+-\\d+) \\[(\\w+)\\] (.*) \\(영향: ([^~]+)~([^,]+), 조건: ([^)]*)\\)(.*)$");
    /** WildFly/Tomcat 예: CVE-2024-3884 [high] 설명 (영향: undertow-core 2.3.0.Alpha1~2.3.21.Final 미만, 조건: undertow-core 2.3.12.Final 설치됨, 출처: GHSA-...) */
    private static final Pattern CVE_LINE_OSV = Pattern.compile(
            "^(CVE-\\d+-\\d+) \\[(\\w+)\\] (.*) \\(영향: ([^~]+)~([^,]+), 조건: ([^,)]*)(?:, 출처: ([^)]*))?\\)\\s*$");
    private static final Pattern SUMMARY = Pattern.compile(
            "\\[위험\\] (\\d+)건\\s+\\[주의\\] (\\d+)건\\s+\\[양호\\] (\\d+)건\\s+\\[정보\\] (\\d+)건");
    private static final Pattern VERSION_APACHE = Pattern.compile("Apache/(\\d+\\.\\d+\\.\\d+)");
    /** "WildFly - Version 41.0.1.Final", "WildFly Full 26.1.3.Final" 등에서 버전만 */
    private static final Pattern VERSION_WILDFLY = Pattern.compile("(\\d+\\.\\d+\\.\\d+\\.[A-Za-z]+\\d*)");
    /** "Apache Tomcat/9.0.85", "Apache Tomcat/11.0.0-M5" */
    private static final Pattern VERSION_TOMCAT = Pattern.compile("Tomcat/(\\d+\\.\\d+\\.\\d+(?:-M\\d+)?)");
    /** "nginx version: nginx/1.24.0 (Ubuntu)", OpenResty 는 "openresty/1.25.3.1" → 1.25.3 */
    private static final Pattern VERSION_NGINX = Pattern.compile("nginx/(\\d+\\.\\d+\\.\\d+)");
    private static final Pattern VERSION_ANY3 = Pattern.compile("[A-Za-z]+/(\\d+\\.\\d+\\.\\d+)");
    /** 기본 설치에서 보통 Include 되지 않는 위치 (소스 설치 conf/extra, conf/original, Debian *-available) */
    private static final Pattern UNINCLUDED_HINT = Pattern.compile("^/\\S*/(extra|original|mods-available|conf-available|sites-available)/");

    /** UTF-8 로 읽되, 깨지면 한글 Windows/EUC-KR(MS949)로 다시 읽음. */
    public static String decode(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            return new String(bytes, Charset.forName("MS949"));
        }
    }

    public static boolean looksLikeReport(String text) {
        return Product.fromText(text) != null;
    }

    /** CVE 등급 통일: Apache 의 important 는 GitHub Advisory 의 high 와 같은 단계로 봄 */
    static String normSeverity(String s) {
        String v = s == null ? "moderate" : s.toLowerCase(Locale.ROOT);
        return switch (v) {
            case "important" -> "high";
            case "medium" -> "moderate";
            case "critical", "high", "moderate", "low" -> v;
            default -> "moderate";
        };
    }

    public static Report parse(String fileName, String text) {
        Report r = new Report();
        r.id = fileName;
        r.raw = text;
        Product fromText = Product.fromText(text);
        Product fromName = Product.fromFileName(fileName);
        r.product = fromText != null ? fromText : fromName != null ? fromName : Product.APACHE;
        String headerMark = r.product.headerMark;

        Matcher fm = FILE_NAME.matcher(fileName);
        if (fm.matches()) {
            r.source = fm.group(1);
            r.host = fm.group(3);
            String d = fm.group(4), t = fm.group(5);
            r.checkedAt = d.substring(0, 4) + "-" + d.substring(4, 6) + "-" + d.substring(6) + " "
                    + t.substring(0, 2) + ":" + t.substring(2, 4) + ":" + t.substring(4);
            r.pid = fm.group(6);
        }

        String section = "0";
        Report.Finding last = null;
        boolean inSummary = false;

        for (String line : text.split("\\r?\\n", -1)) {
            if (line.contains(headerMark)) {
                Matcher h = HEADER.matcher(line);
                if (h.find()) {
                    r.host = h.group(1);
                    r.checkedAt = h.group(2);
                }
                continue;
            }
            Matcher sm = SECTION.matcher(line);
            if (sm.find()) {
                section = sm.group(1);
                last = null;
                continue;
            }
            if (line.startsWith(" 점검 요약")) {
                inSummary = true;
                last = null;
                continue;
            }
            // [4] 침해 흔적 섹션은 원문 그대로 보관 (PDF 발췌용). 구분선(=====)만 제외
            if ("4".equals(section) && !inSummary && !line.startsWith("=====")) {
                r.section4Raw.add(line);
            }
            if (inSummary) {
                Matcher s = SUMMARY.matcher(line);
                if (s.find()) {
                    r.risk = Integer.parseInt(s.group(1));
                    r.warn = Integer.parseInt(s.group(2));
                    r.ok = Integer.parseInt(s.group(3));
                    r.info = Integer.parseInt(s.group(4));
                    r.summaryFound = true;
                }
                continue;
            }
            Matcher na = NOT_APPLICABLE.matcher(line);
            if (na.find()) {
                Report.Cve c = new Report.Cve();
                c.id = na.group(1);
                c.severity = normSeverity(na.group(2));
                c.condition = na.group(3);
                c.applicable = false;
                r.cves.add(c);
                last = null;
                continue;
            }
            Matcher f = FINDING.matcher(line);
            if (f.find()) {
                String level = switch (f.group(1)) {
                    case "위험" -> "risk";
                    case "주의" -> "warn";
                    case "양호" -> "ok";
                    default -> "info";
                };
                String body = f.group(2).trim();
                last = new Report.Finding(level, section, body);
                r.findings.add(last);
                interpret(r, section, body);
                continue;
            }
            if (line.startsWith("        ") && last != null) {
                String d = line.trim();
                if (!d.isEmpty()) last.details.add(d);
                continue;
            }
            if (!line.isBlank() && !line.startsWith("=====")) last = null;
        }

        // 요약 줄이 없으면(스크립트가 중간에 종료) 직접 집계
        if (!r.summaryFound) {
            for (Report.Finding x : r.findings) {
                switch (x.level) {
                    case "risk" -> r.risk++;
                    case "warn" -> r.warn++;
                    case "ok" -> r.ok++;
                    default -> r.info++;
                }
            }
            r.dataQuality.add("리포트에 '점검 요약'이 없습니다. 스크립트가 중간에 종료되었을 수 있어 결과가 불완전합니다.");
        }
        if (r.product == Product.APACHE) {
            apachePost(r);
        } else if (r.product == Product.NGINX) {
            // 점검한 설정 파일 목록 = "점검한 설정 파일: N개" 항목의 상세 줄
            r.findings.stream().filter(x -> x.text.startsWith("점검한 설정 파일: ")).findFirst()
                    .ifPresent(x -> x.details.stream().filter(d -> d.startsWith("/")).forEach(r.confFiles::add));
            if (r.confFiles.isEmpty() && r.mainConfig != null) r.confFiles.add(r.mainConfig);
        } else if (r.mainConfig != null) {
            r.confFiles.add(r.mainConfig);
        }
        if (r.host == null) r.host = "(알 수 없음)";
        while (!r.section4Raw.isEmpty() && r.section4Raw.get(r.section4Raw.size() - 1).isBlank()) {
            r.section4Raw.remove(r.section4Raw.size() - 1);
        }
        return r;
    }

    /** 스크립트의 특정 문구에서 서버 정보·데이터 품질 경고를 뽑아냄. */
    private static void interpret(Report r, String section, String body) {
        // --- 세 스크립트 공통 문구 ---
        if (body.startsWith("서버 IP: ")) {
            for (String ip : body.substring("서버 IP: ".length()).trim().split("\\s+")) {
                if (ip.matches("[0-9A-Fa-f:.]{2,45}")) r.ips.add(ip);
            }
            return;
        } else if (body.startsWith("메인 설정 파일: ")) {
            String c = body.substring("메인 설정 파일: ".length()).trim();
            if (c.startsWith("/")) r.mainConfig = c;
            return;
        } else if (body.startsWith("CVE 목록 출처: ")) {
            r.cveDbInfo = body.substring("CVE 목록 출처: ".length()).trim();
            return;
        } else if (body.startsWith("root 권한이 아닙니다")) {
            r.dataQuality.add("root 권한 없이 실행되어 로그/설정/프로세스 점검이 불완전할 수 있습니다.");
            return;
        }
        switch (r.product) {
            case APACHE -> interpretApache(r, body);
            case WILDFLY -> interpretWildfly(r, body);
            case TOMCAT -> interpretTomcat(r, body);
            case NGINX -> interpretNginx(r, body);
        }

        if ("2".equals(section)) {
            if (r.product == Product.APACHE || r.product == Product.NGINX) {
                Matcher c = CVE_LINE_APACHE.matcher(body);
                if (c.find()) {
                    Report.Cve cve = new Report.Cve();
                    cve.id = c.group(1);
                    cve.severity = normSeverity(c.group(2));
                    cve.description = c.group(3);
                    cve.affected = c.group(4).trim() + "~" + c.group(5).trim();
                    cve.condition = c.group(6).trim();
                    cve.applicable = true;
                    cve.backported = c.group(7).contains("changelog");
                    r.cves.add(cve);
                }
            } else {
                Matcher c = CVE_LINE_OSV.matcher(body);
                if (c.find()) {
                    Report.Cve cve = new Report.Cve();
                    cve.id = c.group(1);
                    cve.severity = normSeverity(c.group(2));
                    cve.description = c.group(3);
                    cve.affected = c.group(4).trim() + "~" + c.group(5).trim();
                    cve.condition = c.group(6).trim();
                    cve.advisory = c.group(7) == null ? null : c.group(7).trim();
                    cve.applicable = true;
                    r.cves.add(cve);
                }
            }
        }
    }

    private static void interpretApache(Report r, String body) {
        if (body.startsWith("실행파일: ")) {
            r.binary = body.substring("실행파일: ".length()).trim();
        } else if (body.startsWith("버전 정보: ")) {
            r.versionLine = body.substring("버전 정보: ".length()).trim();
            Matcher v = VERSION_APACHE.matcher(body);
            if (v.find()) r.version = v.group(1);
        } else if (body.startsWith("설치 방식: ")) {
            String t = body.substring("설치 방식: ".length());
            r.installType = t.startsWith("RPM") ? "RPM" : t.startsWith("DEB") ? "DEB" : "소스";
        } else if (body.startsWith("로드된 모듈 수: ")) {
            r.moduleCount = intOrNull(body.substring("로드된 모듈 수: ".length()));
            if (r.moduleCount != null && r.moduleCount == 0) {
                r.dataQuality.add("로드된 모듈 수가 0입니다. httpd -M 실행이 실패한 것으로 보이며, "
                        + "이 경우 모듈 조건이 있는 CVE가 모두 '미해당'으로 잘못 판정됩니다. 수동 확인이 필요합니다.");
            }
        } else if (body.startsWith("인스턴스 실행 인자: ")) {
            String a = body.substring("인스턴스 실행 인자: ".length()).trim();
            Matcher fa = Pattern.compile("(?:^|\\s)-f\\s+(\\S+)").matcher(a);
            if (fa.find()) r.confArg = fa.group(1);
            if (a.matches("\\d+")) {
                if (r.pid == null) r.pid = a;
                r.dataQuality.add("'인스턴스 실행 인자'에 PID(" + a + ")가 들어가 있습니다. 원본 스크립트의 인스턴스 탐지 버그로, "
                        + "httpd 가 잘못된 인자로 호출되어 모듈·설정 파일 목록이 부정확할 수 있습니다. scripts/apache_precheck.sh(수정본)로 재점검하세요.");
            }
        } else if (body.startsWith("실행 중인 Apache 프로세스 자동 탐지: 마스터 PID ")) {
            String p = body.replaceAll("\\D+", " ").trim();
            if (!p.isEmpty() && r.pid == null) r.pid = p.split(" ")[0];
        } else if (body.startsWith("설정 파일 목록 확인 방법: ")) {
            r.confMethod = body.substring("설정 파일 목록 확인 방법: ".length()).trim();
        } else if (body.startsWith("워커 실행 계정: ")) {
            r.runUser = body.substring("워커 실행 계정: ".length()).trim();
        } else if (body.startsWith("워커 실행 계정이 root")) {
            r.runUser = "root";
        } else if (body.startsWith("접근 로그 파일을 찾지 못했습니다")) {
            r.dataQuality.add("접근 로그를 찾지 못해 로그 기반 침해 흔적 점검이 수행되지 않았습니다.");
        } else if (body.startsWith("DocumentRoot 를 찾지 못했습니다")) {
            r.dataQuality.add("DocumentRoot 를 찾지 못해 웹쉘 파일 점검이 수행되지 않았습니다.");
        } else if (body.startsWith("2.4.x 가 아니므로")) {
            r.dataQuality.add("2.4.x 가 아니어서 CVE 판정이 수행되지 않았습니다.");
        } else if (body.startsWith("버전을 해석하지 못했습니다") || body.startsWith("httpd 실행파일을 찾지 못했습니다")) {
            r.dataQuality.add("스크립트가 초기 단계에서 중단되었습니다: " + body);
        }
    }

    /** Apache 리포트 후처리: 설정 파일 목록, 이전 스크립트 오탐 경고, EOL 판정 */
    private static void apachePost(Report r) {
        r.findings.stream().filter(x -> x.text.startsWith("점검 대상 설정 파일 수")).findFirst()
                .ifPresent(x -> x.details.stream().filter(d -> d.startsWith("/")).forEach(r.confFiles::add));
        // 이전 스크립트는 DUMP_INCLUDES 가 실패하면 설정 폴더의 *.conf 를 전부 점검했음 → Include 안 된 파일 오탐 가능성 경고
        if (r.confMethod == null) {
            java.util.Set<String> suspicious = new java.util.TreeSet<>();
            for (Report.Finding x : r.findings) {
                if (!"3".equals(x.section)) continue;
                for (String d : x.details) {
                    Matcher sp = UNINCLUDED_HINT.matcher(d);
                    if (sp.find()) suspicious.add(d.substring(0, d.indexOf(':') > 0 ? d.indexOf(':') : d.length()));
                }
            }
            if (!suspicious.isEmpty()) {
                r.dataQuality.add("이전 버전 스크립트로 만든 리포트라 httpd.conf 에 Include 되지 않은 설정 파일까지 점검했을 수 있습니다 "
                        + "(의심: " + String.join(", ", suspicious) + "). 수정본 스크립트로 재점검하면 실제로 Include 된 파일만 점검합니다.");
            }
        }
        if (r.version != null) {
            r.eol = r.version.startsWith("2.2.") || r.version.startsWith("2.0.") || r.version.startsWith("1.");
        }
    }

    private static void interpretWildfly(Report r, String body) {
        if (body.startsWith("설치 폴더: ")) {
            r.binary = body.substring("설치 폴더: ".length()).trim();
        } else if (body.startsWith("버전 정보: ")) {
            r.versionLine = body.substring("버전 정보: ".length()).trim();
            Matcher v = VERSION_WILDFLY.matcher(r.versionLine);
            if (v.find()) r.version = v.group(1);
        } else if (body.startsWith("설치 방식: ")) {
            String t = body.substring("설치 방식: ".length());
            r.installType = t.startsWith("RPM") ? "RPM" : t.startsWith("DEB") ? "DEB" : t.startsWith("Galleon") ? "Galleon" : "ZIP";
        } else if (body.startsWith("실행 모드: ")) {
            r.runMode = body.substring("실행 모드: ".length()).trim();
        } else if (body.startsWith("Java: ")) {
            r.javaVersion = body.substring("Java: ".length()).replaceAll("\\s*\\(/.*\\)$", "").trim();
        } else if (body.startsWith("구성요소(jar) 수: ")) {
            r.moduleCount = intOrNull(body.substring("구성요소(jar) 수: ".length()));
            if (r.moduleCount != null && r.moduleCount == 0) {
                r.dataQuality.add("구성요소(jar) 수가 0입니다. modules 폴더를 읽지 못한 것으로 보이며, "
                        + "이 경우 CVE 가 모두 '미해당'으로 잘못 판정됩니다. 수동 확인이 필요합니다.");
            }
        } else if (body.startsWith("인스턴스 구분: ")) {
            r.confArg = body.substring("인스턴스 구분: ".length()).trim();
        } else if (body.startsWith("실행 중인 WildFly 프로세스 자동 탐지: PID ")) {
            String p = body.replaceAll("\\D+", " ").trim();
            if (!p.isEmpty() && r.pid == null) r.pid = p.split(" ")[0];
        } else if (body.startsWith("실행 계정: ")) {
            r.runUser = body.substring("실행 계정: ".length()).trim();
        } else if (body.startsWith("실행 계정이 root")) {
            r.runUser = "root";
        } else if (body.startsWith("Java EE 8(javax) 계열")) {
            r.eol = true;
        } else if (body.startsWith("접근 로그 파일을 찾지 못했습니다")) {
            r.dataQuality.add("접근 로그가 없어(WildFly 기본값은 접근 로그 꺼짐) 로그 기반 침해 흔적 점검이 수행되지 않았습니다.");
        } else if (body.startsWith("server.log 를 찾지 못했습니다")) {
            r.dataQuality.add("server.log 를 찾지 못해 WildFly 로그 기반 공격 흔적 점검이 수행되지 않았습니다.");
        } else if (body.startsWith("배포 폴더를 찾지 못했습니다")) {
            r.dataQuality.add("배포 폴더를 찾지 못해 웹쉘 JSP 점검이 수행되지 않았습니다.");
        } else if (body.startsWith("unzip/python3 이 없어")) {
            r.dataQuality.add("unzip/python3 이 없어 압축된 배포 파일(war/ear) 안의 웹쉘 점검이 수행되지 않았습니다.");
        } else if (body.startsWith("메인 설정 파일을 읽지 못했습니다")) {
            r.dataQuality.add("메인 설정 파일을 읽지 못해 설정 점검이 불완전합니다.");
        } else if (body.startsWith("버전을 해석하지 못했습니다") || body.startsWith("WildFly 설치 폴더를 찾지 못했습니다")) {
            r.dataQuality.add("스크립트가 초기 단계에서 중단되었습니다: " + body);
        }
    }

    private static void interpretTomcat(Report r, String body) {
        if (body.startsWith("설치 폴더: ")) {
            r.binary = body.substring("설치 폴더: ".length()).trim();
        } else if (body.startsWith("버전 정보: ")) {
            r.versionLine = body.substring("버전 정보: ".length()).trim();
            Matcher v = VERSION_TOMCAT.matcher(r.versionLine);
            if (v.find()) r.version = v.group(1);
        } else if (body.startsWith("설치 방식: ")) {
            String t = body.substring("설치 방식: ".length());
            r.installType = t.startsWith("RPM") ? "RPM" : t.startsWith("DEB") ? "DEB" : "ZIP";
        } else if (body.startsWith("Java: ")) {
            r.javaVersion = body.substring("Java: ".length()).replaceAll("\\s*\\(/.*\\)$", "").trim();
        } else if (body.startsWith("구성요소(jar) 수: ")) {
            r.moduleCount = intOrNull(body.substring("구성요소(jar) 수: ".length()));
        } else if (body.startsWith("인스턴스 구분: ")) {
            r.confArg = body.substring("인스턴스 구분: ".length()).trim();
        } else if (body.startsWith("실행 중인 Tomcat 프로세스 자동 탐지: PID ")) {
            String p = body.replaceAll("\\D+", " ").trim();
            if (!p.isEmpty() && r.pid == null) r.pid = p.split(" ")[0];
        } else if (body.startsWith("실행 계정: ")) {
            r.runUser = body.substring("실행 계정: ".length()).trim();
        } else if (body.startsWith("실행 계정이 root")) {
            r.runUser = "root";
        } else if (body.startsWith("지원 종료(EOL) 브랜치")) {
            r.eol = true;
        } else if (body.startsWith("접근 로그 파일을 찾지 못했습니다")) {
            r.dataQuality.add("접근 로그(AccessLogValve)를 찾지 못해 로그 기반 침해 흔적 점검이 수행되지 않았습니다.");
        } else if (body.startsWith("catalina 로그를 찾지 못했습니다")) {
            r.dataQuality.add("catalina 로그를 찾지 못해 Tomcat 로그 기반 공격 흔적 점검이 수행되지 않았습니다.");
        } else if (body.startsWith("배포 폴더를 찾지 못했습니다")) {
            r.dataQuality.add("배포 폴더(webapps)를 찾지 못해 웹쉘 JSP 점검이 수행되지 않았습니다.");
        } else if (body.startsWith("unzip/python3 이 없어")) {
            r.dataQuality.add("unzip/python3 이 없어 압축된 배포 파일(war) 안의 웹쉘 점검이 수행되지 않았습니다.");
        } else if (body.startsWith("메인 설정 파일을 읽지 못했습니다")) {
            r.dataQuality.add("server.xml 을 읽지 못해 설정 점검이 불완전합니다.");
        } else if (body.startsWith("버전을 해석하지 못했습니다") || body.startsWith("Tomcat 설치 폴더를 찾지 못했습니다")) {
            r.dataQuality.add("스크립트가 초기 단계에서 중단되었습니다: " + body);
        }
    }

    private static void interpretNginx(Report r, String body) {
        if (body.startsWith("실행파일: ")) {
            r.binary = body.substring("실행파일: ".length()).trim();
        } else if (body.startsWith("버전 정보: ")) {
            r.versionLine = body.substring("버전 정보: ".length()).trim();
            Matcher v = VERSION_NGINX.matcher(r.versionLine);
            if (v.find()) r.version = v.group(1);
            else {
                Matcher a = VERSION_ANY3.matcher(r.versionLine);
                if (a.find()) r.version = a.group(1);
            }
        } else if (body.startsWith("설치 방식: ")) {
            String t = body.substring("설치 방식: ".length());
            r.installType = t.startsWith("RPM") ? "RPM" : t.startsWith("DEB") ? "DEB" : "소스";
        } else if (body.startsWith("빌드 옵션(--with-*): ")) {
            r.moduleCount = intOrNull(body.substring("빌드 옵션(--with-*): ".length()));
        } else if (body.startsWith("인스턴스 구분: ")) {
            String c = body.substring("인스턴스 구분: ".length()).trim();
            r.confArg = c.startsWith("-c ") ? c.substring(3).trim() : c;
        } else if (body.startsWith("실행 중인 Nginx 프로세스 자동 탐지: ")) {
            String p = body.replaceAll("\\D+", " ").trim();
            if (!p.isEmpty() && r.pid == null) r.pid = p.split(" ")[0];
        } else if (body.startsWith("실행 계정: ")) {
            String u = body.substring("실행 계정: ".length()).trim();
            r.runUser = u.contains(" ") ? u.substring(0, u.indexOf(' ')) : u;
        } else if (body.startsWith("점검한 설정 파일: ")) {
            Matcher m = Pattern.compile("\\(확인 방법: (.*)\\)$").matcher(body);
            if (m.find()) r.confMethod = m.group(1);
        } else if (body.startsWith("지원 종료(EOL) 브랜치")) {
            r.eol = true;
        } else if (body.startsWith("접근 로그 파일을 찾지 못했습니다")) {
            r.dataQuality.add("접근 로그(access_log)를 찾지 못해 로그 기반 침해 흔적 점검이 수행되지 않았습니다.");
        } else if (body.startsWith("웹 루트(root·alias) 폴더를 찾지 못했습니다")) {
            r.dataQuality.add("웹 루트(root·alias)를 찾지 못해 웹쉘 파일 점검이 수행되지 않았습니다.");
        } else if (body.startsWith("메인 설정 파일을 읽지 못했습니다")) {
            r.dataQuality.add("nginx 설정을 읽지 못해 설정 점검이 수행되지 않았습니다.");
        } else if (body.startsWith("버전을 해석하지 못했습니다") || body.startsWith("nginx 실행파일을 찾지 못했습니다")) {
            r.dataQuality.add("스크립트가 초기 단계에서 중단되었습니다: " + body);
        }
    }

    private static Integer intOrNull(String s) {
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Maven 식 버전 비교 (스크립트의 vcmp 와 같은 규칙).
     * 숫자 부분(최대 5자리) → 수식어 순위(Alpha &lt; Beta &lt; CR &lt; SNAPSHOT &lt; Final=GA &lt; SP) → 수식어 번호.
     * 예: 41.0.0.Beta1 &lt; 41.0.0.Final &lt; 41.0.1.Final
     */
    public static int compareVersions(String a, String b) {
        long[] x = parse(a), y = parse(b);
        for (int i = 0; i < x.length; i++) {
            if (x[i] != y[i]) return Long.compare(x[i], y[i]);
        }
        return 0;
    }

    private static long[] parse(String v) {
        long[] out = new long[7];
        String[] t = v.toLowerCase(Locale.ROOT).replace('-', '.').split("\\.");
        int k = 0;
        String q = null;
        long qn = 0;
        for (String s : t) {
            if (q == null && s.matches("\\d+")) {
                if (k < 5) out[k++] = parseLong(s);
                continue;
            }
            if (q == null) {
                Matcher m = Pattern.compile("^(.*?)(\\d+)$").matcher(s);
                if (m.matches()) {
                    q = m.group(1);
                    qn = parseLong(m.group(2));
                } else {
                    q = s;
                }
                continue;
            }
            if (s.matches("\\d+") && qn == 0) qn = parseLong(s);
        }
        if (q == null || q.isEmpty() || q.matches("final|ga|release")) out[5] = 6;
        else if (q.matches("alpha|a")) out[5] = 1;
        else if (q.matches("beta|b")) out[5] = 2;
        else if (q.matches("milestone|m")) out[5] = 3;
        else if (q.matches("cr|rc")) out[5] = 4;
        else if (q.equals("snapshot")) out[5] = 5;
        else if (q.equals("sp")) out[5] = 7;
        else out[5] = 6;
        out[6] = qn;
        return out;
    }

    private static long parseLong(String s) {
        try {
            return Long.parseLong(s.length() > 15 ? s.substring(0, 15) : s);
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
