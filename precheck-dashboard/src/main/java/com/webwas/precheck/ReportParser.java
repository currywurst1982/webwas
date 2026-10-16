package com.webwas.precheck;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * apache_precheck.sh 가 만드는 리포트(/tmp/apache_precheck_<호스트>_<시각>[_pid<PID>].txt) 해석기.
 * 스크립트의 출력 형식(risk/warn/ok/info/detail/section 함수)에 맞춰 작성됨.
 */
public final class ReportParser {
    private ReportParser() {}

    public static final String HEADER_MARK = "Apache 패치 전 보안 사전 점검";

    private static final Pattern HEADER = Pattern.compile("호스트:\\s*(.*?)\\s*\\|\\s*일시:\\s*(.+?)\\s*$");
    private static final Pattern FILE_NAME = Pattern.compile(
            "^(?:agent-([A-Za-z0-9.-]+)__)?apache_precheck_(.+)_(\\d{8})_(\\d{6})(?:_pid(\\d+))?\\.txt$");
    private static final Pattern SECTION = Pattern.compile("^ \\[(\\d)\\] ");
    private static final Pattern FINDING = Pattern.compile("^\\[(위험|주의|양호|정보)\\] (.*)$");
    private static final Pattern NOT_APPLICABLE = Pattern.compile("^\\[미해당\\] (CVE-\\d+-\\d+) \\((\\w+)\\) - 필요 모듈\\((.*)\\) 미사용");
    private static final Pattern CVE_LINE = Pattern.compile(
            "^(CVE-\\d+-\\d+) \\[(\\w+)\\] (.*) \\(영향: ([^~]+)~([^,]+), 조건: ([^)]*)\\)(.*)$");
    private static final Pattern SUMMARY = Pattern.compile(
            "\\[위험\\] (\\d+)건\\s+\\[주의\\] (\\d+)건\\s+\\[양호\\] (\\d+)건\\s+\\[정보\\] (\\d+)건");
    private static final Pattern VERSION = Pattern.compile("Apache/(\\d+\\.\\d+\\.\\d+)");
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
        int nl = text.indexOf('\n');
        String first = nl < 0 ? text : text.substring(0, nl);
        return first.contains(HEADER_MARK);
    }

    public static Report parse(String fileName, String text) {
        Report r = new Report();
        r.id = fileName;
        r.raw = text;

        Matcher fm = FILE_NAME.matcher(fileName);
        if (fm.matches()) {
            r.source = fm.group(1);
            r.host = fm.group(2);
            String d = fm.group(3), t = fm.group(4);
            r.checkedAt = d.substring(0, 4) + "-" + d.substring(4, 6) + "-" + d.substring(6) + " "
                    + t.substring(0, 2) + ":" + t.substring(2, 4) + ":" + t.substring(4);
            r.pid = fm.group(5);
        }

        String section = "0";
        Report.Finding last = null;
        boolean inSummary = false;

        for (String line : text.split("\\r?\\n", -1)) {
            if (line.contains(HEADER_MARK)) {
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
                c.severity = na.group(2).toLowerCase();
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
        // 설정 파일 목록 (점검 대상 설정 파일 수 항목의 상세 줄)
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
            r.below2469 = compareVersions(r.version, "2.4.69") < 0;
            r.eol = r.version.startsWith("2.2.") || r.version.startsWith("2.0.") || r.version.startsWith("1.");
        }
        if (r.host == null) r.host = "(알 수 없음)";
        while (!r.section4Raw.isEmpty() && r.section4Raw.get(r.section4Raw.size() - 1).isBlank()) {
            r.section4Raw.remove(r.section4Raw.size() - 1);
        }
        return r;
    }

    /** 스크립트의 특정 문구에서 서버 정보·데이터 품질 경고를 뽑아냄. */
    private static void interpret(Report r, String section, String body) {
        if (body.startsWith("실행파일: ")) {
            r.binary = body.substring("실행파일: ".length()).trim();
        } else if (body.startsWith("버전 정보: ")) {
            r.versionLine = body.substring("버전 정보: ".length()).trim();
            Matcher v = VERSION.matcher(body);
            if (v.find()) r.version = v.group(1);
        } else if (body.startsWith("설치 방식: ")) {
            String t = body.substring("설치 방식: ".length());
            r.installType = t.startsWith("RPM") ? "RPM" : t.startsWith("DEB") ? "DEB" : "소스";
        } else if (body.startsWith("로드된 모듈 수: ")) {
            try {
                r.moduleCount = Integer.parseInt(body.substring("로드된 모듈 수: ".length()).trim());
            } catch (NumberFormatException ignored) {
                // 형식이 다르면 무시
            }
            if (r.moduleCount != null && r.moduleCount == 0) {
                r.dataQuality.add("로드된 모듈 수가 0입니다. httpd -M 실행이 실패한 것으로 보이며, "
                        + "이 경우 모듈 조건이 있는 CVE가 모두 '미해당'으로 잘못 판정됩니다. 수동 확인이 필요합니다.");
            }
        } else if (body.startsWith("인스턴스 실행 인자: ")) {
            String a = body.substring("인스턴스 실행 인자: ".length()).trim();
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
        } else if (body.startsWith("root 권한이 아닙니다")) {
            r.dataQuality.add("root 권한 없이 실행되어 로그/설정/프로세스 점검이 불완전할 수 있습니다.");
        } else if (body.startsWith("접근 로그 파일을 찾지 못했습니다")) {
            r.dataQuality.add("접근 로그를 찾지 못해 로그 기반 침해 흔적 점검이 수행되지 않았습니다.");
        } else if (body.startsWith("DocumentRoot 를 찾지 못했습니다")) {
            r.dataQuality.add("DocumentRoot 를 찾지 못해 웹쉘 파일 점검이 수행되지 않았습니다.");
        } else if (body.startsWith("2.4.x 가 아니므로")) {
            r.dataQuality.add("2.4.x 가 아니어서 CVE 판정이 수행되지 않았습니다.");
        } else if (body.startsWith("버전을 해석하지 못했습니다") || body.startsWith("httpd 실행파일을 찾지 못했습니다")) {
            r.dataQuality.add("스크립트가 초기 단계에서 중단되었습니다: " + body);
        }

        if ("2".equals(section)) {
            Matcher c = CVE_LINE.matcher(body);
            if (c.find()) {
                Report.Cve cve = new Report.Cve();
                cve.id = c.group(1);
                cve.severity = c.group(2).toLowerCase();
                cve.description = c.group(3);
                cve.affected = c.group(4) + "~" + c.group(5);
                cve.condition = c.group(6);
                cve.applicable = true;
                cve.backported = c.group(7).contains("changelog");
                r.cves.add(cve);
            }
        }
    }

    /** 2.4.9 < 2.4.10 처럼 숫자 단위 비교. */
    public static int compareVersions(String a, String b) {
        String[] x = a.split("\\."), y = b.split("\\.");
        for (int i = 0; i < Math.max(x.length, y.length); i++) {
            int p = i < x.length ? parseIntSafe(x[i]) : 0;
            int q = i < y.length ? parseIntSafe(y[i]) : 0;
            if (p != q) return Integer.compare(p, q);
        }
        return 0;
    }

    private static int parseIntSafe(String s) {
        try {
            return Integer.parseInt(s.replaceAll("\\D.*", ""));
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
