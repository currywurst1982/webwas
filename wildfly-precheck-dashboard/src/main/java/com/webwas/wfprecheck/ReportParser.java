package com.webwas.wfprecheck;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * wildfly_precheck.sh 가 만드는 리포트(/tmp/wildfly_precheck_<호스트>_<시각>[_pid<PID>].txt) 해석기.
 * 스크립트의 출력 형식(risk/warn/ok/info/detail/section 함수)에 맞춰 작성됨.
 */
public final class ReportParser {
    private ReportParser() {}

    public static final String HEADER_MARK = "WildFly 패치 전 보안 사전 점검";

    private static final Pattern HEADER = Pattern.compile("호스트:\\s*(.*?)\\s*\\|\\s*일시:\\s*(.+?)\\s*$");
    private static final Pattern FILE_NAME = Pattern.compile(
            "^(?:agent-([A-Za-z0-9.-]+)__)?wildfly_precheck_(.+)_(\\d{8})_(\\d{6})(?:_pid(\\d+))?\\.txt$");
    private static final Pattern SECTION = Pattern.compile("^ \\[(\\d)\\] ");
    private static final Pattern FINDING = Pattern.compile("^\\[(위험|주의|양호|정보)\\] (.*)$");
    private static final Pattern NOT_APPLICABLE = Pattern.compile("^\\[미해당\\] (CVE-\\d+-\\d+) \\((\\w+)\\) - 필요 모듈\\((.*)\\) 미사용");
    /** 예: CVE-2024-3884 [high] 설명 (영향: undertow-core 2.3.0.Alpha1~2.3.21.Final 미만, 조건: undertow-core 2.3.12.Final 설치됨, 출처: GHSA-...) */
    private static final Pattern CVE_LINE = Pattern.compile(
            "^(CVE-\\d+-\\d+) \\[(\\w+)\\] (.*) \\(영향: ([^~]+)~([^,]+), 조건: ([^,)]*)(?:, 출처: ([^)]*))?\\)\\s*$");
    private static final Pattern SUMMARY = Pattern.compile(
            "\\[위험\\] (\\d+)건\\s+\\[주의\\] (\\d+)건\\s+\\[양호\\] (\\d+)건\\s+\\[정보\\] (\\d+)건");
    /** "WildFly - Version 41.0.1.Final", "WildFly Full 26.1.3.Final" 등에서 버전만 */
    private static final Pattern VERSION = Pattern.compile("(\\d+\\.\\d+\\.\\d+\\.[A-Za-z]+\\d*)");

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
                c.severity = na.group(2).toLowerCase(Locale.ROOT);
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
        if (r.mainConfig != null) r.confFiles.add(r.mainConfig);
        if (r.host == null) r.host = "(알 수 없음)";
        while (!r.section4Raw.isEmpty() && r.section4Raw.get(r.section4Raw.size() - 1).isBlank()) {
            r.section4Raw.remove(r.section4Raw.size() - 1);
        }
        return r;
    }

    /** 스크립트의 특정 문구에서 서버 정보·데이터 품질 경고를 뽑아냄. */
    private static void interpret(Report r, String section, String body) {
        if (body.startsWith("설치 폴더: ")) {
            r.binary = body.substring("설치 폴더: ".length()).trim();
        } else if (body.startsWith("버전 정보: ")) {
            r.versionLine = body.substring("버전 정보: ".length()).trim();
            Matcher v = VERSION.matcher(r.versionLine);
            if (v.find()) r.version = v.group(1);
        } else if (body.startsWith("설치 방식: ")) {
            String t = body.substring("설치 방식: ".length());
            r.installType = t.startsWith("RPM") ? "RPM" : t.startsWith("DEB") ? "DEB" : t.startsWith("Galleon") ? "Galleon" : "ZIP";
        } else if (body.startsWith("실행 모드: ")) {
            r.runMode = body.substring("실행 모드: ".length()).trim();
        } else if (body.startsWith("Java: ")) {
            r.javaVersion = body.substring("Java: ".length()).replaceAll("\\s*\\(/.*\\)$", "").trim();
        } else if (body.startsWith("구성요소(jar) 수: ")) {
            try {
                r.moduleCount = Integer.parseInt(body.substring("구성요소(jar) 수: ".length()).trim());
            } catch (NumberFormatException ignored) {
                // 형식이 다르면 무시
            }
            if (r.moduleCount != null && r.moduleCount == 0) {
                r.dataQuality.add("구성요소(jar) 수가 0입니다. modules 폴더를 읽지 못한 것으로 보이며, "
                        + "이 경우 CVE 가 모두 '미해당'으로 잘못 판정됩니다. 수동 확인이 필요합니다.");
            }
        } else if (body.startsWith("서버 IP: ")) {
            for (String ip : body.substring("서버 IP: ".length()).trim().split("\\s+")) {
                if (ip.matches("[0-9A-Fa-f:.]{2,45}")) r.ips.add(ip);
            }
        } else if (body.startsWith("메인 설정 파일: ")) {
            String c = body.substring("메인 설정 파일: ".length()).trim();
            if (c.startsWith("/")) r.mainConfig = c;
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
        } else if (body.startsWith("root 권한이 아닙니다")) {
            r.dataQuality.add("root 권한 없이 실행되어 로그/설정/프로세스 점검이 불완전할 수 있습니다.");
        } else if (body.startsWith("접근 로그 파일을 찾지 못했습니다")) {
            r.dataQuality.add("접근 로그가 없어(WildFly 기본값은 접근 로그 꺼짐) 로그 기반 침해 흔적 점검이 수행되지 않았습니다.");
        } else if (body.startsWith("배포 폴더를 찾지 못했습니다")) {
            r.dataQuality.add("배포 폴더를 찾지 못해 웹쉘 JSP 점검이 수행되지 않았습니다.");
        } else if (body.startsWith("unzip/python3 이 없어")) {
            r.dataQuality.add("unzip/python3 이 없어 압축된 배포 파일(war/ear) 안의 웹쉘 점검이 수행되지 않았습니다.");
        } else if (body.startsWith("메인 설정 파일을 읽지 못했습니다")) {
            r.dataQuality.add("메인 설정 파일을 읽지 못해 설정 점검이 불완전합니다.");
        } else if (body.startsWith("버전을 해석하지 못했습니다") || body.startsWith("WildFly 설치 폴더를 찾지 못했습니다")) {
            r.dataQuality.add("스크립트가 초기 단계에서 중단되었습니다: " + body);
        }

        if ("2".equals(section)) {
            Matcher c = CVE_LINE.matcher(body);
            if (c.find()) {
                Report.Cve cve = new Report.Cve();
                cve.id = c.group(1);
                cve.severity = c.group(2).toLowerCase(Locale.ROOT);
                cve.description = c.group(3);
                cve.affected = c.group(4).trim() + "~" + c.group(5).trim();
                cve.condition = c.group(6).trim();
                cve.advisory = c.group(7) == null ? null : c.group(7).trim();
                cve.applicable = true;
                r.cves.add(cve);
            }
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
