package com.webwas.precheck;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * 점검 스크립트가 쓰는 CVE 목록 자동 업데이트.
 *
 * 대시보드가 12시간마다 공개 취약점 DB 를 받아 스크립트와 같은 형식의 CVE 목록을 만들어 두고,
 * 에이전트는 점검할 때마다 GET /agent-api/cve/{제품} 으로 최신 목록을 받아 스크립트에 넘김(PRECHECK_CVE_DB).
 * → 웹서버/WAS 에서 인터넷이 안 돼도, 대시보드 서버만 인터넷(또는 사내 미러)에 닿으면 CVE 목록이 자동으로 최신이 됨.
 *
 *  - Apache  : https://httpd.apache.org/security/vulnerabilities-httpd.json (Apache 보안팀 공식 CVE JSON 전체)
 *              스크립트에 들어 있는 CVE(한글 설명·모듈 조건을 사람이 정리한 것)는 그대로 두고, 새 CVE 만 추가.
 *              새 CVE 의 모듈 조건은 제목·설명의 "mod_xxx" 로 추정(못 찾으면 core = 항상 해당, 보수적으로 판정)
 *  - WildFly / Tomcat : OSV(https://osv.dev) Maven 전체 데이터
 *              https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip (약 10MB, 한 번 받아 두 제품에 사용)
 *              등급은 GitHub Advisory Database 기준.
 *  주소는 -Dwebwas.precheck.cve.apache.url / -Dwebwas.precheck.cve.osv.url 로 바꿀 수 있음
 *  (file:/경로 도 가능 → 인터넷이 막힌 대시보드는 관리자가 받아 둔 파일을 지정).
 *  -Dwebwas.precheck.cve.auto=false 면 자동 업데이트를 끄고 스크립트 내장 목록만 사용.
 *
 * 받은 데이터가 이상해서(0건 등) 실패하면 이전 목록을 그대로 쓰고, 이전 목록도 없으면 스크립트 내장 목록을 내려 줌.
 * 결과는 <데이터폴더>/cve/{제품}.txt 와 {제품}.meta.properties 에 저장.
 */
public class CveFeed {
    private static final Logger LOG = Logger.getLogger(CveFeed.class.getName());
    public static final String START = "# --- CVE_DB 시작";
    public static final String END = "# --- CVE_DB 끝 ---";
    public static final String APACHE_URL = "https://httpd.apache.org/security/vulnerabilities-httpd.json";
    /**
     * httpd.apache.org 에 접속하지 못할 때 쓰는 대체 경로: Apache 웹사이트 원본 저장소(github.com/apache/httpd-site)의
     * content/security/json 폴더 목록(GitHub API) → 각 CVE JSON(raw.githubusercontent.com). 통합 JSON 이 이 폴더를 합친 것.
     * -Dwebwas.precheck.cve.apache.fallback=off 로 끔
     */
    public static final String APACHE_FALLBACK = "https://api.github.com/repos/apache/httpd-site/contents/content/security/json?ref=main";
    public static final String OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip";

    /** 스크립트 CVE 표의 한 줄 형식 (에이전트에서도 같은 정규식으로 검사) */
    static final Pattern APACHE_ROW = Pattern.compile("^CVE-\\d{4}-\\d{4,7}\\|\\d+\\.\\d+\\.\\d+\\|\\d+\\.\\d+\\.\\d+\\|[a-z]+\\|[a-z0-9_&,]+\\|[^|]*$");
    static final Pattern OSV_ROW = Pattern.compile("^CVE-\\d{4}-\\d{4,7}\\|[A-Za-z0-9-]*\\|[a-z]+\\|[A-Za-z0-9._-]+\\|[A-Za-z0-9._-]*\\|[A-Za-z0-9._-]*\\|[A-Za-z0-9._-]*\\|[A-Za-z0-9._-]*\\|[^|]*$");

    /** OSV Maven 패키지 → wildfly_precheck.sh 가 버전을 읽을 jar 이름 (tools/gen_cve_table.py 와 같은 목록) */
    static final Map<String, String> WILDFLY_PACKAGES = new LinkedHashMap<>();
    static {
        String[][] m = {
                {"io.undertow:undertow-core", "undertow-core"},
                {"io.undertow:undertow-servlet", "undertow-servlet"},
                {"org.jboss.resteasy:resteasy-core", "resteasy-core"},
                {"org.jboss.resteasy:resteasy-client", "resteasy-client"},
                {"org.jboss.resteasy:resteasy-jaxrs", "resteasy-jaxrs"},
                {"org.jboss.resteasy:resteasy-multipart-provider", "resteasy-multipart-provider"},
                {"org.jboss.remoting:jboss-remoting", "jboss-remoting"},
                {"org.jboss.xnio:xnio-api", "xnio-api"},
                {"org.jboss.xnio:xnio-nio", "xnio-nio"},
                {"org.jboss.hal:hal-console", "hal-console"},
                {"org.jboss:jboss-ejb-client", "jboss-ejb-client"},
                {"org.wildfly.core:wildfly-controller", "wildfly-controller"},
                {"org.wildfly.core:wildfly-elytron-integration", "wildfly-elytron-integration"},
                {"org.wildfly.core:wildfly-host-controller", "wildfly-host-controller"},
                {"org.wildfly.core:wildfly-server", "wildfly-server"},
                {"org.wildfly.core:wildfly-core-parent", "wildfly-server"},
                {"org.wildfly.security:wildfly-elytron", "wildfly-elytron-base"},
                {"org.wildfly.security:wildfly-elytron-http-oidc", "wildfly-elytron-http-oidc"},
                {"org.wildfly.security:wildfly-elytron-realm-token", "wildfly-elytron-realm-token"},
                {"org.wildfly:wildfly-undertow", "wildfly-undertow"},
                {"org.wildfly:wildfly-metrics", "wildfly-metrics"},
                {"org.wildfly:wildfly-domain-http", "WILDFLY"},
                {"org.wildfly:wildfly-parent", "WILDFLY"},
                {"org.wildfly:wildfly-dist", "WILDFLY"},
                {"org.wildfly.bom:wildfly", "WILDFLY"},
        };
        for (String[] e : m) WILDFLY_PACKAGES.put(e[0], e[1]);
    }

    /**
     * OSV Maven 패키지 → tomcat_precheck.sh 구성요소 이름.
     * "tomcat" = Tomcat 본체(항상 설치됨), 나머지는 lib/ 에 해당 jar 가 있을 때만 해당.
     * 단독 설치 Tomcat 은 모든 jar 버전이 Tomcat 버전과 같으므로 버전은 Tomcat 버전으로 비교.
     */
    static final Map<String, String> TOMCAT_PACKAGES = new LinkedHashMap<>();
    static {
        String[][] m = {
                {"org.apache.tomcat:tomcat", "tomcat"},
                {"org.apache.tomcat.embed:tomcat-embed-core", "tomcat"},
                {"org.apache.tomcat:tomcat-embed-core", "tomcat"},
                {"org.apache.tomcat:tomcat-catalina", "tomcat"},
                {"org.apache.tomcat:tomcat-coyote", "tomcat"},
                {"org.apache.tomcat:tomcat-util", "tomcat"},
                {"org.apache.tomcat:tomcat-juli", "tomcat"},
                {"org.apache.tomcat:tomcat-servlet-api", "tomcat"},
                {"org.apache.tomcat:tomcat-jasper", "tomcat-jasper"},
                {"org.apache.tomcat.embed:tomcat-embed-jasper", "tomcat-jasper"},
                {"org.apache.tomcat:tomcat-websocket", "tomcat-websocket"},
                {"org.apache.tomcat.embed:tomcat-embed-websocket", "tomcat-websocket"},
                {"org.apache.tomcat:tomcat-tribes", "tomcat-tribes"},
                {"org.apache.tomcat:tomcat-catalina-jmx-remote", "tomcat-catalina-jmx-remote"},
                {"org.apache.tomcat:tomcat-coyote-ffm", "tomcat-coyote-ffm"},
        };
        for (String[] e : m) TOMCAT_PACKAGES.put(e[0], e[1]);
    }

    /** 제품 1개의 CVE 목록 상태 */
    static final class State {
        String embeddedRows = "";    // 스크립트에 들어 있는 CVE 표
        String embeddedNote = "";    // 스크립트 머리말의 기준일
        String generatedRows;        // 자동 생성 목록 (없으면 null)
        long generatedAt;
        String source;
        int addedCves;               // 스크립트 내장 목록에 없던 CVE 수
        long checkedAt;
        String error;
    }

    private final Path dir;
    private final boolean auto;
    private final String apacheUrl;
    private final String apacheFallback;
    private final String osvUrl;
    private final Map<Product, State> states = new EnumMap<>(Product.class);

    public CveFeed(Path dir, Map<Product, String> scripts) throws IOException {
        this.dir = dir;
        Files.createDirectories(dir);
        this.auto = !"false".equalsIgnoreCase(System.getProperty("webwas.precheck.cve.auto"));
        this.apacheUrl = prop("webwas.precheck.cve.apache.url", APACHE_URL);
        this.apacheFallback = prop("webwas.precheck.cve.apache.fallback", APACHE_FALLBACK);
        this.osvUrl = prop("webwas.precheck.cve.osv.url", OSV_URL);
        for (Product p : Product.values()) {
            State s = new State();
            String script = scripts.get(p);
            if (script != null) {
                s.embeddedRows = String.join("\n", rowsOf(script, p));
                Matcher m = Pattern.compile("\\((\\d{4}-\\d{2}-\\d{2})[^)]*(?:기준|내려받음)").matcher(script);
                if (m.find()) s.embeddedNote = m.group(1);
            }
            load(p, s);
            states.put(p, s);
        }
    }

    private static String prop(String k, String def) {
        String v = System.getProperty(k);
        return v == null || v.isBlank() ? def : v.trim();
    }

    /** 스크립트(또는 생성 파일)의 시작~끝 표시 사이에서 형식에 맞는 CVE 줄만 */
    static List<String> rowsOf(String text, Product p) {
        List<String> out = new ArrayList<>();
        int a = text.indexOf(START), b = text.indexOf(END, Math.max(a, 0));
        if (a < 0 || b < 0) return out;
        Pattern row = p == Product.APACHE ? APACHE_ROW : OSV_ROW;
        for (String line : text.substring(a, b).split("\\r?\\n")) {
            if (row.matcher(line).matches()) out.add(line);
        }
        return out;
    }

    private static int cveCount(String rows) {
        Set<String> s = new HashSet<>();
        for (String line : rows.split("\n")) if (line.startsWith("CVE-")) s.add(line.substring(0, line.indexOf('|')));
        return s.size();
    }

    /**
     * 에이전트에 내려 줄 CVE 목록 (스크립트 형식). latest 는 "# LATEST=" 줄로 넣어
     * 스크립트의 최신 버전 기준값(2.4.69 등)도 대시보드 기준으로 맞춤.
     */
    public synchronized String dbText(Product p, String latest) {
        State s = states.get(p);
        boolean gen = s.generatedRows != null;
        String rows = gen ? s.generatedRows : s.embeddedRows;
        StringBuilder sb = new StringBuilder();
        sb.append("# webwas-precheck CVE 목록 (").append(p.label).append(")\n");
        sb.append("# GENERATED=").append(gen ? fmt(s.generatedAt) : "스크립트 내장본 " + s.embeddedNote).append('\n');
        sb.append("# SOURCE=").append(gen ? s.source : p.script).append('\n');
        if (latest != null) sb.append("# LATEST=").append(latest).append('\n');
        sb.append("# COUNT=").append(cveCount(rows)).append('\n');
        sb.append(START).append(" (대시보드 자동 생성) ---\n");
        sb.append(rows).append('\n');
        sb.append(END).append('\n');
        return sb.toString();
    }

    public synchronized Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("auto", auto);
        m.put("running", running.get());
        Map<String, Object> ps = new LinkedHashMap<>();
        for (Map.Entry<Product, State> e : states.entrySet()) {
            State s = e.getValue();
            Map<String, Object> x = new LinkedHashMap<>();
            x.put("label", e.getKey().label);
            x.put("using", s.generatedRows != null ? "generated" : "embedded");
            x.put("generatedAt", s.generatedAt);
            x.put("source", s.generatedRows != null ? s.source : (e.getKey() == Product.APACHE ? apacheUrl : osvUrl));
            x.put("cveCount", cveCount(s.generatedRows != null ? s.generatedRows : s.embeddedRows));
            x.put("embeddedCount", cveCount(s.embeddedRows));
            x.put("embeddedNote", s.embeddedNote);
            x.put("addedCves", s.addedCves);
            x.put("checkedAt", s.checkedAt);
            x.put("error", s.error);
            ps.put(e.getKey().id, x);
        }
        m.put("products", ps);
        return m;
    }

    /** 세 제품 모두 갱신 (자동 업데이트가 꺼져 있으면 아무것도 안 함) */
    public void refreshAll() {
        if (!auto || !running.compareAndSet(false, true)) return; // 이미 갱신 중이면 건너뜀
        try {
            refreshApache();
            refreshOsv();
        } finally {
            running.set(false);
        }
    }

    public boolean running() {
        return running.get();
    }

    private final java.util.concurrent.atomic.AtomicBoolean running = new java.util.concurrent.atomic.AtomicBoolean();

    public void refreshApache() {
        String err = null;
        try {
            Object json = JsonParser.parse(Fetch.text(apacheUrl));
            List<String> feedRows = apacheRows(json);
            if (feedRows.isEmpty()) throw new IOException("Apache CVE 를 하나도 찾지 못함");
            store(Product.APACHE, mergeApache(rowsOfText(states.get(Product.APACHE).embeddedRows), feedRows), apacheUrl);
        } catch (IOException | IllegalArgumentException e) {
            err = e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            fail(Product.APACHE, "중단됨");
            return;
        }
        if (err != null && !"off".equalsIgnoreCase(apacheFallback)) {
            String first = err;
            try {
                List<String> feedRows = apacheRows(fetchApacheFolder(apacheFallback));
                if (feedRows.isEmpty()) throw new IOException("대체 경로에서도 Apache CVE 를 찾지 못함");
                store(Product.APACHE, mergeApache(rowsOfText(states.get(Product.APACHE).embeddedRows), feedRows),
                        "github.com/apache/httpd-site (대체 경로)");
                LOG.info("[webwas-precheck] Apache CVE: 기본 주소 실패(" + first + ") → GitHub 대체 경로로 갱신");
                err = null;
            } catch (IOException | IllegalArgumentException e) {
                err = first + " / 대체 경로(GitHub)도 실패: " + e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                err = "중단됨";
            }
        }
        fail(Product.APACHE, err);
    }

    /**
     * 폴더 목록(GitHub contents API 형식: [{name, download_url}]) → CVE-*.json 을 하나씩 받아 배열로.
     * 받은 주소가 목록과 같은 호스트 또는 raw.githubusercontent.com 일 때만 받음 (목록이 엉뚱한 곳을 가리키지 않도록)
     */
    static List<Object> fetchApacheFolder(String listUrl) throws IOException, InterruptedException {
        Object list = JsonParser.parse(Fetch.text(listUrl));
        if (!(list instanceof List<?> items)) throw new IOException("폴더 목록 형식이 아님");
        java.net.URI base = java.net.URI.create(listUrl);
        List<Object> out = new ArrayList<>();
        for (Object it : items) {
            String name = JsonParser.str(it, "name"), url = JsonParser.str(it, "download_url");
            if (name == null || url == null || !name.matches("CVE-\\d{4}-\\d{4,7}\\.json")) continue;
            java.net.URI u = base.resolve(url);
            boolean okHost = "raw.githubusercontent.com".equalsIgnoreCase(u.getHost())
                    || (u.getScheme() != null && u.getScheme().equals(base.getScheme()) && java.util.Objects.equals(u.getHost(), base.getHost()));
            if (!okHost) continue;
            if (out.size() >= 5000) break;
            out.add(JsonParser.parse(Fetch.text(u.toString())));
        }
        if (out.isEmpty()) throw new IOException("폴더 목록에 CVE JSON 이 없음");
        return out;
    }

    public void refreshOsv() {
        String err = null;
        try {
            Map<Product, List<String>> rows = osvRows(Fetch.bytes(osvUrl, Duration.ofMinutes(5)));
            for (Product p : List.of(Product.WILDFLY, Product.TOMCAT)) {
                List<String> feed = rows.get(p);
                if (feed.isEmpty()) {
                    fail(p, "OSV 데이터에서 " + p.label + " CVE 를 하나도 찾지 못함");
                    continue;
                }
                store(p, mergeOsv(rowsOfText(states.get(p).embeddedRows), feed), osvUrl);
                fail(p, null);
            }
            return;
        } catch (IOException | IllegalArgumentException e) {
            err = e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            err = "중단됨";
        }
        fail(Product.WILDFLY, err);
        fail(Product.TOMCAT, err);
    }

    private static List<String> rowsOfText(String rows) {
        List<String> out = new ArrayList<>();
        for (String l : rows.split("\n")) if (l.startsWith("CVE-")) out.add(l);
        return out;
    }

    private synchronized void fail(Product p, String err) {
        State s = states.get(p);
        s.checkedAt = System.currentTimeMillis();
        s.error = err;
        if (err != null) LOG.warning("[webwas-precheck] " + p.label + " CVE 목록 자동 업데이트 실패: " + err);
        saveMetaQuietly(p, s);
    }

    private synchronized void store(Product p, List<String> rows, String source) throws IOException {
        State s = states.get(p);
        Set<String> before = new HashSet<>();
        for (String l : rowsOfText(s.embeddedRows)) before.add(l.substring(0, l.indexOf('|')));
        Set<String> now = new TreeSet<>();
        for (String l : rows) now.add(l.substring(0, l.indexOf('|')));
        now.removeAll(before);
        int prev = s.generatedRows == null ? -1 : cveCount(s.generatedRows);
        s.generatedRows = String.join("\n", rows);
        s.generatedAt = System.currentTimeMillis();
        s.source = source;
        s.addedCves = now.size();
        Path tmp = Files.createTempFile(dir, ".cve", ".tmp");
        Files.writeString(tmp, START + " ---\n" + s.generatedRows + "\n" + END + "\n", StandardCharsets.UTF_8);
        Files.move(tmp, dir.resolve(p.id + ".txt"), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        int cur = cveCount(s.generatedRows);
        if (prev >= 0 && prev != cur) LOG.warning("[webwas-precheck] " + p.label + " CVE 목록 변경: " + prev + "건 → " + cur + "건");
        else if (prev < 0) LOG.info("[webwas-precheck] " + p.label + " CVE 목록 생성: " + cur + "건 (스크립트 내장 목록 대비 추가 " + s.addedCves + "건)");
    }

    // ------------------------------------------------------------------ Apache

    /** Apache 보안 JSON(배열 또는 객체 1개) → 스크립트 줄 "CVE|최소|최대|등급|조건|설명" (2.4.x 영향 CVE 만) */
    static List<String> apacheRows(Object json) {
        List<Object> items = json instanceof List<?> l ? new ArrayList<>(l) : List.of(json);
        Map<String, String> out = new LinkedHashMap<>();
        for (Object o : items) {
            String row = apacheRow(o);
            if (row != null) out.putIfAbsent(row.substring(0, row.indexOf('|')), row);
        }
        List<String> rows = new ArrayList<>(out.values());
        rows.sort(Comparator.comparing((String r) -> r.split("\\|")[2], ReportParser::compareVersions)
                .thenComparing(r -> r.substring(0, r.indexOf('|'))));
        return rows;
    }

    private static String apacheRow(Object o) {
        String id, title, desc, impact;
        String min = null, max = null;
        Map<String, Object> cna = JsonParser.obj(JsonParser.obj(o, "containers"), "cna");
        if (cna != null) { // CVE JSON 5.x
            id = JsonParser.str(JsonParser.obj(o, "cveMetadata"), "cveId");
            if (id == null) id = JsonParser.str(o, "id");
            title = JsonParser.str(cna, "title");
            desc = firstValue(JsonParser.arr(cna, "descriptions"));
            impact = null;
            for (Object mt : JsonParser.arr(cna, "metrics")) {
                String t = JsonParser.str(JsonParser.obj(JsonParser.obj(mt, "other"), "content"), "text");
                if (t != null) impact = t;
            }
            for (Object a : JsonParser.arr(cna, "affected")) {
                String product = JsonParser.str(a, "product");
                if (product != null && !product.contains("HTTP Server")) continue;
                for (Object v : JsonParser.arr(a, "versions")) {
                    if (!"affected".equals(JsonParser.str(v, "status"))) continue;
                    String start = JsonParser.str(v, "version");
                    String lo = start == null || start.equals("0") || start.equals("*") ? "2.4.0" : start;
                    String hi;
                    if (JsonParser.str(v, "lessThanOrEqual") != null) hi = JsonParser.str(v, "lessThanOrEqual");
                    else if (JsonParser.str(v, "lessThan") != null) hi = prev(JsonParser.str(v, "lessThan"));
                    else hi = start;
                    String[] r = clamp24(lo, hi);
                    if (r == null) continue;
                    min = min == null || ReportParser.compareVersions(r[0], min) < 0 ? r[0] : min;
                    max = max == null || ReportParser.compareVersions(r[1], max) > 0 ? r[1] : max;
                }
            }
        } else { // CVE JSON 4.0 (오래된 CVE)
            Map<String, Object> meta = JsonParser.obj(o, "CVE_data_meta");
            if (meta == null) return null;
            id = JsonParser.str(meta, "ID");
            title = JsonParser.str(meta, "TITLE");
            desc = firstValue(JsonParser.arr(JsonParser.obj(o, "description"), "description_data"));
            impact = null;
            for (Object im : JsonParser.arr(o, "impact")) {
                if (JsonParser.str(im, "other") != null) impact = JsonParser.str(im, "other");
            }
            List<String> lows = new ArrayList<>(), highs = new ArrayList<>();
            for (Object vd : JsonParser.arr(JsonParser.obj(JsonParser.obj(o, "affects"), "vendor"), "vendor_data")) {
                for (Object pd : JsonParser.arr(JsonParser.obj(vd, "product"), "product_data")) {
                    for (Object v : JsonParser.arr(JsonParser.obj(pd, "version"), "version_data")) {
                        String op = JsonParser.str(v, "version_affected");
                        String val = JsonParser.str(v, "version_value");
                        if (op == null || val == null || !val.matches("\\d+\\.\\d+\\.\\d+")) continue;
                        switch (op) {
                            case "=", "?=" -> { lows.add(val); highs.add(val); }
                            case "<=" -> highs.add(val);
                            case "<" -> { String p = prev(val); if (p != null) highs.add(p); }
                            case "!<", ">=" -> lows.add(val);
                            default -> { }
                        }
                    }
                }
            }
            String lo = lows.stream().filter(x -> x.startsWith("2.4.")).min(ReportParser::compareVersions).orElse("2.4.0");
            String hi = highs.stream().filter(x -> x.startsWith("2.4.")).max(ReportParser::compareVersions).orElse(null);
            if (hi != null) {
                String[] r = clamp24(lo, hi);
                if (r != null) { min = r[0]; max = r[1]; }
            }
        }
        if (id == null || !id.matches("CVE-\\d{4}-\\d{4,7}") || min == null) return null;
        String sev = impact == null ? "moderate" : impact.trim().toLowerCase(Locale.ROOT);
        if (!sev.matches("critical|important|moderate|low")) sev = sev.equals("high") ? "important" : "moderate";
        String text = (title == null ? "" : title) + " " + (desc == null ? "" : desc);
        return id + "|" + min + "|" + max + "|" + sev + "|" + moduleCondition(text) + "|" + clean(title != null ? title : desc);
    }

    private static String firstValue(List<Object> list) {
        for (Object d : list) {
            String v = JsonParser.str(d, "value");
            if (v != null) return v;
        }
        return null;
    }

    /** 2.4.x 와 겹치는 구간만 [최소, 최대] 로. 겹치지 않으면 null */
    private static String[] clamp24(String lo, String hi) {
        if (lo == null || hi == null || !hi.matches("2\\.4\\.\\d+")) return null;
        if (!lo.matches("\\d+\\.\\d+\\.\\d+") || ReportParser.compareVersions(lo, "2.4.0") < 0) lo = "2.4.0";
        if (!lo.startsWith("2.4.") || ReportParser.compareVersions(lo, hi) > 0) return null;
        return new String[] {lo, hi};
    }

    /** "2.4.60" → "2.4.59" (lessThan 을 '이하'로 바꿀 때). 마지막 자리가 0이면 null */
    static String prev(String v) {
        if (v == null || !v.matches("\\d+\\.\\d+\\.\\d+")) return null;
        String[] t = v.split("\\.");
        int last = Integer.parseInt(t[2]);
        return last == 0 ? null : t[0] + "." + t[1] + "." + (last - 1);
    }

    private static final Pattern MOD = Pattern.compile("\\bmod_([a-z0-9_]+)");

    /**
     * 새 CVE 의 모듈 조건 추정. 제목·설명에 나온 mod_xxx → xxx_module (여러 개면 "또는").
     * 못 찾으면 core(항상 해당) — 놓치는 것보다 과하게 잡는 쪽을 택함.
     */
    static String moduleCondition(String text) {
        String t = text.toLowerCase(Locale.ROOT);
        Set<String> mods = new LinkedHashSet<>();
        Matcher m = MOD.matcher(t);
        while (m.find() && mods.size() < 3) {
            String name = m.group(1).replaceAll("_+$", "");
            if (!name.isEmpty()) mods.add(name + "_module");
        }
        if (mods.isEmpty() && (t.contains("http/2") || t.contains("http2"))) mods.add("http2_module");
        if (mods.isEmpty() && t.contains("ajp")) mods.add("proxy_ajp_module");
        return mods.isEmpty() ? "core" : String.join(",", mods);
    }

    private static String clean(String s) {
        if (s == null) return "";
        String c = s.replace('|', '/').replaceAll("[\\r\\n\\t]+", " ").replaceAll("\\s{2,}", " ").trim();
        return c.length() > 150 ? c.substring(0, 150) : c;
    }

    /** 사람이 정리한 내장 목록(한글 설명·모듈 조건)을 우선, 자동 목록에서는 새 CVE 만 추가 */
    static List<String> mergeApache(List<String> curated, List<String> feed) {
        Set<String> known = new HashSet<>();
        List<String> out = new ArrayList<>(curated);
        for (String r : curated) known.add(r.substring(0, r.indexOf('|')));
        for (String r : feed) {
            if (known.add(r.substring(0, r.indexOf('|')))) out.add(r);
        }
        return out;
    }

    // ------------------------------------------------------------------ OSV (WildFly / Tomcat)

    /** OSV Maven all.zip → 제품별 스크립트 줄 "CVE|권고ID|등급|구성요소|groupId|시작|수정|마지막영향|설명" */
    static Map<Product, List<String>> osvRows(byte[] zip) throws IOException {
        Map<Product, Set<String>> rows = new EnumMap<>(Product.class);
        rows.put(Product.WILDFLY, new TreeSet<>(OSV_ORDER));
        rows.put(Product.TOMCAT, new TreeSet<>(OSV_ORDER));
        try (ZipInputStream zin = new ZipInputStream(new ByteArrayInputStream(zip))) {
            ZipEntry e;
            int entries = 0;
            while ((e = zin.getNextEntry()) != null) {
                if (e.isDirectory() || !e.getName().endsWith(".json")) continue;
                if (++entries > 500_000) throw new IOException("zip 항목이 너무 많습니다");
                byte[] b = zin.readNBytes(5 * 1024 * 1024);
                String text = new String(b, StandardCharsets.UTF_8);
                // 빠른 거르기: 관심 있는 패키지 이름이 없으면 JSON 해석 안 함
                if (!text.contains("org.apache.tomcat") && !text.contains("wildfly") && !text.contains("undertow")
                        && !text.contains("org.jboss")) continue;
                osvAdvisory(JsonParser.parse(text), rows);
            }
            if (entries == 0) throw new IOException("zip 안에 JSON 파일이 없습니다 (OSV Maven all.zip 이 맞는지 확인)");
        }
        Map<Product, List<String>> out = new EnumMap<>(Product.class);
        rows.forEach((p, s) -> out.put(p, new ArrayList<>(s)));
        return out;
    }

    /** 구성요소 → CVE → 시작버전 순 (스크립트가 앞에서부터 읽음) */
    private static final Comparator<String> OSV_ORDER = Comparator
            .comparing((String r) -> r.split("\\|", -1)[3])
            .thenComparing(r -> r.split("\\|", -1)[0])
            .thenComparing(r -> r.split("\\|", -1)[5])
            .thenComparing(Comparator.naturalOrder());

    private static void osvAdvisory(Object d, Map<Product, Set<String>> rows) {
        if (JsonParser.str(d, "withdrawn") != null) return;
        String cve = null;
        for (Object a : JsonParser.arr(d, "aliases")) {
            if (a instanceof String s && s.matches("CVE-\\d{4}-\\d{4,7}")) {
                cve = s;
                break;
            }
        }
        String id = JsonParser.str(d, "id");
        if (cve == null && id != null && id.matches("CVE-\\d{4}-\\d{4,7}")) cve = id;
        if (cve == null || id == null || !id.matches("[A-Za-z0-9-]{1,40}")) return;
        String sevRaw = JsonParser.str(JsonParser.obj(d, "database_specific"), "severity");
        String sev = switch (sevRaw == null ? "" : sevRaw.toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> "critical";
            case "HIGH" -> "high";
            case "LOW" -> "low";
            default -> "moderate";
        };
        String summary = JsonParser.str(d, "summary");
        if (summary == null) {
            String det = JsonParser.str(d, "details");
            summary = det == null ? "" : det.split("\n")[0];
        }
        summary = clean(summary);
        for (Object a : JsonParser.arr(d, "affected")) {
            String pkg = JsonParser.str(JsonParser.obj(a, "package"), "name");
            if (pkg == null) continue;
            Product product;
            String comp, group;
            if (WILDFLY_PACKAGES.containsKey(pkg)) {
                product = Product.WILDFLY;
                comp = WILDFLY_PACKAGES.get(pkg);
                group = comp.equals("WILDFLY") ? "" : pkg.split(":")[0];
            } else if (TOMCAT_PACKAGES.containsKey(pkg)) {
                product = Product.TOMCAT;
                comp = TOMCAT_PACKAGES.get(pkg);
                group = "";
            } else {
                continue;
            }
            for (Object r : JsonParser.arr(a, "ranges")) {
                if (!"ECOSYSTEM".equals(JsonParser.str(r, "type"))) continue;
                String intro = null;
                for (Object ev : JsonParser.arr(r, "events")) {
                    String in = JsonParser.str(ev, "introduced"), fx = JsonParser.str(ev, "fixed"), la = JsonParser.str(ev, "last_affected");
                    if (in != null) {
                        intro = in;
                    } else if (fx != null) {
                        add(rows, product, cve, id, sev, comp, group, intro, fx, "", summary);
                        intro = null;
                    } else if (la != null) {
                        add(rows, product, cve, id, sev, comp, group, intro, "", la, summary);
                        intro = null;
                    }
                }
                if (intro != null) add(rows, product, cve, id, sev, comp, group, intro, "", "", summary);
            }
        }
    }

    private static final Pattern VER_TOKEN = Pattern.compile("^[A-Za-z0-9._-]{0,60}$");

    private static void add(Map<Product, Set<String>> rows, Product p, String cve, String id, String sev, String comp,
                            String group, String intro, String fixed, String last, String summary) {
        String in = intro == null ? "0" : intro;
        if (!VER_TOKEN.matcher(in).matches() || !VER_TOKEN.matcher(fixed).matches() || !VER_TOKEN.matcher(last).matches()) return;
        String row = String.join("|", cve, id, sev, comp, group, in, fixed, last, summary);
        if (OSV_ROW.matcher(row).matches()) rows.get(p).add(row);
    }

    /** 자동 목록 우선. 내장 목록은 자동 목록에 없는 CVE 만 남김 */
    static List<String> mergeOsv(List<String> embedded, List<String> feed) {
        Set<String> feedCves = new HashSet<>();
        for (String r : feed) feedCves.add(r.substring(0, r.indexOf('|')));
        Set<String> out = new TreeSet<>(OSV_ORDER);
        out.addAll(feed);
        for (String r : embedded) if (!feedCves.contains(r.substring(0, r.indexOf('|')))) out.add(r);
        return new ArrayList<>(out);
    }

    // ------------------------------------------------------------------ 저장

    private static String fmt(long t) {
        return t == 0 ? "-" : LocalDateTime.ofInstant(java.time.Instant.ofEpochMilli(t), java.time.ZoneId.systemDefault())
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"));
    }

    private void load(Product p, State s) throws IOException {
        Path f = dir.resolve(p.id + ".txt");
        if (Files.exists(f)) {
            List<String> rows = rowsOf(Files.readString(f, StandardCharsets.UTF_8), p);
            if (!rows.isEmpty()) s.generatedRows = String.join("\n", rows);
        }
        Path m = dir.resolve(p.id + ".meta.properties");
        if (Files.exists(m)) {
            Properties pr = new Properties();
            try (Reader r = Files.newBufferedReader(m, StandardCharsets.UTF_8)) {
                pr.load(r);
            }
            s.generatedAt = num(pr.getProperty("generatedAt"));
            s.source = pr.getProperty("source");
            s.addedCves = (int) num(pr.getProperty("addedCves"));
            s.checkedAt = num(pr.getProperty("checkedAt"));
            s.error = pr.getProperty("error");
        }
        if (s.generatedRows != null && s.generatedAt == 0) s.generatedAt = Files.getLastModifiedTime(f).toMillis();
    }

    private static long num(String v) {
        try {
            return v == null ? 0 : Long.parseLong(v);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private void saveMetaQuietly(Product p, State s) {
        try {
            Properties pr = new Properties();
            pr.setProperty("generatedAt", String.valueOf(s.generatedAt));
            if (s.source != null) pr.setProperty("source", s.source);
            pr.setProperty("addedCves", String.valueOf(s.addedCves));
            pr.setProperty("checkedAt", String.valueOf(s.checkedAt));
            if (s.error != null) pr.setProperty("error", s.error);
            Path tmp = Files.createTempFile(dir, ".meta", ".tmp");
            try (Writer w = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
                pr.store(w, "webwas-precheck: " + p.label + " CVE feed status");
            }
            Files.move(tmp, dir.resolve(p.id + ".meta.properties"), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            LOG.warning("[webwas-precheck] CVE 목록 상태 저장 실패: " + e.getMessage());
        }
    }
}
