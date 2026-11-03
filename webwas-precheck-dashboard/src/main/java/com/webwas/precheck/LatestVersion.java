package com.webwas.precheck;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 제품 1개의 최신 버전 확인.
 *
 * - 자동(12시간마다, LatestVersions 가 호출)
 *   Apache  : https://downloads.apache.org/httpd/ 의 "httpd-2.4.N.tar.gz" 중 가장 높은 번호
 *   WildFly : https://repo1.maven.org/maven2/org/wildfly/wildfly-dist/maven-metadata.xml 의 "N.N.N.Final" 중 가장 높은 번호
 *   Tomcat  : https://downloads.apache.org/tomcat/ 의 tomcat-N/ 폴더 → 각 폴더의 vX.Y.Z/ 중 브랜치(X.Y)별 가장 높은 번호
 *             (ASF 공식 배포 서버에는 지원 중인 브랜치만 올라와 있으므로, 여기에 없는 브랜치는 "지원 종료"로 봄)
 *   주소는 -Dwebwas.precheck.latest.<제품>.url 로 바꿀 수 있음 (사내 미러를 쓸 때)
 * - 수동: 인터넷이 막힌 환경을 위해 관리자가 직접 지정 (Tomcat 은 "11.0.27, 10.1.61, 9.0.123" 처럼 브랜치별로)
 * - 둘 다 실패하면 점검 스크립트의 기준 버전(scriptBaseline)을 사용
 * 결과는 <데이터폴더>/latest-version-<제품>.properties 에 저장되어 재시작 후에도 유지됨.
 */
public class LatestVersion {
    private static final Logger LOG = Logger.getLogger(LatestVersion.class.getName());

    private static final Pattern APACHE_TARBALL = Pattern.compile("httpd-(2\\.4\\.\\d{1,3})\\.tar\\.(?:gz|bz2)");
    private static final Pattern APACHE_VERSION = Pattern.compile("^2\\.4\\.\\d{1,3}$");
    private static final Pattern WILDFLY_META = Pattern.compile("<version>\\s*(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.Final)\\s*</version>");
    private static final Pattern WILDFLY_VERSION = Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.Final$");
    private static final Pattern TOMCAT_DIR = Pattern.compile("href=\"(tomcat-\\d{1,2})/\"");
    private static final Pattern TOMCAT_RELEASE = Pattern.compile("href=\"v(\\d{1,2}\\.\\d{1,2}\\.\\d{1,3})/\"");
    private static final Pattern TOMCAT_META = Pattern.compile("<version>\\s*(\\d{1,2}\\.\\d{1,2}\\.\\d{1,3})\\s*</version>");
    private static final Pattern TOMCAT_ONE = Pattern.compile("^\\d{1,2}\\.\\d{1,2}\\.\\d{1,3}$");

    public final Product product;
    private final Path file;
    private final String url;
    private final String scriptBaseline;

    private String mode = "auto";          // auto | manual
    private String manualVersion;
    private String autoVersion;            // 마지막으로 자동 확인에 성공한 버전
    private long autoCheckedAt;            // 마지막 자동 확인 시도 시각
    private long autoSuccessAt;            // 마지막 자동 확인 성공 시각
    private String autoError;              // 마지막 자동 확인 실패 사유 (성공 시 null)

    public LatestVersion(Product product, Path file, String url, String scriptBaseline) throws IOException {
        this.product = product;
        this.file = file;
        this.url = url == null || url.isBlank() ? defaultUrl(product) : url;
        this.scriptBaseline = scriptBaseline == null ? null : normalize(product, scriptBaseline);
        load();
    }

    public static String defaultUrl(Product p) {
        return switch (p) {
            case APACHE -> "https://downloads.apache.org/httpd/";
            case WILDFLY -> "https://repo1.maven.org/maven2/org/wildfly/wildfly-dist/maven-metadata.xml";
            case TOMCAT -> "https://downloads.apache.org/tomcat/";
        };
    }

    /** 스크립트 기준값도 못 읽었을 때 쓰는 값 (2026-11-03 공식 배포 목록 기준) */
    public static String fallback(Product p) {
        return switch (p) {
            case APACHE -> "2.4.69";
            case WILDFLY -> "41.0.1.Final";
            case TOMCAT -> "11.0.27,10.1.61,9.0.123";
        };
    }

    public static String example(Product p) {
        return switch (p) {
            case APACHE -> "2.4.69";
            case WILDFLY -> "41.0.1.Final";
            case TOMCAT -> "11.0.27, 10.1.61, 9.0.123";
        };
    }

    /** Tomcat "11.0.27 10.1.61, 9.0.123" → "11.0.27,10.1.61,9.0.123" (브랜치별 최고 버전, 높은 브랜치 먼저). 다른 제품은 공백 제거만 */
    static String normalize(Product p, String v) {
        if (v == null) return null;
        if (p != Product.TOMCAT) return v.trim();
        Map<String, String> best = new TreeMap<>((a, b) -> ReportParser.compareVersions(b, a));
        for (String one : v.trim().split("[,\\s/]+")) {
            if (!TOMCAT_ONE.matcher(one).matches()) return null;
            String br = branch(one);
            if (!best.containsKey(br) || ReportParser.compareVersions(one, best.get(br)) > 0) best.put(br, one);
        }
        return best.isEmpty() ? null : String.join(",", best.values());
    }

    public static boolean validVersion(Product p, String v) {
        if (v == null) return false;
        return switch (p) {
            case APACHE -> APACHE_VERSION.matcher(v.trim()).matches();
            case WILDFLY -> WILDFLY_VERSION.matcher(v.trim()).matches();
            case TOMCAT -> normalize(p, v) != null;
        };
    }

    /** "9.0.85" → "9.0", "11.0.0-M5" → "11.0" */
    static String branch(String v) {
        String[] t = v.split("[.-]");
        return t.length >= 2 ? t[0] + "." + t[1] : v;
    }

    /** 배포 목록(HTML/XML)에서 가장 높은 버전 추출. 없으면 null. (Tomcat 은 parseTomcatVersions 사용) */
    public static String parseListing(Product p, String body) {
        Pattern pat = p == Product.APACHE ? APACHE_TARBALL : WILDFLY_META;
        String best = null;
        Matcher m = pat.matcher(body == null ? "" : body);
        while (m.find()) {
            String v = m.group(1);
            if (best == null || ReportParser.compareVersions(v, best) > 0) best = v;
        }
        return best;
    }

    /** Tomcat 버전 목록에서 브랜치별 최고 버전 (예: "11.0.27,10.1.61,9.0.123") */
    static String bestPerBranch(List<String> versions, int keepMajors) {
        Map<String, String> best = new TreeMap<>((a, b) -> ReportParser.compareVersions(b, a));
        for (String v : versions) {
            String br = branch(v);
            if (!best.containsKey(br) || ReportParser.compareVersions(v, best.get(br)) > 0) best.put(br, v);
        }
        // 메이저 버전마다 가장 높은 브랜치 하나만 (10.0 은 EOL, 10.1 만 지원)
        Map<String, String> perMajor = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : best.entrySet()) {
            String major = e.getKey().split("\\.")[0];
            perMajor.putIfAbsent(major, e.getValue());
        }
        List<String> out = new ArrayList<>(perMajor.values());
        if (keepMajors > 0 && out.size() > keepMajors) out = out.subList(0, keepMajors);
        return out.isEmpty() ? null : String.join(",", out);
    }

    /** 지금 판정에 쓰는 "최신 버전" (Tomcat 은 "11.0.27,10.1.61,9.0.123") */
    public synchronized String current() {
        if ("manual".equals(mode) && manualVersion != null) return manualVersion;
        if (autoVersion != null) {
            if (scriptBaseline == null) return autoVersion;
            if (product == Product.TOMCAT) {
                // 자동 확인한 브랜치 목록을 기준으로, 브랜치마다 스크립트 기준값과 높은 쪽
                List<String> out = new ArrayList<>();
                for (String v : autoVersion.split(",")) {
                    String b = baselineFor(v);
                    out.add(b != null && ReportParser.compareVersions(b, v) > 0 ? b : v);
                }
                return String.join(",", out);
            }
            // 목록이 비정상이라 스크립트 기준보다 낮게 나오면 스크립트 기준을 사용
            return ReportParser.compareVersions(autoVersion, scriptBaseline) < 0 ? scriptBaseline : autoVersion;
        }
        return scriptBaseline != null ? scriptBaseline : fallback(product);
    }

    private String baselineFor(String v) {
        if (scriptBaseline == null) return null;
        for (String b : scriptBaseline.split(",")) {
            if (branch(b).equals(branch(v))) return b;
        }
        return null;
    }

    /** 화면 표시용 (Tomcat 은 "11.0.27 / 10.1.61 / 9.0.123") */
    public String display() {
        return current().replace(",", " / ");
    }

    /**
     * version 과 비교할 최신 버전. Tomcat 은 같은 브랜치의 최신 버전이며, 지원 브랜치가 아니면 null.
     * 버전을 모르면 null.
     */
    public String latestFor(String version) {
        if (version == null) return null;
        String cur = current();
        if (product != Product.TOMCAT) return cur;
        String br = branch(version);
        for (String v : cur.split(",")) {
            if (branch(v).equals(br)) return v;
        }
        return null;
    }

    /** Tomcat 지원 브랜치가 아닌가 (다른 제품은 항상 false) */
    public boolean unsupportedBranch(String version) {
        return product == Product.TOMCAT && version != null && latestFor(version) == null;
    }

    /** 최신 미만인가 (버전을 모르면 false). Tomcat 지원 종료 브랜치는 항상 true */
    public boolean below(String version) {
        if (version == null) return false;
        String l = latestFor(version);
        if (l == null) return product == Product.TOMCAT;
        return ReportParser.compareVersions(version, l) < 0;
    }

    /** version 이 최신 이상인가 (버전을 모르면 false) */
    public boolean isUpToDate(String version) {
        return version != null && !below(version);
    }

    /** 현재 값이 어디서 왔는지: manual | auto | baseline */
    public synchronized String origin() {
        if ("manual".equals(mode) && manualVersion != null) return "manual";
        if (autoVersion != null) return "auto";
        return "baseline";
    }

    public synchronized Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("product", product.id);
        m.put("label", product.label);
        m.put("version", current());
        m.put("display", display());
        m.put("origin", origin());
        m.put("mode", mode);
        m.put("manualVersion", manualVersion);
        m.put("autoVersion", autoVersion);
        m.put("autoCheckedAt", autoCheckedAt);
        m.put("autoSuccessAt", autoSuccessAt);
        m.put("autoError", autoError);
        m.put("source", url);
        m.put("scriptBaseline", scriptBaseline);
        m.put("example", example(product));
        boolean newer = false;
        if (scriptBaseline != null) {
            for (String v : current().split(",")) {
                String b = product == Product.TOMCAT ? baselineFor(v) : scriptBaseline;
                if (b == null || ReportParser.compareVersions(v, b) > 0) newer = true;
            }
        }
        m.put("newerThanScript", newer);
        return m;
    }

    /** 공식 배포 목록에서 최신 버전을 읽어 옴. 실패해도 예외를 던지지 않고 사유를 기록. */
    public void refresh() {
        String found = null;
        String error = null;
        try {
            if (product == Product.TOMCAT) {
                found = fetchTomcat();
                if (found == null) error = "목록에서 Tomcat 버전을 찾지 못함";
            } else {
                found = parseListing(product, Fetch.text(url));
                if (found == null) error = product == Product.APACHE ? "목록에서 httpd-2.4.x 파일을 찾지 못함" : "목록에서 N.N.N.Final 버전을 찾지 못함";
            }
        } catch (IOException e) {
            error = e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            error = "중단됨";
        } catch (IllegalArgumentException e) {
            error = "주소가 올바르지 않음: " + url;
        }
        synchronized (this) {
            autoCheckedAt = System.currentTimeMillis();
            autoError = error;
            if (found != null) {
                if (autoVersion != null && !autoVersion.equals(found)) {
                    LOG.warning("[webwas-precheck] " + product.label + " 최신 버전 변경: " + autoVersion + " → " + found);
                }
                autoVersion = found;
                autoSuccessAt = autoCheckedAt;
            } else {
                LOG.warning("[webwas-precheck] " + product.label + " 최신 버전 자동 확인 실패 (" + url + "): " + error);
            }
            saveQuietly();
        }
    }

    /** Tomcat: 배포 서버 폴더 목록(기본) 또는 Maven maven-metadata.xml(주소가 .xml 로 끝날 때) */
    private String fetchTomcat() throws IOException, InterruptedException {
        String body = Fetch.text(url);
        List<String> versions = new ArrayList<>();
        if (url.endsWith(".xml")) {
            Matcher m = TOMCAT_META.matcher(body);
            while (m.find()) versions.add(m.group(1));
            // Maven 목록에는 지원 종료 브랜치도 있으므로 높은 메이저 3개만 지원 중으로 봄
            return bestPerBranch(versions, 3);
        }
        Matcher d = TOMCAT_DIR.matcher(body);
        List<String> dirs = new ArrayList<>();
        while (d.find()) if (!dirs.contains(d.group(1))) dirs.add(d.group(1));
        String base = url.endsWith("/") ? url : url + "/";
        for (String dir : dirs) {
            Matcher v = TOMCAT_RELEASE.matcher(Fetch.text(URI.create(base).resolve(dir + "/").toString()));
            while (v.find()) versions.add(v.group(1));
        }
        versions.sort(Comparator.comparing((String s) -> s, ReportParser::compareVersions));
        return bestPerBranch(versions, 0);
    }

    public synchronized void setManual(String version) throws IOException {
        if (!validVersion(product, version)) {
            throw new IllegalArgumentException(product.label + " 버전 형식이 올바르지 않습니다. 예: " + example(product));
        }
        mode = "manual";
        manualVersion = normalize(product, version);
        save();
    }

    public synchronized void setAuto() throws IOException {
        mode = "auto";
        save();
    }

    private void load() throws IOException {
        if (!Files.exists(file)) return;
        Properties p = new Properties();
        try (Reader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            p.load(r);
        }
        mode = "manual".equals(p.getProperty("mode")) ? "manual" : "auto";
        manualVersion = validVersion(product, p.getProperty("manualVersion")) ? normalize(product, p.getProperty("manualVersion")) : null;
        autoVersion = validVersion(product, p.getProperty("autoVersion")) ? normalize(product, p.getProperty("autoVersion")) : null;
        autoCheckedAt = num(p.getProperty("autoCheckedAt"));
        autoSuccessAt = num(p.getProperty("autoSuccessAt"));
        autoError = p.getProperty("autoError");
    }

    private static long num(String s) {
        try {
            return s == null ? 0 : Long.parseLong(s);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private void saveQuietly() {
        try {
            save();
        } catch (IOException e) {
            LOG.warning("[webwas-precheck] latest-version 저장 실패: " + e.getMessage());
        }
    }

    private void save() throws IOException {
        Properties p = new Properties();
        p.setProperty("mode", mode);
        if (manualVersion != null) p.setProperty("manualVersion", manualVersion);
        if (autoVersion != null) p.setProperty("autoVersion", autoVersion);
        p.setProperty("autoCheckedAt", String.valueOf(autoCheckedAt));
        p.setProperty("autoSuccessAt", String.valueOf(autoSuccessAt));
        if (autoError != null) p.setProperty("autoError", autoError);
        Path tmp = Files.createTempFile(file.getParent(), ".latest", ".tmp");
        try (Writer w = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
            p.store(w, "webwas-precheck: " + product.label + " latest version");
        }
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
