package com.webwas.wfprecheck;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * WildFly 최신 Final 버전 확인.
 *
 * - 자동: WildFly 배포본(org.wildfly:wildfly-dist)의 Maven Central 버전 목록
 *   https://repo1.maven.org/maven2/org/wildfly/wildfly-dist/maven-metadata.xml 에서
 *   "N.N.N.Final" 중 가장 높은 번호를 12시간마다 확인 (Alpha/Beta/CR 은 제외)
 *   (주소는 -Dwfprecheck.latest.url 로 바꿀 수 있음 — 사내 Nexus/Artifactory 미러를 쓸 때)
 * - 수동: 인터넷이 막힌 환경을 위해 관리자가 버전을 직접 지정
 * - 둘 다 실패하면 점검 스크립트의 기준 버전(scriptBaseline)을 사용
 * 결과는 <데이터폴더>/latest-version.properties 에 저장되어 재시작 후에도 유지됨.
 */
public class LatestVersion {
    private static final Logger LOG = Logger.getLogger(LatestVersion.class.getName());
    public static final String DEFAULT_URL = "https://repo1.maven.org/maven2/org/wildfly/wildfly-dist/maven-metadata.xml";
    /** 스크립트 기준값도 못 읽었을 때 쓰는 값 (2026-10-16 공식 다운로드 페이지 기준) */
    public static final String FALLBACK = "41.0.1.Final";
    private static final Pattern FINAL_VERSION = Pattern.compile("<version>\\s*(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.Final)\\s*</version>");
    private static final Pattern VERSION = Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.Final$");
    private static final long REFRESH_HOURS = 12;

    private final Path file;
    private final String url;
    private final String scriptBaseline;
    private ScheduledExecutorService scheduler;

    private String mode = "auto";          // auto | manual
    private String manualVersion;
    private String autoVersion;            // 마지막으로 자동 확인에 성공한 버전
    private long autoCheckedAt;            // 마지막 자동 확인 시도 시각
    private long autoSuccessAt;            // 마지막 자동 확인 성공 시각
    private String autoError;              // 마지막 자동 확인 실패 사유 (성공 시 null)
    private boolean skipUpToDate = true;   // 최신 버전 서버는 자동 점검에서 제외

    public LatestVersion(Path file, String url, String scriptBaseline) throws IOException {
        this.file = file;
        this.url = url == null || url.isBlank() ? DEFAULT_URL : url;
        this.scriptBaseline = scriptBaseline;
        load();
    }

    public static boolean validVersion(String v) {
        return v != null && VERSION.matcher(v).matches();
    }

    /** maven-metadata.xml 에서 가장 높은 N.N.N.Final 버전 추출. 없으면 null. */
    public static String parseListing(String xml) {
        String best = null;
        Matcher m = FINAL_VERSION.matcher(xml == null ? "" : xml);
        while (m.find()) {
            String v = m.group(1);
            if (best == null || ReportParser.compareVersions(v, best) > 0) best = v;
        }
        return best;
    }

    /** 지금 판정에 쓰는 "최신 버전" */
    public synchronized String current() {
        if ("manual".equals(mode) && manualVersion != null) return manualVersion;
        if (autoVersion != null) {
            // 목록이 비정상이라 스크립트 기준보다 낮게 나오면 스크립트 기준을 사용
            return scriptBaseline != null && ReportParser.compareVersions(autoVersion, scriptBaseline) < 0 ? scriptBaseline : autoVersion;
        }
        return scriptBaseline != null ? scriptBaseline : FALLBACK;
    }

    /** 현재 값이 어디서 왔는지: manual | auto | baseline */
    public synchronized String origin() {
        if ("manual".equals(mode) && manualVersion != null) return "manual";
        if (autoVersion != null) return "auto";
        return "baseline";
    }

    public synchronized boolean skipUpToDate() {
        return skipUpToDate;
    }

    /** version 이 최신 이상인가 (버전을 모르면 false) */
    public boolean isUpToDate(String version) {
        return version != null && ReportParser.compareVersions(version, current()) >= 0;
    }

    public synchronized Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("version", current());
        m.put("origin", origin());
        m.put("mode", mode);
        m.put("manualVersion", manualVersion);
        m.put("autoVersion", autoVersion);
        m.put("autoCheckedAt", autoCheckedAt);
        m.put("autoSuccessAt", autoSuccessAt);
        m.put("autoError", autoError);
        m.put("source", url);
        m.put("scriptBaseline", scriptBaseline);
        m.put("skipUpToDate", skipUpToDate);
        m.put("newerThanScript", scriptBaseline != null && ReportParser.compareVersions(current(), scriptBaseline) > 0);
        return m;
    }

    /** 공식 배포 목록에서 최신 버전을 읽어 옴. 실패해도 예외를 던지지 않고 사유를 기록. */
    public void refresh() {
        String found = null;
        String error = null;
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(15))
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(30))
                    .header("User-Agent", "wfprecheck-dashboard")
                    .GET().build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (resp.statusCode() != 200) {
                error = "HTTP " + resp.statusCode();
            } else {
                found = parseListing(resp.body());
                if (found == null) error = "목록에서 N.N.N.Final 버전을 찾지 못함";
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
                    LOG.warning("[wfprecheck-dashboard] WildFly 최신 버전 변경: " + autoVersion + " → " + found);
                }
                autoVersion = found;
                autoSuccessAt = autoCheckedAt;
            } else {
                LOG.warning("[wfprecheck-dashboard] WildFly 최신 버전 자동 확인 실패 (" + url + "): " + error);
            }
            saveQuietly();
        }
    }

    public synchronized void setManual(String version) throws IOException {
        if (!validVersion(version)) throw new IllegalArgumentException("버전은 숫자.숫자.숫자.Final 형식이어야 합니다. 예: 41.0.1.Final");
        mode = "manual";
        manualVersion = version;
        save();
    }

    public synchronized void setAuto() throws IOException {
        mode = "auto";
        save();
    }

    public synchronized void setSkipUpToDate(boolean v) throws IOException {
        skipUpToDate = v;
        save();
    }

    /** 앱 시작 직후 1회 + 12시간마다 자동 확인 */
    public void start() {
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "wfprecheck-latest-version");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleWithFixedDelay(this::refresh, 5, REFRESH_HOURS * 3600, TimeUnit.SECONDS);
    }

    public void stop() {
        if (scheduler != null) scheduler.shutdownNow();
    }

    private void load() throws IOException {
        if (!Files.exists(file)) return;
        Properties p = new Properties();
        try (Reader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            p.load(r);
        }
        mode = "manual".equals(p.getProperty("mode")) ? "manual" : "auto";
        manualVersion = validVersion(p.getProperty("manualVersion")) ? p.getProperty("manualVersion") : null;
        autoVersion = validVersion(p.getProperty("autoVersion")) ? p.getProperty("autoVersion") : null;
        autoCheckedAt = num(p.getProperty("autoCheckedAt"));
        autoSuccessAt = num(p.getProperty("autoSuccessAt"));
        autoError = p.getProperty("autoError");
        skipUpToDate = !"false".equals(p.getProperty("skipUpToDate"));
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
            LOG.warning("[wfprecheck-dashboard] latest-version 저장 실패: " + e.getMessage());
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
        p.setProperty("skipUpToDate", String.valueOf(skipUpToDate));
        Path tmp = Files.createTempFile(file.getParent(), ".latest", ".tmp");
        try (Writer w = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
            p.store(w, "wfprecheck-dashboard: WildFly latest Final version");
        }
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
