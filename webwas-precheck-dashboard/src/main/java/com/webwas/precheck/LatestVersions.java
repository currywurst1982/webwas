package com.webwas.precheck;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.StringJoiner;

/** 제품별 최신 버전(LatestVersion) 묶음 + "최신 버전 서버는 자동 점검 제외" 설정. */
public class LatestVersions {
    private final Map<Product, LatestVersion> map = new EnumMap<>(Product.class);
    private final Path settings;
    private boolean skipUpToDate = true;

    public LatestVersions(Path dataDir, Map<Product, String> scriptBaselines) throws IOException {
        for (Product p : Product.values()) {
            map.put(p, new LatestVersion(p, dataDir.resolve("latest-version-" + p.id + ".properties"),
                    System.getProperty("webwas.precheck.latest." + p.id + ".url"), scriptBaselines.get(p)));
        }
        this.settings = dataDir.resolve("latest-settings.properties");
        if (Files.exists(settings)) {
            Properties pr = new Properties();
            try (Reader r = Files.newBufferedReader(settings, StandardCharsets.UTF_8)) {
                pr.load(r);
            }
            skipUpToDate = !"false".equals(pr.getProperty("skipUpToDate"));
        }
    }

    public LatestVersion get(Product p) {
        return map.get(p);
    }

    public boolean below(Product p, String version) {
        return p != null && map.get(p).below(version);
    }

    public String latestFor(Product p, String version) {
        return p == null ? null : map.get(p).latestFor(version);
    }

    public boolean isUpToDate(Product p, String version) {
        return p != null && map.get(p).isUpToDate(version);
    }

    /** PDF 머리글용: "Apache 2.4.69 · WildFly 41.0.1.Final · Tomcat 11.0.27 / 10.1.61 / 9.0.123" */
    public String summary() {
        StringJoiner j = new StringJoiner(" · ");
        for (LatestVersion v : map.values()) j.add(v.product.label + " " + v.display());
        return j.toString();
    }

    public void refreshAll() {
        map.values().forEach(LatestVersion::refresh);
    }

    public synchronized boolean skipUpToDate() {
        return skipUpToDate;
    }

    public synchronized void setSkipUpToDate(boolean v) throws IOException {
        skipUpToDate = v;
        Properties pr = new Properties();
        pr.setProperty("skipUpToDate", String.valueOf(v));
        Path tmp = Files.createTempFile(settings.getParent(), ".latest", ".tmp");
        try (Writer w = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
            pr.store(w, "webwas-precheck: latest version settings");
        }
        Files.move(tmp, settings, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        Map<String, Object> products = new LinkedHashMap<>();
        map.forEach((p, v) -> products.put(p.id, v.toMap()));
        m.put("products", products);
        m.put("skipUpToDate", skipUpToDate());
        m.put("summary", summary());
        return m;
    }
}
