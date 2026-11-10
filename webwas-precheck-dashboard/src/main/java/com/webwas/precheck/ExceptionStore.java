package com.webwas.precheck;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

/**
 * 예외(위험 수용): 확인을 마치고 유지하기로 한 [위험]·[주의] 항목.
 * 항목은 "섹션 + 문구(숫자는 #)" 로 찾으므로 다음 점검에서 같은 항목이 다시 나와도 예외로 인식됨 (ReportDiff.key 와 같은 기준).
 * 범위: instance(서버 1대) | product(같은 제품 전체). 만료일이 지나면 자동으로 다시 경고.
 * 예외 처리된 항목은 서버 판정·위험/주의 건수·설정 취약 항목·CVE 집계에서 빠지고, 목록에는 "예외"로 계속 보임.
 * [4] 침해 흔적의 [위험]은 예외 처리할 수 없음 (침해 신호를 숨기지 않기 위해).
 * 저장: <데이터폴더>/exceptions.properties
 */
public class ExceptionStore {

    /** 예외 1건 */
    public static final class Entry {
        public String id;
        public String key;          // 섹션|문구(숫자=#)
        public String scope;        // instance | product
        public String target;       // instanceKey 또는 제품 id
        public String product;
        public String section;
        public String level;        // 예외 처리할 때의 등급
        public String text;         // 예외 처리할 때의 문구 (화면 표시용)
        public String host;         // 예외 처리한 서버 (표시용)
        public String reason;
        public String by;
        public long createdAt;
        public long expiresAt;

        public boolean active(long now) {
            return expiresAt > now;
        }

        boolean matches(Report r, String findingKey, long now) {
            if (!active(now) || !key.equals(findingKey)) return false;
            return "instance".equals(scope) ? target.equals(r.instanceKey()) : target.equals(r.product.id);
        }

        public Map<String, Object> toMap(long now) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("scope", scope);
            m.put("target", target);
            m.put("product", product);
            m.put("section", section);
            m.put("level", level);
            m.put("text", text);
            m.put("host", host);
            m.put("reason", reason);
            m.put("by", by);
            m.put("createdAt", createdAt);
            m.put("expiresAt", expiresAt);
            m.put("active", active(now));
            return m;
        }
    }

    public static final int[] ALLOWED_DAYS = {30, 90, 180, 365};
    private static final SecureRandom RND = new SecureRandom();

    private final Path file;
    private final Map<String, Entry> entries = new TreeMap<>();

    public ExceptionStore(Path file) throws IOException {
        this.file = file;
        load();
    }

    /** 예외 처리 가능한 항목인가 (사유는 화면에 그대로 보여 줌) */
    public static String refuseReason(Report.Finding f) {
        if (!"risk".equals(f.level) && !"warn".equals(f.level)) return "[위험]·[주의] 항목만 예외 처리할 수 있습니다.";
        if ("4".equals(f.section) && "risk".equals(f.level)) return "[4] 침해 흔적의 [위험]은 예외 처리할 수 없습니다. 침해사고 대응이 우선입니다.";
        return null;
    }

    public synchronized Entry add(Report r, Report.Finding f, String scope, String reason, int days, String by, long now) throws IOException {
        String refuse = refuseReason(f);
        if (refuse != null) throw new IllegalArgumentException(refuse);
        if (!"instance".equals(scope) && !"product".equals(scope)) throw new IllegalArgumentException("범위는 이 서버만 또는 같은 제품 전체 중에서 고르세요.");
        String why = reason == null ? "" : reason.replaceAll("[\\r\\n\\t]+", " ").trim();
        if (why.length() < 4) throw new IllegalArgumentException("예외 사유를 4자 이상 적어 주세요. (예: 방화벽으로 외부 차단 확인, 2026-11 점검)");
        if (why.length() > 300) why = why.substring(0, 300);
        boolean okDays = false;
        for (int d : ALLOWED_DAYS) okDays |= d == days;
        if (!okDays) throw new IllegalArgumentException("기간은 30·90·180·365일 중에서 고르세요.");
        Entry e = new Entry();
        byte[] b = new byte[6];
        RND.nextBytes(b);
        e.id = HexFormat.of().formatHex(b);
        e.key = ReportDiff.key(f);
        e.scope = scope;
        e.target = "instance".equals(scope) ? r.instanceKey() : r.product.id;
        e.product = r.product.id;
        e.section = f.section;
        e.level = f.level;
        e.text = f.text.length() > 400 ? f.text.substring(0, 400) : f.text;
        e.host = r.host;
        e.reason = why;
        e.by = by;
        e.createdAt = now;
        e.expiresAt = now + days * 86_400_000L;
        // 같은 범위·항목의 예전 예외는 새 것으로 바꿈
        entries.values().removeIf(x -> x.key.equals(e.key) && x.scope.equals(e.scope) && x.target.equals(e.target));
        entries.put(e.id, e);
        save();
        return e;
    }

    public synchronized boolean remove(String id) throws IOException {
        boolean r = entries.remove(id) != null;
        if (r) save();
        return r;
    }

    /** 지금 유효한 예외들의 요약값 (등록·해제·만료로 바뀜) — 화면 데이터 캐시(ETag) 기준에 넣음 */
    public synchronized String signature(long now) {
        StringBuilder sb = new StringBuilder();
        for (Entry e : entries.values()) if (e.active(now)) sb.append(e.id).append(',');
        return Integer.toHexString(sb.toString().hashCode());
    }

    public synchronized List<Entry> list() {
        List<Entry> out = new ArrayList<>(entries.values());
        out.sort((a, b) -> Long.compare(b.createdAt, a.createdAt));
        return out;
    }

    /** 리포트의 항목마다 해당하는 유효한 예외를 붙임 (요청마다 새로 계산). CVE 항목이면 그 CVE 판정에도 표시 */
    public synchronized void apply(Report r, long now) {
        for (Report.Cve c : r.cves) c.exempt = null;
        for (Report.Finding f : r.findings) {
            f.exempt = null;
            if (refuseReason(f) != null) continue;
            String k = ReportDiff.key(f);
            for (Entry e : entries.values()) {
                if (e.matches(r, k, now)) {
                    f.exempt = e;
                    break;
                }
            }
            if (f.exempt != null && "2".equals(f.section) && f.text.startsWith("CVE-")) {
                String id = f.text.split(" ", 2)[0];
                for (Report.Cve c : r.cves) if (c.id.equals(id)) c.exempt = f.exempt;
            }
        }
    }

    private void load() throws IOException {
        if (!Files.isRegularFile(file)) return;
        Properties p = new Properties();
        try (Reader rd = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            p.load(rd);
        }
        for (String k : p.stringPropertyNames()) {
            if (!k.endsWith(".key")) continue;
            String id = k.substring(0, k.length() - 4);
            if (!id.matches("[0-9a-f]{12}")) continue;
            Entry e = new Entry();
            e.id = id;
            e.key = p.getProperty(k);
            e.scope = p.getProperty(id + ".scope", "instance");
            e.target = p.getProperty(id + ".target", "");
            e.product = p.getProperty(id + ".product", "");
            e.section = p.getProperty(id + ".section", "");
            e.level = p.getProperty(id + ".level", "");
            e.text = p.getProperty(id + ".text", "");
            e.host = p.getProperty(id + ".host", "");
            e.reason = p.getProperty(id + ".reason", "");
            e.by = p.getProperty(id + ".by", "");
            e.createdAt = num(p.getProperty(id + ".createdAt"));
            e.expiresAt = num(p.getProperty(id + ".expiresAt"));
            entries.put(id, e);
        }
    }

    private static long num(String s) {
        try {
            return Long.parseLong(s);
        } catch (RuntimeException e) {
            return 0;
        }
    }

    private void save() throws IOException {
        Properties p = new Properties();
        for (Entry e : entries.values()) {
            String n = e.id;
            p.setProperty(n + ".key", e.key);
            p.setProperty(n + ".scope", e.scope);
            p.setProperty(n + ".target", e.target);
            p.setProperty(n + ".product", e.product);
            p.setProperty(n + ".section", e.section);
            p.setProperty(n + ".level", e.level);
            p.setProperty(n + ".text", e.text);
            p.setProperty(n + ".host", e.host == null ? "" : e.host);
            p.setProperty(n + ".reason", e.reason);
            p.setProperty(n + ".by", e.by == null ? "" : e.by);
            p.setProperty(n + ".createdAt", String.valueOf(e.createdAt));
            p.setProperty(n + ".expiresAt", String.valueOf(e.expiresAt));
        }
        Path dir = file.toAbsolutePath().getParent();
        Files.createDirectories(dir);
        Path tmp = Files.createTempFile(dir, ".exceptions", ".tmp");
        try (Writer w = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
            p.store(w, "webwas-precheck exceptions (위험 수용)");
        }
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
