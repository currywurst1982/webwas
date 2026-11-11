package com.webwas.precheck;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * IP 자동 그룹 규칙: 서버 IP 가 규칙에 맞으면 그 그룹으로 자동 분류.
 * 규칙은 순서가 있으며 먼저 맞는 규칙이 이깁니다. 에이전트에 직접 지정한 그룹(수동 라벨)이 있으면 그쪽이 우선합니다.
 * 패턴: CIDR(10.10.10.0/24) · 와일드카드(10.10.* = 10.10.*.*) · 정확한 IPv4(10.10.10.10). IPv4 전용.
 * 저장: <데이터폴더>/ipgroups.properties (ipgroup.0.pattern / ipgroup.0.group, …)
 */
public class IpGroupRules {

    public static final class Rule {
        public final String pattern;
        public final String group;

        Rule(String pattern, String group) {
            this.pattern = pattern;
            this.group = group;
        }

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("pattern", pattern);
            m.put("group", group);
            return m;
        }
    }

    private final Path file;
    private final List<Rule> rules = new ArrayList<>();

    public IpGroupRules(Path file) throws IOException {
        this.file = file;
        load();
    }

    public synchronized List<Rule> list() {
        return new ArrayList<>(rules);
    }

    /** 규칙 추가 (맨 끝). 패턴·그룹 검증 후 저장. */
    public synchronized Rule add(String pattern, String group) throws IOException {
        String pat = normPattern(pattern);
        String grp = AgentStore.normGroup(group);
        if (grp.isEmpty()) throw new IllegalArgumentException("그룹 이름을 입력하세요.");
        if (rules.size() >= 200) throw new IllegalArgumentException("규칙은 최대 200개까지입니다.");
        Rule r = new Rule(pat, grp);
        rules.add(r);
        save();
        return r;
    }

    /** index 번째 규칙 삭제. 범위를 벗어나면 false. */
    public synchronized boolean remove(int index) throws IOException {
        if (index < 0 || index >= rules.size()) return false;
        rules.remove(index);
        save();
        return true;
    }

    /** ip 에 맞는 첫 규칙의 그룹 (순서대로). 없으면 null. */
    public synchronized String match(String ip) {
        long v = parseIp(ip);
        if (v < 0) return null;
        for (Rule r : rules) if (matches(r.pattern, ip, v)) return r.group;
        return null;
    }

    /** 여러 후보 IP 중 하나라도 맞는 첫 규칙의 그룹 (규칙 순서 우선). 없으면 null. */
    public synchronized String matchAny(List<String> ips) {
        if (ips == null || ips.isEmpty()) return null;
        for (Rule r : rules) {
            for (String ip : ips) {
                long v = parseIp(ip);
                if (v >= 0 && matches(r.pattern, ip, v)) return r.group;
            }
        }
        return null;
    }

    /** 화면 캐시(ETag) 기준값: 규칙이 바뀌면 달라짐 */
    public synchronized String signature() {
        StringBuilder sb = new StringBuilder();
        for (Rule r : rules) sb.append(r.pattern).append('>').append(r.group).append(';');
        return Integer.toHexString(sb.toString().hashCode());
    }

    // ---- 패턴 검증·매칭 -------------------------------------------------

    /** 패턴 정리·검증. 와일드카드 축약(10.10.* → 10.10.*.*) 포함. 잘못되면 예외. */
    static String normPattern(String pattern) {
        String p = pattern == null ? "" : pattern.trim();
        if (p.isEmpty()) throw new IllegalArgumentException("IP 패턴을 입력하세요. 예: 10.10.10.0/24, 10.10.*, 10.10.10.10");
        if (p.indexOf('/') >= 0) {
            String[] cd = p.split("/", -1);
            if (cd.length != 2) throw badPattern(p);
            int prefix;
            try {
                prefix = Integer.parseInt(cd[1].trim());
            } catch (NumberFormatException e) {
                throw badPattern(p);
            }
            if (prefix < 0 || prefix > 32) throw new IllegalArgumentException("CIDR 접두 길이는 0~32 여야 합니다: " + p);
            if (parseIp(cd[0].trim()) < 0) throw badPattern(p);
            return cd[0].trim() + "/" + prefix;
        }
        // 와일드카드/정확한 IP: 4옥텟. 부족하면 끝을 * 로 채움(단, 마지막이 * 일 때만 축약 허용)
        String[] parts = p.split("\\.", -1);
        if (parts.length < 1 || parts.length > 4) throw badPattern(p);
        List<String> out = new ArrayList<>();
        for (int i = 0; i < parts.length; i++) {
            String o = parts[i].trim();
            if (o.equals("*")) {
                out.add("*");
            } else {
                int n;
                try {
                    n = Integer.parseInt(o);
                } catch (NumberFormatException e) {
                    throw badPattern(p);
                }
                if (n < 0 || n > 255) throw badPattern(p);
                out.add(String.valueOf(n));
            }
        }
        if (out.size() < 4) {
            if (!out.get(out.size() - 1).equals("*")) {
                throw new IllegalArgumentException("IP 패턴은 4자리(10.10.10.10)이거나, * 로 끝나야 합니다(10.10.* 처럼): " + p);
            }
            while (out.size() < 4) out.add("*");
        }
        return String.join(".", out);
    }

    private static IllegalArgumentException badPattern(String p) {
        return new IllegalArgumentException("IP 패턴 형식이 올바르지 않습니다: " + p + " (예: 10.10.10.0/24, 10.10.*, 10.10.10.10)");
    }

    private static boolean matches(String pattern, String ip, long ipVal) {
        int slash = pattern.indexOf('/');
        if (slash >= 0) {
            long base = parseIp(pattern.substring(0, slash));
            int prefix = Integer.parseInt(pattern.substring(slash + 1));
            if (base < 0) return false;
            if (prefix == 0) return true;
            long mask = (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
            return (ipVal & mask) == (base & mask);
        }
        String[] pp = pattern.split("\\.", -1);
        String[] ii = ip.split("\\.", -1);
        if (pp.length != 4 || ii.length != 4) return false;
        for (int i = 0; i < 4; i++) {
            if (pp[i].equals("*")) continue;
            if (!pp[i].equals(ii[i])) return false;
        }
        return true;
    }

    /** 점표기 IPv4 → 32비트 값. 아니면 -1. */
    static long parseIp(String ip) {
        if (ip == null) return -1;
        String[] p = ip.trim().split("\\.", -1);
        if (p.length != 4) return -1;
        long v = 0;
        for (String o : p) {
            int n;
            try {
                n = Integer.parseInt(o);
            } catch (NumberFormatException e) {
                return -1;
            }
            if (n < 0 || n > 255) return -1;
            v = (v << 8) | n;
        }
        return v;
    }

    // ---- 저장/로드 -----------------------------------------------------

    private void load() throws IOException {
        rules.clear();
        if (!Files.isRegularFile(file)) return;
        Properties p = new Properties();
        try (Reader rd = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            p.load(rd);
        }
        int count;
        try {
            count = Integer.parseInt(p.getProperty("ipgroup.count", "0"));
        } catch (NumberFormatException e) {
            count = 0;
        }
        for (int i = 0; i < count && i < 1000; i++) {
            String pat = p.getProperty("ipgroup." + i + ".pattern");
            String grp = p.getProperty("ipgroup." + i + ".group");
            if (pat == null || grp == null) continue;
            try {
                rules.add(new Rule(normPattern(pat), AgentStore.normGroup(grp)));
            } catch (RuntimeException ignored) {
                // 잘못된 규칙은 건너뜀
            }
        }
    }

    private void save() throws IOException {
        Properties p = new Properties();
        p.setProperty("ipgroup.count", String.valueOf(rules.size()));
        for (int i = 0; i < rules.size(); i++) {
            p.setProperty("ipgroup." + i + ".pattern", rules.get(i).pattern);
            p.setProperty("ipgroup." + i + ".group", rules.get(i).group);
        }
        Path dir = file.toAbsolutePath().getParent();
        Files.createDirectories(dir);
        Path tmp = Files.createTempFile(dir, ".ipgroups", ".tmp");
        try (Writer w = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
            p.store(w, "webwas-precheck IP 자동 그룹 규칙");
        }
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
