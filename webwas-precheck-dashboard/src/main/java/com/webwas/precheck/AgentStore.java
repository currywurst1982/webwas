package com.webwas.precheck;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * 점검 에이전트 목록과 상태(<데이터폴더>/agents.properties).
 *
 * 에이전트는 서버(웹서버·WAS)에서 1분마다 대시보드에 "점검할 차례인지"를 묻고(heartbeat),
 * 차례이면 그 서버에서 실행 중인 제품(Apache/WildFly/Tomcat)의 점검 스크립트를 실행해 결과를 올림.
 * 대시보드는 "실행해/말아" 만 알려 줄 뿐 명령어나 인자를 보내지 않음.
 */
public class AgentStore {
    /** 에이전트 이름: 리포트 파일명 접두어(agent-이름__…)로 쓰므로, 밑줄(_)은 되지만 구분자와 겹치는 '__'(연속 밑줄)는 불가. */
    private static final Pattern NAME = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._-]{1,39}$");
    private static final SecureRandom RANDOM = new SecureRandom();
    /** 마지막 접속 후 이 시간이 지나면 오프라인 */
    public static final long OFFLINE_MILLIS = 3 * 60 * 1000L;
    /** "실행" 응답 후 이 시간 안에 결과가 없으면 실패로 보고 다시 실행 가능 */
    public static final long RUN_TIMEOUT_MILLIS = 2 * 60 * 60 * 1000L;
    /** lastSeen 만 바뀐 경우 파일 저장 간격 */
    private static final long PERSIST_SEEN_MILLIS = 10 * 60 * 1000L;

    public static final class Agent {
        public String name;
        public String group = "";            // 서버 그룹 라벨 (관리자가 직접 지정, 빈 값 = 그룹 없음)
        public String tokenHash;
        public int intervalHours = 24;       // 0 = 수동 점검만
        public long createdAt;
        public long lastSeen;
        public long lastSeenPersisted;
        public String hostname;
        public String ip;
        public String agentVersion;
        public String scriptSha256;
        /** 마지막 점검에서 읽은 제품별 버전 (같은 제품 인스턴스가 여러 개면 가장 낮은 버전) */
        public Map<Product, String> versions = new java.util.EnumMap<>(Product.class);
        public boolean pendingRun;           // 관리자가 "지금 점검" 요청
        public long runStartedAt;            // 에이전트에게 실행하라고 응답한 시각 (0 = 실행 중 아님)
        public long lastRunAt;               // 마지막 실행 완료 시각
        public int lastExit = -1;
        public int lastReportCount;
        public String lastMessage = "";
        public long lastReportAt;            // 마지막 리포트 수신 시각

        Agent copy() {
            Agent a = new Agent();
            a.name = name; a.group = group; a.tokenHash = tokenHash; a.intervalHours = intervalHours; a.createdAt = createdAt;
            a.lastSeen = lastSeen; a.lastSeenPersisted = lastSeenPersisted; a.hostname = hostname; a.ip = ip;
            a.agentVersion = agentVersion; a.scriptSha256 = scriptSha256; a.pendingRun = pendingRun;
            a.versions = new java.util.EnumMap<>(Product.class);
            a.versions.putAll(versions);
            a.runStartedAt = runStartedAt; a.lastRunAt = lastRunAt; a.lastExit = lastExit;
            a.lastReportCount = lastReportCount; a.lastMessage = lastMessage; a.lastReportAt = lastReportAt;
            a.authFailAt = authFailAt; a.authFailIp = authFailIp; a.authLocked = authLocked;
            return a;
        }

        /** 점검 중에도 1분마다 신호를 보내는 에이전트 버전 (이보다 낮으면 점검이 끝날 때까지 신호가 없음) */
        static final String KEEPALIVE_SINCE = "2.1.0";

        /** online | offline | never | running | requested */
        public String state(long now) {
            if (lastSeen == 0) return "never";
            boolean running = runStartedAt > 0 && now - runStartedAt < RUN_TIMEOUT_MILLIS;
            // 옛 에이전트(2.1.0 미만)는 점검하는 동안 신호를 못 보내므로, 점검 중이면 오프라인으로 보지 않음
            boolean legacy = agentVersion == null || ReportParser.compareVersions(agentVersion, KEEPALIVE_SINCE) < 0;
            if (running && legacy) return "running";
            if (now - lastSeen > OFFLINE_MILLIS) return "offline";
            if (running) return "running";
            if (pendingRun) return "requested";
            return "online";
        }

        /** 마지막 토큰 인증 실패 시각·IP·차단 여부 (메모리에만. 재시작하면 지워짐) */
        public long authFailAt;
        public String authFailIp;
        public boolean authLocked;

        public Map<String, Object> toMap(long now, String expectedSha) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", name);
            m.put("group", group == null ? "" : group);
            m.put("state", state(now));
            // 접속은 하는데 토큰이 틀려 거절되는 중인지 (마지막 정상 접속보다 나중의 실패만)
            boolean failing = authFailAt > lastSeen;
            m.put("authFailAt", failing ? authFailAt : 0);
            m.put("authFailIp", failing ? authFailIp : null);
            m.put("authLocked", failing && authLocked);
            m.put("intervalHours", intervalHours);
            m.put("createdAt", createdAt);
            m.put("lastSeen", lastSeen);
            m.put("hostname", hostname);
            m.put("ip", ip);
            m.put("agentVersion", agentVersion);
            m.put("scriptSha256", scriptSha256);
            Map<String, String> vs = new LinkedHashMap<>();
            versions.forEach((p, v) -> vs.put(p.id, v));
            m.put("versions", vs);
            m.put("scriptMatches", scriptSha256 == null || expectedSha == null ? null : scriptSha256.equals(expectedSha));
            m.put("pendingRun", pendingRun);
            m.put("runStartedAt", runStartedAt);
            m.put("lastRunAt", lastRunAt);
            m.put("lastExit", lastExit);
            m.put("lastReportCount", lastReportCount);
            m.put("lastMessage", lastMessage);
            m.put("lastReportAt", lastReportAt);
            m.put("nextRunAt", intervalHours > 0 ? (lastReportAt == 0 ? 0 : lastReportAt + intervalHours * 3_600_000L) : null);
            return m;
        }
    }

    private final Path file;
    private final Map<String, Agent> agents = new TreeMap<>();

    public AgentStore(Path file) throws IOException {
        this.file = file;
        load();
    }

    public static boolean validName(String n) {
        return n != null && !n.contains("__") && NAME.matcher(n).matches();
    }

    public static boolean validInterval(int h) {
        return h >= 0 && h <= 24 * 31;
    }

    static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    // 화면 보고 손으로 입력하기 쉬운 토큰용 문자 (헷갈리는 0·1·I·O 제외, 32자)
    private static final char[] TOKEN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray();

    /** 입력하기 쉬운 토큰 생성: 20자(=100비트), 5자씩 '-' 로 묶어 표시. 대소문자·하이픈은 검증 때 무시(normToken). */
    private static String newToken() {
        StringBuilder sb = new StringBuilder(24);
        for (int i = 0; i < 20; i++) {
            if (i > 0 && i % 5 == 0) sb.append('-');
            sb.append(TOKEN_ALPHABET[RANDOM.nextInt(TOKEN_ALPHABET.length)]);
        }
        return sb.toString();
    }

    /** 토큰 정규화: 하이픈·공백 등 제거하고 대문자화 → 저장·검증은 이 형태의 해시로. (타이핑 시 대소문자·하이픈 실수 허용) */
    static String normToken(String t) {
        return t == null ? "" : t.toUpperCase(java.util.Locale.ROOT).replaceAll("[^A-Z0-9]", "");
    }

    public synchronized List<Agent> list() {
        List<Agent> out = new ArrayList<>();
        agents.values().forEach(a -> out.add(a.copy()));
        return out;
    }

    public synchronized Agent get(String name) {
        Agent a = agents.get(name);
        return a == null ? null : a.copy();
    }

    /** 새 에이전트 등록. 반환값은 토큰 원문(이 때 한 번만 알 수 있음). */
    /** 그룹 라벨 정리: 제어문자 제거·공백 정리·30자 제한. 빈 값 허용(그룹 없음). 한글·영문·숫자 모두 가능. */
    public static String normGroup(String g) {
        if (g == null) return "";
        String s = g.replaceAll("\\p{Cntrl}", " ").replaceAll("\\s+", " ").trim();
        return s.length() > 30 ? s.substring(0, 30).trim() : s;
    }

    public synchronized String create(String name, int intervalHours) throws IOException {
        return create(name, intervalHours, "");
    }

    public synchronized String create(String name, int intervalHours, String group) throws IOException {
        if (!validName(name)) throw new IllegalArgumentException("에이전트 이름은 영문/숫자/._- 2~40자이고 영문·숫자로 시작해야 합니다. (연속 밑줄 '__' 는 불가 — 파일명 구분자와 겹침)");
        if (agents.containsKey(name)) throw new IllegalArgumentException("이미 있는 에이전트 이름입니다.");
        if (!validInterval(intervalHours)) throw new IllegalArgumentException("점검 주기가 올바르지 않습니다.");
        String token = newToken();
        Agent a = new Agent();
        a.name = name;
        a.group = normGroup(group);
        a.tokenHash = sha256(normToken(token));
        a.intervalHours = intervalHours;
        a.createdAt = System.currentTimeMillis();
        agents.put(name, a);
        save();
        return token;
    }

    /** 그룹 라벨 지정/변경 (빈 값이면 그룹 해제). 바뀐 값을 돌려줌. */
    public synchronized String setGroup(String name, String group) throws IOException {
        Agent a = require(name);
        a.group = normGroup(group);
        save();
        return a.group;
    }

    public synchronized String rotateToken(String name) throws IOException {
        Agent a = require(name);
        String token = newToken();
        a.tokenHash = sha256(normToken(token));
        save();
        return token;
    }

    public synchronized void setInterval(String name, int hours) throws IOException {
        if (!validInterval(hours)) throw new IllegalArgumentException("점검 주기가 올바르지 않습니다.");
        require(name).intervalHours = hours;
        save();
    }

    public synchronized int requestRun(String name) throws IOException {
        int n = 0;
        for (Agent a : agents.values()) {
            if (name == null || a.name.equals(name)) {
                a.pendingRun = true;
                n++;
            }
        }
        if (name != null && n == 0) throw new IllegalArgumentException("에이전트가 없습니다.");
        save();
        return n;
    }

    /**
     * 에이전트의 점검 상태만 초기화 (등록·토큰·주기·접속 정보는 유지).
     * 마지막 점검 시각이 없어지므로 자동 점검 주기가 있으면 다음 접속(1분 안) 때 바로 다시 점검함.
     */
    public synchronized boolean resetHistory(String name) throws IOException {
        Agent a = agents.get(name);
        if (a == null) return false;
        a.versions.clear();
        a.pendingRun = false;
        a.runStartedAt = 0;
        a.lastRunAt = 0;
        a.lastExit = -1;
        a.lastReportCount = 0;
        a.lastMessage = "";
        a.lastReportAt = 0;
        save();
        return true;
    }

    public synchronized boolean remove(String name) throws IOException {
        boolean r = agents.remove(name) != null;
        if (r) save();
        return r;
    }

    /** 토큰 확인. 맞으면 true (시간차 공격 방지를 위해 상수시간 비교). */
    /** 토큰 인증 실패 기록 (등록된 에이전트 이름일 때만). locked = 실패가 반복되어 잠시 차단됨 */
    public synchronized void authFailed(String name, String ip, long now, boolean locked) {
        Agent a = name == null ? null : agents.get(name);
        if (a == null) return;
        a.authFailAt = now;
        a.authFailIp = ip;
        a.authLocked = locked;
    }

    public synchronized boolean authenticate(String name, String token) {
        Agent a = name == null ? null : agents.get(name);
        String expected = a == null ? sha256("no-such-agent") : a.tokenHash;
        byte[] exp = expected.getBytes(StandardCharsets.UTF_8);
        String t = token == null ? "" : token;
        // 새 토큰: 정규화(대소문자·하이픈 무시) 해시 / 예전 토큰: 원문 그대로 해시 — 둘 다 허용(기존 에이전트 호환)
        boolean ok = MessageDigest.isEqual(exp, sha256(normToken(t)).getBytes(StandardCharsets.UTF_8))
                | MessageDigest.isEqual(exp, sha256(t).getBytes(StandardCharsets.UTF_8));
        return a != null && ok;
    }

    /**
     * 에이전트 heartbeat 처리. 지금 점검을 실행해야 하면 실행 사유를, 아니면 null 을 반환.
     * busy=true 는 에이전트 쪽에서 이미 점검이 진행 중이라는 뜻.
     */
    public synchronized String heartbeat(String name, long now, String hostname, String ip, String version,
                                         String scriptSha, boolean busy) throws IOException {
        return heartbeat(name, now, hostname, ip, version, scriptSha, busy, false, null);
    }

    public synchronized String heartbeat(String name, long now, String hostname, String ip, String version,
                                         String scriptSha, boolean busy, boolean probe) throws IOException {
        return heartbeat(name, now, hostname, ip, version, scriptSha, busy, probe, null);
    }

    /**
     * probe=true 는 설치 직후 연결 확인용: 상태만 갱신하고 점검을 지시하지 않음.
     * skipLatest 가 있으면 점검한 모든 제품이 최신 버전인 서버는 자동(주기) 점검을 하지 않음. "지금 점검"은 항상 실행.
     */
    public synchronized String heartbeat(String name, long now, String hostname, String ip, String version,
                                         String scriptSha, boolean busy, boolean probe, LatestVersions skipLatest) throws IOException {
        Agent a = require(name);
        boolean changed = !eq(a.hostname, hostname) || !eq(a.ip, ip) || !eq(a.agentVersion, version) || !eq(a.scriptSha256, scriptSha);
        a.hostname = hostname;
        a.ip = ip;
        a.agentVersion = version;
        a.scriptSha256 = scriptSha;
        a.lastSeen = now;

        String reason = null;
        if (probe) {
            // 아무것도 지시하지 않음
        } else if (busy) {
            if (a.runStartedAt == 0) a.runStartedAt = now;
        } else {
            boolean stale = a.runStartedAt > 0 && now - a.runStartedAt >= RUN_TIMEOUT_MILLIS;
            if (stale) {
                a.runStartedAt = 0;
                a.lastMessage = "점검 결과가 " + (RUN_TIMEOUT_MILLIS / 3_600_000L) + "시간 안에 오지 않았습니다.";
                changed = true;
            }
            if (a.runStartedAt == 0) {
                if (a.pendingRun) reason = "manual";
                else if (a.intervalHours > 0 && !upToDate(a, skipLatest) && (a.lastReportAt == 0 || now - a.lastReportAt >= a.intervalHours * 3_600_000L)
                        && (a.lastRunAt == 0 || now - a.lastRunAt >= 30 * 60 * 1000L)) {
                    // 결과가 없거나 주기가 지났으면 실행 (실패가 반복될 때 1분마다 재실행하지 않도록 최소 30분 간격)
                    reason = "schedule";
                }
            }
            if (reason != null) {
                a.pendingRun = false;
                a.runStartedAt = now;
                changed = true;
            }
        }
        if (changed || now - a.lastSeenPersisted >= PERSIST_SEEN_MILLIS) {
            a.lastSeenPersisted = now;
            save();
        }
        return reason;
    }

    /** 버전을 알고 있고, 그 버전이 기준 이상이면 true */
    public static boolean upToDate(Agent a, LatestVersions latest) {
        if (latest == null || a.versions.isEmpty()) return false;
        return a.versions.entrySet().stream().allMatch(e -> latest.isUpToDate(e.getKey(), e.getValue()));
    }

    /** 마지막 점검 묶음으로 보는 범위: 가장 최근 리포트로부터 이 시간 안에 받은 리포트 (재전송 지연 포함) */
    static final long LAST_RUN_WINDOW_MILLIS = 30 * 60_000L;

    /**
     * 에이전트의 마지막 점검에서 온 인스턴스 목록 (제품·인스턴스마다 한 줄, 버전을 못 읽은 것도 포함).
     * latest = 인스턴스별 최신 리포트 (ConfigIssues.latestPerInstance 결과).
     * 마지막 점검보다 훨씬 전에 온 인스턴스(이미 지운 서버 등)는 뺌.
     */
    public static List<Report> lastRunInstances(List<Report> latest, String agent) {
        List<Report> mine = new ArrayList<>();
        for (Report r : latest) if (agent.equals(r.source)) mine.add(r);
        long newest = mine.stream().mapToLong(r -> r.fileModified).max().orElse(0);
        mine.removeIf(r -> r.fileModified < newest - LAST_RUN_WINDOW_MILLIS);
        mine.sort(java.util.Comparator.comparing((Report r) -> r.product.ordinal())
                .thenComparing(r -> r.binary == null ? "" : r.binary)
                .thenComparing(r -> r.confArg == null ? "" : r.confArg));
        return mine;
    }

    /** 리포트 1건 수신 */
    public synchronized void reportReceived(String name, long now) throws IOException {
        reportReceived(name, now, null, null);
    }

    /** 한 번의 점검에서 온 리포트로 보는 간격 (한 서버에 인스턴스가 여러 개면 리포트가 연달아 옴) */
    static final long SAME_RUN_MILLIS = 10 * 60_000L;

    /**
     * 리포트 1건 수신 (product/version = 리포트에서 읽은 제품·버전, 모르면 null).
     * 같은 점검에서 온 같은 제품 리포트끼리는 가장 낮은 버전을 기억 → 인스턴스 하나라도 최신 미만이면 자동 점검에서 빠지지 않음.
     * 새 점검이 시작되면(SAME_RUN_MILLIS 경과) 이전 점검의 제품 목록을 비움 → 제품을 지운 서버의 옛 버전이 남지 않음.
     */
    public synchronized void reportReceived(String name, long now, Product product, String version) throws IOException {
        Agent a = require(name);
        boolean sameRun = a.lastReportAt > 0 && now - a.lastReportAt < SAME_RUN_MILLIS;
        if (!sameRun) a.versions.clear();
        if (product != null && version != null) {
            String old = a.versions.get(product);
            if (old == null || ReportParser.compareVersions(version, old) < 0) a.versions.put(product, version);
        }
        a.lastReportAt = now;
        a.lastSeen = now;
        save();
    }

    /** 점검 1회 종료 보고 */
    public synchronized void runFinished(String name, long now, int exit, int reports, String message) throws IOException {
        Agent a = require(name);
        a.runStartedAt = 0;
        a.lastRunAt = now;
        a.lastSeen = now;
        a.lastExit = exit;
        a.lastReportCount = reports;
        a.lastMessage = message == null ? "" : message;
        save();
    }

    private Agent require(String name) {
        Agent a = agents.get(name);
        if (a == null) throw new IllegalArgumentException("에이전트가 없습니다.");
        return a;
    }

    private static boolean eq(String a, String b) {
        return a == null ? b == null : a.equals(b);
    }

    // ------------------------------------------------------------ 파일 저장 (Properties, 키: 이름.항목)
    private void load() throws IOException {
        agents.clear();
        if (!Files.exists(file)) return;
        Properties p = new Properties();
        try (Reader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            p.load(r);
        }
        for (String key : p.stringPropertyNames()) {
            if (!key.endsWith(".tokenHash")) continue;
            String n = key.substring(0, key.length() - ".tokenHash".length());
            if (!validName(n)) continue;
            Agent a = new Agent();
            a.name = n;
            a.tokenHash = p.getProperty(key);
            a.intervalHours = (int) num(p, n + ".intervalHours", 24);
            a.createdAt = num(p, n + ".createdAt", 0);
            a.lastSeen = num(p, n + ".lastSeen", 0);
            a.group = normGroup(p.getProperty(n + ".group", ""));
            a.hostname = p.getProperty(n + ".hostname");
            a.ip = p.getProperty(n + ".ip");
            a.agentVersion = p.getProperty(n + ".agentVersion");
            a.scriptSha256 = p.getProperty(n + ".scriptSha256");
            for (Product prod : Product.values()) {
                String v = p.getProperty(n + ".version." + prod.id);
                if (v != null) a.versions.put(prod, v);
            }
            a.pendingRun = "true".equals(p.getProperty(n + ".pendingRun"));
            a.runStartedAt = num(p, n + ".runStartedAt", 0);
            a.lastRunAt = num(p, n + ".lastRunAt", 0);
            a.lastExit = (int) num(p, n + ".lastExit", -1);
            a.lastReportCount = (int) num(p, n + ".lastReportCount", 0);
            a.lastMessage = p.getProperty(n + ".lastMessage", "");
            a.lastReportAt = num(p, n + ".lastReportAt", 0);
            agents.put(n, a);
        }
    }

    private static long num(Properties p, String k, long def) {
        try {
            return Long.parseLong(p.getProperty(k, String.valueOf(def)));
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private void save() throws IOException {
        Properties p = new Properties();
        for (Agent a : agents.values()) {
            String n = a.name;
            p.setProperty(n + ".tokenHash", a.tokenHash);
            p.setProperty(n + ".intervalHours", String.valueOf(a.intervalHours));
            p.setProperty(n + ".createdAt", String.valueOf(a.createdAt));
            p.setProperty(n + ".lastSeen", String.valueOf(a.lastSeen));
            if (a.group != null && !a.group.isEmpty()) p.setProperty(n + ".group", a.group);
            if (a.hostname != null) p.setProperty(n + ".hostname", a.hostname);
            if (a.ip != null) p.setProperty(n + ".ip", a.ip);
            if (a.agentVersion != null) p.setProperty(n + ".agentVersion", a.agentVersion);
            if (a.scriptSha256 != null) p.setProperty(n + ".scriptSha256", a.scriptSha256);
            a.versions.forEach((prod, v) -> p.setProperty(n + ".version." + prod.id, v));
            p.setProperty(n + ".pendingRun", String.valueOf(a.pendingRun));
            p.setProperty(n + ".runStartedAt", String.valueOf(a.runStartedAt));
            p.setProperty(n + ".lastRunAt", String.valueOf(a.lastRunAt));
            p.setProperty(n + ".lastExit", String.valueOf(a.lastExit));
            p.setProperty(n + ".lastReportCount", String.valueOf(a.lastReportCount));
            p.setProperty(n + ".lastMessage", a.lastMessage == null ? "" : a.lastMessage);
            p.setProperty(n + ".lastReportAt", String.valueOf(a.lastReportAt));
        }
        Path tmp = Files.createTempFile(file.getParent(), ".agents", ".tmp");
        UserStore.restrict(tmp);
        try (Writer w = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
            p.store(w, "webwas-precheck agents (token hashes only)");
        }
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
