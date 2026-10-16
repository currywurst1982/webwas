package com.webwas.wfprecheck;

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
import java.util.Base64;
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
 * 에이전트는 WildFly 서버에서 1분마다 대시보드에 "점검할 차례인지"를 묻고(heartbeat),
 * 차례이면 서버에 설치된 wildfly_precheck.sh 를 실행해 결과를 올림.
 * 대시보드는 "실행해/말아" 만 알려 줄 뿐 명령어나 인자를 보내지 않음.
 */
public class AgentStore {
    /** 에이전트 이름: 리포트 파일명 접두어로 쓰므로 밑줄(_) 불가. */
    private static final Pattern NAME = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9.-]{1,39}$");
    private static final SecureRandom RANDOM = new SecureRandom();
    /** 마지막 접속 후 이 시간이 지나면 오프라인 */
    public static final long OFFLINE_MILLIS = 3 * 60 * 1000L;
    /** "실행" 응답 후 이 시간 안에 결과가 없으면 실패로 보고 다시 실행 가능 */
    public static final long RUN_TIMEOUT_MILLIS = 2 * 60 * 60 * 1000L;
    /** lastSeen 만 바뀐 경우 파일 저장 간격 */
    private static final long PERSIST_SEEN_MILLIS = 10 * 60 * 1000L;

    public static final class Agent {
        public String name;
        public String tokenHash;
        public int intervalHours = 24;       // 0 = 수동 점검만
        public long createdAt;
        public long lastSeen;
        public long lastSeenPersisted;
        public String hostname;
        public String ip;
        public String agentVersion;
        public String scriptSha256;
        public String wildflyVersion;         // 마지막 리포트에서 읽은 WildFly 버전
        public boolean pendingRun;           // 관리자가 "지금 점검" 요청
        public long runStartedAt;            // 에이전트에게 실행하라고 응답한 시각 (0 = 실행 중 아님)
        public long lastRunAt;               // 마지막 실행 완료 시각
        public int lastExit = -1;
        public int lastReportCount;
        public String lastMessage = "";
        public long lastReportAt;            // 마지막 리포트 수신 시각

        Agent copy() {
            Agent a = new Agent();
            a.name = name; a.tokenHash = tokenHash; a.intervalHours = intervalHours; a.createdAt = createdAt;
            a.lastSeen = lastSeen; a.lastSeenPersisted = lastSeenPersisted; a.hostname = hostname; a.ip = ip;
            a.agentVersion = agentVersion; a.scriptSha256 = scriptSha256; a.pendingRun = pendingRun;
            a.wildflyVersion = wildflyVersion;
            a.runStartedAt = runStartedAt; a.lastRunAt = lastRunAt; a.lastExit = lastExit;
            a.lastReportCount = lastReportCount; a.lastMessage = lastMessage; a.lastReportAt = lastReportAt;
            return a;
        }

        /** online | offline | never | running | requested */
        public String state(long now) {
            if (lastSeen == 0) return "never";
            if (now - lastSeen > OFFLINE_MILLIS) return "offline";
            if (runStartedAt > 0 && now - runStartedAt < RUN_TIMEOUT_MILLIS) return "running";
            if (pendingRun) return "requested";
            return "online";
        }

        public Map<String, Object> toMap(long now, String expectedSha) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", name);
            m.put("state", state(now));
            m.put("intervalHours", intervalHours);
            m.put("createdAt", createdAt);
            m.put("lastSeen", lastSeen);
            m.put("hostname", hostname);
            m.put("ip", ip);
            m.put("agentVersion", agentVersion);
            m.put("scriptSha256", scriptSha256);
            m.put("wildflyVersion", wildflyVersion);
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
        return n != null && NAME.matcher(n).matches();
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

    private static String newToken() {
        byte[] b = new byte[32];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
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
    public synchronized String create(String name, int intervalHours) throws IOException {
        if (!validName(name)) throw new IllegalArgumentException("에이전트 이름은 영문/숫자/.- 2~40자여야 합니다. (밑줄 불가)");
        if (agents.containsKey(name)) throw new IllegalArgumentException("이미 있는 에이전트 이름입니다.");
        if (!validInterval(intervalHours)) throw new IllegalArgumentException("점검 주기가 올바르지 않습니다.");
        String token = newToken();
        Agent a = new Agent();
        a.name = name;
        a.tokenHash = sha256(token);
        a.intervalHours = intervalHours;
        a.createdAt = System.currentTimeMillis();
        agents.put(name, a);
        save();
        return token;
    }

    public synchronized String rotateToken(String name) throws IOException {
        Agent a = require(name);
        String token = newToken();
        a.tokenHash = sha256(token);
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

    public synchronized boolean remove(String name) throws IOException {
        boolean r = agents.remove(name) != null;
        if (r) save();
        return r;
    }

    /** 토큰 확인. 맞으면 true (시간차 공격 방지를 위해 상수시간 비교). */
    public synchronized boolean authenticate(String name, String token) {
        Agent a = name == null ? null : agents.get(name);
        String expected = a == null ? sha256("no-such-agent") : a.tokenHash;
        boolean ok = MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                sha256(token == null ? "" : token).getBytes(StandardCharsets.UTF_8));
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
     * skipAtOrAbove 가 있으면 이 버전 이상(=최신)인 서버는 자동(주기) 점검을 하지 않음. "지금 점검"은 항상 실행.
     */
    public synchronized String heartbeat(String name, long now, String hostname, String ip, String version,
                                         String scriptSha, boolean busy, boolean probe, String skipAtOrAbove) throws IOException {
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
                else if (a.intervalHours > 0 && !upToDate(a, skipAtOrAbove) && (a.lastReportAt == 0 || now - a.lastReportAt >= a.intervalHours * 3_600_000L)
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
    public static boolean upToDate(Agent a, String latest) {
        return latest != null && a.wildflyVersion != null && ReportParser.compareVersions(a.wildflyVersion, latest) >= 0;
    }

    /** 리포트 1건 수신 */
    public synchronized void reportReceived(String name, long now) throws IOException {
        reportReceived(name, now, null);
    }

    /** 한 번의 점검에서 온 리포트로 보는 간격 (한 서버에 WildFly 인스턴스가 여러 개면 리포트가 연달아 옴) */
    static final long SAME_RUN_MILLIS = 10 * 60_000L;

    /**
     * 리포트 1건 수신 (wildflyVersion = 리포트에서 읽은 버전, 모르면 null).
     * 같은 점검에서 온 리포트끼리는 가장 낮은 버전을 기억 → 인스턴스 하나라도 최신 미만이면 자동 점검에서 빠지지 않음.
     */
    public synchronized void reportReceived(String name, long now, String wildflyVersion) throws IOException {
        Agent a = require(name);
        if (wildflyVersion != null) {
            boolean sameRun = a.lastReportAt > 0 && now - a.lastReportAt < SAME_RUN_MILLIS;
            if (!sameRun || a.wildflyVersion == null || ReportParser.compareVersions(wildflyVersion, a.wildflyVersion) < 0) {
                a.wildflyVersion = wildflyVersion;
            }
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
            a.hostname = p.getProperty(n + ".hostname");
            a.ip = p.getProperty(n + ".ip");
            a.agentVersion = p.getProperty(n + ".agentVersion");
            a.scriptSha256 = p.getProperty(n + ".scriptSha256");
            a.wildflyVersion = p.getProperty(n + ".wildflyVersion");
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
            if (a.hostname != null) p.setProperty(n + ".hostname", a.hostname);
            if (a.ip != null) p.setProperty(n + ".ip", a.ip);
            if (a.agentVersion != null) p.setProperty(n + ".agentVersion", a.agentVersion);
            if (a.scriptSha256 != null) p.setProperty(n + ".scriptSha256", a.scriptSha256);
            if (a.wildflyVersion != null) p.setProperty(n + ".wildflyVersion", a.wildflyVersion);
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
            p.store(w, "wfprecheck-dashboard agents (token hashes only)");
        }
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
