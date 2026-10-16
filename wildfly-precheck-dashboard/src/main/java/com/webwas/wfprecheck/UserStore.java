package com.webwas.wfprecheck;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * 사용자 계정 파일(<데이터폴더>/users.properties).
 * 형식: 아이디=pbkdf2$반복수$솔트$해시$역할$비번변경필요(1/0)
 * 비밀번호 원문은 저장하지 않음 (PBKDF2-HMAC-SHA256).
 */
public class UserStore {
    public static final String ROLE_ADMIN = "admin";
    public static final String ROLE_VIEWER = "viewer";
    private static final int ITERATIONS = 210_000;
    private static final Pattern USERNAME = Pattern.compile("^[A-Za-z0-9._-]{3,32}$");
    private static final SecureRandom RANDOM = new SecureRandom();

    public record User(String name, String role, boolean mustChange) {}

    private record Entry(int iterations, byte[] salt, byte[] hash, String role, boolean mustChange) {}

    private final Path file;
    private final Map<String, Entry> users = new TreeMap<>();
    // 존재하지 않는 아이디로 로그인해도 같은 시간이 걸리도록 비교용 더미 해시
    private final Entry dummy;

    public UserStore(Path file) throws IOException {
        this.file = file;
        byte[] s = new byte[16];
        RANDOM.nextBytes(s);
        this.dummy = new Entry(ITERATIONS, s, hash("dummy-password".toCharArray(), s, ITERATIONS), ROLE_VIEWER, false);
        load();
    }

    public synchronized boolean isEmpty() {
        return users.isEmpty();
    }

    public static boolean validUsername(String name) {
        return name != null && USERNAME.matcher(name).matches();
    }

    /** 비밀번호 규칙: 10자 이상, 영문/숫자/특수문자 중 2종 이상, 아이디와 다름. null 이면 통과. */
    public static String passwordProblem(String username, String password) {
        if (password == null || password.length() < 10) return "비밀번호는 10자 이상이어야 합니다.";
        if (password.length() > 128) return "비밀번호가 너무 깁니다.";
        int kinds = 0;
        if (password.matches(".*[A-Za-z].*")) kinds++;
        if (password.matches(".*[0-9].*")) kinds++;
        if (password.matches(".*[^A-Za-z0-9].*")) kinds++;
        if (kinds < 2) return "영문·숫자·특수문자 중 2가지 이상을 섞어 주세요.";
        if (username != null && password.toLowerCase().contains(username.toLowerCase())) {
            return "비밀번호에 아이디를 포함할 수 없습니다.";
        }
        return null;
    }

    public synchronized User authenticate(String name, String password) {
        Entry e = name == null ? null : users.get(name);
        Entry check = e == null ? dummy : e;
        byte[] h = hash(password == null ? new char[0] : password.toCharArray(), check.salt, check.iterations);
        boolean match = MessageDigest.isEqual(h, check.hash);
        if (e == null || !match) return null;
        return new User(name, e.role, e.mustChange);
    }

    public synchronized User find(String name) {
        Entry e = users.get(name);
        return e == null ? null : new User(name, e.role, e.mustChange);
    }

    public synchronized List<User> list() {
        List<User> out = new ArrayList<>();
        users.forEach((k, e) -> out.add(new User(k, e.role, e.mustChange)));
        return out;
    }

    public synchronized void put(String name, String password, String role, boolean mustChange) throws IOException {
        if (!validUsername(name)) throw new IllegalArgumentException("아이디는 영문/숫자/._- 3~32자여야 합니다.");
        if (!ROLE_ADMIN.equals(role) && !ROLE_VIEWER.equals(role)) throw new IllegalArgumentException("잘못된 역할");
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        users.put(name, new Entry(ITERATIONS, salt, hash(password.toCharArray(), salt, ITERATIONS), role, mustChange));
        save();
    }

    public synchronized void changePassword(String name, String newPassword) throws IOException {
        Entry e = users.get(name);
        if (e == null) throw new IllegalArgumentException("사용자 없음");
        put(name, newPassword, e.role, false);
    }

    public synchronized boolean remove(String name) throws IOException {
        boolean removed = users.remove(name) != null;
        if (removed) save();
        return removed;
    }

    public synchronized long adminCount() {
        return users.values().stream().filter(e -> ROLE_ADMIN.equals(e.role)).count();
    }

    public static String randomPassword() {
        String chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) sb.append(chars.charAt(RANDOM.nextInt(chars.length())));
        return sb.append("#").append(RANDOM.nextInt(10)).toString();
    }

    private static byte[] hash(char[] password, byte[] salt, int iterations) {
        try {
            KeySpec spec = new PBEKeySpec(password, salt, iterations, 256);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private void load() throws IOException {
        users.clear();
        if (!Files.exists(file)) return;
        Properties p = new Properties();
        try (Reader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            p.load(r);
        }
        Base64.Decoder d = Base64.getDecoder();
        for (String name : p.stringPropertyNames()) {
            String[] f = p.getProperty(name).split("\\$");
            if (f.length != 6 || !"pbkdf2".equals(f[0])) continue;
            users.put(name, new Entry(Integer.parseInt(f[1]), d.decode(f[2]), d.decode(f[3]), f[4], "1".equals(f[5])));
        }
    }

    private void save() throws IOException {
        Properties p = new Properties();
        Base64.Encoder enc = Base64.getEncoder();
        users.forEach((k, e) -> p.setProperty(k, String.join("$", "pbkdf2", String.valueOf(e.iterations),
                enc.encodeToString(e.salt), enc.encodeToString(e.hash), e.role, e.mustChange ? "1" : "0")));
        Path tmp = Files.createTempFile(file.getParent(), ".users", ".tmp");
        restrict(tmp);
        try (Writer w = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
            p.store(w, "wfprecheck-dashboard users (password hashes only)");
        }
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    /** 소유자만 읽기/쓰기 (리눅스). 윈도우 등 미지원 환경은 무시. */
    static void restrict(Path p) {
        try {
            Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException ignored) {
            // 권한 설정을 지원하지 않는 파일시스템
        }
    }
}
