package com.webwas.precheck;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * 리포트 보관 폴더(<데이터폴더>/reports)를 읽어 해석 결과를 캐시.
 * 웹 업로드 외에 scp 등으로 폴더에 직접 넣은 파일도 자동으로 반영됨.
 */
public class ReportStore {
    public static final long MAX_FILE_BYTES = 5L * 1024 * 1024;
    private static final Pattern SAFE_NAME = Pattern.compile("^[A-Za-z0-9._-]{1,200}\\.txt$");

    private final Path dir;
    private final Map<String, Report> cache = new ConcurrentHashMap<>();

    public ReportStore(Path dir) {
        this.dir = dir;
    }

    public Path dir() {
        return dir;
    }

    public static boolean isSafeName(String name) {
        return name != null && SAFE_NAME.matcher(name).matches() && !name.startsWith(".");
    }

    /** 전체 리포트 (점검 일시 최신순). */
    public synchronized List<Report> all() {
        List<Report> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, "*.txt")) {
            for (Path p : ds) {
                String name = p.getFileName().toString();
                if (!isSafeName(name) || !Files.isRegularFile(p)) continue;
                long size = Files.size(p), mod = Files.getLastModifiedTime(p).toMillis();
                if (size > MAX_FILE_BYTES) continue;
                Report r = cache.get(name);
                if (r == null || r.fileSize != size || r.fileModified != mod) {
                    String text = ReportParser.decode(Files.readAllBytes(p));
                    if (!ReportParser.looksLikeReport(text)) continue;
                    r = ReportParser.parse(name, text);
                    r.fileSize = size;
                    r.fileModified = mod;
                    cache.put(name, r);
                }
                seen.add(name);
                out.add(r);
            }
        } catch (IOException e) {
            throw new IllegalStateException("리포트 폴더를 읽을 수 없습니다: " + dir, e);
        }
        cache.keySet().retainAll(seen);
        out.sort(Comparator.comparing((Report r) -> r.checkedAt == null ? "" : r.checkedAt).reversed()
                .thenComparing(r -> r.id));
        return out;
    }

    public Report get(String id) {
        if (!isSafeName(id)) return null;
        return all().stream().filter(r -> r.id.equals(id)).findFirst().orElse(null);
    }

    /** 업로드 파일 저장. 리포트 형식이 아니면 예외. 반환값은 저장된 파일명. */
    public synchronized String save(String originalName, byte[] bytes) throws IOException {
        if (bytes.length == 0 || bytes.length > MAX_FILE_BYTES) {
            throw new IllegalArgumentException("파일 크기가 0이거나 5MB를 넘습니다.");
        }
        String text = ReportParser.decode(bytes);
        if (!ReportParser.looksLikeReport(text)) {
            throw new IllegalArgumentException("apache_precheck.sh 리포트 형식이 아닙니다 (첫 줄에 '"
                    + ReportParser.HEADER_MARK + "' 없음).");
        }
        String base = originalName == null ? "" : originalName.replace('\\', '/');
        base = base.substring(base.lastIndexOf('/') + 1).replaceAll("[^A-Za-z0-9._-]", "_");
        if (!base.endsWith(".txt")) base = base + ".txt";
        if (!isSafeName(base)) base = "report_" + System.currentTimeMillis() + ".txt";
        Path target = dir.resolve(base).normalize();
        if (!target.getParent().equals(dir.normalize())) throw new IllegalArgumentException("잘못된 파일명");
        Path tmp = Files.createTempFile(dir, ".upload", ".tmp");
        Files.write(tmp, bytes);
        Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        return base;
    }

    public synchronized boolean delete(String id) throws IOException {
        if (!isSafeName(id)) return false;
        cache.remove(id);
        return Files.deleteIfExists(dir.resolve(id));
    }
}
