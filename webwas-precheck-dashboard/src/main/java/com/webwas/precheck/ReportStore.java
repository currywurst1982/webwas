package com.webwas.precheck;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collection;
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
        long h = 17;
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
                    // 원문·[4] 원문은 캐시에 두지 않음 (서버 300대 × 30개 = 9,000개면 수백 MB). 상세·PDF 는 full() 로 다시 읽음
                    r.raw = null;
                    r.section4Raw.clear();
                    cache.put(name, r);
                }
                seen.add(name);
                out.add(r);
                h = h * 31 + name.hashCode();
                h = h * 31 + Long.hashCode(size);
                h = h * 31 + Long.hashCode(mod);
            }
        } catch (IOException e) {
            throw new IllegalStateException("리포트 폴더를 읽을 수 없습니다: " + dir, e);
        }
        cache.keySet().retainAll(seen);
        version = h ^ out.size();
        out.sort(Comparator.comparing((Report r) -> r.checkedAt == null ? "" : r.checkedAt).reversed()
                .thenComparing(r -> r.id));
        return out;
    }

    public Report get(String id) {
        if (!isSafeName(id)) return null;
        return all().stream().filter(r -> r.id.equals(id)).findFirst().orElse(null);
    }

    /** 마지막 all() 때의 폴더 상태(파일명·크기·수정 시각) 요약값. 바뀌지 않았으면 화면에 같은 데이터를 다시 보내지 않음 */
    private volatile long version;

    public long version() {
        return version;
    }

    /** 원문까지 포함한 리포트 1건 (상세 화면·원본 받기·PDF 용). 캐시에 넣지 않음. 없으면 null */
    public Report full(String id) throws IOException {
        if (!isSafeName(id)) return null;
        Path p = dir.resolve(id);
        if (!Files.isRegularFile(p) || Files.size(p) > MAX_FILE_BYTES) return null;
        String text = ReportParser.decode(Files.readAllBytes(p));
        if (!ReportParser.looksLikeReport(text)) return null;
        Report r = ReportParser.parse(id, text);
        r.fileSize = Files.size(p);
        r.fileModified = Files.getLastModifiedTime(p).toMillis();
        return r;
    }

    /** 업로드 파일 저장. 리포트 형식이 아니면 예외. 반환값은 저장된 파일명. */
    public synchronized String save(String originalName, byte[] bytes) throws IOException {
        if (bytes.length == 0 || bytes.length > MAX_FILE_BYTES) {
            throw new IllegalArgumentException("파일 크기가 0이거나 5MB를 넘습니다.");
        }
        String text = ReportParser.decode(bytes);
        if (!ReportParser.looksLikeReport(text)) {
            throw new IllegalArgumentException("점검 리포트 형식이 아닙니다 (첫 줄에 '"
                    + ReportParser.HEADER_MARK + "' 없음). apache_precheck.sh / wildfly_precheck.sh / tomcat_precheck.sh / nginx_precheck.sh 결과 파일을 올려 주세요.");
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

    /**
     * 직접 업로드한 리포트를 인스턴스(호스트·제품·설치 폴더)마다 보관하는 개수. 넘으면 오래된 것부터 삭제.
     * -Dwebwas.precheck.keep.uploads=개수 로 바꿈 (0 = 제한 없음). 기본 30 (에이전트 리포트와 같은 기준)
     */
    public static int keepUploads() {
        try {
            return Math.max(0, Integer.parseInt(System.getProperty("webwas.precheck.keep.uploads", "30").trim()));
        } catch (NumberFormatException e) {
            return 30;
        }
    }

    /** 화면에서 직접 업로드: 저장한 뒤 같은 인스턴스의 직접 업로드분이 보관 개수를 넘으면 오래된 것 삭제. 반환값 = 저장된 파일명 */
    public synchronized String saveUpload(String originalName, byte[] bytes) throws IOException {
        String saved = save(originalName, bytes);
        int keep = keepUploads();
        if (keep <= 0) return saved;
        List<Report> all = all();                    // 최신순
        Report me = all.stream().filter(r -> r.id.equals(saved)).findFirst().orElse(null);
        if (me == null) return saved;
        List<Report> same = all.stream().filter(r -> r.source == null && r.instanceKey().equals(me.instanceKey())).toList();
        for (Report old : same.subList(Math.min(keep, same.size()), same.size())) {
            if (old.id.equals(saved)) continue;      // 방금 올린 것은 (점검 일시가 오래됐어도) 지우지 않음
            cache.remove(old.id);
            Files.deleteIfExists(dir.resolve(old.id));
        }
        return saved;
    }

    /** 에이전트 1대가 보관하는 최근 리포트 수 (이보다 오래된 것은 자동 삭제) */
    public static final int KEEP_PER_AGENT = 30;
    private static final Pattern AGENT_REPORT = Pattern.compile("^(apache|wildfly|tomcat|nginx)_precheck_[A-Za-z0-9._-]{1,150}\\.txt$");

    /**
     * 에이전트가 보낸 리포트 저장. 파일명은 agent-<에이전트>__<원래 파일명> 이 되어
     * 화면에 "어느 에이전트가 보냈는지"가 표시되고, 다른 에이전트 파일을 덮어쓸 수 없음.
     */
    public synchronized String saveAgentReport(String agent, String originalName, byte[] bytes) throws IOException {
        if (!AgentStore.validName(agent)) throw new IllegalArgumentException("잘못된 에이전트 이름");
        if (originalName == null || !AGENT_REPORT.matcher(originalName).matches()) {
            throw new IllegalArgumentException("리포트 파일명은 {apache|wildfly|tomcat|nginx}_precheck_*.txt 형식이어야 합니다.");
        }
        String saved = save("agent-" + agent + "__" + originalName, bytes);
        prune("agent-" + agent + "__", KEEP_PER_AGENT);
        return saved;
    }

    /** 접두어가 같은 파일 중 최근 keep 개만 남기고 삭제 (수정 시각 기준). */
    private void prune(String prefix, int keep) throws IOException {
        List<Path> files = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, prefix + "*.txt")) {
            ds.forEach(files::add);
        }
        if (files.size() <= keep) return;
        files.sort(Comparator.comparing((Path p) -> {
            try {
                return Files.getLastModifiedTime(p).toMillis();
            } catch (IOException e) {
                return 0L;
            }
        }).reversed().thenComparing(Comparator.<Path>naturalOrder().reversed()));
        for (Path p : files.subList(keep, files.size())) {
            cache.remove(p.getFileName().toString());
            Files.deleteIfExists(p);
        }
    }

    /** 리포트 1건 삭제 = 휴지통으로 이동 */
    public synchronized boolean delete(String id) throws IOException {
        return trash(List.of(id), "one") == 1;
    }

    /** 휴지통 보관 일수 (-Dwebwas.precheck.trash.days, 기본 30. 0 이면 바로 지움) */
    public static int trashDays() {
        try {
            return Math.max(0, Integer.parseInt(System.getProperty("webwas.precheck.trash.days", "30").trim()));
        } catch (NumberFormatException e) {
            return 30;
        }
    }

    /** 휴지통 위치: <데이터폴더>/reports-trash */
    public Path trashRoot() {
        Path parent = dir.toAbsolutePath().getParent();
        return (parent == null ? dir.toAbsolutePath() : parent).resolve("reports-trash");
    }

    private static final java.time.format.DateTimeFormatter TRASH_TS = java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS");

    /**
     * 리포트들을 휴지통(<데이터>/reports-trash/<시각>_<사유>/)으로 옮김. 옮긴 개수를 돌려줌.
     * 되살리기: 그 폴더의 파일을 reports 폴더로 다시 옮기면 됨. 보관 기간이 지난 휴지통 폴더는 이때 함께 비움.
     */
    public synchronized int trash(Collection<String> ids, String reason) throws IOException {
        String tag = reason == null ? "reset" : reason.replaceAll("[^A-Za-z0-9_-]", "").toLowerCase(java.util.Locale.ROOT);
        Path target = trashRoot().resolve(java.time.LocalDateTime.now().format(TRASH_TS) + "_" + (tag.isEmpty() ? "reset" : tag));
        int n = 0;
        for (String id : ids) {
            if (!isSafeName(id)) continue;
            Path src = dir.resolve(id);
            if (!Files.isRegularFile(src)) continue;
            if (n == 0) Files.createDirectories(target);
            Files.move(src, target.resolve(id), StandardCopyOption.REPLACE_EXISTING);
            cache.remove(id);
            n++;
        }
        lastTrash = n > 0 ? target : null;
        purgeTrash();
        return n;
    }

    private volatile Path lastTrash;

    /** 마지막 trash() 가 옮긴 폴더 (없으면 null) */
    public Path lastTrash() {
        return lastTrash;
    }

    /** 보관 기간이 지난 휴지통 폴더 삭제 (실패해도 조용히 넘어감) */
    public void purgeTrash() {
        Path root = trashRoot();
        if (!Files.isDirectory(root)) return;
        long limit = System.currentTimeMillis() - trashDays() * 86_400_000L;
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(root)) {
            for (Path d : ds) {
                if (!Files.isDirectory(d) || Files.getLastModifiedTime(d).toMillis() > limit) continue;
                try (java.util.stream.Stream<Path> w = Files.walk(d)) {
                    w.sorted(Comparator.reverseOrder()).forEach(x -> {
                        try {
                            Files.deleteIfExists(x);
                        } catch (IOException ignored) {
                            // 다음 정리 때 다시 시도
                        }
                    });
                }
            }
        } catch (IOException ignored) {
            // 휴지통을 못 읽어도 대시보드 동작에는 영향 없음
        }
    }
}
