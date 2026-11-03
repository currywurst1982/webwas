package com.webwas.precheck;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

/**
 * 인터넷 자료(최신 버전 목록, CVE 데이터) 받기.
 * 주소가 file: 로 시작하면 대시보드 서버의 파일을 읽음 → 인터넷이 막힌 환경에서는 관리자가 내려받은 파일을 두고 그 경로를 지정.
 */
final class Fetch {
    private Fetch() {}

    /** 한 번에 받을 수 있는 최대 크기 (OSV Maven 전체 zip 이 약 10MB) */
    static final long MAX_BYTES = 200L * 1024 * 1024;

    private static final HttpClient CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    static String text(String url) throws IOException, InterruptedException {
        return new String(bytes(url, Duration.ofSeconds(30)), StandardCharsets.UTF_8);
    }

    static byte[] bytes(String url, Duration timeout) throws IOException, InterruptedException {
        URI uri = URI.create(url);
        if ("file".equalsIgnoreCase(uri.getScheme())) {
            Path p = Path.of(uri);
            if (Files.size(p) > MAX_BYTES) throw new IOException("파일이 너무 큽니다: " + p);
            return Files.readAllBytes(p);
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) && !"http".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("지원하지 않는 주소: " + url);
        }
        HttpRequest req = HttpRequest.newBuilder(uri)
                .timeout(timeout)
                .header("User-Agent", "webwas-precheck")
                .GET().build();
        HttpResponse<byte[]> resp = CLIENT.send(req, HttpResponse.BodyHandlers.ofByteArray());
        if (resp.statusCode() != 200) throw new IOException("HTTP " + resp.statusCode());
        if (resp.body().length > MAX_BYTES) throw new IOException("응답이 너무 큽니다");
        return resp.body();
    }
}
