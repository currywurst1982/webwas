package com.webwas.precheck;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Properties;
import java.util.regex.Pattern;

/**
 * 화면 설정 중 서버에 저장하는 값. 지금은 "에이전트 접속 주소" 하나.
 * 에이전트 추가 화면의 설치 명령에 들어가는 대시보드 주소 (비우면 브라우저 주소창 주소를 씀).
 * 예: 관리자는 https://dash.example.com/webwas-precheck 로 접속하지만, 점검 서버는 http://10.0.0.5:8580/webwas-precheck 로 붙어야 할 때.
 * 저장: <데이터폴더>/settings.properties
 */
public class SiteSettings {

    /** 명령에 그대로 들어가므로 셸 특수문자가 없는 주소만 허용 (http(s)://호스트[:포트][/경로]) */
    static final Pattern URL = Pattern.compile(
            "https?://([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|\\[[0-9A-Fa-f:.]+\\])(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?");

    private final Path file;
    private String agentUrl = "";

    public SiteSettings(Path file) throws IOException {
        this.file = file;
        if (Files.isRegularFile(file)) {
            Properties p = new Properties();
            try (Reader rd = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                p.load(rd);
            }
            String v = p.getProperty("agent.url", "");
            agentUrl = v.isEmpty() || URL.matcher(v).matches() ? v : "";
        }
    }

    public synchronized String agentUrl() {
        return agentUrl;
    }

    /** 빈 값이면 해제(브라우저 주소 사용). 끝의 / 는 뗌. 잘못된 주소면 IllegalArgumentException */
    public synchronized String setAgentUrl(String v) throws IOException {
        String s = v == null ? "" : v.trim();
        while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        if (!s.isEmpty()) {
            if (!URL.matcher(s).matches()) {
                throw new IllegalArgumentException("주소 형식이 맞지 않습니다. 예: http://10.0.0.5:8580/webwas-precheck (http:// 또는 https:// 로 시작, 공백·따옴표 없이)");
            }
            String port = s.replaceFirst("^https?://(\\[[^\\]]*\\]|[^/:]*)(:([0-9]+))?.*$", "$3");
            if (!port.isEmpty() && (Integer.parseInt(port) < 1 || Integer.parseInt(port) > 65535)) {
                throw new IllegalArgumentException("포트 번호는 1~65535 사이여야 합니다.");
            }
        }
        agentUrl = s;
        save();
        return agentUrl;
    }

    private void save() throws IOException {
        Properties p = new Properties();
        p.setProperty("agent.url", agentUrl);
        Path dir = file.toAbsolutePath().getParent();
        Files.createDirectories(dir);
        Path tmp = Files.createTempFile(dir, ".settings", ".tmp");
        try (Writer w = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
            p.store(w, "webwas-precheck settings");
        }
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
