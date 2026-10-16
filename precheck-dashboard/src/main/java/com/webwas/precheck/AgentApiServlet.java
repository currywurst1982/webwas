package com.webwas.precheck;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

/**
 * 웹서버에 설치된 에이전트(precheck-agent.sh)가 호출하는 API. 로그인 세션 대신 에이전트 토큰으로 인증.
 *  GET  /agent-api/files/{install.sh|precheck-agent.sh|apache_precheck.sh}  설치 파일 받기 (비밀 정보 없음, 인증 없음)
 *  POST /agent-api/heartbeat   1분마다 상태 보고 → {"run":true|false}
 *  POST /agent-api/report?name=apache_precheck_....txt   리포트 원문 업로드 (본문 = 텍스트)
 *  POST /agent-api/result      점검 1회 종료 보고 (exit, reports, message)
 * 인증 헤더:  X-Precheck-Agent: <에이전트 이름>  /  Authorization: Bearer <토큰>
 */
@WebServlet("/agent-api/*")
public class AgentApiServlet extends HttpServlet {
    private static final Logger LOG = Logger.getLogger(AgentApiServlet.class.getName());
    public static final Set<String> FILES = Set.of("install.sh", "precheck-agent.sh", "apache_precheck.sh");

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String p = req.getPathInfo() == null ? "" : req.getPathInfo();
        if (p.startsWith("/files/") && FILES.contains(p.substring("/files/".length()))) {
            String name = p.substring("/files/".length());
            try (InputStream in = AgentApiServlet.class.getResourceAsStream("/agent/" + name)) {
                if (in == null) {
                    Web.json(resp, 404, Map.of("error", "파일이 WAR 에 없습니다: " + name));
                    return;
                }
                resp.setContentType("text/x-shellscript;charset=UTF-8");
                resp.setHeader("Content-Disposition", "attachment; filename=\"" + name + "\"");
                resp.setHeader("Cache-Control", "no-store");
                in.transferTo(resp.getOutputStream());
            }
            return;
        }
        Web.json(resp, 404, Map.of("error", "없는 주소입니다."));
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String p = req.getPathInfo() == null ? "" : req.getPathInfo();
        AgentStore agents = Web.agents(getServletContext());
        String name = req.getHeader("X-Precheck-Agent");
        String auth = req.getHeader("Authorization");
        String token = auth != null && auth.startsWith("Bearer ") ? auth.substring(7).trim() : null;
        String ip = req.getRemoteAddr();

        LoginThrottle throttle = Web.throttle(getServletContext());
        String key = "agent:" + name;
        long locked = throttle.lockedSeconds(key, ip);
        if (locked > 0) {
            Web.json(resp, 429, Map.of("error", "인증 실패가 반복되어 " + locked + "초 동안 차단되었습니다."));
            return;
        }
        if (!agents.authenticate(name, token)) {
            throttle.failure(key, ip);
            LOG.warning("[precheck-dashboard] 에이전트 인증 실패: agent=" + safe(name) + " ip=" + ip);
            Web.json(resp, 401, Map.of("error", "에이전트 이름 또는 토큰이 올바르지 않습니다."));
            return;
        }
        throttle.success(key, ip);
        long now = System.currentTimeMillis();
        LatestVersion latest = Web.latest(getServletContext());

        try {
            switch (p) {
                case "/heartbeat" -> {
                    String reason = agents.heartbeat(name, now, limit(req.getParameter("hostname"), 255), ip,
                            limit(req.getParameter("version"), 40), limit(req.getParameter("scriptSha256"), 64),
                            "1".equals(req.getParameter("busy")), "1".equals(req.getParameter("probe")),
                            latest.skipUpToDate() ? latest.current() : null);
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("run", reason != null);
                    out.put("reason", reason);
                    out.put("expectedScriptSha256", getServletContext().getAttribute(AppInit.ATTR_SCRIPT_SHA));
                    if (reason != null) LOG.info("[precheck-dashboard] 에이전트 점검 지시: " + name + " (" + reason + ")");
                    Web.json(resp, 200, out);
                }
                case "/report" -> {
                    byte[] body;
                    try (InputStream in = req.getInputStream()) {
                        body = in.readNBytes((int) ReportStore.MAX_FILE_BYTES + 1);
                    }
                    String saved = Web.reports(getServletContext()).saveAgentReport(name, req.getParameter("name"), body);
                    Report saved_ = Web.reports(getServletContext()).get(saved);
                    agents.reportReceived(name, now, saved_ == null ? null : saved_.version);
                    LOG.info("[precheck-dashboard] 에이전트 리포트 수신: " + saved);
                    Web.json(resp, 200, Map.of("saved", saved));
                }
                case "/result" -> {
                    int exit = parseInt(req.getParameter("exit"), -1);
                    int reports = parseInt(req.getParameter("reports"), 0);
                    agents.runFinished(name, now, exit, reports, limit(req.getParameter("message"), 500));
                    Web.json(resp, 200, Map.of("ok", true));
                }
                default -> Web.json(resp, 404, Map.of("error", "없는 주소입니다."));
            }
        } catch (IllegalArgumentException e) {
            Web.json(resp, 400, Map.of("error", e.getMessage()));
        }
    }

    private static int parseInt(String s, int def) {
        try {
            return Integer.parseInt(s == null ? "" : s.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private static String limit(String s, int max) {
        if (s == null) return null;
        s = s.replaceAll("[\\p{Cntrl}&&[^\n]]", "").trim();
        return s.length() > max ? s.substring(0, max) : s;
    }

    private static String safe(String s) {
        return s == null ? "(없음)" : s.replaceAll("[^A-Za-z0-9._-]", "?");
    }
}
