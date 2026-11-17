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
 * 서버(웹서버·WAS)에 설치된 에이전트(webwas-precheck-agent.sh)가 호출하는 API. 로그인 세션 대신 에이전트 토큰으로 인증.
 *  GET  /agent-api/files/{install.sh|webwas-precheck-agent.sh|apache_precheck.sh|wildfly_precheck.sh|tomcat_precheck.sh|nginx_precheck.sh}
 *       설치 파일 받기 (비밀 정보 없음, 인증 없음)
 *  GET  /agent-api/cve/{apache|wildfly|tomcat|nginx}   최신 CVE 목록 (스크립트 형식, 공개 정보라 인증 없음)
 *  POST /agent-api/heartbeat   1분마다 상태 보고 → {"run":true|false}
 *  POST /agent-api/report?name={apache|wildfly|tomcat|nginx}_precheck_....txt   리포트 원문 업로드 (본문 = 텍스트)
 *  POST /agent-api/result      점검 1회 종료 보고 (exit, reports, message)
 * 인증 헤더:  X-Precheck-Agent: <에이전트 이름>  /  Authorization: Bearer <토큰>
 */
@WebServlet("/agent-api/*")
public class AgentApiServlet extends HttpServlet {
    private static final Logger LOG = Logger.getLogger(AgentApiServlet.class.getName());
    public static final Set<String> FILES = Set.of("install.sh", "webwas-precheck-agent.sh",
            "apache_precheck.sh", "wildfly_precheck.sh", "tomcat_precheck.sh", "nginx_precheck.sh");

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
        if (p.startsWith("/cve/") && Product.byId(p.substring("/cve/".length())) != null) {
            Product prod = Product.byId(p.substring("/cve/".length()));
            String text = Web.cve(getServletContext()).dbText(prod, Web.latest(getServletContext()).get(prod).current());
            resp.setContentType("text/plain;charset=UTF-8");
            resp.setHeader("Content-Disposition", "attachment; filename=\"" + prod.id + "_cve.txt\"");
            resp.setHeader("Cache-Control", "no-store");
            resp.getWriter().write(text);
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
            agents.authFailed(name, ip, System.currentTimeMillis(), true);
            Web.json(resp, 429, Map.of("error", "인증 실패가 반복되어 " + locked + "초 동안 차단되었습니다."));
            return;
        }
        if (!agents.authenticate(name, token)) {
            throttle.failure(key, ip);
            agents.authFailed(name, ip, System.currentTimeMillis(), false);
            LOG.warning("[webwas-precheck] 에이전트 인증 실패: agent=" + safe(name) + " ip=" + ip);
            Web.json(resp, 401, Map.of("error", "에이전트 이름 또는 토큰이 올바르지 않습니다."));
            return;
        }
        throttle.success(key, ip);
        long now = System.currentTimeMillis();
        LatestVersions latest = Web.latest(getServletContext());

        try {
            switch (p) {
                case "/heartbeat" -> {
                    boolean busy = "1".equals(req.getParameter("busy"));
                    boolean probe = "1".equals(req.getParameter("probe"));
                    String reason = agents.heartbeat(name, now, limit(req.getParameter("hostname"), 255), ip,
                            limit(req.getParameter("version"), 40), limit(req.getParameter("scriptSha256"), 64),
                            busy, probe, latest.skipUpToDate() ? latest : null);
                    Map<String, Object> out = new LinkedHashMap<>();
                    // 점검 중(busy)·설치 확인(probe) heartbeat 에서는 업데이트 플래그를 소모하지 않는다.
                    // 그때 에이전트는 응답을 버리므로(점검이 끝날 때까지 스크립트를 안 받음), 소모하면 요청이 유실돼 영영 업데이트가 안 됨.
                    // 점검이 끝난 뒤의 정식 poll(busy=0)에서 플래그를 받아 실제로 교체한다.
                    boolean doUpdate = !busy && !probe && agents.takePendingUpdate(name);
                    out.put("run", reason != null);
                    out.put("reason", reason);
                    out.put("update", doUpdate);
                    out.put("expectedScriptSha256", getServletContext().getAttribute(AppInit.ATTR_SCRIPT_SHA));
                    SiteSettings settings = Web.settings(getServletContext());
                    // 이 에이전트 전용값(설정돼 있으면)이 공통값보다 우선
                    int rd = agents.effectiveRecentDays(name, settings.recentDays());
                    int rt = agents.effectiveRunTimeout(name, settings.runTimeout());
                    int ms = agents.effectiveMaxLogScanMb(name, settings.maxLogScanMb());
                    if (rd > 0) out.put("recentDays", rd);
                    if (rt > 0) out.put("runTimeout", rt);
                    if (ms > 0) out.put("maxLogScanMb", ms);
                    // 점검 중단 요청: 소모하지 않고(idempotent) 점검이 끝날 때까지 계속 내려준다. keepalive(점검 중 busy 신호)가 받아 중단.
                    if (agents.isAbortPending(name)) out.put("abort", true);
                    if (reason != null) LOG.info("[webwas-precheck] 에이전트 점검 지시: " + name + " (" + reason + ")");
                    if (doUpdate) LOG.info("[webwas-precheck] 에이전트 스크립트 업데이트 지시: " + name);
                    Web.json(resp, 200, out);
                }
                case "/report" -> {
                    byte[] body;
                    try (InputStream in = req.getInputStream()) {
                        body = in.readNBytes((int) ReportStore.MAX_FILE_BYTES + 1);
                    }
                    String saved = Web.reports(getServletContext()).saveAgentReport(name, req.getParameter("name"), body);
                    Report saved_ = Web.reports(getServletContext()).get(saved);
                    agents.reportReceived(name, now, saved_ == null ? null : saved_.product, saved_ == null ? null : saved_.version);
                    LOG.info("[webwas-precheck] 에이전트 리포트 수신: " + saved);
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
