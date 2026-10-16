package com.webwas.precheck;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.MultipartConfig;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Part;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * 대시보드 화면이 사용하는 JSON API. (로그인·CSRF 검사는 AuthFilter 에서 끝난 상태)
 *  GET    /api/me                    현재 사용자
 *  GET    /api/reports               리포트 요약 목록
 *  GET    /api/reports/{파일명}       리포트 상세
 *  GET    /api/reports/{파일명}/raw   원본 텍스트
 *  POST   /api/reports               리포트 업로드 (관리자, multipart "files")
 *  DELETE /api/reports/{파일명}       리포트 삭제 (관리자)
 *  GET    /api/users                 사용자 목록 (관리자)
 *  POST   /api/users                 사용자 추가 (관리자) → 임시 비밀번호 반환
 *  POST   /api/users/{아이디}/reset   비밀번호 초기화 (관리자) → 임시 비밀번호 반환
 *  DELETE /api/users/{아이디}         사용자 삭제 (관리자)
 *  GET    /api/agents                에이전트 목록·상태
 *  POST   /api/agents                에이전트 등록 (관리자) → 토큰 반환(한 번만)
 *  POST   /api/agents-run            전체 에이전트 "지금 점검" 요청 (관리자)
 *  POST   /api/agents/{이름}/run      "지금 점검" 요청 (관리자)
 *  POST   /api/agents/{이름}/token    토큰 재발급 (관리자)
 *  POST   /api/agents/{이름}/interval 점검 주기 변경 (관리자, hours)
 *  DELETE /api/agents/{이름}          에이전트 삭제 (관리자)
 *  GET    /api/reports/{파일명}/intrusion.pdf  [4] 침해 흔적만 발췌한 PDF
 *  GET    /api/suspects.pdf          침해 의심 서버 전체 PDF (인스턴스별 최신 점검)
 *  GET    /api/latest-version        Apache 최신 버전 정보
 *  POST   /api/latest-version        (관리자) action=refresh | auto | manual(version) | skip(value=true/false)
 */
@WebServlet("/api/*")
@MultipartConfig(maxFileSize = ReportStore.MAX_FILE_BYTES, maxRequestSize = 60L * 1024 * 1024, fileSizeThreshold = 1024 * 1024)
public class ApiServlet extends HttpServlet {
    private static final Logger LOG = Logger.getLogger(ApiServlet.class.getName());

    private String[] parts(HttpServletRequest req) {
        String p = req.getPathInfo();
        if (p == null || p.equals("/")) return new String[0];
        return p.substring(1).split("/");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String[] p = parts(req);
        ReportStore store = Web.reports(getServletContext());
        if (p.length == 1 && p[0].equals("me")) {
            Web.json(resp, 200, Map.of("user", Web.user(req), "admin", Web.isAdmin(req),
                    "csrf", Web.csrf(req.getSession()), "reportDir", Web.isAdmin(req) ? store.dir().toString() : ""));
        } else if (p.length == 1 && p[0].equals("reports")) {
            String latest = Web.latest(getServletContext()).current();
            Web.json(resp, 200, store.all().stream().map(r -> r.toSummary(latest)).toList());
        } else if ((p.length == 2 || p.length == 3) && p[0].equals("reports")) {
            Report r = store.get(p[1]);
            if (r == null) {
                Web.json(resp, 404, Map.of("error", "리포트를 찾을 수 없습니다."));
            } else if (p.length == 3 && p[2].equals("raw")) {
                resp.setContentType("text/plain;charset=UTF-8");
                resp.setHeader("Content-Disposition", "attachment; filename=\"" + r.id + "\"");
                resp.setHeader("Cache-Control", "no-store");
                resp.getWriter().write(r.raw);
            } else if (p.length == 3 && p[2].equals("intrusion.pdf")) {
                LOG.info("[precheck-dashboard] 침해 흔적 PDF: " + r.id + " by " + Web.user(req));
                sendPdf(resp, IntrusionPdf.single(r, Web.latest(getServletContext()).current(), Web.user(req)),
                        "intrusion_" + ascii(r.host) + "_" + ascii(r.checkedAt) + ".pdf");
            } else if (p.length == 2) {
                Web.json(resp, 200, r.toDetail(Web.latest(getServletContext()).current()));
            } else {
                Web.json(resp, 404, Map.of("error", "없는 주소입니다."));
            }
        } else if (p.length == 1 && p[0].equals("suspects.pdf")) {
            List<Report> suspects = suspects(store.all());
            if (suspects.isEmpty()) {
                Web.json(resp, 404, Map.of("error", "침해 의심 서버가 없습니다."));
                return;
            }
            LOG.info("[precheck-dashboard] 침해 의심 서버 전체 PDF (" + suspects.size() + "대) by " + Web.user(req));
            sendPdf(resp, IntrusionPdf.combined(suspects, Web.latest(getServletContext()).current(), Web.user(req)),
                    "intrusion_suspects_" + java.time.LocalDate.now() + ".pdf");
        } else if (p.length == 1 && p[0].equals("latest-version")) {
            Web.json(resp, 200, Web.latest(getServletContext()).toMap());
        } else if (p.length == 1 && p[0].equals("agents")) {
            long now = System.currentTimeMillis();
            Object sha = getServletContext().getAttribute(AppInit.ATTR_SCRIPT_SHA);
            String expected = sha == null ? null : sha.toString();
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("now", now);
            out.put("expectedScriptSha256", expected);
            LatestVersion lv = Web.latest(getServletContext());
            String latest = lv.current();
            out.put("latest", latest);
            out.put("agents", Web.agents(getServletContext()).list().stream().map(a -> {
                Map<String, Object> m = a.toMap(now, expected);
                m.put("upToDate", AgentStore.upToDate(a, latest));
                m.put("autoSkipped", lv.skipUpToDate() && AgentStore.upToDate(a, latest));
                return m;
            }).toList());
            Web.json(resp, 200, out);
        } else if (p.length == 1 && p[0].equals("users")) {
            if (!requireAdmin(req, resp)) return;
            List<Map<String, Object>> out = new ArrayList<>();
            for (UserStore.User u : Web.users(getServletContext()).list()) {
                out.add(Map.of("name", u.name(), "role", u.role(), "mustChange", u.mustChange()));
            }
            Web.json(resp, 200, out);
        } else {
            Web.json(resp, 404, Map.of("error", "없는 주소입니다."));
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        String[] p = parts(req);
        if (!requireAdmin(req, resp)) return;
        if (p.length >= 1 && (p[0].equals("agents") || p[0].equals("agents-run"))) {
            agentAction(req, resp, p);
        } else if (p.length == 1 && p[0].equals("latest-version")) {
            LatestVersion lv = Web.latest(getServletContext());
            String action = req.getParameter("action");
            try {
                switch (action == null ? "" : action) {
                    case "refresh" -> lv.refresh();
                    case "auto" -> lv.setAuto();
                    case "manual" -> lv.setManual(req.getParameter("version") == null ? null : req.getParameter("version").trim());
                    case "skip" -> lv.setSkipUpToDate("true".equals(req.getParameter("value")));
                    default -> throw new IllegalArgumentException("알 수 없는 작업입니다.");
                }
            } catch (IllegalArgumentException e) {
                Web.json(resp, 400, Map.of("error", e.getMessage()));
                return;
            }
            LOG.info("[precheck-dashboard] 최신 버전 설정 변경(" + action + ") by " + Web.user(req) + " → " + lv.current());
            Web.json(resp, 200, lv.toMap());
        } else if (p.length == 1 && p[0].equals("reports")) {
            upload(req, resp);
        } else if (p.length == 1 && p[0].equals("users")) {
            String name = trim(req.getParameter("name"));
            String role = req.getParameter("role");
            UserStore users = Web.users(getServletContext());
            if (!UserStore.validUsername(name)) {
                Web.json(resp, 400, Map.of("error", "아이디는 영문/숫자/._- 3~32자여야 합니다."));
                return;
            }
            if (users.find(name) != null) {
                Web.json(resp, 409, Map.of("error", "이미 있는 아이디입니다."));
                return;
            }
            String temp = UserStore.randomPassword();
            users.put(name, temp, UserStore.ROLE_ADMIN.equals(role) ? UserStore.ROLE_ADMIN : UserStore.ROLE_VIEWER, true);
            LOG.info("[precheck-dashboard] 사용자 추가: " + name + " by " + Web.user(req));
            Web.json(resp, 200, Map.of("name", name, "tempPassword", temp));
        } else if (p.length == 3 && p[0].equals("users") && p[2].equals("reset")) {
            UserStore users = Web.users(getServletContext());
            UserStore.User u = users.find(p[1]);
            if (u == null) {
                Web.json(resp, 404, Map.of("error", "사용자가 없습니다."));
                return;
            }
            String temp = UserStore.randomPassword();
            users.put(u.name(), temp, u.role(), true);
            LOG.info("[precheck-dashboard] 비밀번호 초기화: " + u.name() + " by " + Web.user(req));
            Web.json(resp, 200, Map.of("name", u.name(), "tempPassword", temp));
        } else {
            Web.json(resp, 404, Map.of("error", "없는 주소입니다."));
        }
    }

    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String[] p = parts(req);
        if (!requireAdmin(req, resp)) return;
        if (p.length == 2 && p[0].equals("reports")) {
            boolean ok = Web.reports(getServletContext()).delete(p[1]);
            if (ok) LOG.info("[precheck-dashboard] 리포트 삭제: " + p[1] + " by " + Web.user(req));
            Web.json(resp, ok ? 200 : 404, Map.of("deleted", ok));
        } else if (p.length == 2 && p[0].equals("agents")) {
            boolean ok = Web.agents(getServletContext()).remove(p[1]);
            if (ok) LOG.info("[precheck-dashboard] 에이전트 삭제: " + p[1] + " by " + Web.user(req));
            Web.json(resp, ok ? 200 : 404, Map.of("deleted", ok));
        } else if (p.length == 2 && p[0].equals("users")) {
            UserStore users = Web.users(getServletContext());
            UserStore.User u = users.find(p[1]);
            if (u == null) {
                Web.json(resp, 404, Map.of("error", "사용자가 없습니다."));
            } else if (u.name().equals(Web.user(req))) {
                Web.json(resp, 400, Map.of("error", "자기 자신은 삭제할 수 없습니다."));
            } else if (UserStore.ROLE_ADMIN.equals(u.role()) && users.adminCount() <= 1) {
                Web.json(resp, 400, Map.of("error", "마지막 관리자는 삭제할 수 없습니다."));
            } else {
                users.remove(u.name());
                LOG.info("[precheck-dashboard] 사용자 삭제: " + u.name() + " by " + Web.user(req));
                Web.json(resp, 200, Map.of("deleted", true));
            }
        } else {
            Web.json(resp, 404, Map.of("error", "없는 주소입니다."));
        }
    }

    private void agentAction(HttpServletRequest req, HttpServletResponse resp, String[] p) throws IOException {
        AgentStore agents = Web.agents(getServletContext());
        String by = Web.user(req);
        try {
            if (p.length == 1 && p[0].equals("agents-run")) {
                int n = agents.requestRun(null);
                LOG.info("[precheck-dashboard] 전체 에이전트 점검 요청 (" + n + "대) by " + by);
                Web.json(resp, 200, Map.of("requested", n));
            } else if (p.length == 1) {
                String name = req.getParameter("name");
                name = name == null ? null : name.trim();
                String token = agents.create(name, parseHours(req.getParameter("intervalHours")));
                LOG.info("[precheck-dashboard] 에이전트 등록: " + name + " by " + by);
                Web.json(resp, 200, Map.of("name", name, "token", token));
            } else if (p.length == 3 && p[2].equals("run")) {
                agents.requestRun(p[1]);
                LOG.info("[precheck-dashboard] 에이전트 점검 요청: " + p[1] + " by " + by);
                Web.json(resp, 200, Map.of("requested", 1));
            } else if (p.length == 3 && p[2].equals("token")) {
                String token = agents.rotateToken(p[1]);
                LOG.info("[precheck-dashboard] 에이전트 토큰 재발급: " + p[1] + " by " + by);
                Web.json(resp, 200, Map.of("name", p[1], "token", token));
            } else if (p.length == 3 && p[2].equals("interval")) {
                agents.setInterval(p[1], parseHours(req.getParameter("hours")));
                Web.json(resp, 200, Map.of("ok", true));
            } else {
                Web.json(resp, 404, Map.of("error", "없는 주소입니다."));
            }
        } catch (IllegalArgumentException e) {
            Web.json(resp, 400, Map.of("error", e.getMessage()));
        }
    }

    private static int parseHours(String s) {
        try {
            return Integer.parseInt(s == null ? "24" : s.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("점검 주기는 숫자(시간)로 입력하세요.");
        }
    }

    private void upload(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        ReportStore store = Web.reports(getServletContext());
        List<Map<String, Object>> results = new ArrayList<>();
        for (Part part : req.getParts()) {
            if (!"files".equals(part.getName()) || part.getSubmittedFileName() == null) continue;
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("file", part.getSubmittedFileName());
            try (InputStream in = part.getInputStream()) {
                String saved = store.save(part.getSubmittedFileName(), in.readNBytes((int) ReportStore.MAX_FILE_BYTES + 1));
                r.put("ok", true);
                r.put("saved", saved);
                LOG.info("[precheck-dashboard] 리포트 업로드: " + saved + " by " + Web.user(req));
            } catch (IllegalArgumentException e) {
                r.put("ok", false);
                r.put("error", e.getMessage());
            }
            results.add(r);
        }
        if (results.isEmpty()) {
            Web.json(resp, 400, Map.of("error", "업로드할 파일이 없습니다."));
            return;
        }
        Web.json(resp, 200, results);
    }

    /** 인스턴스별 최신 리포트 중 [4] 침해 흔적에 [위험]이 있는 것 */
    static List<Report> suspects(List<Report> all) {
        java.util.Set<String> seen = new java.util.HashSet<>();
        List<Report> out = new ArrayList<>();
        for (Report r : all) { // all() 은 최신순
            if (!seen.add(r.instanceKey())) continue;
            if ("compromise".equals(r.intrusionStatus())) out.add(r);
        }
        return out;
    }

    private static void sendPdf(HttpServletResponse resp, byte[] pdf, String fileName) throws IOException {
        resp.setContentType("application/pdf");
        resp.setHeader("Content-Disposition", "attachment; filename=\"" + fileName + "\"");
        resp.setHeader("Cache-Control", "no-store");
        resp.setContentLength(pdf.length);
        resp.getOutputStream().write(pdf);
    }

    private static String ascii(String s) {
        return s == null ? "unknown" : s.replaceAll("[^A-Za-z0-9.-]+", "_");
    }

    private boolean requireAdmin(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (Web.isAdmin(req)) return true;
        Web.json(resp, 403, Map.of("error", "관리자만 사용할 수 있는 기능입니다."));
        return false;
    }

    private static String trim(String s) {
        return s == null ? null : s.trim();
    }
}
