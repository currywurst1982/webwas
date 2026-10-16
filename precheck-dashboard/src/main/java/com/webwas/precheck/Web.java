package com.webwas.precheck;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** 서블릿 공통 도우미: 세션 키, CSRF 토큰, HTML 이스케이프, JSON 응답. */
final class Web {
    private Web() {}

    static final String S_USER = "precheck.user";
    static final String S_ROLE = "precheck.role";
    static final String S_MUST_CHANGE = "precheck.mustChange";
    static final String S_CSRF = "precheck.csrf";
    private static final SecureRandom RANDOM = new SecureRandom();

    static UserStore users(ServletContext c) {
        return (UserStore) c.getAttribute(AppInit.ATTR_USERS);
    }

    static ReportStore reports(ServletContext c) {
        return (ReportStore) c.getAttribute(AppInit.ATTR_REPORTS);
    }

    static AgentStore agents(ServletContext c) {
        return (AgentStore) c.getAttribute(AppInit.ATTR_AGENTS);
    }

    static LatestVersion latest(ServletContext c) {
        return (LatestVersion) c.getAttribute(AppInit.ATTR_LATEST);
    }

    static LoginThrottle throttle(ServletContext c) {
        return (LoginThrottle) c.getAttribute(AppInit.ATTR_THROTTLE);
    }

    static String newToken() {
        byte[] b = new byte[32];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    static String csrf(HttpSession s) {
        String t = (String) s.getAttribute(S_CSRF);
        if (t == null) {
            t = newToken();
            s.setAttribute(S_CSRF, t);
        }
        return t;
    }

    static boolean csrfOk(HttpServletRequest req, String supplied) {
        HttpSession s = req.getSession(false);
        if (s == null || supplied == null) return false;
        String t = (String) s.getAttribute(S_CSRF);
        return t != null && MessageDigest.isEqual(t.getBytes(StandardCharsets.UTF_8), supplied.getBytes(StandardCharsets.UTF_8));
    }

    static String user(HttpServletRequest req) {
        HttpSession s = req.getSession(false);
        return s == null ? null : (String) s.getAttribute(S_USER);
    }

    static boolean isAdmin(HttpServletRequest req) {
        HttpSession s = req.getSession(false);
        return s != null && UserStore.ROLE_ADMIN.equals(s.getAttribute(S_ROLE));
    }

    static String esc(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            switch (c) {
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '&' -> sb.append("&amp;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&#39;");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    static void json(HttpServletResponse resp, int status, Object body) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json;charset=UTF-8");
        resp.setHeader("Cache-Control", "no-store");
        resp.getWriter().write(Json.write(body));
    }

    /** 로그인/비밀번호 변경 화면 공통 HTML 틀. */
    static void page(HttpServletRequest req, HttpServletResponse resp, String title, String body) throws IOException {
        resp.setContentType("text/html;charset=UTF-8");
        resp.setHeader("Cache-Control", "no-store");
        String cp = esc(req.getContextPath());
        resp.getWriter().write("<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                + "<title>" + esc(title) + "</title>"
                + "<link rel=\"stylesheet\" href=\"" + cp + "/static/app.css\"></head>"
                + "<body class=\"auth-body\"><main class=\"auth-card\">"
                + "<div class=\"brand\"><span class=\"brand-mark\" aria-hidden=\"true\"></span>Apache 사전점검 대시보드</div>"
                + body + "</main></body></html>");
    }
}
