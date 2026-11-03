package com.webwas.precheck;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Map;
import java.util.Set;

/**
 * 모든 요청에 대해: 보안 헤더 추가 → 로그인 여부 확인 → 첫 로그인 비밀번호 변경 강제 → CSRF 검사.
 * 로그인하지 않은 사용자는 로그인 화면과 CSS 외에는 아무것도 볼 수 없음.
 */
@WebFilter("/*")
public class AuthFilter extends HttpFilter {
    private static final Set<String> PUBLIC = Set.of("/login", "/static/app.css", "/static/theme.js");
    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD");

    @Override
    protected void doFilter(HttpServletRequest req, HttpServletResponse resp, FilterChain chain)
            throws IOException, ServletException {
        req.setCharacterEncoding("UTF-8");
        resp.setHeader("X-Content-Type-Options", "nosniff");
        resp.setHeader("X-Frame-Options", "DENY");
        resp.setHeader("Referrer-Policy", "no-referrer");
        resp.setHeader("Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                        + "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");

        String path = req.getRequestURI().substring(req.getContextPath().length());
        // 에이전트 API 는 로그인 세션 대신 에이전트 토큰으로 인증 (AgentApiServlet)
        if (PUBLIC.contains(path) || path.startsWith("/agent-api/")) {
            chain.doFilter(req, resp);
            return;
        }

        boolean api = path.startsWith("/api/");
        HttpSession session = req.getSession(false);
        String user = session == null ? null : (String) session.getAttribute(Web.S_USER);

        // 로그인 후 관리자가 계정을 삭제했으면 즉시 로그아웃
        if (user != null && Web.users(getServletContext()).find(user) == null) {
            session.invalidate();
            user = null;
        }
        if (user == null) {
            if (api) Web.json(resp, 401, Map.of("error", "로그인이 필요합니다."));
            else resp.sendRedirect(req.getContextPath() + "/login");
            return;
        }

        if (Boolean.TRUE.equals(session.getAttribute(Web.S_MUST_CHANGE))
                && !path.equals("/password") && !path.equals("/logout")) {
            if (api) Web.json(resp, 403, Map.of("error", "비밀번호를 먼저 변경해야 합니다."));
            else resp.sendRedirect(req.getContextPath() + "/password");
            return;
        }

        if (!SAFE_METHODS.contains(req.getMethod())) {
            // API 는 헤더로, 일반 화면 폼은 _csrf 필드로 토큰을 받음
            String token = api ? req.getHeader("X-CSRF-Token") : req.getParameter("_csrf");
            if (!Web.csrfOk(req, token)) {
                if (api) Web.json(resp, 403, Map.of("error", "보안 토큰이 맞지 않습니다. 새로고침 후 다시 시도하세요."));
                else resp.sendError(403);
                return;
            }
        }
        chain.doFilter(req, resp);
    }
}
