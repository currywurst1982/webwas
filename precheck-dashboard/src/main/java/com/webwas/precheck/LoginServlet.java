package com.webwas.precheck;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.logging.Logger;

@WebServlet("/login")
public class LoginServlet extends HttpServlet {
    private static final Logger LOG = Logger.getLogger(LoginServlet.class.getName());

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (Web.user(req) != null) {
            resp.sendRedirect(req.getContextPath() + "/");
            return;
        }
        render(req, resp, null, "");
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String username = req.getParameter("username");
        String password = req.getParameter("password");
        String ip = req.getRemoteAddr();
        username = username == null ? "" : username.trim();

        if (!Web.csrfOk(req, req.getParameter("_csrf"))) {
            render(req, resp, "화면이 오래되었습니다. 다시 시도해 주세요.", username);
            return;
        }
        LoginThrottle throttle = Web.throttle(getServletContext());
        long locked = throttle.lockedSeconds(username, ip);
        if (locked > 0) {
            render(req, resp, "로그인 실패가 반복되어 잠시 차단되었습니다. " + locked + "초 후 다시 시도하세요.", username);
            return;
        }
        UserStore.User u = Web.users(getServletContext()).authenticate(username, password);
        if (u == null) {
            throttle.failure(username, ip);
            LOG.warning("[precheck-dashboard] 로그인 실패: user=" + username.replaceAll("[^A-Za-z0-9._-]", "?") + " ip=" + ip);
            render(req, resp, "아이디 또는 비밀번호가 올바르지 않습니다.", username);
            return;
        }
        throttle.success(username, ip);
        req.changeSessionId(); // 세션 고정 공격 방지
        HttpSession s = req.getSession();
        s.setAttribute(Web.S_USER, u.name());
        s.setAttribute(Web.S_ROLE, u.role());
        s.setAttribute(Web.S_MUST_CHANGE, u.mustChange());
        s.setAttribute(Web.S_CSRF, Web.newToken());
        LOG.info("[precheck-dashboard] 로그인: user=" + u.name() + " ip=" + ip);
        resp.sendRedirect(req.getContextPath() + (u.mustChange() ? "/password" : "/"));
    }

    private void render(HttpServletRequest req, HttpServletResponse resp, String error, String username) throws IOException {
        String token = Web.csrf(req.getSession());
        String err = error == null ? "" : "<p class=\"auth-error\" role=\"alert\">" + Web.esc(error) + "</p>";
        Web.page(req, resp, "로그인 · Apache 사전점검", "<h1>로그인</h1>"
                + "<p class=\"auth-sub\">점검 결과는 로그인한 사용자만 볼 수 있습니다.</p>" + err
                + "<form method=\"post\" action=\"" + Web.esc(req.getContextPath()) + "/login\" autocomplete=\"on\">"
                + "<input type=\"hidden\" name=\"_csrf\" value=\"" + Web.esc(token) + "\">"
                + "<label>아이디<input name=\"username\" required autofocus autocomplete=\"username\" value=\"" + Web.esc(username) + "\"></label>"
                + "<label>비밀번호<input type=\"password\" name=\"password\" required autocomplete=\"current-password\"></label>"
                + "<button type=\"submit\" class=\"btn btn-primary\">로그인</button></form>");
    }
}
