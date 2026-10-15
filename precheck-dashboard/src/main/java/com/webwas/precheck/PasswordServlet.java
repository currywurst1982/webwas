package com.webwas.precheck;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.nio.file.Files;

/** 비밀번호 변경 화면. 첫 로그인(초기 비밀번호) 사용자는 여기를 거쳐야만 대시보드를 쓸 수 있음. */
@WebServlet("/password")
public class PasswordServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        render(req, resp, null);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String user = Web.user(req);
        UserStore users = Web.users(getServletContext());
        String current = req.getParameter("current");
        String next = req.getParameter("next");
        String confirm = req.getParameter("confirm");

        if (users.authenticate(user, current) == null) {
            render(req, resp, "현재 비밀번호가 올바르지 않습니다.");
            return;
        }
        if (next == null || !next.equals(confirm)) {
            render(req, resp, "새 비밀번호와 확인 값이 다릅니다.");
            return;
        }
        if (next.equals(current)) {
            render(req, resp, "현재 비밀번호와 다른 비밀번호를 입력하세요.");
            return;
        }
        String problem = UserStore.passwordProblem(user, next);
        if (problem != null) {
            render(req, resp, problem);
            return;
        }
        users.changePassword(user, next);
        if ("admin".equals(user)) {
            Files.deleteIfExists(AppInit.dataDir().resolve(AppInit.INITIAL_PASSWORD_FILE));
        }
        HttpSession s = req.getSession();
        s.setAttribute(Web.S_MUST_CHANGE, false);
        s.setAttribute(Web.S_CSRF, Web.newToken());
        resp.sendRedirect(req.getContextPath() + "/");
    }

    private void render(HttpServletRequest req, HttpServletResponse resp, String error) throws IOException {
        HttpSession s = req.getSession();
        boolean forced = Boolean.TRUE.equals(s.getAttribute(Web.S_MUST_CHANGE));
        String cp = Web.esc(req.getContextPath());
        String token = Web.esc(Web.csrf(s));
        String err = error == null ? "" : "<p class=\"auth-error\" role=\"alert\">" + Web.esc(error) + "</p>";
        String lead = forced
                ? "<p class=\"auth-sub\">처음 로그인하셨습니다. 초기 비밀번호를 새 비밀번호로 바꿔야 대시보드를 사용할 수 있습니다.</p>"
                : "<p class=\"auth-sub\"><a href=\"" + cp + "/\">← 대시보드로 돌아가기</a></p>";
        Web.page(req, resp, "비밀번호 변경 · Apache 사전점검", "<h1>비밀번호 변경</h1>" + lead + err
                + "<form method=\"post\" action=\"" + cp + "/password\">"
                + "<input type=\"hidden\" name=\"_csrf\" value=\"" + token + "\">"
                + "<label>현재 비밀번호<input type=\"password\" name=\"current\" required autocomplete=\"current-password\"></label>"
                + "<label>새 비밀번호<input type=\"password\" name=\"next\" required minlength=\"10\" autocomplete=\"new-password\"></label>"
                + "<label>새 비밀번호 확인<input type=\"password\" name=\"confirm\" required minlength=\"10\" autocomplete=\"new-password\"></label>"
                + "<p class=\"auth-hint\">10자 이상, 영문·숫자·특수문자 중 2가지 이상, 아이디 포함 불가</p>"
                + "<button type=\"submit\" class=\"btn btn-primary\">변경</button></form>"
                + "<form method=\"post\" action=\"" + cp + "/logout\" class=\"auth-logout\">"
                + "<input type=\"hidden\" name=\"_csrf\" value=\"" + token + "\">"
                + "<button type=\"submit\" class=\"btn btn-link\">로그아웃</button></form>");
    }
}
