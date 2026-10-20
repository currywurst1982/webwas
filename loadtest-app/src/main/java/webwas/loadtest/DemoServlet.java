package webwas.loadtest;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 부하테스트 "대상" 예제 기능 (/demo/*).
 * 대시보드의 시나리오들이 기본으로 이 주소들을 호출하므로, 실제 서비스 없이도 WAS 위에서 부하테스트를 해볼 수 있습니다.
 *
 *  조회          GET  /demo/products , /demo/products/{id}
 *  폼 로그인     GET/POST /demo/form/login → GET /demo/form/mypage           (세션 쿠키)
 *  토큰 로그인   POST /demo/api/login(JSON) → GET /demo/api/me , /demo/api/orders (Authorization: Bearer)
 *  CSRF 로그인   GET/POST /demo/csrf/login(_csrf) → GET /demo/csrf/mypage → POST /demo/csrf/order
 *
 *  테스트 계정: loadtest001 ~ loadtest200 / 비밀번호 Test1234!
 */
@WebServlet("/demo/*")
public class DemoServlet extends HttpServlet {

	static final String PASSWORD = "Test1234!";
	static final int USER_COUNT = 200;
	private static final Map<String, String> TOKENS = new ConcurrentHashMap<>();
	private static final SecureRandom RANDOM = new SecureRandom();

	static boolean validUser(String u, String p) {
		if (u == null || p == null || !u.matches("loadtest\\d{3}") || !PASSWORD.equals(p)) return false;
		int n = Integer.parseInt(u.substring(8));
		return n >= 1 && n <= USER_COUNT;
	}

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		String p = path(req);
		String ctx = req.getContextPath();
		simulateWork();
		if (p.equals("/") || p.isEmpty()) {
			html(resp, 200, page("부하테스트 대상 예제", "<p>대시보드의 시나리오들이 호출하는 예제 기능입니다.</p><ul>"
				+ "<li><a href='" + ctx + "/demo/products'>상품 목록 (조회)</a></li>"
				+ "<li><a href='" + ctx + "/demo/form/login'>폼 로그인</a></li>"
				+ "<li><a href='" + ctx + "/demo/csrf/login'>CSRF 로그인</a></li>"
				+ "<li>토큰 로그인 API: POST " + ctx + "/demo/api/login</li></ul>"
				+ "<p>테스트 계정: loadtest001 ~ loadtest" + USER_COUNT + " / " + PASSWORD + "</p>", null));
			return;
		}
		if (p.equals("/products")) {
			List<Object> list = new ArrayList<>();
			for (int i = 1; i <= 20; i++) list.add(product(i));
			json(resp, 200, list);
			return;
		}
		if (p.matches("/products/\\d{1,6}")) {
			json(resp, 200, product(Integer.parseInt(p.substring(10))));
			return;
		}
		if (p.equals("/form/login")) {
			html(resp, 200, page("로그인", loginForm(ctx + "/demo/form/login", null), null));
			return;
		}
		if (p.equals("/form/mypage")) {
			String u = loggedIn(req);
			if (u == null) { resp.sendRedirect(ctx + "/demo/form/login"); return; }
			html(resp, 200, page("마이페이지", "<h1>" + esc(u) + "님 환영합니다</h1>", null));
			return;
		}
		if (p.equals("/api/me") || p.equals("/api/orders")) {
			String u = bearer(req);
			if (u == null) { json(resp, 401, map("error", "unauthorized")); return; }
			if (p.equals("/api/me")) { json(resp, 200, map("username", u)); return; }
			List<Object> orders = new ArrayList<>();
			for (int i = 1; i <= 5; i++) orders.add(map("orderId", u + "-" + i, "amount", 1000 * i));
			json(resp, 200, orders);
			return;
		}
		if (p.equals("/csrf/login")) {
			String t = csrfToken(req.getSession(true));
			html(resp, 200, page("로그인", loginForm(ctx + "/demo/csrf/login", t), t));
			return;
		}
		if (p.equals("/csrf/mypage")) {
			String u = loggedIn(req);
			if (u == null) { resp.sendRedirect(ctx + "/demo/csrf/login"); return; }
			String t = csrfToken(req.getSession());
			html(resp, 200, page("마이페이지", "<h1>" + esc(u) + "님 환영합니다</h1>"
				+ "<form method='post' action='" + ctx + "/demo/csrf/order'>" + hidden(t)
				+ "<input name='item' value='book'><button>주문</button></form>", t));
			return;
		}
		html(resp, 404, page("없음", "없는 주소입니다", null));
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		req.setCharacterEncoding("UTF-8");
		String p = path(req);
		String ctx = req.getContextPath();
		simulateWork();
		if (p.equals("/form/login")) {
			String u = req.getParameter("username");
			if (!validUser(u, req.getParameter("password"))) {
				html(resp, 200, page("로그인", loginForm(ctx + "/demo/form/login", null) + "<p>로그인 실패</p>", null));
				return;
			}
			HttpSession s = req.getSession(true);
			s.setAttribute("user", u);
			req.changeSessionId();
			resp.sendRedirect(ctx + "/demo/form/mypage");
			return;
		}
		if (p.equals("/api/login")) {
			Map<String, Object> body;
			try {
				body = Json.parseObject(new String(req.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
			} catch (RuntimeException e) {
				json(resp, 400, map("error", "JSON 본문이 필요합니다"));
				return;
			}
			String u = Json.str(body, "username", null);
			if (!validUser(u, Json.str(body, "password", null))) { json(resp, 401, map("error", "bad credentials")); return; }
			if (TOKENS.size() > 100_000) TOKENS.clear();
			String token = randomToken();
			TOKENS.put(token, u);
			json(resp, 200, map("accessToken", token, "tokenType", "Bearer"));
			return;
		}
		if (p.equals("/csrf/login")) {
			HttpSession s = req.getSession(false);
			if (s == null || !csrfMatches(req, s)) { html(resp, 403, page("거부", "CSRF 토큰이 없거나 틀렸습니다", null)); return; }
			String u = req.getParameter("username");
			if (!validUser(u, req.getParameter("password"))) {
				html(resp, 200, page("로그인", loginForm(ctx + "/demo/csrf/login", csrfToken(s)) + "<p>로그인 실패</p>", csrfToken(s)));
				return;
			}
			s.setAttribute("user", u);
			req.changeSessionId();
			s.setAttribute("csrf", randomToken());   // 로그인 성공 시 토큰 교체 (Spring Security와 같은 동작)
			resp.sendRedirect(ctx + "/demo/csrf/mypage");
			return;
		}
		if (p.equals("/csrf/order")) {
			HttpSession s = req.getSession(false);
			if (s == null || s.getAttribute("user") == null || !csrfMatches(req, s)) { html(resp, 403, page("거부", "CSRF 토큰이 없거나 틀렸습니다", null)); return; }
			html(resp, 200, page("주문 완료", "주문이 완료되었습니다", null));
			return;
		}
		html(resp, 404, page("없음", "없는 주소입니다", null));
	}

	// ------------------------------------------------------------------

	private static String path(HttpServletRequest req) {
		return req.getPathInfo() == null ? "" : req.getPathInfo();
	}

	/** DB 조회 등을 흉내 내는 처리 시간 (약 10~30ms 대기 + 약간의 CPU 사용) */
	private static void simulateWork() {
		try {
			Thread.sleep(10 + ThreadLocalRandom.current().nextInt(21));
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] b = new byte[256];
			for (int i = 0; i < 200; i++) b = md.digest(b);
		} catch (Exception e) {
			Thread.currentThread().interrupt();
		}
	}

	private static Map<String, Object> product(int id) {
		return map("id", id, "name", "상품 " + id, "price", 1000 + id * 100);
	}

	private static String loggedIn(HttpServletRequest req) {
		HttpSession s = req.getSession(false);
		return s == null ? null : (String) s.getAttribute("user");
	}

	private static String bearer(HttpServletRequest req) {
		String a = req.getHeader("Authorization");
		return a != null && a.startsWith("Bearer ") ? TOKENS.get(a.substring(7)) : null;
	}

	private static String csrfToken(HttpSession s) {
		String t = (String) s.getAttribute("csrf");
		if (t == null) {
			t = randomToken();
			s.setAttribute("csrf", t);
		}
		return t;
	}

	private static boolean csrfMatches(HttpServletRequest req, HttpSession s) {
		String want = (String) s.getAttribute("csrf");
		String got = req.getParameter("_csrf");
		if (got == null || got.isEmpty()) got = req.getHeader("X-CSRF-TOKEN");
		return want != null && want.equals(got);
	}

	private static String randomToken() {
		byte[] b = new byte[18];
		RANDOM.nextBytes(b);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
	}

	private static String loginForm(String action, String csrf) {
		return "<form method='post' action='" + action + "'>" + (csrf == null ? "" : hidden(csrf))
			+ "<p>아이디 <input name='username'></p><p>비밀번호 <input type='password' name='password'></p>"
			+ "<button>로그인</button></form>";
	}

	private static String hidden(String csrf) {
		return "<input type='hidden' name='_csrf' value='" + esc(csrf) + "'>";
	}

	private static String page(String title, String body, String csrf) {
		String meta = csrf == null ? "" : "<meta name='_csrf' content='" + esc(csrf) + "'><meta name='_csrf_header' content='X-CSRF-TOKEN'>";
		return "<!doctype html><html lang='ko'><head><meta charset='utf-8'>" + meta + "<title>" + esc(title)
			+ "</title></head><body>" + body + "</body></html>";
	}

	private static String esc(String s) {
		return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;").replace("\"", "&quot;");
	}

	private static Map<String, Object> map(Object... kv) {
		Map<String, Object> m = new LinkedHashMap<>();
		for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
		return m;
	}

	private static void html(HttpServletResponse resp, int code, String html) throws IOException {
		byte[] b = html.getBytes(StandardCharsets.UTF_8);
		resp.setStatus(code);
		resp.setContentType("text/html; charset=UTF-8");
		resp.setContentLength(b.length);
		resp.getOutputStream().write(b);
	}

	private static void json(HttpServletResponse resp, int code, Object o) throws IOException {
		byte[] b = Json.stringify(o).getBytes(StandardCharsets.UTF_8);
		resp.setStatus(code);
		resp.setContentType("application/json; charset=UTF-8");
		resp.setContentLength(b.length);
		resp.getOutputStream().write(b);
	}
}
