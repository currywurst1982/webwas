package webwas.loadtest;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * 대시보드 접근 제한 (선택).
 * DASHBOARD_USER / DASHBOARD_PASSWORD 환경변수(또는 같은 이름의 시스템 프로퍼티)를 설정하면
 * /demo/* (부하테스트 대상 예제)를 뺀 모든 화면에 아이디/비밀번호 입력창이 뜹니다.
 * 설정하지 않으면 누구나 대시보드에서 테스트를 시작할 수 있으니, 사내망 외부에 노출하지 마세요.
 */
@WebFilter("/*")
public class AccessFilter implements Filter {

	private static String setting(String key) {
		String v = System.getProperty(key);
		if (v == null || v.isEmpty()) v = System.getenv(key);
		return v == null ? "" : v;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest) request;
		String user = setting("DASHBOARD_USER");
		String pass = setting("DASHBOARD_PASSWORD");
		String path = req.getRequestURI().substring(req.getContextPath().length());
		if (user.isEmpty() || path.startsWith("/demo/") || path.equals("/demo")) {
			chain.doFilter(request, response);
			return;
		}
		String h = req.getHeader("Authorization");
		if (h != null && h.startsWith("Basic ")) {
			String got;
			try {
				got = new String(Base64.getDecoder().decode(h.substring(6).trim()), StandardCharsets.UTF_8);
			} catch (IllegalArgumentException e) {
				got = "";
			}
			if (MessageDigest.isEqual(got.getBytes(StandardCharsets.UTF_8), (user + ":" + pass).getBytes(StandardCharsets.UTF_8))) {
				chain.doFilter(request, response);
				return;
			}
		}
		HttpServletResponse resp = (HttpServletResponse) response;
		resp.setHeader("WWW-Authenticate", "Basic realm=\"loadtest-dashboard\", charset=\"UTF-8\"");
		resp.sendError(401);
	}
}
