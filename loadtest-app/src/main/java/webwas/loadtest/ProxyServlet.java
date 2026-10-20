package webwas.loadtest;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 실시간 모니터 화면(monitor/index.html)용 nGrinder 중계.
 * 화면의 "api/..." 요청을 nGrinder 컨트롤러로 그대로 전달합니다 (허용한 경로만).
 * ngrinder-dashboard/server.py 와 같은 역할을 WAS 안에서 합니다.
 */
@WebServlet(urlPatterns = {"/api/*", "/monitor/api/*", "/config.json", "/monitor/config.json"})
public class ProxyServlet extends HttpServlet {

	private static final String[] ALLOWED = {"/perftest/api", "/agent/api"};

	@Override
	protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		String sp = req.getServletPath();
		if (sp.endsWith("config.json")) {
			Map<String, Object> cfg = new LinkedHashMap<>();
			cfg.put("ngrinderUrl", NGrinderClient.url());
			cfg.put("hasUser", !NGrinderClient.user().isEmpty());
			send(resp, 200, "application/json; charset=UTF-8", Json.stringify(cfg).getBytes(StandardCharsets.UTF_8));
			return;
		}
		String path = req.getPathInfo() == null ? "" : req.getPathInfo();
		boolean allowed = false;
		for (String a : ALLOWED) allowed |= path.equals(a) || path.startsWith(a + "/") || path.startsWith(a + "?");
		if (!allowed || path.contains("..")) {
			send(resp, 403, "application/json", "{\"error\":\"path not allowed\"}".getBytes(StandardCharsets.UTF_8));
			return;
		}
		String method = req.getMethod();
		if (!method.equals("GET") && !method.equals("POST") && !method.equals("PUT")) {
			send(resp, 405, "application/json", "{}".getBytes(StandardCharsets.UTF_8));
			return;
		}
		String q = req.getQueryString();
		byte[] body = method.equals("GET") ? null : req.getInputStream().readAllBytes();
		try {
			NGrinderClient.Resp r = NGrinderClient.call(method, path + (q == null ? "" : "?" + q),
				req.getContentType() == null ? "application/json" : req.getContentType(), body);
			send(resp, r.code, r.contentType == null ? "application/json" : r.contentType, r.body);
		} catch (IOException e) {
			String msg = "{\"error\":\"nGrinder 연결 실패: " + e.getClass().getSimpleName() + "\"}";
			send(resp, 502, "application/json; charset=UTF-8", msg.getBytes(StandardCharsets.UTF_8));
		}
	}

	static void send(HttpServletResponse resp, int code, String ctype, byte[] data) throws IOException {
		resp.setStatus(code);
		resp.setContentType(ctype);
		resp.setHeader("Cache-Control", "no-store");
		resp.setContentLength(data.length);
		resp.getOutputStream().write(data);
	}
}
