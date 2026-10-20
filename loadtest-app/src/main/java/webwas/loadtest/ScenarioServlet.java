package webwas.loadtest;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 시나리오 대시보드 API (/scenario/*)
 *
 *  GET  /scenario/info      nGrinder 연결 상태, 사용 가능 에이전트 수
 *  POST /scenario/settings  nGrinder 주소/계정 변경 + 연결 확인
 *  POST /scenario/preview   입력값으로 만든 스크립트/계정파일 미리보기
 *  POST /scenario/run       스크립트 업로드 → 테스트 생성 → 바로 시작(READY)
 */
@WebServlet("/scenario/*")
public class ScenarioServlet extends HttpServlet {

	/** 시나리오 id → [템플릿 파일, 화면에서 바꿀 수 있는 ★설정 이름들..., 계정 파일 필요 여부] */
	static final class Scenario {
		final String template;
		final List<String> keys;
		final boolean needsUsers;
		final boolean hasActionParams;

		Scenario(String template, boolean needsUsers, boolean hasActionParams, String... keys) {
			this.template = template;
			this.keys = Arrays.asList(keys);
			this.needsUsers = needsUsers;
			this.hasActionParams = hasActionParams;
		}
	}

	static final Map<String, Scenario> SCENARIOS = new LinkedHashMap<>();

	static {
		SCENARIOS.put("get", new Scenario("simple_get.groovy", false, false, "BASE_URL", "PATHS", "SUCCESS_TEXT"));
		SCENARIOS.put("form_login", new Scenario("login_session_cookie.groovy", true, false,
			"BASE_URL", "LOGIN_PATH", "ID_FIELD", "PW_FIELD", "TARGET_PATH", "SUCCESS_TEXT"));
		SCENARIOS.put("token_api", new Scenario("login_token_api.groovy", true, false,
			"BASE_URL", "LOGIN_PATH", "ID_FIELD", "PW_FIELD", "TOKEN_FIELD", "API1_PATH", "API2_PATH"));
		SCENARIOS.put("csrf_login", new Scenario("login_csrf.groovy", true, true,
			"BASE_URL", "LOGIN_PAGE_PATH", "LOGIN_PATH", "ID_FIELD", "PW_FIELD", "CSRF_NAME", "CSRF_COOKIE",
			"CSRF_COOKIE_HEADER", "TARGET_PATH", "SUCCESS_TEXT", "ACTION_PAGE_PATH", "ACTION_PATH"));
	}

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		String p = req.getPathInfo() == null ? "" : req.getPathInfo();
		try {
			if (p.equals("/info")) send(resp, 200, info());
			else if (p.equals("/jobs")) send(resp, 200, TestJobs.list());
			else if (p.matches("/job/\\d+")) send(resp, 200, TestJobs.get(Long.parseLong(p.substring(5))));
			else send(resp, 404, error("없는 주소"));
		} catch (IllegalArgumentException e) {
			send(resp, 404, error(e.getMessage()));
		}
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		Map<String, Object> in;
		try {
			in = Json.parseObject(new String(req.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
		} catch (RuntimeException e) {
			send(resp, 400, error("요청 형식 오류: " + e.getMessage()));
			return;
		}
		String p = req.getPathInfo() == null ? "" : req.getPathInfo();
		try {
			switch (p) {
				case "/settings":
					NGrinderClient.configure(Json.str(in, "url", null), Json.str(in, "user", null), Json.str(in, "password", null));
					send(resp, 200, info());
					return;
				case "/preview":
					send(resp, 200, generate(in));
					return;
				case "/unit": {
					// 단위테스트: 이 WAS에서 요청을 1건씩 직접 보내 점검
					Map<String, Object> gen = generate(in);   // 입력값 검사 겸용
					send(resp, 200, UnitTester.run(Json.str(in, "scenario", ""), params(in), Json.str(in, "users", "")));
					return;
				}
				case "/job": {
					// 통합·성능·임계 테스트: nGrinder로 실행 (백그라운드 작업)
					Map<String, Object> gen = generate(in);
					send(resp, 200, TestJobs.start(Json.str(in, "type", ""), Json.str(in, "scenario", ""), gen,
						obj(in, "options"), obj(in, "sla")));
					return;
				}
				default:
					if (p.matches("/job/\\d+/stop")) {
						send(resp, 200, TestJobs.stop(Long.parseLong(p.substring(5, p.length() - 5))));
						return;
					}
					send(resp, 404, error("없는 주소"));
			}
		} catch (IllegalArgumentException | IllegalStateException e) {
			send(resp, 400, error(e.getMessage()));
		} catch (IOException e) {
			send(resp, 502, error("nGrinder 연결 실패: " + e.getClass().getSimpleName() + " " + e.getMessage()));
		}
	}

	// ------------------------------------------------------------------ 연결 정보

	private Map<String, Object> info() {
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("ngrinderUrl", NGrinderClient.url());
		m.put("user", NGrinderClient.user());
		m.put("hasPassword", NGrinderClient.hasPassword());
		try {
			NGrinderClient.Resp r = NGrinderClient.call("GET", "/agent/api/list", null, null);
			if (r.ok() && !r.looksLikeLoginPage()) {
				int total = 0, ready = 0;
				for (Object o : (List<?>) Json.parse(r.text())) {
					Map<?, ?> a = (Map<?, ?>) o;
					total++;
					Object st = a.get("state");
					String cat = st instanceof Map ? String.valueOf(((Map<?, ?>) st).get("category")) : String.valueOf(st);
					if ("READY".equals(cat) && Boolean.TRUE.equals(a.get("approved"))) ready++;
				}
				m.put("connected", true);
				m.put("agents", total);
				m.put("readyAgents", ready);
			} else {
				m.put("connected", false);
				m.put("message", r.looksLikeLoginPage() || r.code == 401 ? "로그인 실패 (아이디/비밀번호 확인)" : "HTTP " + r.code);
			}
		} catch (Exception e) {
			m.put("connected", false);
			m.put("message", "연결 실패: " + e.getClass().getSimpleName() + " " + e.getMessage());
		}
		return m;
	}

	// ------------------------------------------------------------------ 스크립트 생성

	@SuppressWarnings("unchecked")
	static Map<String, Object> generate(Map<String, Object> in) throws IOException {
		String id = Json.str(in, "scenario", "");
		Scenario sc = SCENARIOS.get(id);
		if (sc == null) throw new IllegalArgumentException("알 수 없는 시나리오: " + id);
		Map<String, Object> params = in.get("params") instanceof Map ? (Map<String, Object>) in.get("params") : new LinkedHashMap<>();

		String script = template(sc.template);
		for (String key : sc.keys) {
			if (!params.containsKey(key)) continue;
			String v = Json.str(params, key, "");
			if (v.contains("\n") || v.contains("\r")) throw new IllegalArgumentException(key + " 에는 줄바꿈을 넣을 수 없습니다");
			if (key.equals("BASE_URL")) v = checkBaseUrl(v);
			script = replaceString(script, key, v);
		}
		if (sc.hasActionParams) script = replaceActionParams(script, Json.str(params, "ACTION_PARAMS", ""));

		Map<String, Object> out = new LinkedHashMap<>();
		out.put("script", script);
		if (sc.needsUsers) {
			String users = Json.str(in, "users", "");
			List<String> lines = new ArrayList<>();
			for (String line : users.split("\\r?\\n")) {
				line = line.trim();
				if (line.isEmpty() || line.startsWith("#")) continue;
				if (!line.contains(",")) throw new IllegalArgumentException("계정 목록은 한 줄에 \"아이디,비밀번호\" 형식이어야 합니다: " + line);
				lines.add(line);
			}
			if (lines.isEmpty()) throw new IllegalArgumentException("계정을 1개 이상 입력하세요");
			out.put("users", String.join("\n", lines) + "\n");
			out.put("userCount", lines.size());
		}
		return out;
	}

	private static String checkBaseUrl(String v) {
		String u = v.replaceAll("/+$", "");
		try {
			URI uri = URI.create(u);
			if (!("http".equals(uri.getScheme()) || "https".equals(uri.getScheme())) || uri.getHost() == null) throw new IllegalArgumentException();
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException("대상 서버 주소가 올바르지 않습니다 (예: http://10.0.0.5:8080/loadtest): " + v);
		}
		return u;
	}

	static String template(String name) throws IOException {
		try (InputStream in = ScenarioServlet.class.getResourceAsStream("/templates/" + name)) {
			if (in == null) throw new IOException("템플릿이 WAR에 없습니다: " + name);
			return new String(in.readAllBytes(), StandardCharsets.UTF_8);
		}
	}

	/** static String KEY = "..." 의 값만 바꿈. 템플릿에 KEY가 정확히 1번 있어야 함 */
	static String replaceString(String script, String key, String value) {
		Pattern p = Pattern.compile("(static\\s+String\\s+" + key + "\\s*=\\s*)\"(?:[^\"\\\\]|\\\\.)*\"");
		Matcher m = p.matcher(script);
		if (!m.find()) throw new IllegalStateException("템플릿에서 " + key + " 설정을 찾지 못했습니다");
		int start = m.start(), end = m.end();
		String prefix = m.group(1);
		if (m.find()) throw new IllegalStateException("템플릿에 " + key + " 설정이 여러 번 있습니다");
		return script.substring(0, start) + prefix + groovyString(value) + script.substring(end);
	}

	/** "title=부하테스트&qty=1" → ["title": "부하테스트", "qty": "1"] */
	static String replaceActionParams(String script, String spec) {
		StringBuilder map = new StringBuilder();
		for (String pair : spec.split("&")) {
			if (pair.trim().isEmpty()) continue;
			String[] kv = pair.split("=", 2);
			if (map.length() > 0) map.append(", ");
			map.append(groovyString(kv[0].trim())).append(": ").append(groovyString(kv.length > 1 ? kv[1].trim() : ""));
		}
		String literal = map.length() == 0 ? "[:]" : "[" + map + "]";
		Pattern p = Pattern.compile("(static\\s+Map<String,\\s*String>\\s+ACTION_PARAMS\\s*=\\s*)\\[[^\\]]*\\]");
		Matcher m = p.matcher(script);
		if (!m.find()) throw new IllegalStateException("템플릿에서 ACTION_PARAMS 설정을 찾지 못했습니다");
		return m.replaceFirst(Matcher.quoteReplacement(m.group(1) + literal));
	}

	/** Groovy 큰따옴표 문자열로 안전하게 만들기 ($, ", \ 처리) */
	static String groovyString(String v) {
		return "\"" + v.replace("\\", "\\\\").replace("\"", "\\\"").replace("$", "\\$") + "\"";
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> obj(Map<String, Object> in, String key) {
		return in.get(key) instanceof Map ? (Map<String, Object>) in.get(key) : new LinkedHashMap<>();
	}

	private static Map<String, Object> params(Map<String, Object> in) {
		return obj(in, "params");
	}

	private static Map<String, Object> error(String msg) {
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("error", msg);
		return m;
	}

	private static void send(HttpServletResponse resp, int code, Object o) throws IOException {
		ProxyServlet.send(resp, code, "application/json; charset=UTF-8", Json.stringify(o).getBytes(StandardCharsets.UTF_8));
	}
}
