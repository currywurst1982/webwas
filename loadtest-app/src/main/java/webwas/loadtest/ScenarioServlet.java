package webwas.loadtest;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
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

	private static final String ROOT_FOLDER = "loadtest_dashboard";

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		if ("/info".equals(req.getPathInfo())) {
			send(resp, 200, info());
		} else {
			send(resp, 404, error("없는 주소"));
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
				case "/run":
					send(resp, 200, run(in));
					return;
				default:
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

	// ------------------------------------------------------------------ 실행

	@SuppressWarnings("unchecked")
	private Map<String, Object> run(Map<String, Object> in) throws IOException {
		Map<String, Object> gen = generate(in);
		String id = Json.str(in, "scenario", "");
		Map<String, Object> opt = in.get("options") instanceof Map ? (Map<String, Object>) in.get("options") : new LinkedHashMap<>();

		String testName = Json.str(opt, "testName", "");
		if (testName.isEmpty()) throw new IllegalArgumentException("테스트 이름을 입력하세요");
		int agents = Json.integer(opt, "agentCount", 1);
		int vuser = Json.integer(opt, "vuserPerAgent", 10);
		int minutes = Json.integer(opt, "durationMinutes", 1);
		String targetIp = Json.str(opt, "targetHostIp", "");
		if (agents < 1) throw new IllegalArgumentException("에이전트 수는 1 이상이어야 합니다");
		if (vuser < 1) throw new IllegalArgumentException("에이전트당 Vuser는 1 이상이어야 합니다");
		if (minutes < 1 || minutes > 600) throw new IllegalArgumentException("테스트 시간은 1~600분 사이로 입력하세요");
		if (!targetIp.isEmpty() && !targetIp.matches("[0-9a-fA-F.:]+")) throw new IllegalArgumentException("모니터 대상 IP 형식이 올바르지 않습니다: " + targetIp);

		// nGrinder 규칙: vuserPerAgent = processes × threads (스레드 100개 이하로 나눔)
		int processes = Math.max(1, (int) Math.ceil(vuser / 100.0));
		int threads = (int) Math.ceil(vuser / (double) processes);
		int vuserPerAgent = processes * threads;

		// 실행마다 새 폴더 → 각 테스트가 어떤 스크립트로 돌았는지 그대로 남음
		String folder = ROOT_FOLDER + "/" + id + "/run_" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
		String scriptFile = id + ".groovy";
		NGrinderClient.Resp up = NGrinderClient.upload(folder, scriptFile, ((String) gen.get("script")).getBytes(StandardCharsets.UTF_8),
			"loadtest dashboard: " + testName);
		check(up, "스크립트 업로드");
		if (gen.containsKey("users")) {
			check(NGrinderClient.upload(folder + "/resources", "users.csv", ((String) gen.get("users")).getBytes(StandardCharsets.UTF_8),
				"accounts"), "계정 파일 업로드");
		}

		Map<String, Object> test = new LinkedHashMap<>();
		test.put("testName", testName);
		test.put("tagString", "loadtest_dashboard," + id);
		test.put("description", "시나리오 대시보드에서 실행 (" + id + ")");
		test.put("scriptName", folder + "/" + scriptFile);
		test.put("agentCount", agents);
		test.put("vuserPerAgent", vuserPerAgent);
		test.put("processes", processes);
		test.put("threads", threads);
		test.put("threshold", "D");
		test.put("duration", minutes * 60_000L);
		test.put("targetHosts", targetIp);
		test.put("samplingInterval", 2);
		test.put("status", "READY");   // READY = 저장 후 바로 실행 대기열에 넣음
		NGrinderClient.Resp created = NGrinderClient.json("POST", "/perftest/api", test);
		check(created, "테스트 생성");
		Map<String, Object> t = Json.parseObject(created.text());

		Map<String, Object> out = new LinkedHashMap<>();
		out.put("testId", t.get("id"));
		out.put("testName", testName);
		out.put("scriptPath", folder + "/" + scriptFile);
		out.put("agentCount", agents);
		out.put("processes", processes);
		out.put("threads", threads);
		out.put("vuserPerAgent", vuserPerAgent);
		out.put("totalVuser", vuserPerAgent * agents);
		out.put("ngrinderTestUrl", NGrinderClient.url() + "/perftest/" + t.get("id"));
		return out;
	}

	private static void check(NGrinderClient.Resp r, String step) {
		if (r.looksLikeLoginPage()) throw new IllegalArgumentException(step + " 실패: nGrinder 로그인 실패 (연결 설정의 아이디/비밀번호 확인)");
		if (!r.ok()) {
			String msg = r.text();
			try {
				Object o = Json.parse(msg);
				if (o instanceof Map && ((Map<?, ?>) o).get("message") != null) msg = String.valueOf(((Map<?, ?>) o).get("message"));
			} catch (RuntimeException ignore) {
				// 그대로 사용
			}
			throw new IllegalArgumentException(step + " 실패 (HTTP " + r.code + "): " + (msg.length() > 300 ? msg.substring(0, 300) : msg));
		}
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
