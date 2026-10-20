package webwas.loadtest;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** 스크립트 생성(★설정 값 바꿔 넣기)이 안전하고 정확한지 */
class ScriptGenerationTest {

	private static Map<String, Object> req(String scenario, Map<String, Object> params, String users) {
		Map<String, Object> in = new LinkedHashMap<>();
		in.put("scenario", scenario);
		in.put("params", params);
		in.put("users", users);
		return in;
	}

	@Test
	void everyScenarioTemplateHasAllEditableKeys() throws Exception {
		// 템플릿(ngrinder-scripts)이 바뀌어 ★설정 이름이 사라지면 여기서 바로 잡힘
		for (Map.Entry<String, ScenarioServlet.Scenario> e : ScenarioServlet.SCENARIOS.entrySet()) {
			Map<String, Object> params = new LinkedHashMap<>();
			for (String k : e.getValue().keys) params.put(k, k.equals("BASE_URL") ? "http://10.0.0.5:8080/app" : "v_" + k);
			Map<String, Object> out = ScenarioServlet.generate(req(e.getKey(), params, "u1,p1"));
			String script = (String) out.get("script");
			for (String k : e.getValue().keys) {
				String expected = k.equals("BASE_URL") ? "\"http://10.0.0.5:8080/app\"" : "\"v_" + k + "\"";
				assertTrue(script.matches("(?s).*static\\s+String\\s+" + k + "\\s*=\\s*" + java.util.regex.Pattern.quote(expected) + ".*"),
					e.getKey() + " 의 " + k + " 값이 들어가지 않음");
			}
		}
	}

	@Test
	void specialCharactersAreEscapedForGroovy() {
		String s = ScenarioServlet.replaceString("static String SUCCESS_TEXT = \"old\" // c", "SUCCESS_TEXT", "a\"b$c\\d");
		assertEquals("static String SUCCESS_TEXT = \"a\\\"b\\$c\\\\d\" // c", s);
	}

	@Test
	void missingKeyIsReported() {
		assertThrows(IllegalStateException.class, () -> ScenarioServlet.replaceString("nothing here", "BASE_URL", "x"));
	}

	@Test
	void actionParamsBecomeGroovyMap() {
		String s = ScenarioServlet.replaceActionParams("static Map<String, String> ACTION_PARAMS = [:]", "item=book&qty=1&memo=a\"b");
		assertEquals("static Map<String, String> ACTION_PARAMS = [\"item\": \"book\", \"qty\": \"1\", \"memo\": \"a\\\"b\"]", s);
		assertEquals("static Map<String, String> ACTION_PARAMS = [:]", ScenarioServlet.replaceActionParams("static Map<String, String> ACTION_PARAMS = [\"a\": \"b\"]", ""));
	}

	@Test
	void trailingSlashOfBaseUrlIsRemoved() throws Exception {
		Map<String, Object> p = new LinkedHashMap<>();
		p.put("BASE_URL", "http://10.0.0.5:8080/loadtest///");
		String script = (String) ScenarioServlet.generate(req("get", p, null)).get("script");
		assertTrue(script.contains("\"http://10.0.0.5:8080/loadtest\""));
	}

	@Test
	void badInputIsRejected() {
		Map<String, Object> p = new LinkedHashMap<>();
		p.put("BASE_URL", "ftp://x");
		assertThrows(IllegalArgumentException.class, () -> ScenarioServlet.generate(req("get", p, null)));
		Map<String, Object> p2 = new LinkedHashMap<>();
		p2.put("PATHS", "/a\n/b");
		assertThrows(IllegalArgumentException.class, () -> ScenarioServlet.generate(req("get", p2, null)));
		assertThrows(IllegalArgumentException.class, () -> ScenarioServlet.generate(req("form_login", new LinkedHashMap<>(), "no-comma")));
		assertThrows(IllegalArgumentException.class, () -> ScenarioServlet.generate(req("nope", new LinkedHashMap<>(), null)));
	}

	@Test
	void usersFileSkipsCommentsAndBlankLines() throws Exception {
		Map<String, Object> out = ScenarioServlet.generate(req("token_api", new LinkedHashMap<>(), "# c\n\nu1,p1\r\nu2,p,2\n"));
		assertEquals("u1,p1\nu2,p,2\n", out.get("users"));
		assertEquals(2, out.get("userCount"));
	}

	@Test
	void jsonRoundTrip() {
		Object o = Json.parse("{\"a\":[1,2.5,\"x\\\"y\\u00e9\"],\"b\":{\"c\":null,\"d\":true}}");
		assertEquals("{\"a\":[1,2.5,\"x\\\"yé\"],\"b\":{\"c\":null,\"d\":true}}", Json.stringify(o));
		assertEquals(List.of(), Json.parse("[]"));
		assertThrows(IllegalArgumentException.class, () -> Json.parse("{\"a\":1} x"));
	}

	@Test
	void logHintsMatchRealAgentErrors() {
		// 실제 에이전트 로그에서 본 문구 그대로
		assertTrue(NGrinderTests.explain("java.net.SocketTimeoutException: 30000 MILLISECONDS\n at org.apache.hc.core5.reactor.InternalConnectChannel.onTimeout(InternalConnectChannel.java:93)")
			.contains("연결"));
		assertTrue(NGrinderTests.explain("java.net.ConnectException: Connection refused").contains("거부"));
		assertTrue(NGrinderTests.explain("AssertionError: [NOT_LOGGED_IN] ????").contains("성공 글자"));
		assertNull(NGrinderTests.explain("all good"));
	}
}
