package webwas.loadtest;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 단위테스트: 시나리오의 요청을 "1건씩" 직접 보내 단계마다 응답코드·응답시간·확인 결과를 보여줌.
 * nGrinder를 거치지 않고 이 WAS에서 바로 보내므로 몇 초 안에 끝남.
 * (주의: 요청을 보내는 곳이 에이전트가 아니라 이 WAS 서버임)
 */
public final class UnitTester {

	private final Map<String, Object> p;
	private final String base;
	private final HttpClient client;
	private final CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
	private final List<Map<String, Object>> steps = new ArrayList<>();
	private boolean failed;

	private UnitTester(Map<String, Object> params) {
		this.p = params;
		this.base = s("BASE_URL").replaceAll("/+$", "");
		this.client = HttpClient.newBuilder().cookieHandler(cookies).followRedirects(HttpClient.Redirect.NEVER)
			.connectTimeout(Duration.ofSeconds(5)).build();
	}

	public static Map<String, Object> run(String scenario, Map<String, Object> params, String users) {
		UnitTester t = new UnitTester(params);
		String[] account = firstAccount(users);
		try {
			switch (scenario) {
				case "get": t.get(); break;
				case "form_login": t.formLogin(account); break;
				case "token_api": t.tokenApi(account); break;
				case "csrf_login": t.csrfLogin(account); break;
				default: throw new IllegalArgumentException("알 수 없는 시나리오: " + scenario);
			}
		} catch (StopException ignore) {
			// 앞 단계가 실패해서 중단
		}
		Map<String, Object> out = new LinkedHashMap<>();
		out.put("ok", !t.failed);
		out.put("steps", t.steps);
		out.put("note", "요청은 이 WAS 서버에서 보냈습니다. nGrinder 에이전트가 다른 서버에 있으면 에이전트에서는 결과가 다를 수 있습니다(통합테스트로 확인).");
		return out;
	}

	// ------------------------------------------------------------------ 시나리오별 단계

	private void get() {
		String[] paths = s("PATHS").split(",");
		int n = 0;
		for (String path : paths) {
			path = path.trim();
			if (path.isEmpty()) continue;
			n++;
			Resp r = send("조회 " + path, "GET", path, null, null);
			expectStatus(r, 200);
			if (!s("SUCCESS_TEXT").isEmpty()) expectText(r, s("SUCCESS_TEXT"));
			done(r, false);
		}
		if (n == 0) fail("주소 목록이 비어 있습니다");
	}

	private void formLogin(String[] acc) {
		Resp r = send("로그인 (" + acc[0] + ")", "POST", s("LOGIN_PATH"),
			form(s("ID_FIELD"), acc[0], s("PW_FIELD"), acc[1]), Map.of("Content-Type", "application/x-www-form-urlencoded"));
		expectStatus(r, 200, 302, 303);
		if (r.ok && cookies.getCookieStore().getCookies().isEmpty()) r.fail("로그인 후 받은 쿠키가 없습니다");
		else if (r.ok) r.detail("받은 쿠키: " + cookieNames());
		done(r, true);
		Resp m = send("로그인 후 페이지", "GET", s("TARGET_PATH"), null, null);
		expectStatus(m, 200);
		expectText(m, s("SUCCESS_TEXT"));
		done(m, true);
	}

	private void tokenApi(String[] acc) {
		String body = Json.stringify(Map.of(s("ID_FIELD"), acc[0], s("PW_FIELD"), acc[1]));
		Resp r = send("로그인 API (" + acc[0] + ")", "POST", s("LOGIN_PATH"), body, Map.of("Content-Type", "application/json"));
		expectStatus(r, 200);
		String token = null;
		if (r.ok) {
			try {
				Object v = Json.parseObject(r.body).get(s("TOKEN_FIELD"));
				token = v == null ? null : String.valueOf(v);
			} catch (RuntimeException e) {
				r.fail("응답이 JSON이 아닙니다: " + cut(r.body));
			}
			if (r.ok && token == null) r.fail("응답에 토큰 항목 '" + s("TOKEN_FIELD") + "' 이 없습니다: " + cut(r.body));
			if (r.ok) r.detail("토큰 받음 (" + token.length() + "자)");
		}
		done(r, true);
		Map<String, String> auth = Map.of("Authorization", "Bearer " + token);
		Resp a1 = send("API 1", "GET", s("API1_PATH"), null, auth);
		expectStatus(a1, 200);
		done(a1, false);
		if (!s("API2_PATH").isEmpty()) {
			Resp a2 = send("API 2", "GET", s("API2_PATH"), null, auth);
			expectStatus(a2, 200);
			done(a2, false);
		}
	}

	private void csrfLogin(String[] acc) {
		Resp page = send("로그인 화면", "GET", s("LOGIN_PAGE_PATH"), null, null);
		expectStatus(page, 200);
		String[] csrf = page.ok ? findCsrf(page) : null;
		if (page.ok && csrf == null) page.fail("화면에서 CSRF 토큰 '" + s("CSRF_NAME") + "' 을 찾지 못했습니다");
		else if (csrf != null) page.detail("토큰 발견 (위치: " + csrf[2] + ")");
		done(page, true);

		Map<String, String> h = new LinkedHashMap<>();
		h.put("Content-Type", "application/x-www-form-urlencoded");
		if (csrf[1] != null) h.put(csrf[1], csrf[0]);
		Resp r = send("로그인 (" + acc[0] + ")", "POST", s("LOGIN_PATH"),
			form(s("ID_FIELD"), acc[0], s("PW_FIELD"), acc[1], s("CSRF_NAME"), csrf[0]), h);
		expectStatus(r, 200, 302, 303);
		if (r.status == 403) r.fail("403 거부: CSRF 토큰을 보내는 이름/헤더가 서버 기대와 다를 가능성");
		done(r, true);

		Resp m = send("로그인 후 페이지", "GET", s("TARGET_PATH"), null, null);
		expectStatus(m, 200);
		expectText(m, s("SUCCESS_TEXT"));
		done(m, true);

		if (!s("ACTION_PATH").isEmpty()) {
			String pagePath = s("ACTION_PAGE_PATH").isEmpty() ? s("TARGET_PATH") : s("ACTION_PAGE_PATH");
			Resp ap = pagePath.equals(s("TARGET_PATH")) ? m : send("POST 전 화면", "GET", pagePath, null, null);
			String[] t2 = findCsrf(ap);
			if (ap != m) {
				expectStatus(ap, 200);
				done(ap, true);
			}
			Map<String, String> h2 = new LinkedHashMap<>();
			h2.put("Content-Type", "application/x-www-form-urlencoded");
			List<String> kv = new ArrayList<>();
			for (String pair : s("ACTION_PARAMS").split("&")) {
				if (pair.trim().isEmpty()) continue;
				String[] x = pair.split("=", 2);
				kv.add(x[0].trim());
				kv.add(x.length > 1 ? x[1].trim() : "");
			}
			if (t2 != null) {
				kv.add(s("CSRF_NAME"));
				kv.add(t2[0]);
				if (t2[1] != null) h2.put(t2[1], t2[0]);
			}
			Resp post = send("로그인 후 POST", "POST", s("ACTION_PATH"), form(kv.toArray(new String[0])), h2);
			if (t2 == null) post.fail("POST 전에 새 CSRF 토큰을 찾지 못했습니다");
			expectStatus(post, 200, 201, 302, 303);
			done(post, false);
		}
	}

	// ------------------------------------------------------------------ 요청과 확인

	private final class Resp {
		final Map<String, Object> step = new LinkedHashMap<>();
		int status = -1;
		String body = "";
		HttpResponse<byte[]> raw;
		boolean ok = true;
		final List<String> details = new ArrayList<>();

		void fail(String why) {
			if (ok) step.put("error", why);
			ok = false;
		}

		void detail(String d) {
			details.add(d);
		}
	}

	private Resp send(String name, String method, String path, String body, Map<String, String> headers) {
		Resp r = new Resp();
		String url = base + path;
		r.step.put("name", name);
		r.step.put("method", method);
		r.step.put("url", url);
		long t0 = System.nanoTime();
		try {
			HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10));
			if (headers != null) headers.forEach(b::header);
			b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
			r.raw = client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
			r.status = r.raw.statusCode();
			r.body = new String(r.raw.body(), charset(r.raw));
			r.step.put("status", r.status);
			r.raw.headers().firstValue("Location").ifPresent(loc -> r.detail("이동: " + loc));
		} catch (HttpConnectTimeoutException e) {
			r.fail("연결 시간 초과(5초): 이 WAS에서 대상 주소로 연결이 안 됩니다. IP·포트·방화벽을 확인하세요.");
		} catch (HttpTimeoutException e) {
			r.fail("응답 시간 초과(10초): 대상 서버가 너무 느립니다.");
		} catch (java.net.ConnectException e) {
			r.fail("연결 거부: 그 주소·포트에서 서버가 실행 중이 아닙니다.");
		} catch (IllegalArgumentException e) {
			r.fail("주소 형식이 잘못됐습니다: " + url);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			r.fail("중단됨");
		} catch (Exception e) {
			r.fail(e.getClass().getSimpleName() + ": " + e.getMessage());
		}
		r.step.put("ms", Math.round((System.nanoTime() - t0) / 1_000_000.0));
		return r;
	}

	private void expectStatus(Resp r, int... allowed) {
		if (!r.ok) return;
		for (int a : allowed) if (r.status == a) return;
		StringBuilder sb = new StringBuilder();
		for (int a : allowed) sb.append(sb.length() == 0 ? "" : "/").append(a);
		r.fail("응답코드 " + r.status + " (기대: " + sb + ")" + (r.status == 302 ? " — 로그인 화면으로 돌려보내졌을 수 있음" : ""));
	}

	private void expectText(Resp r, String text) {
		if (!r.ok || text.isEmpty()) return;
		if (r.body.contains(text)) r.detail("'" + text + "' 확인");
		else r.fail("응답에 '" + text + "' 이(가) 없습니다");
	}

	/** 단계 기록. stopOnFail 이면 실패 시 다음 단계 중단 */
	private void done(Resp r, boolean stopOnFail) {
		r.step.put("ok", r.ok);
		if (!r.details.isEmpty()) r.step.put("detail", String.join(" · ", r.details));
		steps.add(r.step);
		if (!r.ok) {
			failed = true;
			if (stopOnFail) throw new StopException();
		}
	}

	private void fail(String why) {
		Map<String, Object> st = new LinkedHashMap<>();
		st.put("name", "입력 확인");
		st.put("ok", false);
		st.put("error", why);
		steps.add(st);
		failed = true;
	}

	private static final class StopException extends RuntimeException {
		StopException() {
			super(null, null, false, false);
		}
	}

	// ------------------------------------------------------------------ CSRF 토큰 찾기 (스크립트와 같은 규칙)

	/** [토큰, 같이 보낼 헤더 이름(없으면 null), 찾은 위치] */
	private String[] findCsrf(Resp r) {
		String name = s("CSRF_NAME");
		String v = attrOfTag(r.body, "input", name, "value");
		if (v != null) return new String[]{v, null, "숨은 입력칸"};
		v = attrOfTag(r.body, "meta", name, "content");
		if (v != null) return new String[]{v, attrOfTag(r.body, "meta", name + "_header", "content"), "meta 태그"};
		for (HttpCookie c : cookies.getCookieStore().getCookies()) {
			if (c.getName().equals(s("CSRF_COOKIE")) && !c.getValue().isEmpty())
				return new String[]{URLDecoder.decode(c.getValue(), StandardCharsets.UTF_8), s("CSRF_COOKIE_HEADER"), "쿠키"};
		}
		return null;
	}

	private static String attrOfTag(String html, String tag, String nameValue, String want) {
		Matcher m = Pattern.compile("(?is)<" + tag + "\\b[^>]*>").matcher(html);
		while (m.find()) {
			String t = m.group();
			if (nameValue.equals(attr(t, "name"))) return attr(t, want);
		}
		return null;
	}

	private static String attr(String tag, String name) {
		Matcher m = Pattern.compile("(?is)\\s" + Pattern.quote(name) + "\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))").matcher(tag);
		if (!m.find()) return null;
		String v = m.group(1) != null ? m.group(1) : m.group(2) != null ? m.group(2) : m.group(3);
		return v.replace("&quot;", "\"").replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&");
	}

	// ------------------------------------------------------------------ 도우미

	private String s(String key) {
		return Json.str(p, key, "");
	}

	private static String[] firstAccount(String users) {
		for (String line : (users == null ? "" : users).split("\\r?\\n")) {
			line = line.trim();
			if (line.isEmpty() || line.startsWith("#") || !line.contains(",")) continue;
			String[] a = line.split(",", 2);
			return new String[]{a[0].trim(), a[1].trim()};
		}
		return new String[]{"", ""};
	}

	private static String form(String... kv) {
		StringBuilder b = new StringBuilder();
		for (int i = 0; i + 1 < kv.length; i += 2) {
			if (b.length() > 0) b.append('&');
			b.append(URLEncoder.encode(kv[i], StandardCharsets.UTF_8)).append('=').append(URLEncoder.encode(kv[i + 1] == null ? "" : kv[i + 1], StandardCharsets.UTF_8));
		}
		return b.toString();
	}

	private static Charset charset(HttpResponse<?> r) {
		String ct = r.headers().firstValue("Content-Type").orElse("");
		Matcher m = Pattern.compile("(?i)charset=([\\w.-]+)").matcher(ct);
		if (m.find()) {
			try {
				return Charset.forName(m.group(1));
			} catch (RuntimeException ignore) {
				// UTF-8 사용
			}
		}
		return StandardCharsets.UTF_8;
	}

	private String cookieNames() {
		List<String> n = new ArrayList<>();
		for (HttpCookie c : cookies.getCookieStore().getCookies()) n.add(c.getName());
		return String.join(", ", n);
	}

	private static String cut(String s) {
		return s.length() > 200 ? s.substring(0, 200) + "…" : s;
	}
}
