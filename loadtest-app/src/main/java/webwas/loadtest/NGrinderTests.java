package webwas.loadtest;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/** nGrinder 테스트 만들기·상태 조회·중지·로그 분석 */
public final class NGrinderTests {

	private static final String ROOT_FOLDER = "loadtest_dashboard";
	private static final AtomicInteger SEQ = new AtomicInteger();

	private NGrinderTests() {
	}

	/** 실행 크기 */
	public static final class Size {
		final int agents;
		final int vuser;          // 에이전트당
		final int minutes;        // 시간 기준일 때 (runCount 가 0일 때)
		final int runCount;       // 횟수 기준일 때 (스레드당 반복 횟수)

		Size(int agents, int vuser, int minutes, int runCount) {
			if (agents < 1) throw new IllegalArgumentException("에이전트 수는 1 이상이어야 합니다");
			if (vuser < 1) throw new IllegalArgumentException("에이전트당 Vuser는 1 이상이어야 합니다");
			if (runCount <= 0 && (minutes < 1 || minutes > 600)) throw new IllegalArgumentException("테스트 시간은 1~600분 사이로 입력하세요");
			this.agents = agents;
			this.vuser = vuser;
			this.minutes = minutes;
			this.runCount = runCount;
		}
	}

	/** 스크립트(+계정 파일) 업로드 후 테스트 생성·바로 시작. 결과: testId, processes, threads 등 */
	public static Map<String, Object> create(String scenario, Map<String, Object> generated, String testName, String tag,
											 Size size, String targetIp) throws IOException {
		if (testName == null || testName.trim().isEmpty()) throw new IllegalArgumentException("테스트 이름을 입력하세요");
		if (targetIp != null && !targetIp.isEmpty() && !targetIp.matches("[0-9a-fA-F.:]+"))
			throw new IllegalArgumentException("모니터 대상 IP 형식이 올바르지 않습니다: " + targetIp);

		// nGrinder 규칙: vuserPerAgent = processes × threads (스레드 100개 이하로 나눔)
		int processes = Math.max(1, (int) Math.ceil(size.vuser / 100.0));
		int threads = (int) Math.ceil(size.vuser / (double) processes);
		int vuserPerAgent = processes * threads;

		// 실행마다 새 폴더 → 각 테스트가 어떤 스크립트로 돌았는지 그대로 남음
		String folder = ROOT_FOLDER + "/" + scenario + "/run_" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"))
			+ "_" + (SEQ.incrementAndGet() % 1000);
		String scriptFile = scenario + ".groovy";
		check(NGrinderClient.upload(folder, scriptFile, ((String) generated.get("script")).getBytes(StandardCharsets.UTF_8),
			"loadtest dashboard: " + testName), "스크립트 업로드");
		if (generated.containsKey("users")) {
			check(NGrinderClient.upload(folder + "/resources", "users.csv",
				((String) generated.get("users")).getBytes(StandardCharsets.UTF_8), "accounts"), "계정 파일 업로드");
		}

		Map<String, Object> test = new LinkedHashMap<>();
		test.put("testName", testName.trim());
		test.put("tagString", "loadtest_dashboard," + scenario + (tag == null ? "" : "," + tag));
		test.put("description", "시나리오 대시보드에서 실행 (" + scenario + (tag == null ? "" : ", " + tag) + ")");
		test.put("scriptName", folder + "/" + scriptFile);
		test.put("agentCount", size.agents);
		test.put("vuserPerAgent", vuserPerAgent);
		test.put("processes", processes);
		test.put("threads", threads);
		if (size.runCount > 0) {
			test.put("threshold", "R");          // 횟수 기준
			test.put("runCount", size.runCount);
		} else {
			test.put("threshold", "D");          // 시간 기준
			test.put("duration", size.minutes * 60_000L);
		}
		test.put("targetHosts", targetIp == null ? "" : targetIp);
		test.put("samplingInterval", 2);
		test.put("status", "READY");             // READY = 저장 후 바로 실행 대기열에 넣음
		NGrinderClient.Resp created = NGrinderClient.json("POST", "/perftest/api", test);
		check(created, "테스트 생성");
		Map<String, Object> t = Json.parseObject(created.text());

		Map<String, Object> out = new LinkedHashMap<>();
		out.put("testId", t.get("id"));
		out.put("testName", testName.trim());
		out.put("scriptPath", folder + "/" + scriptFile);
		out.put("agentCount", size.agents);
		out.put("processes", processes);
		out.put("threads", threads);
		out.put("vuserPerAgent", vuserPerAgent);
		out.put("totalVuser", vuserPerAgent * size.agents);
		out.put("ngrinderTestUrl", NGrinderClient.url() + "/perftest/" + t.get("id"));
		return out;
	}

	public static Map<String, Object> get(long id) throws IOException {
		NGrinderClient.Resp r = NGrinderClient.call("GET", "/perftest/api/" + id, null, null);
		check(r, "테스트 조회");
		return Json.parseObject(r.text());
	}

	public static void stop(long id) throws IOException {
		NGrinderClient.call("PUT", "/perftest/api/" + id + "?action=stop", "application/json", new byte[0]);
	}

	/** 상태 이름 (READY, TESTING, FINISHED ...) */
	public static String statusName(Map<String, Object> test) {
		Object s = test.get("status");
		if (s instanceof Map) return String.valueOf(((Map<?, ?>) s).get("name"));
		return String.valueOf(s);
	}

	/** 상태 분류 (PREPARE, PROGRESSING, TESTING, FINISHED, WARNED, ERROR, STOP ...) */
	public static String category(Map<String, Object> test) {
		Object s = test.get("status");
		if (s instanceof Map) {
			Object c = ((Map<?, ?>) s).get("category");
			if (c instanceof Map) return String.valueOf(((Map<?, ?>) c).get("name"));
			return String.valueOf(c);
		}
		return "";
	}

	public static boolean isDone(Map<String, Object> test) {
		String c = category(test);
		return c.equals("FINISHED") || c.equals("WARNED") || c.equals("ERROR") || c.equals("STOP");
	}

	public static double num(Map<String, Object> m, String key) {
		Object v = m.get(key);
		return v instanceof Number ? ((Number) v).doubleValue() : 0;
	}

	/** 결과 요약 (TPS, 응답시간, 성공·에러 건수, 에러율) */
	public static Map<String, Object> summary(Map<String, Object> test) {
		Map<String, Object> s = new LinkedHashMap<>();
		double tests = num(test, "tests"), errors = num(test, "errors");
		s.put("testId", test.get("id"));
		s.put("status", statusName(test));
		s.put("category", category(test));
		s.put("tps", round(num(test, "tps")));
		s.put("peakTps", round(num(test, "peakTps")));
		s.put("mtt", round(num(test, "meanTestTime")));
		s.put("tests", (long) tests);
		s.put("errors", (long) errors);
		s.put("errorRate", tests + errors > 0 ? round(errors / (tests + errors) * 100) : 0.0);
		s.put("message", stripTags(String.valueOf(test.get("lastProgressMessage") == null ? "" : test.get("lastProgressMessage"))));
		return s;
	}

	static double round(double v) {
		return Math.round(v * 100) / 100.0;
	}

	private static String stripTags(String s) {
		String t = s.replaceAll("<[^>]+>", " ").replaceAll("\\s+", " ").trim();
		return t.length() > 400 ? t.substring(0, 400) : t;
	}

	/**
	 * 에이전트 로그에서 첫 오류와 원인 설명 뽑기.
	 * (GET /perftest/api/{id}/logs 로 파일 목록 → GET /perftest/{id}/show_log/{파일} 로 내용)
	 */
	public static Map<String, Object> analyzeLogs(long id) {
		Map<String, Object> out = new LinkedHashMap<>();
		try {
			NGrinderClient.Resp list = NGrinderClient.call("GET", "/perftest/api/" + id + "/logs", null, null);
			if (!list.ok() || list.looksLikeLoginPage()) return out;
			Object files = Json.parse(list.text());
			if (!(files instanceof List) || ((List<?>) files).isEmpty()) {
				out.put("pending", true);
				out.put("hint", "에이전트 로그가 아직 없습니다 (테스트가 끝나고 잠시 뒤에 올라옵니다). nGrinder 화면에서 로그를 확인하세요.");
				return out;
			}
			String name = String.valueOf(((List<?>) files).get(0));
			NGrinderClient.Resp log = NGrinderClient.call("GET", "/perftest/" + id + "/show_log/"
				+ URLEncoder.encode(name, "UTF-8").replace("+", "%20"), null, null);
			if (!log.ok()) return out;
			String text = log.text();
			List<String> lines = new ArrayList<>();
			String firstError = null;
			for (String line : text.split("\\r?\\n")) {
				String l = line.trim();
				if (firstError == null && (l.contains(" ERROR ") || l.startsWith("java.lang.AssertionError"))) firstError = l;
				if ((l.startsWith("Caused by:") || l.contains("AssertionError")) && !lines.contains(l) && lines.size() < 6) lines.add(l);
			}
			out.put("logFile", name);
			if (firstError != null) out.put("firstError", firstError.length() > 500 ? firstError.substring(0, 500) : firstError);
			out.put("causes", lines);
			out.put("hint", explain(text));
		} catch (Exception e) {
			out.put("hint", "로그를 가져오지 못했습니다: " + e.getMessage());
		}
		return out;
	}

	/** 자주 나는 오류 → 쉬운 설명 */
	static String explain(String log) {
		if (log.contains("InternalConnectChannel.onTimeout"))
			return "대상 서버에 '연결' 자체가 시간 초과됐습니다. 에이전트 서버에서 '대상 서버 주소(BASE_URL)'로 갈 수 없습니다 → "
				+ "에이전트 서버에서 curl 로 그 주소가 열리는지, IP·방화벽을 확인하세요. 에이전트와 WAS가 같은 서버라면 http://127.0.0.1:포트/... 를 써 보세요.";
		if (log.contains("Connection refused"))
			return "대상 서버가 연결을 거부했습니다. 그 IP·포트에서 WAS가 실행 중인지(ss -lntp), 포트 번호가 맞는지 확인하세요.";
		if (log.contains("UnknownHostException"))
			return "대상 서버 이름을 찾지 못했습니다. 주소에 도메인 대신 IP를 쓰거나, 에이전트 서버의 DNS·/etc/hosts 를 확인하세요.";
		if (log.contains("SocketTimeoutException"))
			return "대상 서버의 응답이 너무 느려 시간 초과됐습니다. 부하를 줄이거나 서버 상태(CPU, DB)를 확인하세요.";
		if (log.contains("[NOT_LOGGED_IN]")) return "로그인 후 페이지에 '성공 글자'가 없습니다. 성공 글자 오타, 동시 로그인 제한, 로그인 실패를 확인하세요.";
		if (log.contains("[LOGIN_FAILED]")) return "로그인 요청이 실패했습니다. 로그인 주소, 아이디·비밀번호 항목 이름, 계정을 확인하세요 (CSRF면 403 여부).";
		if (log.contains("[NO_CSRF_TOKEN]")) return "로그인 화면에서 CSRF 토큰을 찾지 못했습니다. 고급 설정의 'CSRF 토큰 이름'을 확인하세요.";
		if (log.contains("[NO_TOKEN]")) return "로그인 API 응답에서 토큰 항목을 찾지 못했습니다. 고급 설정의 '토큰 항목 이름'을 확인하세요.";
		if (log.contains("[NO_LOGIN_COOKIE]")) return "로그인했는데 쿠키를 받지 못했습니다. 로그인 주소와 계정을 확인하세요.";
		if (log.contains("[BAD_STATUS]")) return "응답코드가 200이 아닙니다. 주소(경로)가 맞는지 확인하세요.";
		if (log.contains("[TEXT_NOT_FOUND]")) return "응답에 기대한 글자가 없습니다. '응답에 꼭 있어야 하는 글자'를 확인하세요.";
		if (log.contains("[POST_FAILED]")) return "로그인 후 POST가 실패했습니다 (403이면 CSRF 토큰 문제).";
		if (log.contains("FileNotFoundException")) return "파일을 찾지 못했습니다 (resources/users.csv 등).";
		return null;
	}

	static void check(NGrinderClient.Resp r, String step) {
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
}
