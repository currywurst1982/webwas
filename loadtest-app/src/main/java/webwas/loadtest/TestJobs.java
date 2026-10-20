package webwas.loadtest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

/**
 * nGrinder로 실행하는 테스트 작업 (WAS 안에서 백그라운드로 진행 → 브라우저를 닫아도 계속됨)
 *
 *  통합(integration)  가상 사용자 1명이 시나리오를 N회 실행 → 에러 0건이면 통과
 *  성능(performance)  정한 Vuser·시간으로 실행 → 합격 기준(TPS·응답시간·에러율)으로 판정
 *  임계(breakpoint)   Vuser를 단계적으로 늘려 반복 → 기준 초과/TPS 정체/오류 시 멈추고 임계점 보고
 *
 * 작업 목록은 WAS 메모리에만 있습니다 (재시작하면 사라짐. nGrinder의 테스트 기록은 남음).
 */
public final class TestJobs {

	private static final Map<Long, Job> JOBS = new ConcurrentHashMap<>();
	private static final AtomicLong IDS = new AtomicLong(System.currentTimeMillis() / 1000 % 100000 * 10);
	private static final ExecutorService POOL = Executors.newCachedThreadPool(r -> {
		Thread t = new Thread(r, "loadtest-job");
		t.setDaemon(true);
		return t;
	});
	private static final int MAX_STRESS_STEPS = 20;
	private static final long POLL_MS = 3000;

	private TestJobs() {
	}

	public static final class Job {
		final long id = IDS.incrementAndGet();
		final String type;
		final String scenario;
		final String name;
		final Map<String, Object> generated;
		final Map<String, Object> options;
		final Map<String, Object> sla;
		final long createdAt = System.currentTimeMillis();
		final List<Map<String, Object>> steps = Collections.synchronizedList(new ArrayList<>());
		volatile String status = "RUNNING";     // RUNNING, PASSED, FAILED, STOPPED, ERROR
		volatile String conclusion = "";
		volatile Long currentTestId;
		volatile boolean stopRequested;

		Job(String type, String scenario, String name, Map<String, Object> generated, Map<String, Object> options, Map<String, Object> sla) {
			this.type = type;
			this.scenario = scenario;
			this.name = name;
			this.generated = generated;
			this.options = options;
			this.sla = sla;
		}

		Map<String, Object> snapshot() {
			Map<String, Object> m = new LinkedHashMap<>();
			m.put("id", id);
			m.put("type", type);
			m.put("scenario", scenario);
			m.put("name", name);
			m.put("createdAt", createdAt);
			m.put("status", status);
			m.put("conclusion", conclusion);
			m.put("currentTestId", currentTestId);
			m.put("sla", sla);
			synchronized (steps) {
				List<Object> copy = new ArrayList<>();
				for (Map<String, Object> s : steps) copy.add(new LinkedHashMap<>(s));
				m.put("steps", copy);
			}
			return m;
		}
	}

	// ------------------------------------------------------------------ 공개 API

	public static Map<String, Object> start(String type, String scenario, Map<String, Object> generated,
											Map<String, Object> options, Map<String, Object> sla) {
		String name = Json.str(options, "testName", "");
		if (name.isEmpty()) throw new IllegalArgumentException("테스트 이름을 입력하세요");
		validate(type, options);
		Job job = new Job(type, scenario, name, generated, options, sla);
		JOBS.put(job.id, job);
		trim();
		POOL.submit(() -> {
			try {
				switch (type) {
					case "integration": integration(job); break;
					case "performance": performance(job); break;
					case "breakpoint": breakpoint(job); break;
					default: throw new IllegalArgumentException("알 수 없는 테스트 종류: " + type);
				}
			} catch (Exception e) {
				job.status = "ERROR";
				job.conclusion = "실행 중 오류: " + e.getMessage();
			} finally {
				job.currentTestId = null;
			}
		});
		return job.snapshot();
	}

	public static List<Object> list() {
		List<Job> all = new ArrayList<>(JOBS.values());
		all.sort((a, b) -> Long.compare(b.id, a.id));
		List<Object> out = new ArrayList<>();
		for (Job j : all) out.add(j.snapshot());
		return out;
	}

	public static Map<String, Object> get(long id) {
		Job j = JOBS.get(id);
		if (j == null) throw new IllegalArgumentException("없는 작업입니다 (WAS를 재시작했다면 목록이 지워집니다)");
		return j.snapshot();
	}

	public static Map<String, Object> stop(long id) throws java.io.IOException {
		Job j = JOBS.get(id);
		if (j == null) throw new IllegalArgumentException("없는 작업입니다");
		j.stopRequested = true;
		Long t = j.currentTestId;
		if (t != null) NGrinderTests.stop(t);
		return j.snapshot();
	}

	// ------------------------------------------------------------------ 종류별 진행

	private static void integration(Job job) throws Exception {
		int runs = Json.integer(job.options, "runCount", 3);
		Map<String, Object> st = runOne(job, new NGrinderTests.Size(1, 1, 0, runs), "통합", "가상 사용자 1명 × " + runs + "회");
		if (job.stopRequested) { finishStopped(job); return; }
		boolean ok = "FINISHED".equals(st.get("category")) && ((Number) st.get("errors")).longValue() == 0
			&& ((Number) st.get("tests")).longValue() > 0;
		st.put("verdict", ok ? "통과" : "실패");
		job.status = ok ? "PASSED" : "FAILED";
		job.conclusion = ok
			? "통과: 실제 nGrinder 에이전트에서 시나리오 전체가 에러 없이 " + st.get("tests") + "건 실행됐습니다. 이제 성능테스트로 넘어가도 됩니다."
			: "실패: " + failureText(st);
	}

	private static void performance(Job job) throws Exception {
		NGrinderTests.Size size = new NGrinderTests.Size(Json.integer(job.options, "agentCount", 1),
			Json.integer(job.options, "vuserPerAgent", 10), Json.integer(job.options, "durationMinutes", 1), 0);
		Map<String, Object> st = runOne(job, size, "성능", null);
		if (job.stopRequested) { finishStopped(job); return; }
		List<String> fails = slaFailures(job, st, true);
		boolean ended = "FINISHED".equals(st.get("category")) || "WARNED".equals(st.get("category"));
		if (!ended) fails.add(0, "테스트가 정상 종료되지 않음(" + st.get("status") + ")");
		st.put("verdict", fails.isEmpty() ? "합격" : "불합격");
		job.status = fails.isEmpty() ? "PASSED" : "FAILED";
		job.conclusion = fails.isEmpty()
			? String.format("합격: 총 Vuser %s명에서 TPS %s, 평균 응답시간 %sms, 에러율 %s%% — 모든 기준 충족.", st.get("totalVuser"), st.get("tps"), st.get("mtt"), st.get("errorRate"))
			: "불합격: " + String.join(" / ", fails) + (ended ? "" : " — " + failureText(st));
	}

	private static void breakpoint(Job job) throws Exception {
		int agents = Json.integer(job.options, "agentCount", 1);
		int start = Json.integer(job.options, "startVuser", 10);
		int step = Json.integer(job.options, "stepVuser", 10);
		int max = Json.integer(job.options, "maxVuser", 100);
		int minutes = Json.integer(job.options, "stepMinutes", 1);
		Map<String, Object> lastGood = null;
		String stopReason = null;
		Map<String, Object> prev = null;
		int n = 0;
		for (int v = start; v <= max && n < MAX_STRESS_STEPS; v += step, n++) {
			Map<String, Object> st = runOne(job, new NGrinderTests.Size(agents, v, minutes, 0), "임계 " + (n + 1) + "단계", null);
			if (job.stopRequested) break;
			List<String> fails = new ArrayList<>();
			String cat = String.valueOf(st.get("category"));
			if (!cat.equals("FINISHED") && !cat.equals("WARNED")) fails.add("테스트가 오류로 중지(" + st.get("status") + ")");
			fails.addAll(slaFailures(job, st, false));
			if (fails.isEmpty() && prev != null) {
				double p = ((Number) prev.get("tps")).doubleValue(), c = ((Number) st.get("tps")).doubleValue();
				if (c < p * 1.05) fails.add(String.format("Vuser를 늘렸는데 TPS가 거의 늘지 않음(%s → %s, 5%% 미만) — 포화", p, c));
			}
			if (fails.isEmpty()) {
				st.put("verdict", "통과");
				lastGood = st;
				prev = st;
			} else {
				st.put("verdict", "한계");
				st.put("reason", String.join(" / ", fails));
				stopReason = "Vuser " + st.get("totalVuser") + "명: " + String.join(" / ", fails);
				if (!cat.equals("FINISHED") && !cat.equals("WARNED")) st.put("reason", st.get("reason") + " — " + failureText(st));
				break;
			}
		}
		if (job.stopRequested) { finishStopped(job); return; }
		if (lastGood == null) {
			job.status = "FAILED";
			job.conclusion = "첫 단계부터 기준을 넘었습니다. 시작 Vuser를 낮추거나, 먼저 통합·성능테스트로 정상 동작을 확인하세요. (" + stopReason + ")";
		} else if (stopReason == null) {
			job.status = "PASSED";
			job.conclusion = String.format("최대 설정치(총 Vuser %s명)까지 모든 기준 이내 — 임계점은 이보다 높습니다. 최대 TPS %s. 최대 Vuser를 늘려 다시 실행하세요.",
				lastGood.get("totalVuser"), lastGood.get("tps"));
		} else {
			job.status = "PASSED";
			job.conclusion = String.format("임계점 추정: 총 Vuser 약 %s명 (그때 TPS %s, 응답시간 %sms). 다음 단계에서 한계 도달 → %s",
				lastGood.get("totalVuser"), lastGood.get("tps"), lastGood.get("mtt"), stopReason);
		}
	}

	// ------------------------------------------------------------------ 공통

	/** 테스트 1개 만들고 끝날 때까지 기다림. 단계 기록을 job.steps 에 실시간 반영 */
	private static Map<String, Object> runOne(Job job, NGrinderTests.Size size, String label, String desc) throws Exception {
		Map<String, Object> step = Collections.synchronizedMap(new LinkedHashMap<>());
		step.put("label", label);
		step.put("status", "생성 중");
		job.steps.add(step);
		String tag = job.type;
		Map<String, Object> created;
		try {
			created = NGrinderTests.create(job.scenario, job.generated, job.name, tag, size, Json.str(job.options, "targetHostIp", ""));
		} catch (Exception e) {
			step.put("status", "생성 실패");
			step.put("error", e.getMessage());
			throw e;
		}
		long id = ((Number) created.get("testId")).longValue();
		job.currentTestId = id;
		step.putAll(created);
		if (desc != null) step.put("desc", desc);
		while (true) {
			Thread.sleep(POLL_MS);
			Map<String, Object> t = NGrinderTests.get(id);
			Map<String, Object> s = NGrinderTests.summary(t);
			s.put("totalVuser", created.get("totalVuser"));
			boolean done = NGrinderTests.isDone(t);
			if (!done) {
				// nGrinder는 TPS·응답시간 등을 테스트가 끝나야 채움 → 진행 중에는 비워 둠 (화면에 0 대신 "–")
				for (String k : new String[]{"tps", "peakTps", "mtt", "tests", "errors", "errorRate"}) s.put(k, null);
			}
			step.putAll(s);
			if (done) break;
			if (job.stopRequested) NGrinderTests.stop(id);
		}
		job.currentTestId = null;
		String cat = String.valueOf(step.get("category"));
		boolean needLog = !cat.equals("FINISHED") || ((Number) step.get("errors")).longValue() > 0;
		if (needLog) {
			// 에이전트 로그는 테스트가 끝나고 몇 초 뒤에 컨트롤러에 올라옴 → 최대 30초 기다림
			Map<String, Object> log = NGrinderTests.analyzeLogs(id);
			for (int i = 0; i < 10 && Boolean.TRUE.equals(log.get("pending")); i++) {
				Thread.sleep(POLL_MS);
				log = NGrinderTests.analyzeLogs(id);
			}
			log.remove("pending");
			step.put("log", log);
		}
		return step;
	}

	private static List<String> slaFailures(Job job, Map<String, Object> st, boolean checkTps) {
		List<String> f = new ArrayList<>();
		double tps = ((Number) st.get("tps")).doubleValue(), mtt = ((Number) st.get("mtt")).doubleValue();
		double er = ((Number) st.get("errorRate")).doubleValue();
		double minTps = num(job.sla, "minTps"), maxMtt = num(job.sla, "maxMtt"), maxErr = num(job.sla, "maxErrorRate");
		if (checkTps && minTps > 0 && tps < minTps) f.add("TPS " + tps + " < 목표 " + minTps);
		if (maxMtt > 0 && mtt > maxMtt) f.add("응답시간 " + mtt + "ms > 기준 " + maxMtt + "ms");
		if (er > maxErr) f.add("에러율 " + er + "% > 기준 " + maxErr + "%");
		return f;
	}

	private static String failureText(Map<String, Object> st) {
		StringBuilder b = new StringBuilder();
		b.append("상태 ").append(st.get("status")).append(", 성공 ").append(st.get("tests")).append("건, 에러 ").append(st.get("errors")).append("건");
		Object log = st.get("log");
		if (log instanceof Map && ((Map<?, ?>) log).get("hint") != null) b.append(". 원인 추정: ").append(((Map<?, ?>) log).get("hint"));
		return b.toString();
	}

	private static void finishStopped(Job job) {
		job.status = "STOPPED";
		job.conclusion = "사용자가 중지했습니다.";
	}

	private static double num(Map<String, Object> m, String k) {
		Object v = m == null ? null : m.get(k);
		if (v == null || String.valueOf(v).trim().isEmpty()) return 0;
		return v instanceof Number ? ((Number) v).doubleValue() : Double.parseDouble(String.valueOf(v).trim());
	}

	private static void validate(String type, Map<String, Object> o) {
		switch (type) {
			case "integration": {
				int r = Json.integer(o, "runCount", 3);
				if (r < 1 || r > 100) throw new IllegalArgumentException("통합테스트 반복 횟수는 1~100 사이로 입력하세요");
				break;
			}
			case "performance":
				new NGrinderTests.Size(Json.integer(o, "agentCount", 1), Json.integer(o, "vuserPerAgent", 10), Json.integer(o, "durationMinutes", 1), 0);
				break;
			case "breakpoint": {
				int start = Json.integer(o, "startVuser", 10), step = Json.integer(o, "stepVuser", 10), max = Json.integer(o, "maxVuser", 100);
				new NGrinderTests.Size(Json.integer(o, "agentCount", 1), start, Json.integer(o, "stepMinutes", 1), 0);
				if (step < 1) throw new IllegalArgumentException("증가량은 1 이상이어야 합니다");
				if (max < start) throw new IllegalArgumentException("최대 Vuser는 시작 Vuser 이상이어야 합니다");
				if ((max - start) / step + 1 > MAX_STRESS_STEPS) throw new IllegalArgumentException("단계가 너무 많습니다 (최대 " + MAX_STRESS_STEPS + "단계). 증가량을 키우세요");
				break;
			}
			default:
				throw new IllegalArgumentException("알 수 없는 테스트 종류: " + type);
		}
	}

	/** 오래된 끝난 작업 정리 (최대 50개 보관) */
	private static void trim() {
		if (JOBS.size() <= 50) return;
		List<Job> done = new ArrayList<>();
		for (Job j : JOBS.values()) if (!"RUNNING".equals(j.status)) done.add(j);
		done.sort((a, b) -> Long.compare(a.id, b.id));
		for (int i = 0; i < done.size() && JOBS.size() > 50; i++) JOBS.remove(done.get(i).id);
	}
}
