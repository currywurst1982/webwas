import static net.grinder.script.Grinder.grinder
import static org.junit.Assert.*
import static org.hamcrest.Matchers.*
import groovy.json.JsonSlurper
import net.grinder.script.GTest
import net.grinder.scriptengine.groovy.junit.GrinderRunner
import net.grinder.scriptengine.groovy.junit.annotation.BeforeProcess
import net.grinder.scriptengine.groovy.junit.annotation.BeforeThread
import net.grinder.util.GrinderUtils
import org.junit.Test
import org.junit.runner.RunWith

import org.ngrinder.http.HTTPRequest
import org.ngrinder.http.HTTPRequestControl
import org.ngrinder.http.HTTPResponse

/**
 * [예제 2] 로그인 API(JSON)로 토큰을 받고 → 이후 요청 헤더에 "Authorization: Bearer 토큰"을 붙여 호출
 *
 * 이런 서비스에 맞습니다:
 *   - 로그인 API가 {"accessToken":"..."} 같은 JSON을 돌려주는 방식 (모바일 앱 API, SPA 백엔드 등)
 *
 * 사용 전 바꿀 곳: 아래 "★ 설정" 부분만 고치면 됩니다.
 * 계정 목록: 스크립트와 같은 위치의 resources/users.csv (한 줄에 "아이디,비밀번호")
 *
 * nGrinder 3.5.x 기준 (org.ngrinder.http.HTTPRequest 사용)
 */
@RunWith(GrinderRunner)
class TestRunner {

	// ===================== ★ 설정 (여기만 고치세요) =====================
	static String BASE_URL    = "http://localhost:18080"   // 테스트 대상 서버 주소
	static String LOGIN_PATH  = "/api/login"               // 로그인 API 주소
	static String ID_FIELD    = "username"                 // 로그인 API에 보내는 아이디 항목 이름
	static String PW_FIELD    = "password"                 // 로그인 API에 보내는 비밀번호 항목 이름
	static String TOKEN_FIELD = "accessToken"              // 로그인 응답 JSON에서 토큰이 들어있는 항목 이름
	static String API1_PATH   = "/api/me"                  // 측정할 API 1
	static String API2_PATH   = "/api/orders"              // 측정할 API 2 (없으면 "" 로 비워두기)
	// ====================================================================

	public static GTest test1
	public static GTest test2
	public static HTTPRequest request
	public static List<List<String>> users = []

	// 스레드(가상 사용자)마다 따로 가지는 값
	String myId
	Map<String, String> authHeaders = [:]

	@BeforeProcess
	public static void beforeProcess() {
		HTTPRequestControl.setConnectionTimeout(30000)
		test1 = new GTest(1, "내 정보 API")
		test2 = new GTest(2, "주문목록 API")
		request = new HTTPRequest()
		users = new File("./resources/users.csv").readLines()
			.collect { it.trim() }
			.findAll { it && !it.startsWith("#") }
			.collect { it.split(",", 2).collect { s -> s.trim() } }
		grinder.logger.info("계정 {}개를 읽었습니다.", users.size())
	}

	/** 가상 사용자마다 1번: 로그인 API 호출 → 토큰 저장 */
	@BeforeThread
	public void beforeThread() {
		test1.record(this, "test1")
		if (API2_PATH) test2.record(this, "test2")   // 비어 있으면 측정하지 않음
		grinder.statistics.delayReports = true

		def account = users[GrinderUtils.getThreadUniqId() % users.size()]
		myId = account[0]

		// Content-Type을 JSON으로 주면 nGrinder가 아래 Map을 JSON 본문으로 바꿔 보냄
		HTTPResponse res = request.POST(BASE_URL + LOGIN_PATH,
			[(ID_FIELD): account[0], (PW_FIELD): account[1]],
			["Content-Type": "application/json"])
		assertThat("[LOGIN_FAILED] 로그인 API 실패: " + myId + " / " + text(res), res.statusCode, is(200))

		def token = new JsonSlurper().parseText(text(res))[TOKEN_FIELD]
		assertNotNull("[NO_TOKEN] 응답에서 토큰(" + TOKEN_FIELD + ")을 찾지 못했습니다: " + text(res), token)
		authHeaders = ["Authorization": "Bearer " + token]
		grinder.logger.info("{} 로그인 성공", myId)
	}

	@Test
	public void test1() {
		HTTPResponse res = request.GET(BASE_URL + API1_PATH, [:], authHeaders)
		assertThat(res.statusCode, is(200))
	}

	@Test
	public void test2() {
		if (!API2_PATH) return
		HTTPResponse res = request.GET(BASE_URL + API2_PATH, [:], authHeaders)
		assertThat(res.statusCode, is(200))
	}

	/**
	 * 응답 본문을 글자로 바꾸기. 서버가 알려준 문자셋(Content-Type의 charset, 없으면 UTF-8)을 씀.
	 * ⚠ nGrinder의 res.bodyText 는 "에이전트 PC의 기본 문자셋"을 써서, 한국어 Windows(MS949)나
	 *   로캘 설정이 없는 리눅스(Java 11 이하)에서는 한글이 깨져 글자 비교가 실패함 (실제 에이전트에서 확인)
	 */
	static String text(HTTPResponse res) {
		String ct = res.getHeader("Content-Type")?.value ?: ""
		def m = (ct =~ /(?i)charset=([\w.-]+)/)
		java.nio.charset.Charset cs = java.nio.charset.StandardCharsets.UTF_8
		if (m.find()) {
			try { cs = java.nio.charset.Charset.forName(m.group(1)) } catch (Exception ignored) { }
		}
		return res.getBodyText(cs)
	}
}
