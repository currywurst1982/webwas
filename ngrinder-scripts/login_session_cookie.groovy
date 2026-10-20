import static net.grinder.script.Grinder.grinder
import static org.junit.Assert.*
import static org.hamcrest.Matchers.*
import net.grinder.script.GTest
import net.grinder.scriptengine.groovy.junit.GrinderRunner
import net.grinder.scriptengine.groovy.junit.annotation.BeforeProcess
import net.grinder.scriptengine.groovy.junit.annotation.BeforeThread
import net.grinder.util.GrinderUtils
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

import org.ngrinder.http.HTTPRequest
import org.ngrinder.http.HTTPRequestControl
import org.ngrinder.http.HTTPResponse
import org.ngrinder.http.cookie.Cookie
import org.ngrinder.http.cookie.CookieManager

/**
 * [예제 1] 로그인 화면(폼)으로 로그인 → 세션 쿠키로 로그인 상태 유지 → 로그인 후 페이지 호출
 *
 * 이런 서비스에 맞습니다:
 *   - 로그인하면 서버가 쿠키(예: JSESSIONID)를 내려주고, 이후 요청은 그 쿠키로 "로그인한 사람"을 구분하는 방식
 *
 * 사용 전 바꿀 곳: 아래 "★ 설정" 부분만 고치면 됩니다.
 * 계정 목록: 스크립트와 같은 위치의 resources/users.csv (한 줄에 "아이디,비밀번호")
 *
 * nGrinder 3.5.x 기준 (org.ngrinder.http.HTTPRequest 사용)
 */
@RunWith(GrinderRunner)
class TestRunner {

	// ===================== ★ 설정 (여기만 고치세요) =====================
	static String BASE_URL     = "http://localhost:18080"   // 테스트 대상 서버 주소
	static String LOGIN_PATH   = "/login"                   // 로그인 요청을 보내는 주소
	static String ID_FIELD     = "username"                 // 로그인 폼의 아이디 입력칸 이름
	static String PW_FIELD     = "password"                 // 로그인 폼의 비밀번호 입력칸 이름
	static String TARGET_PATH  = "/mypage"                  // 로그인해야 볼 수 있는 페이지 (측정 대상)
	static String SUCCESS_TEXT = "님 환영합니다"             // 로그인 성공 시 그 페이지에 꼭 들어있는 글자
	// ====================================================================

	public static GTest test1
	public static HTTPRequest request
	public static List<List<String>> users = []

	// 스레드(가상 사용자)마다 따로 가지는 값
	String myId
	List<Cookie> loginCookies = []

	/** 프로세스 시작 시 1번: 계정 목록 읽기, 측정 항목 이름 정하기 */
	@BeforeProcess
	public static void beforeProcess() {
		HTTPRequestControl.setConnectionTimeout(30000)
		test1 = new GTest(1, "마이페이지")
		request = new HTTPRequest()
		users = new File("./resources/users.csv").readLines()
			.collect { it.trim() }
			.findAll { it && !it.startsWith("#") }
			.collect { it.split(",", 2).collect { s -> s.trim() } }
		grinder.logger.info("계정 {}개를 읽었습니다.", users.size())
	}

	/** 가상 사용자(스레드)마다 1번: 로그인하고, 받은 쿠키를 저장해 둠 */
	@BeforeThread
	public void beforeThread() {
		test1.record(this, "test1")          // test1() 메서드의 시간을 "마이페이지" 항목으로 측정
		grinder.statistics.delayReports = true

		// 전체 가상 사용자 중 몇 번째인지(0,1,2,...)로 계정을 골라 씀 → 사용자마다 다른 계정
		def account = users[GrinderUtils.getThreadUniqId() % users.size()]
		myId = account[0]

		// ⚠ Content-Type을 꼭 지정하세요. 지정하지 않으면 nGrinder 3.5.x는 폼이 아니라 JSON으로 보냅니다.
		HTTPResponse res = request.POST(BASE_URL + LOGIN_PATH,
			[(ID_FIELD): account[0], (PW_FIELD): account[1]],
			["Content-Type": "application/x-www-form-urlencoded"])
		loginCookies = CookieManager.getCookies()   // 서버가 준 로그인 쿠키를 꺼내 저장

		grinder.logger.info("{} 로그인 응답코드 {}, 받은 쿠키 {}개", myId, res.statusCode, loginCookies.size())
		// 로그인 실패면 이 가상 사용자는 여기서 멈춤 (잘못된 계정을 바로 알 수 있게)
		assertThat("로그인 응답코드가 이상합니다: " + myId, res.statusCode, isOneOf(200, 302))
		assertThat("로그인 쿠키를 받지 못했습니다: " + myId, loginCookies.size(), greaterThan(0))
	}

	/** 매 반복 직전: nGrinder가 반복마다 쿠키를 지우므로, 저장해 둔 로그인 쿠키를 다시 넣음 */
	@Before
	public void before() {
		CookieManager.addCookies(loginCookies)
	}

	/** 실제로 반복 측정되는 부분 */
	@Test
	public void test1() {
		HTTPResponse res = request.GET(BASE_URL + TARGET_PATH)
		assertThat(res.statusCode, is(200))
		// 응답코드만 보면 "로그인 화면이 200으로 돌아온 경우"를 놓칠 수 있어 내용까지 확인
		assertThat("로그인이 풀린 것 같습니다: " + myId, res.bodyText, containsString(SUCCESS_TEXT))
	}
}
