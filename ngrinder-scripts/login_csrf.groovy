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
 * [예제 3] CSRF 토큰이 필요한 로그인
 *
 * 흐름: 로그인 화면 열기(GET) → 화면에서 CSRF 토큰 찾기 → 아이디/비밀번호 + 토큰으로 로그인(POST)
 *       → 세션 쿠키로 로그인 상태 유지 → 로그인 후 페이지 반복 측정
 *
 * 토큰을 찾는 곳 (위에서부터 순서대로 시도, 자동):
 *   ① 로그인 폼 안의 숨은 입력칸   <input type="hidden" name="_csrf" value="토큰">
 *   ② 화면 머리의 meta 태그        <meta name="_csrf" content="토큰"> (+ <meta name="_csrf_header" content="헤더이름">)
 *   ③ 쿠키                         Set-Cookie: XSRF-TOKEN=토큰  → 요청 헤더 X-XSRF-TOKEN 으로 돌려보냄
 *   (이름 기본값은 Spring Security 기본값. 다른 이름이면 ★ 설정에서 바꾸세요)
 *
 * 사용 전 바꿀 곳: "★ 설정" 부분만 고치면 됩니다.
 * 계정 목록: 스크립트와 같은 위치의 resources/users.csv (한 줄에 "아이디,비밀번호")
 * nGrinder 3.5.x 기준
 */
@RunWith(GrinderRunner)
class TestRunner {

	// ===================== ★ 설정 (여기만 고치세요) =====================
	static String BASE_URL         = "http://localhost:18080"  // 테스트 대상 서버 주소
	static String LOGIN_PAGE_PATH  = "/login"                  // 로그인 "화면" 주소 (토큰이 들어있는 페이지, GET)
	static String LOGIN_PATH       = "/login"                  // 로그인 "요청"을 보내는 주소 (POST)
	static String ID_FIELD         = "username"                // 아이디 입력칸 이름
	static String PW_FIELD         = "password"                // 비밀번호 입력칸 이름
	static String CSRF_NAME        = "_csrf"                   // ①② 토큰 입력칸/메타 이름, 그리고 로그인 때 보낼 항목 이름
	static String CSRF_COOKIE      = "XSRF-TOKEN"              // ③ 토큰이 담긴 쿠키 이름
	static String CSRF_COOKIE_HEADER = "X-XSRF-TOKEN"          // ③ 쿠키 토큰을 돌려보낼 요청 헤더 이름
	static String TARGET_PATH      = "/mypage"                 // 로그인 후 측정할 페이지
	static String SUCCESS_TEXT     = "님 환영합니다"            // 로그인 성공 시 그 페이지에 꼭 있는 글자

	// (선택) 로그인 후 "저장/주문" 같은 POST 요청도 측정하려면 채우세요. 비워두면 건너뜀.
	static String ACTION_PAGE_PATH = ""                        // 그 요청을 보내는 화면 주소 (새 토큰을 여기서 읽음)
	static String ACTION_PATH      = ""                        // POST 보낼 주소
	static Map<String, String> ACTION_PARAMS = [:]             // 보낼 값, 예: ["title": "부하테스트", "qty": "1"]
	// ====================================================================

	public static GTest test1
	public static GTest test2
	public static HTTPRequest request
	public static List<List<String>> users = []

	String myId
	List<Cookie> loginCookies = []

	@BeforeProcess
	public static void beforeProcess() {
		HTTPRequestControl.setConnectionTimeout(30000)
		test1 = new GTest(1, "로그인 후 페이지")
		test2 = new GTest(2, "로그인 후 POST")
		request = new HTTPRequest()
		users = new File("./resources/users.csv").readLines()
			.collect { it.trim() }
			.findAll { it && !it.startsWith("#") }
			.collect { it.split(",", 2).collect { s -> s.trim() } }
		grinder.logger.info("계정 {}개를 읽었습니다.", users.size())
	}

	@BeforeThread
	public void beforeThread() {
		test1.record(this, "test1")
		if (ACTION_PATH) test2.record(this, "test2")   // 선택 항목이 비어 있으면 측정하지 않음
		grinder.statistics.delayReports = true

		def account = users[GrinderUtils.getThreadUniqId() % users.size()]
		myId = account[0]

		// 1) 로그인 화면 열기 → 토큰 찾기 (이때 받은 세션 쿠키는 자동으로 보관됨)
		HTTPResponse page = request.GET(BASE_URL + LOGIN_PAGE_PATH)
		assertThat("로그인 화면을 열지 못했습니다", page.statusCode, is(200))
		Map csrf = findCsrf(page)
		assertNotNull("로그인 화면에서 CSRF 토큰을 찾지 못했습니다. CSRF_NAME/CSRF_COOKIE 설정을 확인하세요.\n화면 앞부분: "
			+ page.bodyText.take(500), csrf)
		grinder.logger.info("{} CSRF 토큰 발견 (위치: {})", myId, csrf.where)

		// 2) 아이디/비밀번호 + 토큰으로 로그인
		Map<String, String> form = [(ID_FIELD): account[0], (PW_FIELD): account[1], (CSRF_NAME): csrf.token]
		Map<String, String> headers = ["Content-Type": "application/x-www-form-urlencoded"]   // 없으면 JSON으로 감 (nGrinder 3.5.x)
		if (csrf.header) headers.put(csrf.header, csrf.token)
		HTTPResponse res = request.POST(BASE_URL + LOGIN_PATH, form, headers)

		loginCookies = CookieManager.getCookies()
		grinder.logger.info("{} 로그인 응답코드 {}", myId, res.statusCode)
		assertThat("로그인 요청이 거부됐습니다(403이면 CSRF 토큰 문제일 가능성 큼): " + myId, res.statusCode, isOneOf(200, 302, 303))
	}

	@Before
	public void before() {
		CookieManager.addCookies(loginCookies)   // nGrinder는 반복마다 쿠키를 지우므로 다시 넣음
	}

	@Test
	public void test1() {
		HTTPResponse res = request.GET(BASE_URL + TARGET_PATH)
		assertThat(res.statusCode, is(200))
		assertThat("로그인이 안 된 상태입니다: " + myId, res.bodyText, containsString(SUCCESS_TEXT))
	}

	/** (선택) 로그인 후 POST: 로그인하면 토큰이 새로 바뀌는 서비스가 많아서, 매번 화면에서 새 토큰을 읽어 보냄 */
	@Test
	public void test2() {
		if (!ACTION_PATH) return
		HTTPResponse page = request.GET(BASE_URL + (ACTION_PAGE_PATH ?: TARGET_PATH))
		Map csrf = findCsrf(page)
		assertNotNull("POST 전에 새 CSRF 토큰을 찾지 못했습니다", csrf)
		Map<String, String> headers = ["Content-Type": "application/x-www-form-urlencoded"]
		if (csrf.header) headers.put(csrf.header, csrf.token)
		HTTPResponse res = request.POST(BASE_URL + ACTION_PATH, ACTION_PARAMS + [(CSRF_NAME): csrf.token], headers)
		assertThat("POST 실패(403이면 CSRF 토큰 문제): " + myId, res.statusCode, isOneOf(200, 201, 302, 303))
	}

	// ---------------- 아래는 토큰 찾기 도우미 (고칠 필요 없음) ----------------

	/** 응답에서 CSRF 토큰 찾기. 못 찾으면 null. 결과: [token: 값, header: 같이 보낼 헤더이름 또는 null, where: 찾은 위치] */
	static Map findCsrf(HTTPResponse res) {
		String html = res.bodyText ?: ""
		// ① <input type="hidden" name="_csrf" value="...">
		String v = attrOfTag(html, "input", "name", CSRF_NAME, "value")
		if (v) return [token: v, header: null, where: "숨은 입력칸(input)"]
		// ② <meta name="_csrf" content="..."> (+ _csrf_header)
		v = attrOfTag(html, "meta", "name", CSRF_NAME, "content")
		if (v) return [token: v, header: attrOfTag(html, "meta", "name", CSRF_NAME + "_header", "content"), where: "meta 태그"]
		// ③ Set-Cookie: XSRF-TOKEN=...
		for (h in res.getHeaders("Set-Cookie")) {
			def m = (h.value =~ /^\s*${java.util.regex.Pattern.quote(CSRF_COOKIE)}=([^;]*)/)
			if (m.find() && m.group(1)) return [token: URLDecoder.decode(m.group(1), "UTF-8"), header: CSRF_COOKIE_HEADER, where: "쿠키(" + CSRF_COOKIE + ")"]
		}
		// ③-2 이번 응답엔 없지만 이미 받아 둔 쿠키에 있는 경우 (로그인 응답에서 새 토큰 쿠키를 받은 뒤 등)
		v = storedCookie(CSRF_COOKIE)
		if (v) return [token: URLDecoder.decode(v, "UTF-8"), header: CSRF_COOKIE_HEADER, where: "보관 중인 쿠키(" + CSRF_COOKIE + ")"]
		return null
	}

	/** 지금 보관 중인 쿠키에서 값 꺼내기 (nGrinder Cookie에는 값을 꺼내는 공개 함수가 없어 toString 형식을 읽음) */
	static String storedCookie(String name) {
		for (c in CookieManager.getCookies()) {
			def m = (c.toString() =~ /name: (.*?), value: (.*?), domain:/)
			if (m.find() && m.group(1) == name) return m.group(2)
		}
		return null
	}

	/** html 안의 <tag ...> 중 keyAttr="keyValue" 인 태그를 찾아 wantAttr 값을 돌려줌 (속성 순서·줄바꿈·따옴표 종류 무관) */
	static String attrOfTag(String html, String tag, String keyAttr, String keyValue, String wantAttr) {
		def tags = (html =~ /(?is)<${tag}\b[^>]*>/)
		for (t in tags) {
			String s = t as String
			if (attr(s, keyAttr) == keyValue) return attr(s, wantAttr)
		}
		return null
	}

	static String attr(String tagText, String name) {
		def m = (tagText =~ /(?is)\s${name}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/)
		if (!m.find()) return null
		String v = m.group(1) ?: m.group(2) ?: m.group(3)
		return v?.replace("&quot;", '"')?.replace("&#39;", "'")?.replace("&lt;", "<")?.replace("&gt;", ">")
			?.replaceAll(/&#x([0-9a-fA-F]+);/) { all, hex -> new String(Character.toChars(Integer.parseInt(hex, 16))) }
			?.replaceAll(/&#(\d+);/) { all, dec -> new String(Character.toChars(Integer.parseInt(dec))) }
			?.replace("&amp;", "&")
	}
}
