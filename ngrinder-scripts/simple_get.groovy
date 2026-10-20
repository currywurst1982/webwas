import static net.grinder.script.Grinder.grinder
import static org.junit.Assert.*
import static org.hamcrest.Matchers.*
import net.grinder.script.GTest
import net.grinder.scriptengine.groovy.junit.GrinderRunner
import net.grinder.scriptengine.groovy.junit.annotation.BeforeProcess
import net.grinder.scriptengine.groovy.junit.annotation.BeforeThread
import org.junit.Test
import org.junit.runner.RunWith

import org.ngrinder.http.HTTPRequest
import org.ngrinder.http.HTTPRequestControl
import org.ngrinder.http.HTTPResponse

/**
 * [예제 0] 로그인 없이 페이지/API 조회 (가장 기본)
 *
 * PATHS 에 적은 주소들 중 하나를 매번 무작위로 골라 GET 요청 → 응답코드 200(과 선택한 글자) 확인
 * nGrinder 3.5.x 기준
 */
@RunWith(GrinderRunner)
class TestRunner {

	// ===================== ★ 설정 (여기만 고치세요) =====================
	static String BASE_URL     = "http://localhost:18080"          // 테스트 대상 서버 주소
	static String PATHS        = "/products,/products/1"           // 호출할 주소들 (쉼표로 구분)
	static String SUCCESS_TEXT = ""                                // 응답에 꼭 있어야 하는 글자 (없으면 "" 그대로)
	// ====================================================================

	public static GTest test1
	public static HTTPRequest request
	public static List<String> paths = []

	@BeforeProcess
	public static void beforeProcess() {
		HTTPRequestControl.setConnectionTimeout(30000)
		test1 = new GTest(1, "조회")
		request = new HTTPRequest()
		paths = PATHS.split(",").collect { it.trim() }.findAll { it }
		assertThat("[NO_PATHS] PATHS 가 비어 있습니다", paths.size(), greaterThan(0))
	}

	@BeforeThread
	public void beforeThread() {
		test1.record(this, "test1")
		grinder.statistics.delayReports = true
	}

	@Test
	public void test1() {
		String path = paths[new Random().nextInt(paths.size())]
		HTTPResponse res = request.GET(BASE_URL + path)
		assertThat("[BAD_STATUS] 응답코드 이상: " + path, res.statusCode, is(200))
		if (SUCCESS_TEXT) assertThat("[TEXT_NOT_FOUND] 응답에 기대한 글자가 없음: " + path, text(res), containsString(SUCCESS_TEXT))
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
