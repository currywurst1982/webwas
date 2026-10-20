package webwas.loadtest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

/**
 * nGrinder 컨트롤러 REST API 호출 도구.
 * 연결 정보는 시작 시 환경변수/시스템 프로퍼티(NGRINDER_URL, NGRINDER_USER, NGRINDER_PASSWORD)에서 읽고,
 * 대시보드 화면의 "연결 설정"에서 바꿀 수 있습니다(바꾼 값은 WAS 재시작 시 사라짐).
 */
public final class NGrinderClient {

	private static volatile String url = setting("NGRINDER_URL", "http://localhost:8080");
	private static volatile String user = setting("NGRINDER_USER", "");
	private static volatile String password = setting("NGRINDER_PASSWORD", "");

	private NGrinderClient() {
	}

	private static String setting(String key, String def) {
		String v = System.getProperty(key.toLowerCase().replace('_', '.'));
		if (v == null || v.isEmpty()) v = System.getProperty(key);
		if (v == null || v.isEmpty()) v = System.getenv(key);
		return v == null || v.isEmpty() ? def : v;
	}

	public static String url() { return url; }
	public static String user() { return user; }
	public static boolean hasPassword() { return !password.isEmpty(); }

	public static synchronized void configure(String newUrl, String newUser, String newPassword) {
		if (newUrl != null && !newUrl.trim().isEmpty()) {
			String u = newUrl.trim().replaceAll("/+$", "");
			if (!u.startsWith("http://") && !u.startsWith("https://")) throw new IllegalArgumentException("nGrinder 주소는 http:// 또는 https:// 로 시작해야 합니다");
			url = u;
		}
		if (newUser != null && !newUser.trim().isEmpty()) user = newUser.trim();
		if (newPassword != null && !newPassword.isEmpty()) password = newPassword;
	}

	/** HTTP 응답 */
	public static final class Resp {
		public final int code;
		public final byte[] body;
		public final String contentType;

		Resp(int code, byte[] body, String contentType) {
			this.code = code;
			this.body = body;
			this.contentType = contentType;
		}

		public String text() { return new String(body, StandardCharsets.UTF_8); }

		public boolean ok() { return code >= 200 && code < 300; }

		/** 로그인 실패 시 nGrinder는 JSON 대신 로그인 화면(HTML)을 돌려줌 */
		public boolean looksLikeLoginPage() {
			String t = text().trim();
			return t.startsWith("<") && t.toLowerCase().contains("login");
		}
	}

	public static Resp call(String method, String pathAndQuery, String contentType, byte[] body) throws IOException {
		HttpURLConnection c = (HttpURLConnection) new URL(url + pathAndQuery).openConnection();
		c.setInstanceFollowRedirects(false);
		c.setConnectTimeout(10000);
		c.setReadTimeout(30000);
		c.setRequestMethod(method);
		c.setRequestProperty("Accept", "application/json");
		if (!user.isEmpty()) {
			String token = Base64.getEncoder().encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
			c.setRequestProperty("Authorization", "Basic " + token);
		}
		if (body != null) {
			c.setDoOutput(true);
			c.setRequestProperty("Content-Type", contentType);
			try (OutputStream o = c.getOutputStream()) {
				o.write(body);
			}
		}
		int code = c.getResponseCode();
		InputStream in = code >= 400 ? c.getErrorStream() : c.getInputStream();
		byte[] data = in == null ? new byte[0] : readAll(in);
		return new Resp(code, data, c.getContentType());
	}

	public static Resp json(String method, String path, Object payload) throws IOException {
		byte[] body = payload == null ? null : Json.stringify(payload).getBytes(StandardCharsets.UTF_8);
		return call(method, path, "application/json; charset=UTF-8", body);
	}

	/** nGrinder 스크립트 저장소의 folder 경로에 파일 올리기 (POST /script/api/upload/{folder}) */
	public static Resp upload(String folder, String fileName, byte[] content, String description) throws IOException {
		String boundary = "----loadtest" + UUID.randomUUID().toString().replace("-", "");
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		String head1 = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"description\"\r\n\r\n" + description + "\r\n";
		String head2 = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"uploadFile\"; filename=\"" + fileName
			+ "\"\r\nContent-Type: application/octet-stream\r\n\r\n";
		b.write(head1.getBytes(StandardCharsets.UTF_8));
		b.write(head2.getBytes(StandardCharsets.UTF_8));
		b.write(content);
		b.write(("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
		return call("POST", "/script/api/upload/" + folder, "multipart/form-data; boundary=" + boundary, b.toByteArray());
	}

	private static byte[] readAll(InputStream in) throws IOException {
		try (InputStream i = in) {
			ByteArrayOutputStream o = new ByteArrayOutputStream();
			byte[] buf = new byte[8192];
			int n;
			while ((n = i.read(buf)) > 0) o.write(buf, 0, n);
			return o.toByteArray();
		}
	}
}
