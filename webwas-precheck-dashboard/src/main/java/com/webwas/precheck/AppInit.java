package com.webwas.precheck;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 앱 시작 시 데이터 폴더와 계정 파일을 준비.
 * 데이터 폴더: -Dwebwas.precheck.data.dir=... 또는 환경변수 WEBWAS_PRECHECK_DATA_DIR, 없으면 ~/webwas-precheck
 */
@WebListener
public class AppInit implements ServletContextListener {
    private static final Logger LOG = Logger.getLogger(AppInit.class.getName());
    public static final String ATTR_USERS = "precheck.users";
    public static final String ATTR_REPORTS = "precheck.reports";
    public static final String ATTR_THROTTLE = "precheck.throttle";
    public static final String ATTR_AGENTS = "precheck.agents";
    public static final String ATTR_EXCEPTIONS = "precheck.exceptions";
    public static final String ATTR_SETTINGS = "precheck.settings";
    /**
     * WAR 에 들어 있는 점검 스크립트 전체(Product 순서: apache → wildfly → tomcat → nginx 로 이어 붙인 내용)의 SHA-256.
     * 에이전트도 같은 순서로 계산해 보내므로 "에이전트 쪽 스크립트가 대시보드와 같은지" 비교에 씀.
     */
    public static final String ATTR_SCRIPT_SHA = "precheck.scriptSha";
    /** WAR 에 들어 있는 에이전트(webwas-precheck-agent.sh)의 AGENT_VERSION (재설치 필요 여부 판단 기준) */
    public static final String ATTR_AGENT_VERSION = "precheck.agentVersion";
    static final Pattern AGENT_VERSION = Pattern.compile("(?m)^AGENT_VERSION=\"([0-9.]+)\"");
    public static final String ATTR_LATEST = "precheck.latest";
    public static final String ATTR_CVE = "precheck.cve";
    /** 스크립트의 최신 버전 기준값 */
    private static final Map<Product, Pattern> SCRIPT_BASELINE = Map.of(
            Product.APACHE, Pattern.compile("^LATEST_VER=\"(2\\.4\\.\\d+)\"", Pattern.MULTILINE),
            Product.WILDFLY, Pattern.compile("^LATEST_FINAL=\"([0-9A-Za-z.]+)\"", Pattern.MULTILINE),
            Product.TOMCAT, Pattern.compile("^LATEST_BRANCHES=\"([0-9. ]+)\"", Pattern.MULTILINE),
            Product.NGINX, Pattern.compile("^LATEST_BRANCHES=\"([0-9. ]+)\"", Pattern.MULTILINE));
    private static final long REFRESH_HOURS = 12;
    private ScheduledExecutorService scheduler;
    /**
     * HTTPS 전용 모드: -Dwebwas.precheck.https=true (또는 환경변수 WEBWAS_PRECHECK_HTTPS=true).
     * 켜면 로그인 쿠키에 Secure 를 붙이고(HTTP 로는 쿠키가 전송되지 않음), 브라우저의 HTTP 접속을 HTTPS 로 돌리고, HSTS 헤더를 보냄.
     * 에이전트 API(/agent-api) 는 돌리지 않음 (HTTP 로 설치된 에이전트가 갑자기 끊기지 않도록. 에이전트는 https 주소로 재설치 권장)
     */
    public static boolean httpsOnly() {
        String v = System.getProperty("webwas.precheck.https");
        if (v == null || v.isBlank()) v = System.getenv("WEBWAS_PRECHECK_HTTPS");
        return "true".equalsIgnoreCase(v == null ? "" : v.trim());
    }

    /** HTTP → HTTPS 로 돌릴 때의 포트 (WildFly 기본 8443). -Dwebwas.precheck.https.port */
    public static int httpsPort() {
        try {
            return Integer.parseInt(System.getProperty("webwas.precheck.https.port", "8443").trim());
        } catch (NumberFormatException e) {
            return 8443;
        }
    }

    public static final String INITIAL_PASSWORD_FILE = "initial-admin-password.txt";

    public static Path dataDir() {
        String d = System.getProperty("webwas.precheck.data.dir");
        if (d == null || d.isBlank()) d = System.getenv("WEBWAS_PRECHECK_DATA_DIR");
        if (d == null || d.isBlank()) d = Paths.get(System.getProperty("user.home"), "webwas-precheck").toString();
        return Paths.get(d).toAbsolutePath().normalize();
    }

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        ServletContext ctx = sce.getServletContext();
        try {
            Path data = dataDir();
            Path reports = data.resolve("reports");
            Files.createDirectories(reports);
            UserStore users = new UserStore(data.resolve("users.properties"));
            if (users.isEmpty()) createInitialAdmin(users, data);
            ctx.setAttribute(ATTR_USERS, users);
            ReportStore store = new ReportStore(reports);
            store.purgeTrash();   // 보관 기간이 지난 휴지통 비우기
            ctx.setAttribute(ATTR_REPORTS, store);
            if (httpsOnly()) {
                ctx.getSessionCookieConfig().setSecure(true);
                LOG.info("[webwas-precheck] HTTPS 전용 모드: 로그인 쿠키 Secure, 브라우저 HTTP 접속은 https 포트 " + httpsPort() + " 로 이동");
            }
            ctx.setAttribute(ATTR_THROTTLE, new LoginThrottle());
            ctx.setAttribute(ATTR_AGENTS, new AgentStore(data.resolve("agents.properties")));
            ctx.setAttribute(ATTR_EXCEPTIONS, new ExceptionStore(data.resolve("exceptions.properties")));
            ctx.setAttribute(ATTR_SETTINGS, new SiteSettings(data.resolve("settings.properties")));
            Map<Product, String> scripts = new EnumMap<>(Product.class);
            Map<Product, String> baselines = new EnumMap<>(Product.class);
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            for (Product prod : Product.values()) {
                try (InputStream in = AppInit.class.getResourceAsStream("/agent/" + prod.script)) {
                    if (in == null) {
                        LOG.warning("[webwas-precheck] WAR 에 " + prod.script + " 가 없습니다.");
                        continue;
                    }
                    byte[] script = in.readAllBytes();
                    sha.update(script);
                    String text = new String(script, StandardCharsets.UTF_8);
                    scripts.put(prod, text);
                    Matcher m = SCRIPT_BASELINE.get(prod).matcher(text);
                    if (m.find()) baselines.put(prod, m.group(1));
                }
            }
            ctx.setAttribute(ATTR_SCRIPT_SHA, HexFormat.of().formatHex(sha.digest()));
            try (InputStream in = AppInit.class.getResourceAsStream("/agent/webwas-precheck-agent.sh")) {
                if (in != null) {
                    Matcher av = AGENT_VERSION.matcher(new String(in.readAllBytes(), StandardCharsets.UTF_8));
                    if (av.find()) ctx.setAttribute(ATTR_AGENT_VERSION, av.group(1));
                }
            }
            LatestVersions latest = new LatestVersions(data, baselines);
            ctx.setAttribute(ATTR_LATEST, latest);
            CveFeed cve = new CveFeed(data.resolve("cve"), scripts);
            ctx.setAttribute(ATTR_CVE, cve);
            // 앱 시작 직후 1회 + 12시간마다: 최신 버전 확인 → CVE 목록 갱신
            scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "webwas-precheck-refresh");
                t.setDaemon(true);
                return t;
            });
            scheduler.scheduleWithFixedDelay(() -> {
                try {
                    latest.refreshAll();
                    cve.refreshAll();
                } catch (RuntimeException e) {
                    LOG.warning("[webwas-precheck] 자동 갱신 오류: " + e);
                }
            }, 5, REFRESH_HOURS * 3600, TimeUnit.SECONDS);
            LOG.info("[webwas-precheck] 데이터 폴더: " + data + " / 리포트 폴더: " + reports);
        } catch (IOException e) {
            throw new IllegalStateException("데이터 폴더 초기화 실패", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        if (scheduler != null) scheduler.shutdownNow();
    }

    private static void createInitialAdmin(UserStore users, Path data) throws IOException {
        String pw = System.getenv("WEBWAS_PRECHECK_ADMIN_PASSWORD");
        boolean fromEnv = pw != null && UserStore.passwordProblem("admin", pw) == null;
        if (!fromEnv) pw = UserStore.randomPassword();
        users.put("admin", pw, UserStore.ROLE_ADMIN, true);
        if (fromEnv) {
            LOG.warning("[webwas-precheck] 초기 관리자 계정 'admin' 생성 (비밀번호: 환경변수 WEBWAS_PRECHECK_ADMIN_PASSWORD). 첫 로그인 시 변경해야 합니다.");
        } else {
            Path f = data.resolve(INITIAL_PASSWORD_FILE);
            Files.writeString(f, "아이디: admin\n초기 비밀번호: " + pw
                    + "\n\n첫 로그인 후 비밀번호를 바꾸면 이 파일은 자동으로 삭제됩니다.\n", StandardCharsets.UTF_8);
            UserStore.restrict(f);
            LOG.warning("[webwas-precheck] 초기 관리자 계정 'admin' 생성. 초기 비밀번호는 " + f + " 파일에 있습니다.");
        }
    }
}
