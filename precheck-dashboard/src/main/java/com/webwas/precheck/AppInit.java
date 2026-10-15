package com.webwas.precheck;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Logger;

/**
 * 앱 시작 시 데이터 폴더와 계정 파일을 준비.
 * 데이터 폴더: -Dprecheck.data.dir=... 또는 환경변수 PRECHECK_DATA_DIR, 없으면 ~/precheck-dashboard
 */
@WebListener
public class AppInit implements ServletContextListener {
    private static final Logger LOG = Logger.getLogger(AppInit.class.getName());
    public static final String ATTR_USERS = "precheck.users";
    public static final String ATTR_REPORTS = "precheck.reports";
    public static final String ATTR_THROTTLE = "precheck.throttle";
    public static final String INITIAL_PASSWORD_FILE = "initial-admin-password.txt";

    public static Path dataDir() {
        String d = System.getProperty("precheck.data.dir");
        if (d == null || d.isBlank()) d = System.getenv("PRECHECK_DATA_DIR");
        if (d == null || d.isBlank()) d = Paths.get(System.getProperty("user.home"), "precheck-dashboard").toString();
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
            ctx.setAttribute(ATTR_REPORTS, new ReportStore(reports));
            ctx.setAttribute(ATTR_THROTTLE, new LoginThrottle());
            LOG.info("[precheck-dashboard] 데이터 폴더: " + data + " / 리포트 폴더: " + reports);
        } catch (IOException e) {
            throw new IllegalStateException("데이터 폴더 초기화 실패", e);
        }
    }

    private static void createInitialAdmin(UserStore users, Path data) throws IOException {
        String pw = System.getenv("PRECHECK_ADMIN_PASSWORD");
        boolean fromEnv = pw != null && UserStore.passwordProblem("admin", pw) == null;
        if (!fromEnv) pw = UserStore.randomPassword();
        users.put("admin", pw, UserStore.ROLE_ADMIN, true);
        if (fromEnv) {
            LOG.warning("[precheck-dashboard] 초기 관리자 계정 'admin' 생성 (비밀번호: 환경변수 PRECHECK_ADMIN_PASSWORD). 첫 로그인 시 변경해야 합니다.");
        } else {
            Path f = data.resolve(INITIAL_PASSWORD_FILE);
            Files.writeString(f, "아이디: admin\n초기 비밀번호: " + pw
                    + "\n\n첫 로그인 후 비밀번호를 바꾸면 이 파일은 자동으로 삭제됩니다.\n", StandardCharsets.UTF_8);
            UserStore.restrict(f);
            LOG.warning("[precheck-dashboard] 초기 관리자 계정 'admin' 생성. 초기 비밀번호는 " + f + " 파일에 있습니다.");
        }
    }
}
