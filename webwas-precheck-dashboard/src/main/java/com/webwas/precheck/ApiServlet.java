package com.webwas.precheck;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.MultipartConfig;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Part;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * 대시보드 화면이 사용하는 JSON API. (로그인·CSRF 검사는 AuthFilter 에서 끝난 상태)
 *  GET    /api/me                    현재 사용자
 *  GET    /api/reports               인스턴스별 최신 리포트 요약 (화면 기본. ETag·gzip)
 *  GET    /api/reports?scope=all     전체 리포트 요약 (서버 목록에서 "인스턴스별 최신만" 을 끌 때)
 *  GET    /api/reports?instance=키   한 인스턴스의 점검 이력
 *  GET    /api/daily?days=14         일자·제품·에이전트별 점검 건수 / 침해 의심 건수 (추이 차트용)
 *  GET    /api/reports/{파일명}       리포트 상세
 *  GET    /api/reports/{파일명}/raw   원본 텍스트
 *  POST   /api/reports               리포트 업로드 (관리자, multipart "files")
 *  DELETE /api/reports/{파일명}       리포트 삭제 (관리자)
 *  GET    /api/users                 사용자 목록 (관리자)
 *  POST   /api/users                 사용자 추가 (관리자) → 임시 비밀번호 반환
 *  POST   /api/users/{아이디}/reset   비밀번호 초기화 (관리자) → 임시 비밀번호 반환
 *  DELETE /api/users/{아이디}         사용자 삭제 (관리자)
 *  GET    /api/agents                에이전트 목록·상태
 *  POST   /api/agents                에이전트 등록 (관리자) → 토큰 반환(한 번만)
 *  POST   /api/agents-run            전체 에이전트 "지금 점검" 요청 (관리자)
 *  POST   /api/agents/{이름}/run      "지금 점검" 요청 (관리자)
 *  POST   /api/agents/{이름}/token    토큰 재발급 (관리자)
 *  POST   /api/agents/{이름}/interval 점검 주기 변경 (관리자, hours)
 *  DELETE /api/agents/{이름}          에이전트 삭제 (관리자)
 *  GET    /api/reports/{파일명}/intrusion.pdf  [4] 침해 흔적만 발췌한 PDF
 *  GET    /api/suspects.pdf          침해 의심 서버 전체 PDF (인스턴스별 최신 점검)
 *  GET    /api/config.pdf[?source=에이전트][&product=제품]  설정 취약 항목별 대상 서버 PDF (인스턴스별 최신 점검)
 *  GET    /api/cve.pdf[?source=에이전트][&product=제품]     CVE별 대상 서버 PDF (인스턴스별 최신 점검)
 *  GET    /api/latest-version        제품별(Apache/WildFly/Tomcat) 최신 버전 정보
 *  POST   /api/latest-version        (관리자) action=refresh | auto(product) | manual(product, version) | skip(value=true/false)
 *  GET    /api/cve-feed              CVE 목록 자동 업데이트 상태
 *  POST   /api/cve-feed              (관리자) action=refresh → 지금 다시 받기 (백그라운드)
 */
@WebServlet("/api/*")
@MultipartConfig(maxFileSize = ReportStore.MAX_FILE_BYTES, maxRequestSize = 60L * 1024 * 1024, fileSizeThreshold = 1024 * 1024)
public class ApiServlet extends HttpServlet {
    private static final Logger LOG = Logger.getLogger(ApiServlet.class.getName());

    private String[] parts(HttpServletRequest req) {
        String p = req.getPathInfo();
        if (p == null || p.equals("/")) return new String[0];
        return p.substring(1).split("/");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String[] p = parts(req);
        ReportStore store = Web.reports(getServletContext());
        if (p.length == 1 && p[0].equals("me")) {
            Web.json(resp, 200, Map.of("user", Web.user(req), "admin", Web.isAdmin(req),
                    "csrf", Web.csrf(req.getSession()), "reportDir", Web.isAdmin(req) ? store.dir().toString() : "",
                    "httpsOnly", AppInit.httpsOnly(),
                    "secure", req.isSecure() || "https".equalsIgnoreCase(req.getHeader("X-Forwarded-Proto"))));
        } else if (p.length == 1 && p[0].equals("reports")) {
            LatestVersions latest = Web.latest(getServletContext());
            List<Report> all = allReports(store);
            String scope = "all".equals(req.getParameter("scope")) ? "all" : "latest";
            String instance = req.getParameter("instance");
            List<Report> out;
            if (instance != null) {
                out = all.stream().filter(r -> r.instanceKey().equals(instance)).toList();
                scope = "instance:" + instance;
            } else if (scope.equals("all")) {
                out = all;
            } else {
                out = ConfigIssues.latestPerInstance(all);
            }
            resp.setHeader("X-Total-Reports", String.valueOf(all.size()));
            Web.json(req, resp, out.stream().map(r -> r.toSummary(latest)).toList(), etag(store, scope));
        } else if (p.length == 1 && p[0].equals("daily")) {
            int days = 14;
            try {
                days = Math.max(1, Math.min(90, Integer.parseInt(req.getParameter("days"))));
            } catch (RuntimeException ignored) {
                // 기본 14일
            }
            Web.json(req, resp, daily(allReports(store), days), etag(store, "daily" + days));
        } else if ((p.length == 2 || p.length == 3) && p[0].equals("reports")) {
            Report light = p[1] == null ? null : allReports(store).stream().filter(x -> x.id.equals(p[1])).findFirst().orElse(null);
            Report r = light == null ? null : store.full(light.id);
            if (r != null) r.fallbackIp = light.fallbackIp;
            if (r == null) {
                Web.json(resp, 404, Map.of("error", "리포트를 찾을 수 없습니다."));
            } else if (p.length == 3 && p[2].equals("raw")) {
                resp.setContentType("text/plain;charset=UTF-8");
                resp.setHeader("Content-Disposition", "attachment; filename=\"" + r.id + "\"");
                resp.setHeader("Cache-Control", "no-store");
                resp.getWriter().write(r.raw);
            } else if (p.length == 3 && p[2].equals("intrusion.pdf")) {
                LOG.info("[webwas-precheck] 침해 흔적 PDF: " + r.id + " by " + Web.user(req));
                sendPdf(resp, IntrusionPdf.single(r, Web.latest(getServletContext()), Web.user(req)),
                        "intrusion_" + ascii(r.host) + "_" + ascii(r.checkedAt) + ".pdf");
            } else if (p.length == 2) {
                Web.json(req, resp, r.toDetail(Web.latest(getServletContext())), null);
            } else {
                Web.json(resp, 404, Map.of("error", "없는 주소입니다."));
            }
        } else if (p.length == 1 && p[0].equals("suspects.pdf")) {
            List<Report> suspects = new ArrayList<>();
            for (Report light : suspects(allReports(store))) { // PDF 에는 [4] 원문이 필요하므로 파일에서 다시 읽음
                Report full = store.full(light.id);
                if (full == null) continue;
                full.fallbackIp = light.fallbackIp;
                suspects.add(full);
            }
            if (suspects.isEmpty()) {
                Web.json(resp, 404, Map.of("error", "침해 의심 서버가 없습니다."));
                return;
            }
            LOG.info("[webwas-precheck] 침해 의심 서버 전체 PDF (" + suspects.size() + "대) by " + Web.user(req));
            sendPdf(resp, IntrusionPdf.combined(suspects, Web.latest(getServletContext()), Web.user(req)),
                    "intrusion_suspects_" + java.time.LocalDate.now() + ".pdf");
        } else if (p.length == 1 && (p[0].equals("config.pdf") || p[0].equals("cve.pdf"))) {
            String source = req.getParameter("source");
            if (source != null && !source.isBlank() && !AgentStore.validName(source)) {
                Web.json(resp, 400, Map.of("error", "잘못된 에이전트 이름"));
                return;
            }
            boolean bySource = source != null && !source.isBlank();
            Product product = Product.byId(req.getParameter("product"));
            List<Report> latestReports = ConfigIssues.latestPerInstance(allReports(store)).stream()
                    .filter(r -> !bySource || source.equals(r.source))
                    .filter(r -> product == null || r.product == product).toList();
            String scope = (product == null ? "전체 제품" : product.label + "만") + " · " + (bySource ? "에이전트 " + source + " 수집분만" : "전체 서버");
            String suffix = (product == null ? "" : product.id + "_") + (bySource ? ascii(source) + "_" : "") + java.time.LocalDate.now() + ".pdf";
            LatestVersions lvs = Web.latest(getServletContext());
            String latest = product == null ? lvs.summary() : product.label + " " + lvs.get(product).display();
            if (p[0].equals("cve.pdf")) {
                List<CveIssues.Item> cves = CveIssues.group(latestReports);
                LOG.info("[webwas-precheck] CVE PDF (" + cves.size() + "건, " + scope + ") by " + Web.user(req));
                sendPdf(resp, CvePdf.build(cves, latestReports.size(), latest, scope, Web.user(req)), "cve_targets_" + suffix);
                return;
            }
            List<ConfigIssues.Item> items = ConfigIssues.group(latestReports);
            LOG.info("[webwas-precheck] 설정 취약 PDF (" + items.size() + "종, " + scope + ") by " + Web.user(req));
            sendPdf(resp, ConfigPdf.build(items, latestReports.size(), latest, scope, Web.user(req)), "config_issues_" + suffix);
        } else if (p.length == 1 && p[0].equals("latest-version")) {
            Web.json(resp, 200, Web.latest(getServletContext()).toMap());
        } else if (p.length == 1 && p[0].equals("cve-feed")) {
            Web.json(resp, 200, Web.cve(getServletContext()).toMap());
        } else if (p.length == 1 && p[0].equals("agents")) {
            long now = System.currentTimeMillis();
            Object sha = getServletContext().getAttribute(AppInit.ATTR_SCRIPT_SHA);
            String expected = sha == null ? null : sha.toString();
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("now", now);
            out.put("expectedScriptSha256", expected);
            Object av = getServletContext().getAttribute(AppInit.ATTR_AGENT_VERSION);
            String expectedAgent = av == null ? null : av.toString();
            out.put("expectedAgentVersion", expectedAgent);
            LatestVersions lv = Web.latest(getServletContext());
            List<Report> latestReports = ConfigIssues.latestPerInstance(allReports(Web.reports(getServletContext())));
            out.put("agents", Web.agents(getServletContext()).list().stream().map(a -> {
                Map<String, Object> m = a.toMap(now, expected);
                // 마지막 점검의 제품·인스턴스 전체 (같은 제품이 여러 개여도, 버전을 못 읽었어도 모두)
                List<Map<String, Object>> insts = new ArrayList<>();
                for (Report r : AgentStore.lastRunInstances(latestReports, a.name)) {
                    Map<String, Object> im = new LinkedHashMap<>();
                    im.put("product", r.product.id);
                    im.put("version", r.version);
                    im.put("upToDate", r.version != null && lv.isUpToDate(r.product, r.version));
                    im.put("binary", r.binary);
                    im.put("confArg", r.confArg);
                    im.put("reportId", r.id);
                    insts.add(im);
                }
                m.put("instances", insts);
                // 에이전트 본체가 WAR 의 에이전트보다 낮으면 재설치 필요 (점검 스크립트 비교와 별개)
                m.put("agentOutdated", expectedAgent != null && a.agentVersion != null
                        && ReportParser.compareVersions(a.agentVersion, expectedAgent) < 0);
                Map<String, Boolean> each = new LinkedHashMap<>();
                a.versions.forEach((prod, v) -> each.put(prod.id, lv.isUpToDate(prod, v)));
                m.put("versionUpToDate", each);
                m.put("upToDate", AgentStore.upToDate(a, lv));
                m.put("autoSkipped", lv.skipUpToDate() && AgentStore.upToDate(a, lv));
                return m;
            }).toList());
            Web.json(resp, 200, out);
        } else if (p.length == 1 && p[0].equals("users")) {
            if (!requireAdmin(req, resp)) return;
            List<Map<String, Object>> out = new ArrayList<>();
            for (UserStore.User u : Web.users(getServletContext()).list()) {
                out.add(Map.of("name", u.name(), "role", u.role(), "mustChange", u.mustChange()));
            }
            Web.json(resp, 200, out);
        } else {
            Web.json(resp, 404, Map.of("error", "없는 주소입니다."));
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        String[] p = parts(req);
        if (!requireAdmin(req, resp)) return;
        if (p.length >= 1 && (p[0].equals("agents") || p[0].equals("agents-run"))) {
            agentAction(req, resp, p);
        } else if (p.length == 1 && p[0].equals("latest-version")) {
            LatestVersions lvs = Web.latest(getServletContext());
            String action = req.getParameter("action");
            Product product = Product.byId(req.getParameter("product"));
            try {
                switch (action == null ? "" : action) {
                    case "refresh" -> {
                        if (product == null) lvs.refreshAll();
                        else lvs.get(product).refresh();
                    }
                    case "auto" -> requireProduct(product, lvs).setAuto();
                    case "manual" -> requireProduct(product, lvs).setManual(req.getParameter("version") == null ? null : req.getParameter("version").trim());
                    case "skip" -> lvs.setSkipUpToDate("true".equals(req.getParameter("value")));
                    default -> throw new IllegalArgumentException("알 수 없는 작업입니다.");
                }
            } catch (IllegalArgumentException e) {
                Web.json(resp, 400, Map.of("error", e.getMessage()));
                return;
            }
            LOG.info("[webwas-precheck] 최신 버전 설정 변경(" + action + (product == null ? "" : ", " + product.label) + ") by "
                    + Web.user(req) + " → " + lvs.summary());
            Web.json(resp, 200, lvs.toMap());
        } else if (p.length == 1 && p[0].equals("cve-feed")) {
            if (!"refresh".equals(req.getParameter("action"))) {
                Web.json(resp, 400, Map.of("error", "알 수 없는 작업입니다."));
                return;
            }
            CveFeed cve = Web.cve(getServletContext());
            LOG.info("[webwas-precheck] CVE 목록 즉시 갱신 요청 by " + Web.user(req));
            Thread t = new Thread(cve::refreshAll, "webwas-precheck-cve-refresh");
            t.setDaemon(true);
            t.start();
            Web.json(resp, 202, Map.of("started", true));
        } else if (p.length == 1 && p[0].equals("reports")) {
            upload(req, resp);
        } else if (p.length == 1 && p[0].equals("users")) {
            String name = trim(req.getParameter("name"));
            String role = req.getParameter("role");
            UserStore users = Web.users(getServletContext());
            if (!UserStore.validUsername(name)) {
                Web.json(resp, 400, Map.of("error", "아이디는 영문/숫자/._- 3~32자여야 합니다."));
                return;
            }
            if (users.find(name) != null) {
                Web.json(resp, 409, Map.of("error", "이미 있는 아이디입니다."));
                return;
            }
            String temp = UserStore.randomPassword();
            users.put(name, temp, UserStore.ROLE_ADMIN.equals(role) ? UserStore.ROLE_ADMIN : UserStore.ROLE_VIEWER, true);
            LOG.info("[webwas-precheck] 사용자 추가: " + name + " by " + Web.user(req));
            Web.json(resp, 200, Map.of("name", name, "tempPassword", temp));
        } else if (p.length == 3 && p[0].equals("users") && p[2].equals("reset")) {
            UserStore users = Web.users(getServletContext());
            UserStore.User u = users.find(p[1]);
            if (u == null) {
                Web.json(resp, 404, Map.of("error", "사용자가 없습니다."));
                return;
            }
            String temp = UserStore.randomPassword();
            users.put(u.name(), temp, u.role(), true);
            LOG.info("[webwas-precheck] 비밀번호 초기화: " + u.name() + " by " + Web.user(req));
            Web.json(resp, 200, Map.of("name", u.name(), "tempPassword", temp));
        } else {
            Web.json(resp, 404, Map.of("error", "없는 주소입니다."));
        }
    }

    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String[] p = parts(req);
        if (!requireAdmin(req, resp)) return;
        if (p.length == 2 && p[0].equals("reports")) {
            boolean ok = Web.reports(getServletContext()).delete(p[1]);
            if (ok) LOG.info("[webwas-precheck] 리포트 삭제: " + p[1] + " by " + Web.user(req));
            Web.json(resp, ok ? 200 : 404, Map.of("deleted", ok));
        } else if (p.length == 2 && p[0].equals("agents")) {
            boolean ok = Web.agents(getServletContext()).remove(p[1]);
            if (ok) LOG.info("[webwas-precheck] 에이전트 삭제: " + p[1] + " by " + Web.user(req));
            Web.json(resp, ok ? 200 : 404, Map.of("deleted", ok));
        } else if (p.length == 2 && p[0].equals("users")) {
            UserStore users = Web.users(getServletContext());
            UserStore.User u = users.find(p[1]);
            if (u == null) {
                Web.json(resp, 404, Map.of("error", "사용자가 없습니다."));
            } else if (u.name().equals(Web.user(req))) {
                Web.json(resp, 400, Map.of("error", "자기 자신은 삭제할 수 없습니다."));
            } else if (UserStore.ROLE_ADMIN.equals(u.role()) && users.adminCount() <= 1) {
                Web.json(resp, 400, Map.of("error", "마지막 관리자는 삭제할 수 없습니다."));
            } else {
                users.remove(u.name());
                LOG.info("[webwas-precheck] 사용자 삭제: " + u.name() + " by " + Web.user(req));
                Web.json(resp, 200, Map.of("deleted", true));
            }
        } else {
            Web.json(resp, 404, Map.of("error", "없는 주소입니다."));
        }
    }

    private void agentAction(HttpServletRequest req, HttpServletResponse resp, String[] p) throws IOException {
        AgentStore agents = Web.agents(getServletContext());
        String by = Web.user(req);
        try {
            if (p.length == 1 && p[0].equals("agents-run")) {
                int n = agents.requestRun(null);
                long nowMs = System.currentTimeMillis();
                long offline = agents.list().stream().filter(a -> "offline".equals(a.state(nowMs)) || "never".equals(a.state(nowMs))).count();
                LOG.info("[webwas-precheck] 전체 에이전트 점검 요청 (" + n + "대) by " + by);
                Web.json(resp, 200, Map.of("requested", n, "offline", offline));
            } else if (p.length == 1) {
                String name = req.getParameter("name");
                name = name == null ? null : name.trim();
                String token = agents.create(name, parseHours(req.getParameter("intervalHours")));
                LOG.info("[webwas-precheck] 에이전트 등록: " + name + " by " + by);
                Web.json(resp, 200, Map.of("name", name, "token", token));
            } else if (p.length == 3 && p[2].equals("run")) {
                agents.requestRun(p[1]);
                LOG.info("[webwas-precheck] 에이전트 점검 요청: " + p[1] + " by " + by);
                Web.json(resp, 200, Map.of("requested", 1));
            } else if (p.length == 3 && p[2].equals("token")) {
                String token = agents.rotateToken(p[1]);
                LOG.info("[webwas-precheck] 에이전트 토큰 재발급: " + p[1] + " by " + by);
                Web.json(resp, 200, Map.of("name", p[1], "token", token));
            } else if (p.length == 3 && p[2].equals("interval")) {
                agents.setInterval(p[1], parseHours(req.getParameter("hours")));
                Web.json(resp, 200, Map.of("ok", true));
            } else {
                Web.json(resp, 404, Map.of("error", "없는 주소입니다."));
            }
        } catch (IllegalArgumentException e) {
            Web.json(resp, 400, Map.of("error", e.getMessage()));
        }
    }

    private static LatestVersion requireProduct(Product p, LatestVersions lvs) {
        if (p == null) throw new IllegalArgumentException("제품(product)을 지정하세요: apache | wildfly | tomcat");
        return lvs.get(p);
    }

    private static int parseHours(String s) {
        try {
            return Integer.parseInt(s == null ? "24" : s.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("점검 주기는 숫자(시간)로 입력하세요.");
        }
    }

    private void upload(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        ReportStore store = Web.reports(getServletContext());
        List<Map<String, Object>> results = new ArrayList<>();
        for (Part part : req.getParts()) {
            if (!"files".equals(part.getName()) || part.getSubmittedFileName() == null) continue;
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("file", part.getSubmittedFileName());
            try (InputStream in = part.getInputStream()) {
                String saved = store.saveUpload(part.getSubmittedFileName(), in.readNBytes((int) ReportStore.MAX_FILE_BYTES + 1));
                r.put("ok", true);
                r.put("saved", saved);
                LOG.info("[webwas-precheck] 리포트 업로드: " + saved + " by " + Web.user(req));
            } catch (IllegalArgumentException e) {
                r.put("ok", false);
                r.put("error", e.getMessage());
            }
            results.add(r);
        }
        if (results.isEmpty()) {
            Web.json(resp, 400, Map.of("error", "업로드할 파일이 없습니다."));
            return;
        }
        Web.json(resp, 200, results);
    }

    /**
     * 화면 데이터가 바뀌었는지 판단하는 값: 리포트 폴더 상태 + 최신 버전 기준 + 에이전트 접속 IP(이전 리포트의 IP 대신 표시).
     * 같으면 304 로 응답해 30초마다 같은 데이터를 다시 보내지 않음. (allReports() 를 먼저 불러 폴더 상태를 갱신한 뒤 호출)
     */
    private String etag(ReportStore store, String scope) {
        StringBuilder sb = new StringBuilder();
        sb.append(store.version()).append('|').append(scope).append('|').append(Web.latest(getServletContext()).summary());
        for (AgentStore.Agent a : Web.agents(getServletContext()).list()) sb.append('|').append(a.name).append('=').append(a.ip);
        return "\"" + Integer.toHexString(sb.toString().hashCode()) + Long.toHexString(store.version()) + "\"";
    }

    /** 일자(점검 일시 앞 10자리)·제품·에이전트별 점검 건수와 침해 의심 건수. 최근 days 일만 */
    static Map<String, Object> daily(List<Report> all, int days) {
        java.time.LocalDate today = java.time.LocalDate.now();
        String from = today.minusDays(days - 1L).toString();
        Map<String, int[]> agg = new java.util.TreeMap<>();
        for (Report r : all) {
            String d = r.checkedAt == null || r.checkedAt.length() < 10 ? null : r.checkedAt.substring(0, 10);
            if (d == null || d.compareTo(from) < 0) continue;
            String k = d + "\t" + r.product.id + "\t" + (r.source == null ? "" : r.source);
            int[] v = agg.computeIfAbsent(k, x -> new int[2]);
            v[0]++;
            if ("compromise".equals(r.intrusionStatus())) v[1]++;
        }
        List<Object> rows = new ArrayList<>();
        agg.forEach((k, v) -> {
            String[] t = k.split("\t", -1);
            rows.add(List.of(t[0], t[1], t[2], v[0], v[1]));
        });
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("from", from);
        m.put("to", today.toString());
        m.put("rows", rows);                 // [일자, 제품, 에이전트("" = 수동 업로드), 점검 건수, 침해 의심 건수]
        m.put("totalReports", all.size());
        return m;
    }

    /**
     * 전체 리포트 (최신순). IP 기록이 없는 이전 스크립트 리포트는 보낸 에이전트의 접속 IP 를 대신 표시하도록 채움.
     */
    private List<Report> allReports(ReportStore store) {
        Map<String, String> agentIps = new java.util.HashMap<>();
        for (AgentStore.Agent a : Web.agents(getServletContext()).list()) {
            if (a.ip != null) agentIps.put(a.name, a.ip);
        }
        List<Report> all = store.all();
        for (Report r : all) {
            r.fallbackIp = r.source == null ? null : agentIps.get(r.source);
        }
        return all;
    }

    /** 인스턴스별 최신 리포트 중 [4] 침해 흔적에 [위험]이 있는 것 */
    static List<Report> suspects(List<Report> all) {
        java.util.Set<String> seen = new java.util.HashSet<>();
        List<Report> out = new ArrayList<>();
        for (Report r : all) { // all() 은 최신순
            if (!seen.add(r.instanceKey())) continue;
            if ("compromise".equals(r.intrusionStatus())) out.add(r);
        }
        return out;
    }

    private static void sendPdf(HttpServletResponse resp, byte[] pdf, String fileName) throws IOException {
        resp.setContentType("application/pdf");
        resp.setHeader("Content-Disposition", "attachment; filename=\"" + fileName + "\"");
        resp.setHeader("Cache-Control", "no-store");
        resp.setContentLength(pdf.length);
        resp.getOutputStream().write(pdf);
    }

    private static String ascii(String s) {
        return s == null ? "unknown" : s.replaceAll("[^A-Za-z0-9.-]+", "_");
    }

    private boolean requireAdmin(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (Web.isAdmin(req)) return true;
        Web.json(resp, 403, Map.of("error", "관리자만 사용할 수 있는 기능입니다."));
        return false;
    }

    private static String trim(String s) {
        return s == null ? null : s.trim();
    }
}
