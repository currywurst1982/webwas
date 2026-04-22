<%@ page import="javax.naming.*,javax.sql.*,java.sql.*,java.util.concurrent.ThreadLocalRandom" contentType="application/json" pageEncoding="UTF-8" trimDirectiveWhitespaces="true" %><%
    String dsJndi = "java:/claude";
    String queryType = request.getParameter("type");
    if (queryType == null) queryType = "select";

    // delay(ms): 커넥션 보유 시간 시뮬레이션 — pg_sleep 사용
    // 기본값 500ms: Prometheus 5초 주기에 InUse가 포착되도록
    int delayMs = 500;
    try { delayMs = Integer.parseInt(request.getParameter("delay")); } catch (Exception ignored) {}
    double delaySec = delayMs / 1000.0;

    long start = System.currentTimeMillis();
    try {
        DataSource ds = (DataSource) new InitialContext().lookup(dsJndi);
        String result = "{}";

        if ("select".equals(queryType)) {
            try (Connection c = ds.getConnection();
                 PreparedStatement ps = c.prepareStatement(
                     "SELECT pg_sleep(?), 1 AS id, 'perf-test' AS name")) {
                ps.setDouble(1, delaySec);
                try (ResultSet r = ps.executeQuery()) {
                    if (r.next()) {
                        result = "{\"id\":" + r.getInt(2) + ",\"name\":\"" + r.getString(3) + "\"}";
                    }
                }
            }
        } else if ("insert".equals(queryType)) {
            int rand = ThreadLocalRandom.current().nextInt(1000000);
            try (Connection c = ds.getConnection()) {
                c.setAutoCommit(false);
                try (PreparedStatement ps = c.prepareStatement(
                        "SELECT pg_sleep(?), ? AS rand_val, NOW() AS ts")) {
                    ps.setDouble(1, delaySec);
                    ps.setInt(2, rand);
                    try (ResultSet r = ps.executeQuery()) { r.next(); }
                }
                c.commit();
                result = "{\"simulated_insert\":\"perf-" + rand + "\"}";
            }
        }

        long elapsed = System.currentTimeMillis() - start;
        response.setStatus(200);
        out.print("{\"status\":\"ok\",\"type\":\"" + queryType + "\",\"delay_ms\":" + delayMs + ",\"ms\":" + elapsed + ",\"data\":" + result + "}");
    } catch (Exception e) {
        response.setStatus(503);
        out.print("{\"status\":\"error\",\"reason\":\"" + e.getMessage().replace("\"","'") + "\"}");
    }
%>
