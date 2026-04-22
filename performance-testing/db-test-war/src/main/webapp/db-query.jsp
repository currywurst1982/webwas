<%@ page import="javax.naming.*,javax.sql.*,java.sql.*,java.util.concurrent.ThreadLocalRandom" contentType="application/json" pageEncoding="UTF-8" trimDirectiveWhitespaces="true" %><%
    String dsJndi = "java:/claude";
    String queryType = request.getParameter("type");
    if (queryType == null) queryType = "select";

    int delayMs = 500;
    try { delayMs = Integer.parseInt(request.getParameter("delay")); } catch (Exception ignored) {}
    double delaySec = delayMs / 1000.0;

    long start = System.currentTimeMillis();
    try {
        DataSource ds = (DataSource) new InitialContext().lookup(dsJndi);
        String result = "{}";

        if ("select".equals(queryType)) {
            // perf_test_log 실제 SELECT + pg_sleep으로 커넥션 점유
            try (Connection c = ds.getConnection();
                 PreparedStatement ps = c.prepareStatement(
                     "SELECT pg_sleep(?), COUNT(*) AS total, MAX(created_at) AS latest FROM perf_test_log")) {
                ps.setDouble(1, delaySec);
                try (ResultSet r = ps.executeQuery()) {
                    if (r.next()) {
                        result = "{\"total\":" + r.getLong(2)
                               + ",\"latest\":\"" + r.getString(3) + "\"}";
                    }
                }
            }

        } else if ("insert".equals(queryType)) {
            int rand = ThreadLocalRandom.current().nextInt(1000000);
            try (Connection c = ds.getConnection()) {
                c.setAutoCommit(false);

                // pg_sleep으로 실제 DB 처리 시간 시뮬레이션 (커넥션 점유)
                try (PreparedStatement sleep = c.prepareStatement("SELECT pg_sleep(?)")) {
                    sleep.setDouble(1, delaySec);
                    sleep.execute();
                }

                // 실제 INSERT
                try (PreparedStatement ins = c.prepareStatement(
                        "INSERT INTO perf_test_log(name) VALUES(?)")) {
                    ins.setString(1, "perf-" + rand);
                    ins.executeUpdate();
                }

                // 10분 이상 된 테스트 데이터 정리 (테이블 무한 증가 방지)
                try (PreparedStatement del = c.prepareStatement(
                        "DELETE FROM perf_test_log WHERE created_at < NOW() - INTERVAL '10 minutes'")) {
                    del.executeUpdate();
                }

                c.commit();
                result = "{\"inserted\":\"perf-" + rand + "\"}";
            }
        }

        long elapsed = System.currentTimeMillis() - start;
        response.setStatus(200);
        out.print("{\"status\":\"ok\",\"type\":\"" + queryType + "\",\"delay_ms\":" + delayMs
                + ",\"ms\":" + elapsed + ",\"data\":" + result + "}");
    } catch (Exception e) {
        response.setStatus(503);
        out.print("{\"status\":\"error\",\"reason\":\"" + e.getMessage().replace("\"","'") + "\"}");
    }
%>
