<%@ page import="javax.naming.*,javax.sql.*,java.sql.*,java.util.concurrent.ThreadLocalRandom" contentType="application/json" pageEncoding="UTF-8" trimDirectiveWhitespaces="true" %><%
    String dsJndi = "java:jboss/datasources/claude";
    String queryType = request.getParameter("type");
    if (queryType == null) queryType = "select";

    long start = System.currentTimeMillis();
    try {
        DataSource ds = (DataSource) new InitialContext().lookup(dsJndi);
        String result = "{}";

        if ("select".equals(queryType)) {
            // DB 읽기: SELECT 1 row (DS InUse 발생)
            try (Connection c = ds.getConnection();
                 PreparedStatement ps = c.prepareStatement("SELECT 1 AS id, 'perf-test' AS name FROM DUAL");
                 ResultSet r = ps.executeQuery()) {
                if (r.next()) {
                    result = "{\"id\":" + r.getInt(1) + ",\"name\":\"" + r.getString(2) + "\"}";
                }
            }
        } else if ("insert".equals(queryType)) {
            // DB 쓰기: 커넥션 풀 InUse 유도용 SELECT (트랜잭션 포함)
            // perf_test_log 테이블 의존성 제거 — DUAL SELECT로 InUse 효과 동일
            int rand = ThreadLocalRandom.current().nextInt(1000000);
            try (Connection c = ds.getConnection()) {
                c.setAutoCommit(false);
                try (PreparedStatement ps = c.prepareStatement(
                        "SELECT " + rand + " AS rand_val, SYSDATE AS ts FROM DUAL")) {
                    try (ResultSet r = ps.executeQuery()) {
                        r.next();
                    }
                }
                c.commit();
                result = "{\"simulated_insert\":\"perf-" + rand + "\"}";
            }
        }

        long elapsed = System.currentTimeMillis() - start;
        response.setStatus(200);
        out.print("{\"status\":\"ok\",\"type\":\"" + queryType + "\",\"ms\":" + elapsed + ",\"data\":" + result + "}");
    } catch (Exception e) {
        response.setStatus(503);
        out.print("{\"status\":\"error\",\"reason\":\"" + e.getMessage().replace("\"","'") + "\"}");
    }
%>
