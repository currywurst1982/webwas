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
            // DB 쓰기: INSERT 후 DELETE (테스트 데이터 정리)
            int rand = ThreadLocalRandom.current().nextInt(1000000);
            try (Connection c = ds.getConnection()) {
                c.setAutoCommit(false);
                try (PreparedStatement ps = c.prepareStatement(
                        "INSERT INTO perf_test_log(name, created_at) VALUES(?, NOW())")) {
                    ps.setString(1, "perf-" + rand);
                    ps.executeUpdate();
                }
                c.commit();
                result = "{\"inserted\":\"perf-" + rand + "\"}";
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
