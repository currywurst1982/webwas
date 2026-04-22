<%@ page import="javax.naming.*,javax.sql.*,java.sql.*" contentType="application/json" pageEncoding="UTF-8" trimDirectiveWhitespaces="true" %><%
    String dsJndi = request.getParameter("ds");
    if (dsJndi == null || dsJndi.isEmpty()) {
        dsJndi = "java:/claude";
    }
    long start = System.currentTimeMillis();
    try {
        DataSource ds = (DataSource) new InitialContext().lookup(dsJndi);
        try (Connection c = ds.getConnection();
             Statement  s = c.createStatement();
             ResultSet  r = s.executeQuery("SELECT 1")) {
            r.next();
        }
        long elapsed = System.currentTimeMillis() - start;
        response.setStatus(200);
        out.print("{\"status\":\"ok\",\"ds\":\"" + dsJndi + "\",\"ms\":" + elapsed + "}");
    } catch (NameNotFoundException e) {
        response.setStatus(503);
        out.print("{\"status\":\"error\",\"reason\":\"JNDI not found: " + dsJndi + "\"}");
    } catch (Exception e) {
        response.setStatus(503);
        out.print("{\"status\":\"error\",\"reason\":\"" + e.getMessage().replace("\"","'") + "\"}");
    }
%>
