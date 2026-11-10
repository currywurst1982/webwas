package com.webwas.precheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * 에이전트 관리 "점검 제품 · 버전": 같은 제품 인스턴스가 여러 개여도, 버전을 못 읽었어도 모두 보여야 함.
 * (2026-11-10 개선 전에는 제품마다 가장 낮은 버전 하나만, 버전을 못 읽은 제품은 빠짐)
 */
class AgentInstancesTest {
    private static final long T = 1_800_000_000_000L;

    private static Report r(String source, Product p, String version, String binary, long at) {
        Report x = new Report();
        x.id = source + "-" + p.id + "-" + binary + "-" + at;
        x.source = source;
        x.product = p;
        x.version = version;
        x.binary = binary;
        x.host = "web01";
        x.fileModified = at;
        return x;
    }

    @Test
    void showsEveryInstanceOfLastRun() {
        List<Report> latest = List.of(
                r("web01", Product.WILDFLY, "41.0.1.Final", "/opt/wildfly-41", T),
                r("web01", Product.APACHE, null, "/usr/sbin/httpd", T - 60_000),          // 버전 못 읽음 → 그래도 표시
                r("web01", Product.WILDFLY, "26.1.3.Final", "/opt/wildfly-26", T - 30_000), // 같은 제품 두 번째
                r("web01", Product.TOMCAT, "9.0.80", "/opt/tomcat-old", T - 3 * 3_600_000L), // 이전 점검에만 있던 것 → 뺌
                r("web02", Product.TOMCAT, "10.1.40", "/opt/tomcat", T));                // 다른 에이전트
        List<Report> got = AgentStore.lastRunInstances(latest, "web01");
        assertEquals(3, got.size(), got.toString());
        assertEquals(Product.APACHE, got.get(0).product);
        assertNull(got.get(0).version);
        assertEquals("/opt/wildfly-26", got.get(1).binary);
        assertEquals("/opt/wildfly-41", got.get(2).binary);
        assertEquals(0, AgentStore.lastRunInstances(latest, "nobody").size());
    }
}
