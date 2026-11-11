package com.webwas.precheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** IP 자동 그룹 규칙: CIDR·와일드카드·정확 IP, 순서 우선, 저장 */
class IpGroupRulesTest {
    @TempDir
    Path tmp;

    @Test
    void matching() throws Exception {
        IpGroupRules g = new IpGroupRules(tmp.resolve("ipgroups.properties"));
        g.add("10.10.10.0/24", "HAPPY");
        g.add("20.10.30.*", "SAMPLE");       // 10.10.30.*.* 아님 → 20.10.30.*.* 로 확장
        g.add("192.168.1.50", "SOLO");
        assertEquals("HAPPY", g.match("10.10.10.10"));
        assertEquals("HAPPY", g.match("10.10.10.255"));
        assertNull(g.match("10.10.11.1"));                 // /24 밖
        assertEquals("SAMPLE", g.match("20.10.30.36"));
        assertNull(g.match("20.10.31.1"));
        assertEquals("SOLO", g.match("192.168.1.50"));
        assertNull(g.match("192.168.1.51"));
        assertNull(g.match("not-an-ip"));

        // 순서 우선: 먼저 넣은 규칙이 이김
        IpGroupRules o = new IpGroupRules(tmp.resolve("order.properties"));
        o.add("10.0.0.0/8", "BROAD");
        o.add("10.1.2.0/24", "NARROW");
        assertEquals("BROAD", o.match("10.1.2.3"));       // 먼저 넣은 /8 이 이김
        assertEquals("BROAD", o.matchAny(List.of("1.1.1.1", "10.1.2.3")));  // 후보 여러 개여도 규칙 순서 우선
        assertNull(o.matchAny(List.of("1.1.1.1", "2.2.2.2")));
    }

    @Test
    void wildcardShorthandAndValidation() throws Exception {
        IpGroupRules g = new IpGroupRules(tmp.resolve("ipgroups.properties"));
        assertEquals("10.10.*.*", IpGroupRules.normPattern("10.10.*"));
        assertEquals("10.*.*.*", IpGroupRules.normPattern("10.*"));
        assertEquals("10.10.10.10", IpGroupRules.normPattern(" 10.10.10.10 "));
        assertEquals("10.10.0.0/16", IpGroupRules.normPattern("10.10.0.0/16"));
        g.add("10.10.*", "HAPPY");
        assertEquals("HAPPY", g.match("10.10.99.5"));
        assertNull(g.match("10.11.0.1"));
        // 잘못된 패턴·그룹
        assertThrows(IllegalArgumentException.class, () -> g.add("10.10", "X"));       // 4자리도 아니고 *로 끝나지도 않음
        assertThrows(IllegalArgumentException.class, () -> g.add("10.10.10.300", "X")); // 옥텟 범위 초과
        assertThrows(IllegalArgumentException.class, () -> g.add("10.0.0.0/40", "X"));  // 접두 범위 초과
        assertThrows(IllegalArgumentException.class, () -> g.add("10.10.10.0/24", ""));  // 그룹 없음
    }

    @Test
    void persistenceAndRemove() throws Exception {
        Path f = tmp.resolve("ipgroups.properties");
        IpGroupRules g = new IpGroupRules(f);
        g.add("10.10.10.0/24", "HAPPY");
        g.add("20.10.30.*", "SAMPLE");
        String sig = g.signature();
        assertEquals(2, new IpGroupRules(f).list().size());
        assertEquals("HAPPY", new IpGroupRules(f).match("10.10.10.1"));
        // 삭제 (index)
        assertEquals(false, g.remove(5));
        assertEquals(true, g.remove(0));
        assertEquals(1, g.list().size());
        assertEquals("SAMPLE", g.list().get(0).group);
        assertEquals(1, new IpGroupRules(f).list().size());
        org.junit.jupiter.api.Assertions.assertNotEquals(sig, g.signature());
    }
}
