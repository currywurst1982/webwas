package com.webwas.precheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** 에이전트 접속 주소: 설치 명령에 그대로 들어가므로 셸 특수문자는 거부 */
class SiteSettingsTest {
    @TempDir
    Path tmp;

    @Test
    void agentUrl() throws Exception {
        Path f = tmp.resolve("settings.properties");
        SiteSettings s = new SiteSettings(f);
        assertEquals("", s.agentUrl());
        assertEquals("http://10.0.0.5:8580/webwas-precheck", s.setAgentUrl(" http://10.0.0.5:8580/webwas-precheck/ "));
        assertEquals("http://10.0.0.5:8580/webwas-precheck", new SiteSettings(f).agentUrl(), "다시 읽어도 유지");
        assertEquals("https://dash.example.com/webwas-precheck", s.setAgentUrl("https://dash.example.com/webwas-precheck"));
        assertEquals("http://[fd00::5]:8580/webwas-precheck", s.setAgentUrl("http://[fd00::5]:8580/webwas-precheck"));
        for (String bad : new String[] {"10.0.0.5:8580", "ftp://x", "http://x:8580/a b", "http://x/$(id)", "http://x/a;rm",
                "http://x/`id`", "http://x/a'b", "http://x:99999/a", "http://x/a?b=1", "http://x/a&b"}) {
            assertThrows(IllegalArgumentException.class, () -> s.setAgentUrl(bad), bad);
        }
        assertEquals("", s.setAgentUrl(""), "비우면 브라우저 주소 사용");
        assertEquals("", new SiteSettings(f).agentUrl());
    }

    @Test
    void scanSettings() throws Exception {
        Path f = tmp.resolve("settings.properties");
        SiteSettings s = new SiteSettings(f);
        assertEquals(0, s.recentDays(), "기본값은 지정 안 함(0)");
        assertEquals(0, s.runTimeout());

        assertEquals(180, s.setRecentDays(180));
        assertEquals(7200, s.setRunTimeout(7200));
        // 다시 읽어도 유지
        SiteSettings s2 = new SiteSettings(f);
        assertEquals(180, s2.recentDays());
        assertEquals(7200, s2.runTimeout());

        // 경계값 허용
        assertEquals(1, s.setRecentDays(1));
        assertEquals(3650, s.setRecentDays(3650));
        assertEquals(60, s.setRunTimeout(60));
        assertEquals(86400, s.setRunTimeout(86400));

        // 0 = 해제
        assertEquals(0, s.setRecentDays(0));
        assertEquals(0, s.setRunTimeout(0));
        // settings.properties 를 다시 읽으면 지정 안 함 상태
        SiteSettings s3 = new SiteSettings(f);
        assertEquals(0, s3.recentDays());
        assertEquals(0, s3.runTimeout());

        // 범위 밖은 거부 (저장 안 됨)
        for (int bad : new int[] {-1, 3651, 100000}) {
            assertThrows(IllegalArgumentException.class, () -> s.setRecentDays(bad));
        }
        for (int bad : new int[] {-1, 59, 86401, 100000}) {
            assertThrows(IllegalArgumentException.class, () -> s.setRunTimeout(bad));
        }

        // 파일에 저장된 범위 밖 값은 읽을 때 0으로 간주
        java.nio.file.Files.writeString(f, "scan.recentDays=99999\nscan.runTimeout=1\n");
        SiteSettings s4 = new SiteSettings(f);
        assertEquals(0, s4.recentDays(), "범위 밖 저장값은 무시");
        assertEquals(0, s4.runTimeout());
    }
}
