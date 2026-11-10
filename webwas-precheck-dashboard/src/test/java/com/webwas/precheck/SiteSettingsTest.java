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
}
