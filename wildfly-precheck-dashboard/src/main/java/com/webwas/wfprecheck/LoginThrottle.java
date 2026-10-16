package com.webwas.wfprecheck;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** 같은 아이디+IP 로 5회 연속 실패하면 5분간 로그인 차단 (무차별 대입 방지). */
public class LoginThrottle {
    private static final int MAX_FAILURES = 5;
    private static final long LOCK_MILLIS = 5 * 60 * 1000L;

    private record State(int failures, long lockedUntil) {}

    private final Map<String, State> states = new ConcurrentHashMap<>();

    private static String key(String user, String ip) {
        return (user == null ? "" : user.toLowerCase()) + "@" + ip;
    }

    /** 남은 차단 시간(초). 0 이면 시도 가능. */
    public long lockedSeconds(String user, String ip) {
        State s = states.get(key(user, ip));
        if (s == null) return 0;
        long left = s.lockedUntil - System.currentTimeMillis();
        return left > 0 ? (left + 999) / 1000 : 0;
    }

    public void failure(String user, String ip) {
        states.compute(key(user, ip), (k, s) -> {
            int n = (s == null || s.lockedUntil < System.currentTimeMillis() && s.failures >= MAX_FAILURES) ? 1 : s.failures + 1;
            long until = n >= MAX_FAILURES ? System.currentTimeMillis() + LOCK_MILLIS : 0;
            return new State(n, until);
        });
        if (states.size() > 10_000) states.clear();
    }

    public void success(String user, String ip) {
        states.remove(key(user, ip));
    }
}
