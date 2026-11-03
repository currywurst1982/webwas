package com.webwas.precheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 외부 라이브러리 없이 JSON 문자열을 Map/List/String/Double/Boolean/null 로 읽는 최소 구현.
 * CVE 데이터(Apache 보안 JSON, OSV 권고)를 읽는 데만 사용.
 */
public final class JsonParser {
    private final String s;
    private int i;

    private JsonParser(String s) {
        this.s = s;
    }

    public static Object parse(String text) {
        JsonParser p = new JsonParser(text);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i != p.s.length()) throw p.err("JSON 뒤에 불필요한 내용");
        return v;
    }

    // ---- 편의 함수: 경로를 따라가며 없으면 null ----
    @SuppressWarnings("unchecked")
    public static Map<String, Object> obj(Object o, String key) {
        Object v = o instanceof Map<?, ?> m ? m.get(key) : null;
        return v instanceof Map<?, ?> ? (Map<String, Object>) v : null;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> arr(Object o, String key) {
        Object v = o instanceof Map<?, ?> m ? m.get(key) : null;
        return v instanceof List<?> ? (List<Object>) v : List.of();
    }

    public static String str(Object o, String key) {
        Object v = o instanceof Map<?, ?> m ? m.get(key) : null;
        return v instanceof String x ? x : null;
    }

    private IllegalArgumentException err(String msg) {
        return new IllegalArgumentException("JSON 해석 오류(" + i + "): " + msg);
    }

    private void ws() {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
    }

    private Object value() {
        if (i >= s.length()) throw err("값이 없음");
        char c = s.charAt(i);
        switch (c) {
            case '{': return object();
            case '[': return array();
            case '"': return string();
            case 't': expect("true"); return Boolean.TRUE;
            case 'f': expect("false"); return Boolean.FALSE;
            case 'n': expect("null"); return null;
            default: return number();
        }
    }

    private void expect(String w) {
        if (!s.startsWith(w, i)) throw err(w + " 예상");
        i += w.length();
    }

    private Map<String, Object> object() {
        Map<String, Object> m = new LinkedHashMap<>();
        i++;
        ws();
        if (i < s.length() && s.charAt(i) == '}') {
            i++;
            return m;
        }
        while (true) {
            ws();
            if (i >= s.length() || s.charAt(i) != '"') throw err("키 예상");
            String k = string();
            ws();
            if (i >= s.length() || s.charAt(i) != ':') throw err(": 예상");
            i++;
            ws();
            m.put(k, value());
            ws();
            if (i >= s.length()) throw err("} 예상");
            char c = s.charAt(i++);
            if (c == '}') return m;
            if (c != ',') throw err(", 예상");
        }
    }

    private List<Object> array() {
        List<Object> a = new ArrayList<>();
        i++;
        ws();
        if (i < s.length() && s.charAt(i) == ']') {
            i++;
            return a;
        }
        while (true) {
            ws();
            a.add(value());
            ws();
            if (i >= s.length()) throw err("] 예상");
            char c = s.charAt(i++);
            if (c == ']') return a;
            if (c != ',') throw err(", 예상");
        }
    }

    private String string() {
        StringBuilder sb = new StringBuilder();
        i++;
        while (i < s.length()) {
            char c = s.charAt(i++);
            if (c == '"') return sb.toString();
            if (c != '\\') {
                sb.append(c);
                continue;
            }
            if (i >= s.length()) break;
            char e = s.charAt(i++);
            switch (e) {
                case 'n' -> sb.append('\n');
                case 't' -> sb.append('\t');
                case 'r' -> sb.append('\r');
                case 'b' -> sb.append('\b');
                case 'f' -> sb.append('\f');
                case 'u' -> {
                    if (i + 4 > s.length()) throw err("\\u 형식");
                    sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                    i += 4;
                }
                default -> sb.append(e);
            }
        }
        throw err("문자열이 끝나지 않음");
    }

    private Object number() {
        int st = i;
        while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
        if (st == i) throw err("알 수 없는 문자 '" + s.charAt(i) + "'");
        try {
            return Double.parseDouble(s.substring(st, i));
        } catch (NumberFormatException e) {
            throw err("숫자 형식");
        }
    }
}
