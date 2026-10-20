package webwas.loadtest;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** 외부 라이브러리 없이 쓰는 아주 작은 JSON 읽기/쓰기 도구 */
public final class Json {
	private final String s;
	private int i;

	private Json(String s) {
		this.s = s;
	}

	public static Object parse(String text) {
		Json p = new Json(text == null ? "" : text.trim());
		if (p.s.isEmpty()) return null;
		Object v = p.value();
		p.ws();
		if (p.i != p.s.length()) throw new IllegalArgumentException("JSON 뒤에 남은 글자가 있습니다: " + p.i);
		return v;
	}

	@SuppressWarnings("unchecked")
	public static Map<String, Object> parseObject(String text) {
		Object o = parse(text);
		if (!(o instanceof Map)) throw new IllegalArgumentException("JSON 객체가 아닙니다");
		return (Map<String, Object>) o;
	}

	private void ws() {
		while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
	}

	private Object value() {
		ws();
		if (i >= s.length()) throw new IllegalArgumentException("JSON이 끝났습니다");
		char c = s.charAt(i);
		if (c == '{') return object();
		if (c == '[') return array();
		if (c == '"') return string();
		if (s.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
		if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
		if (s.startsWith("null", i)) { i += 4; return null; }
		return number();
	}

	private Map<String, Object> object() {
		Map<String, Object> m = new LinkedHashMap<>();
		i++;
		ws();
		if (s.charAt(i) == '}') { i++; return m; }
		while (true) {
			ws();
			String k = string();
			ws();
			expect(':');
			m.put(k, value());
			ws();
			if (s.charAt(i) == ',') { i++; continue; }
			expect('}');
			return m;
		}
	}

	private List<Object> array() {
		List<Object> l = new ArrayList<>();
		i++;
		ws();
		if (s.charAt(i) == ']') { i++; return l; }
		while (true) {
			l.add(value());
			ws();
			if (s.charAt(i) == ',') { i++; continue; }
			expect(']');
			return l;
		}
	}

	private String string() {
		expect('"');
		StringBuilder b = new StringBuilder();
		while (true) {
			char c = s.charAt(i++);
			if (c == '"') return b.toString();
			if (c == '\\') {
				char e = s.charAt(i++);
				switch (e) {
					case 'n': b.append('\n'); break;
					case 'r': b.append('\r'); break;
					case 't': b.append('\t'); break;
					case 'b': b.append('\b'); break;
					case 'f': b.append('\f'); break;
					case 'u': b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; break;
					default: b.append(e);
				}
			} else {
				b.append(c);
			}
		}
	}

	private Object number() {
		int st = i;
		while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
		String n = s.substring(st, i);
		if (n.isEmpty()) throw new IllegalArgumentException("JSON 형식 오류 위치 " + st);
		if (n.contains(".") || n.contains("e") || n.contains("E")) return Double.parseDouble(n);
		return Long.parseLong(n);
	}

	private void expect(char c) {
		if (i >= s.length() || s.charAt(i) != c) throw new IllegalArgumentException("JSON 형식 오류: '" + c + "' 위치 " + i);
		i++;
	}

	public static String stringify(Object o) {
		StringBuilder b = new StringBuilder();
		write(b, o);
		return b.toString();
	}

	private static void write(StringBuilder b, Object o) {
		if (o == null) {
			b.append("null");
		} else if (o instanceof String) {
			quote(b, (String) o);
		} else if (o instanceof Number || o instanceof Boolean) {
			b.append(o);
		} else if (o instanceof Map) {
			b.append('{');
			boolean first = true;
			for (Map.Entry<?, ?> e : ((Map<?, ?>) o).entrySet()) {
				if (!first) b.append(',');
				first = false;
				quote(b, String.valueOf(e.getKey()));
				b.append(':');
				write(b, e.getValue());
			}
			b.append('}');
		} else if (o instanceof Iterable) {
			b.append('[');
			boolean first = true;
			for (Object x : (Iterable<?>) o) {
				if (!first) b.append(',');
				first = false;
				write(b, x);
			}
			b.append(']');
		} else {
			quote(b, o.toString());
		}
	}

	private static void quote(StringBuilder b, String s) {
		b.append('"');
		for (char c : s.toCharArray()) {
			switch (c) {
				case '"': b.append("\\\""); break;
				case '\\': b.append("\\\\"); break;
				case '\n': b.append("\\n"); break;
				case '\r': b.append("\\r"); break;
				case '\t': b.append("\\t"); break;
				default:
					if (c < 0x20 || c == '<' || c == '>' || c == '&') b.append(String.format("\\u%04x", (int) c));
					else b.append(c);
			}
		}
		b.append('"');
	}

	public static String str(Map<String, Object> m, String key, String def) {
		Object v = m.get(key);
		return v == null ? def : String.valueOf(v).trim();
	}

	public static int integer(Map<String, Object> m, String key, int def) {
		Object v = m.get(key);
		if (v == null || String.valueOf(v).trim().isEmpty()) return def;
		if (v instanceof Number) return ((Number) v).intValue();
		return (int) Double.parseDouble(String.valueOf(v).trim());
	}
}
