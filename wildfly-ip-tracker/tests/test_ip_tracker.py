import json, os, subprocess, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import ip_tracker as t

SAMPLES = os.path.join(ROOT, "samples")


class ParseTest(unittest.TestCase):
    def test_common(self):
        e = t.parse_access_line('1.2.3.4 - bob [20/Oct/2026:09:15:02 +0900] "GET /a?b=1 HTTP/1.1" 404 12', "f")
        self.assertEqual((e.ip, e.method, e.path, e.status, e.user), ("1.2.3.4", "GET", "/a?b=1", 404, "bob"))

    def test_combined(self):
        e = t.parse_access_line('1.2.3.4 - - [20/Oct/2026:09:15:02 +0900] "GET / HTTP/1.1" 200 - "-" "curl/8"', "f")
        self.assertEqual((e.size, e.agent), (0, "curl/8"))

    def test_server_line(self):
        evs = t.parse_server_line("2026-10-20 02:13:20,101 WARN  [x.Y] (task-1) Login failed from 9.9.9.9", "server.log")
        self.assertEqual([e.ip for e in evs], ["9.9.9.9"])

    def test_cidr(self):
        m = t.ip_matcher("203.0.113.0/24")
        self.assertTrue(m("203.0.113.45")); self.assertFalse(m("203.0.114.1")); self.assertFalse(m("bad"))


class AnalyzeTest(unittest.TestCase):
    def test_attacker_high(self):
        r = t.analyze(t.collect("203.0.113.45", [SAMPLES]), "203.0.113.45")
        self.assertEqual(r["risk_level"], "높음")
        self.assertIn("expression-filter", r["actions"][0]["cli"][0])

    def test_normal_low(self):
        r = t.analyze(t.collect("192.168.10.35", [SAMPLES]), "192.168.10.35")
        self.assertEqual(r["risk_level"], "낮음")

    def test_time_filter(self):
        ev = t.collect("203.0.113.45", [SAMPLES], since="2026-10-21")
        self.assertTrue(ev and all(e.time.day == 21 for e in ev))


class McpTest(unittest.TestCase):
    def test_stdio(self):
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "getIpHistory", "arguments": {"ip": "203.0.113.45", "maxEvents": 2}}},
        ]
        out = subprocess.run([sys.executable, os.path.join(ROOT, "mcp_server.py")],
                             input="\n".join(json.dumps(m) for m in msgs), capture_output=True, text=True,
                             env={**os.environ, "WILDFLY_LOG_DIR": SAMPLES}).stdout.splitlines()
        self.assertEqual(len(out), 3)  # 알림에는 응답 없음
        self.assertEqual(len(json.loads(out[1])["result"]["tools"]), 3)
        body = json.loads(json.loads(out[2])["result"]["content"][0]["text"])
        self.assertEqual(body["risk_level"], "높음")


if __name__ == "__main__":
    unittest.main()
