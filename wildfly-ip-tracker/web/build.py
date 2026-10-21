"""samples/ 의 예시 로그를 index.template.html 에 넣어 index.html 을 만든다."""
import glob, html, os
here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)
acc = "".join(open(f, encoding="utf-8").read() for f in sorted(glob.glob(os.path.join(root, "samples", "access_log.*.log"))))
srv = open(os.path.join(root, "samples", "server.log"), encoding="utf-8").read()
tpl = open(os.path.join(here, "index.template.html"), encoding="utf-8").read()
safe = lambda s: s.replace("</script", "<\\/script")
out = tpl.replace("__SAMPLE_ACCESS__", safe(acc)).replace("__SAMPLE_SERVER__", safe(srv))
open(os.path.join(here, "index.html"), "w", encoding="utf-8").write(out)
print("web/index.html", len(out), "bytes")
