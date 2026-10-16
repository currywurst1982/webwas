#!/usr/bin/env python3
"""
OSV(https://osv.dev) Maven 취약점 데이터에서 WildFly 구성요소 CVE 표를 만듭니다.
결과는 wildfly_precheck.sh 의 CVE_DB 블록(구분자 |)에 그대로 붙여 넣는 형식입니다.

사용법:
  curl -sSLo all.zip https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip
  mkdir osv && unzip -q all.zip -d osv
  python3 gen_cve_table.py osv > cve_table.txt                       ← 표만 출력
  python3 gen_cve_table.py osv ../scripts/wildfly_precheck.sh        ← 스크립트의 CVE_DB 블록을 바로 교체

줄 형식: CVE|권고ID|등급|구성요소|groupId|시작버전|수정버전|마지막영향버전|설명
  - 구성요소 = WildFly modules 폴더 안 jar 이름(버전 앞부분). WILDFLY 는 WildFly 제품 버전 자체.
  - groupId = OSV 패키지의 groupId. 같은 jar 이름이라도 groupId 가 다르면 다른 프로젝트이므로
    스크립트가 jar 안의 META-INF/maven/.../pom.properties 로 확인합니다.
    (예: WildFly 40 이상의 undertow-servlet 은 io.undertow.ee 그룹의 새 프로젝트라
     io.undertow:undertow-servlet 의 옛 CVE 와 버전 번호가 겹쳐도 해당하지 않음)
  - 수정버전이 비어 있고 마지막영향버전도 비어 있으면 "수정 버전 없음(모든 버전 영향)".
"""
import json
import os
import sys

# OSV 패키지명 → 스크립트가 버전을 읽을 jar 이름
PACKAGES = {
    "io.undertow:undertow-core": "undertow-core",
    "io.undertow:undertow-servlet": "undertow-servlet",
    "org.jboss.resteasy:resteasy-core": "resteasy-core",
    "org.jboss.resteasy:resteasy-client": "resteasy-client",
    "org.jboss.resteasy:resteasy-jaxrs": "resteasy-jaxrs",
    "org.jboss.resteasy:resteasy-multipart-provider": "resteasy-multipart-provider",
    "org.jboss.remoting:jboss-remoting": "jboss-remoting",
    "org.jboss.xnio:xnio-api": "xnio-api",
    "org.jboss.xnio:xnio-nio": "xnio-nio",
    "org.jboss.hal:hal-console": "hal-console",
    "org.jboss:jboss-ejb-client": "jboss-ejb-client",
    "org.wildfly.core:wildfly-controller": "wildfly-controller",
    "org.wildfly.core:wildfly-elytron-integration": "wildfly-elytron-integration",
    "org.wildfly.core:wildfly-host-controller": "wildfly-host-controller",
    "org.wildfly.core:wildfly-server": "wildfly-server",
    "org.wildfly.core:wildfly-core-parent": "wildfly-server",
    "org.wildfly.security:wildfly-elytron": "wildfly-elytron-base",
    "org.wildfly.security:wildfly-elytron-http-oidc": "wildfly-elytron-http-oidc",
    "org.wildfly.security:wildfly-elytron-realm-token": "wildfly-elytron-realm-token",
    "org.wildfly:wildfly-undertow": "wildfly-undertow",
    "org.wildfly:wildfly-metrics": "wildfly-metrics",
    "org.wildfly:wildfly-domain-http": "WILDFLY",  # 버전 번호가 WildFly 제품 버전(예: 24.0.0.Final)
    "org.wildfly:wildfly-parent": "WILDFLY",
    "org.wildfly:wildfly-dist": "WILDFLY",
    "org.wildfly.bom:wildfly": "WILDFLY",
}
SEV = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "moderate", "LOW": "low"}


START = "# --- CVE_DB 시작 (tools/gen_cve_table.py 로 생성) ---"
END = "# --- CVE_DB 끝 ---"


def main(osv_dir, script=None):
    rows = set()
    for f in sorted(os.listdir(osv_dir)):
        d = json.load(open(os.path.join(osv_dir, f), encoding="utf-8"))
        if d.get("withdrawn"):
            continue
        cves = [a for a in d.get("aliases", []) if a.startswith("CVE-")]
        if not cves:
            continue
        sev = SEV.get((d.get("database_specific") or {}).get("severity", ""), "moderate")
        summary = (d.get("summary") or d.get("details", "").split("\n")[0])[:150].replace("|", "/").strip()
        for a in d.get("affected", []):
            pkg = a.get("package", {}).get("name", "")
            comp = PACKAGES.get(pkg)
            if not comp:
                continue
            group = "" if comp == "WILDFLY" else pkg.split(":")[0]
            for r in a.get("ranges", []):
                if r.get("type") != "ECOSYSTEM":
                    continue
                intro = None
                for e in r.get("events", []):
                    if "introduced" in e:
                        intro = e["introduced"]
                    elif "fixed" in e:
                        rows.add((cves[0], d["id"], sev, comp, group, intro or "0", e["fixed"], "", summary))
                        intro = None
                    elif "last_affected" in e:
                        rows.add((cves[0], d["id"], sev, comp, group, intro or "0", "", e["last_affected"], summary))
                        intro = None
                if intro is not None:
                    rows.add((cves[0], d["id"], sev, comp, group, intro, "", "", summary))
    lines = ["|".join(r) for r in sorted(rows, key=lambda x: (x[3], x[0], x[5]))]
    if not script:
        print("\n".join(lines))
        return
    text = open(script, encoding="utf-8").read()
    a, b = text.index(START) + len(START), text.index(END)
    open(script, "w", encoding="utf-8").write(text[:a] + "\n" + "\n".join(lines) + "\n" + text[b:])
    print(f"{script}: CVE {len(set(r.split('|')[0] for r in lines))}건 / {len(lines)}줄 반영")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
