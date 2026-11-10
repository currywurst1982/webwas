package com.webwas.precheck;

import static com.webwas.precheck.IntrusionPdf.CRITICAL;
import static com.webwas.precheck.IntrusionPdf.INK;
import static com.webwas.precheck.IntrusionPdf.INK2;
import static com.webwas.precheck.IntrusionPdf.MUTED;
import static com.webwas.precheck.IntrusionPdf.WARN;
import static com.webwas.precheck.IntrusionPdf.nz;

import java.awt.Color;
import java.io.IOException;
import java.util.List;
import org.apache.pdfbox.pdmodel.PDDocument;

/**
 * CVE별 대상 서버 PDF.
 * 첫 장: CVE 요약표(CVE·제품·등급·미조치/백포트 서버 수) → 이어서 CVE마다 설명·영향 구간·조건과 대상 서버.
 */
public final class CvePdf {
    private CvePdf() {}

    private static final Color SERIOUS = new Color(0x9a, 0x4a, 0x26);

    public static byte[] build(List<CveIssues.Item> items, int serverCount, String latest, String scope, String user) throws IOException {
        try (PDDocument doc = new PDDocument()) {
            IntrusionPdf.Writer w = new IntrusionPdf.Writer(doc);
            String now = IntrusionPdf.now();
            doc.getDocumentInformation().setTitle("CVE별 대상 서버");
            doc.getDocumentInformation().setCreator("webwas-precheck");

            long affected = items.stream().flatMap(i -> i.targets.stream()).map(t -> t.report().instanceKey()).distinct().count();
            long openServers = items.stream().flatMap(i -> i.targets.stream()).filter(t -> !t.backported())
                    .map(t -> t.report().instanceKey()).distinct().count();
            w.newPage();
            w.text(w.bold, 17, INK, "CVE별 대상 서버");
            w.gap(4);
            w.text(w.regular, 9.5f, INK2, "생성 " + now + " · " + user + " · " + scope);
            w.text(w.regular, 9.5f, INK2, "점검 서버 " + serverCount + "대 중 " + affected + "대에 해당 CVE " + items.size() + "건 (미조치 추정 서버 "
                    + openServers + "대, 인스턴스별 최신 점검 기준)");
            w.wrapped(w.regular, 9, INK2, "최신 버전 기준: " + latest, 0);
            w.gap(6);
            w.wrapped(w.regular, 9, MUTED, "근거: 점검 스크립트 리포트의 [2] CVE 판정에서 '해당'으로 나온 CVE. "
                    + "Apache 는 httpd 버전이 Apache 보안팀 공지의 영향 구간에 들고 필요 모듈이 켜져 있는 경우이며, '백포트 추정'은 RPM/DEB 패키지 "
                    + "changelog 에 해당 CVE 번호가 있다는 뜻일 뿐이므로 배포판 보안 공지로 최종 확인하세요. "
                    + "WildFly·Tomcat 은 설치 폴더의 실제 버전을 OSV 취약점 DB(https://osv.dev)의 영향 구간과 비교한 결과입니다(설명은 OSV 원문). "
                    + "등급은 critical > high(Apache 의 important 포함) > moderate > low 입니다. 조건이 맞지 않아 '미해당'인 CVE 는 넣지 않았습니다.", 0);
            w.gap(12);

            if (items.isEmpty()) {
                w.text(w.regular, 10, INK2, "해당 CVE 가 없습니다.");
                return IntrusionPdf.finish(doc, w, now, user);
            }

            float[] cols = {0, 24, 128, 190, 250, 318, 386};
            w.row(w.bold, 9.5f, INK, cols, "#", "CVE", "제품", "등급", "미조치 추정", "백포트 추정", "영향 구간");
            w.rule();
            int n = 1;
            for (CveIssues.Item it : items) {
                w.row(w.regular, 9.5f, INK, cols, String.valueOf(n++), it.id, it.product == null ? "-" : it.product.label, nz(it.severity),
                        it.openCount() + "대", it.backportCount() + "대", nz(it.affected));
            }

            n = 1;
            for (CveIssues.Item it : items) {
                w.gap(16);
                w.ensure(90); // 제목만 쪽 끝에 남지 않도록
                w.text(w.bold, 12.5f, INK, n++ + ". " + it.id);
                w.gap(2);
                w.text(w.bold, 9.5f, color(it.severity), (it.product == null ? "" : it.product.label + " · ") + nz(it.severity)
                        + " · 대상 서버 " + it.targets.size() + "대" + (it.backportCount() > 0 ? " (미조치 추정 " + it.openCount() + " · 백포트 추정 " + it.backportCount() + ")" : ""));
                w.gap(2);
                w.wrapped(w.regular, 9.5f, INK2, "설명: " + nz(it.description), 30);
                w.wrapped(w.regular, 9.5f, INK2, "영향 구간: " + nz(it.affected)
                        + (it.product.moduleStyle() ? "   ·   " + it.product.conditionLabel() + " 조건: " + nz(it.condition) : ""), 30);
                w.wrapped(w.regular, 8.5f, MUTED, "상세: https://www.cve.org/CVERecord?id=" + it.id
                        + (it.advisory != null ? "   ·   https://osv.dev/vulnerability/" + it.advisory : ""), 30);
                w.gap(6);
                for (CveIssues.Target t : it.targets) {
                    Report r = t.report();
                    w.ensure(30);
                    w.gap(3);
                    String installed = r.cves.stream().filter(c -> c.applicable && it.id.equals(c.id)).map(c -> c.condition)
                            .findFirst().orElse("");
                    String state = t.backported() ? "백포트 추정 (changelog 에 수정 기록)" : r.product.moduleStyle() ? "미조치 추정" : installed;
                    w.wrapped(w.bold, 9.5f, t.backported() ? INK2 : INK, "■ " + IntrusionPdf.hostLabel(r)
                            + "  ·  " + r.product.label + " " + nz(r.version) + (state.isEmpty() ? "" : "  ·  " + state), 12);
                    w.wrapped(w.regular, 8.5f, MUTED, "설치 " + nz(r.installType) + " · 점검 " + nz(r.checkedAt) + " · "
                            + (r.source != null ? "에이전트 " + r.source : "수동 업로드") + " · " + r.id, 12);
                }
            }
            w.gap(14);
            w.wrapped(w.regular, 8, MUTED, "※ 근본 대책은 최신 버전(위 '최신 버전 기준', Tomcat 은 같은 브랜치의 최신 버전) 또는 보안 수정이 반영된 패키지로의 업그레이드입니다. "
                    + "업그레이드가 어려우면 해당 모듈·기능(Apache 모듈, AJP 커넥터, HTTP/2, OIDC 등)을 사용하지 않는 경우 끄는 것으로 위험을 줄일 수 있습니다. "
                    + "조치 후에는 에이전트 [지금 점검]으로 재점검해 목록에서 빠지는지 확인하세요.", 0);
            return IntrusionPdf.finish(doc, w, now, user);
        }
    }

    private static Color color(String severity) {
        return switch (severity == null ? "" : severity) {
            case "critical" -> CRITICAL;
            case "high" -> SERIOUS;
            case "moderate" -> WARN;
            default -> MUTED;
        };
    }
}
