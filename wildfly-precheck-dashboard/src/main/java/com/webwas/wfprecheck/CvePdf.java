package com.webwas.wfprecheck;

import static com.webwas.wfprecheck.IntrusionPdf.CRITICAL;
import static com.webwas.wfprecheck.IntrusionPdf.INK;
import static com.webwas.wfprecheck.IntrusionPdf.INK2;
import static com.webwas.wfprecheck.IntrusionPdf.MUTED;
import static com.webwas.wfprecheck.IntrusionPdf.WARN;
import static com.webwas.wfprecheck.IntrusionPdf.nz;

import java.awt.Color;
import java.io.IOException;
import java.util.List;
import org.apache.pdfbox.pdmodel.PDDocument;

/**
 * CVE별 대상 서버 PDF.
 * 첫 장: CVE 요약표(CVE·등급·대상 서버 수·영향 구간) → 이어서 CVE마다 설명(OSV 원문)·영향 구간과 대상 서버.
 */
public final class CvePdf {
    private CvePdf() {}

    private static final Color SERIOUS = new Color(0x9a, 0x4a, 0x26);

    public static byte[] build(List<CveIssues.Item> items, int serverCount, String latest, String scope, String user) throws IOException {
        try (PDDocument doc = new PDDocument()) {
            IntrusionPdf.Writer w = new IntrusionPdf.Writer(doc);
            String now = IntrusionPdf.now();
            doc.getDocumentInformation().setTitle("CVE별 대상 서버");
            doc.getDocumentInformation().setCreator("wfprecheck-dashboard");

            long affected = items.stream().flatMap(i -> i.targets.stream()).map(t -> t.report().instanceKey()).distinct().count();
            long openServers = items.stream().flatMap(i -> i.targets.stream()).filter(t -> !t.backported())
                    .map(t -> t.report().instanceKey()).distinct().count();
            w.newPage();
            w.text(w.bold, 17, INK, "CVE별 대상 서버");
            w.gap(4);
            w.text(w.regular, 9.5f, INK2, "생성 " + now + " · " + user + " · " + scope);
            w.text(w.regular, 9.5f, INK2, "점검 서버 " + serverCount + "대 중 " + affected + "대에 해당 CVE " + items.size() + "건 (미조치 추정 서버 "
                    + openServers + "대, 인스턴스별 최신 점검 기준, WildFly 최신 " + latest + ")");
            w.gap(6);
            w.wrapped(w.regular, 9, MUTED, "근거: wildfly_precheck.sh 리포트의 [2] CVE 판정에서 '해당'으로 나온 CVE. "
                    + "WildFly 설치 폴더(modules)의 실제 구성요소(jar) 버전을 OSV 취약점 DB(https://osv.dev)의 영향 구간과 비교한 결과이며, "
                    + "등급은 GitHub Advisory Database 기준입니다. 해당 구성요소를 실제로 쓰는 기능(예: AJP, OIDC, HTTP/2)이 꺼져 있으면 악용 가능성은 낮아질 수 있습니다. "
                    + "구성요소가 없어 '미해당'인 CVE 는 넣지 않았습니다.", 0);
            w.gap(12);

            if (items.isEmpty()) {
                w.text(w.regular, 10, INK2, "해당 CVE 가 없습니다.");
                return IntrusionPdf.finish(doc, w, now, user);
            }

            float[] cols = {0, 24, 132, 196, 250};
            w.row(w.bold, 9.5f, INK, cols, "#", "CVE", "등급", "대상", "영향 구간");
            w.rule();
            int n = 1;
            for (CveIssues.Item it : items) {
                w.row(w.regular, 9.5f, INK, cols, String.valueOf(n++), it.id, nz(it.severity),
                        it.targets.size() + "대", nz(it.affected));
            }

            n = 1;
            for (CveIssues.Item it : items) {
                w.gap(16);
                w.ensure(90); // 제목만 쪽 끝에 남지 않도록
                w.text(w.bold, 12.5f, INK, n++ + ". " + it.id);
                w.gap(2);
                w.text(w.bold, 9.5f, color(it.severity), nz(it.severity) + " · 대상 서버 " + it.targets.size() + "대");
                w.gap(2);
                w.wrapped(w.regular, 9.5f, INK2, "설명(OSV 원문): " + nz(it.description), 30);
                w.wrapped(w.regular, 9.5f, INK2, "영향 구간: " + nz(it.affected), 30);
                w.wrapped(w.regular, 8.5f, MUTED, "상세: https://www.cve.org/CVERecord?id=" + it.id
                        + (it.advisory != null ? "   ·   https://osv.dev/vulnerability/" + it.advisory : ""), 30);
                w.gap(6);
                for (CveIssues.Target t : it.targets) {
                    Report r = t.report();
                    w.ensure(30);
                    w.gap(3);
                    String installed = r.cves.stream().filter(c -> c.applicable && it.id.equals(c.id)).map(c -> c.condition)
                            .findFirst().orElse("");
                    w.wrapped(w.bold, 9.5f, INK, "■ " + IntrusionPdf.hostLabel(r)
                            + "  ·  WildFly " + nz(r.version) + (installed.isEmpty() ? "" : "  ·  " + installed), 12);
                    w.wrapped(w.regular, 8.5f, MUTED, "설치 " + nz(r.installType) + " · 점검 " + nz(r.checkedAt) + " · "
                            + (r.source != null ? "에이전트 " + r.source : "수동 업로드") + " · " + r.id, 12);
                }
            }
            w.gap(14);
            w.wrapped(w.regular, 8, MUTED, "※ 근본 대책은 최신 Final(" + latest + ")로의 업그레이드입니다. "
                    + "업그레이드가 어려우면 해당 구성요소를 쓰는 기능(AJP 리스너, OIDC, HTTP/2 등)을 사용하지 않는 경우 끄는 것으로 위험을 줄일 수 있습니다. "
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
