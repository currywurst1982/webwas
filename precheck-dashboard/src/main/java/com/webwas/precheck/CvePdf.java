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
 * 첫 장: CVE 요약표(CVE·등급·미조치/백포트 서버 수) → 이어서 CVE마다 설명·영향 버전·필요 모듈과 대상 서버.
 */
public final class CvePdf {
    private CvePdf() {}

    private static final Color SERIOUS = new Color(0x9a, 0x4a, 0x26);

    public static byte[] build(List<CveIssues.Item> items, int serverCount, String latest, String scope, String user) throws IOException {
        try (PDDocument doc = new PDDocument()) {
            IntrusionPdf.Writer w = new IntrusionPdf.Writer(doc);
            String now = IntrusionPdf.now();
            doc.getDocumentInformation().setTitle("CVE별 대상 서버");
            doc.getDocumentInformation().setCreator("precheck-dashboard");

            long affected = items.stream().flatMap(i -> i.targets.stream()).map(t -> t.report().instanceKey()).distinct().count();
            long openServers = items.stream().flatMap(i -> i.targets.stream()).filter(t -> !t.backported())
                    .map(t -> t.report().instanceKey()).distinct().count();
            w.newPage();
            w.text(w.bold, 17, INK, "CVE별 대상 서버");
            w.gap(4);
            w.text(w.regular, 9.5f, INK2, "생성 " + now + " · " + user + " · " + scope);
            w.text(w.regular, 9.5f, INK2, "점검 서버 " + serverCount + "대 중 " + affected + "대에 해당 CVE " + items.size() + "건 (미조치 추정 서버 "
                    + openServers + "대, 인스턴스별 최신 점검 기준, Apache 최신 " + latest + ")");
            w.gap(6);
            w.wrapped(w.regular, 9, MUTED, "근거: apache_precheck.sh 리포트의 [2] CVE 판정에서 '해당'으로 나온 CVE (영향 버전 구간과 필요 모듈 조건을 모두 충족). "
                    + "'백포트 추정'은 RPM/DEB 패키지 changelog 에 해당 CVE 번호가 있다는 뜻일 뿐이므로 배포판 보안 공지로 최종 확인하세요. "
                    + "판정은 업스트림 버전 기준이며, 모듈 조건 미충족으로 '미해당'인 CVE 는 넣지 않았습니다.", 0);
            w.gap(12);

            if (items.isEmpty()) {
                w.text(w.regular, 10, INK2, "해당 CVE 가 없습니다.");
                return IntrusionPdf.finish(doc, w, now, user);
            }

            float[] cols = {0, 24, 140, 225, 330, 430};
            w.row(w.bold, 9.5f, INK, cols, "#", "CVE", "등급", "미조치 추정", "백포트 추정", "영향 버전");
            w.rule();
            int n = 1;
            for (CveIssues.Item it : items) {
                w.row(w.regular, 9.5f, INK, cols, String.valueOf(n++), it.id, nz(it.severity),
                        it.openCount() + "대", it.backportCount() + "대", nz(it.affected));
            }

            n = 1;
            for (CveIssues.Item it : items) {
                w.gap(16);
                w.ensure(90); // 제목만 쪽 끝에 남지 않도록
                w.text(w.bold, 12.5f, INK, n++ + ". " + it.id);
                w.gap(2);
                w.text(w.bold, 9.5f, color(it.severity), nz(it.severity) + " · 대상 서버 " + it.targets.size() + "대 (미조치 추정 "
                        + it.openCount() + " · 백포트 추정 " + it.backportCount() + ")");
                w.gap(2);
                w.wrapped(w.regular, 9.5f, INK2, "설명: " + nz(it.description), 30);
                w.wrapped(w.regular, 9.5f, INK2, "영향 버전: " + nz(it.affected) + "   ·   필요 모듈 조건: " + nz(it.condition), 30);
                w.wrapped(w.regular, 8.5f, MUTED, "상세: https://www.cve.org/CVERecord?id=" + it.id, 30);
                w.gap(6);
                for (CveIssues.Target t : it.targets) {
                    Report r = t.report();
                    w.ensure(30);
                    w.gap(3);
                    w.wrapped(w.bold, 9.5f, t.backported() ? INK2 : INK, "■ " + IntrusionPdf.hostLabel(r)
                            + "  ·  Apache " + nz(r.version) + "  ·  " + (t.backported() ? "백포트 추정 (changelog 에 수정 기록)" : "미조치 추정"), 12);
                    w.wrapped(w.regular, 8.5f, MUTED, "설치 " + nz(r.installType) + " · 점검 " + nz(r.checkedAt) + " · "
                            + (r.source != null ? "에이전트 " + r.source : "수동 업로드") + " · " + r.id, 12);
                }
            }
            w.gap(14);
            w.wrapped(w.regular, 8, MUTED, "※ 근본 대책은 최신 버전(" + latest + ") 또는 보안 수정이 반영된 배포판 패키지로의 업그레이드입니다. "
                    + "업그레이드가 어려우면 '필요 모듈 조건'의 모듈을 사용하지 않는 경우 비활성화하는 것으로 위험을 줄일 수 있습니다. "
                    + "조치 후에는 에이전트 [지금 점검]으로 재점검해 목록에서 빠지는지 확인하세요.", 0);
            return IntrusionPdf.finish(doc, w, now, user);
        }
    }

    private static Color color(String severity) {
        return switch (severity == null ? "" : severity) {
            case "critical" -> CRITICAL;
            case "important" -> SERIOUS;
            case "moderate" -> WARN;
            default -> MUTED;
        };
    }
}
