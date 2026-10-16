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
 * 설정 취약 항목별 대상 서버 PDF.
 * 첫 장: 항목 요약표(항목·등급·서버 수) → 이어서 항목마다 점검 문구와 대상 서버, 서버별 설정 위치(파일:줄).
 */
public final class ConfigPdf {
    private ConfigPdf() {}

    public static byte[] build(List<ConfigIssues.Item> items, int serverCount, String latest, String scope, String user) throws IOException {
        try (PDDocument doc = new PDDocument()) {
            IntrusionPdf.Writer w = new IntrusionPdf.Writer(doc);
            String now = IntrusionPdf.now();
            doc.getDocumentInformation().setTitle("설정 취약 항목별 대상 서버");
            doc.getDocumentInformation().setCreator("precheck-dashboard");

            long affected = items.stream().flatMap(i -> i.targets.stream()).map(t -> t.report().instanceKey()).distinct().count();
            w.newPage();
            w.text(w.bold, 17, INK, "설정 취약 항목별 대상 서버");
            w.gap(4);
            w.text(w.regular, 9.5f, INK2, "생성 " + now + " · " + user + " · " + scope);
            w.text(w.regular, 9.5f, INK2, "점검 서버 " + serverCount + "대 중 " + affected + "대에서 설정 취약 항목 " + items.size() + "종 발견 (인스턴스별 최신 점검 기준, Apache 최신 " + latest + ")");
            w.gap(6);
            w.wrapped(w.regular, 9, MUTED, "근거: apache_precheck.sh 리포트의 [3] 위험 설정 점검에서 [위험]/[주의]로 나온 항목. "
                    + "항목 문구와 권장 조치는 점검 스크립트의 원문이며, 서버별 '설정 위치'는 리포트에 기록된 설정 파일:줄 번호입니다.", 0);
            w.gap(12);

            if (items.isEmpty()) {
                w.text(w.regular, 10, INK2, "설정 취약 항목이 없습니다.");
                return IntrusionPdf.finish(doc, w, now, user);
            }

            float[] cols = {0, 26, 380, 440};
            w.row(w.bold, 9.5f, INK, cols, "#", "설정 취약 항목", "등급", "대상 서버");
            w.rule();
            int n = 1;
            for (ConfigIssues.Item it : items) {
                w.row(w.regular, 9.5f, INK, cols, String.valueOf(n++), it.key, levelLabel(it.level), it.targets.size() + "대");
            }

            n = 1;
            for (ConfigIssues.Item it : items) {
                w.gap(16);
                w.ensure(80); // 제목만 쪽 끝에 남지 않도록
                w.text(w.bold, 12.5f, INK, n++ + ". " + it.key);
                w.gap(2);
                w.text(w.bold, 9.5f, color(it.level), levelLabel(it.level) + " · 대상 서버 " + it.targets.size() + "대"
                        + (it.riskCount() > 0 && it.riskCount() < it.targets.size() ? " (위험 " + it.riskCount() + "대)" : ""));
                w.gap(2);
                w.wrapped(w.regular, 9.5f, INK2, "점검 문구: " + it.text, 52);
                w.gap(6);
                for (ConfigIssues.Target t : it.targets) {
                    Report r = t.report();
                    w.ensure(40);
                    w.gap(3);
                    w.wrapped(w.bold, 9.5f, INK, "■ " + r.host + (r.pid != null ? " (PID " + r.pid + ")" : "")
                            + "  ·  Apache " + nz(r.version) + "  ·  " + levelLabel(t.level()), 12);
                    w.wrapped(w.regular, 8.5f, MUTED, "점검 " + nz(r.checkedAt) + " · " + (r.source != null ? "에이전트 " + r.source : "수동 업로드")
                            + " · " + r.id, 12);
                    if (!t.text().equals(it.text)) w.wrapped(w.regular, 8.5f, INK2, "문구: " + t.text(), 12);
                    if (t.details().isEmpty()) {
                        w.wrapped(w.regular, 8.5f, MUTED, "설정 위치: (리포트에 기록 없음 — 기본값/미설정 상태일 수 있음)", 12);
                    } else {
                        w.gap(2);
                        for (String d : t.details()) w.code(d, INK2);
                    }
                }
            }
            w.gap(14);
            w.wrapped(w.regular, 8, MUTED, "※ 결과는 점검 시점의 설정 파일 기준입니다. 조치 후에는 에이전트 [지금 점검]으로 재점검해 목록에서 빠지는지 확인하세요. "
                    + "설정 변경은 서비스 영향이 있을 수 있으므로 변경 관리 절차에 따라 적용하세요.", 0);
            return IntrusionPdf.finish(doc, w, now, user);
        }
    }

    private static String levelLabel(String level) {
        return "risk".equals(level) ? "위험" : "주의";
    }

    private static Color color(String level) {
        return "risk".equals(level) ? CRITICAL : WARN;
    }
}
