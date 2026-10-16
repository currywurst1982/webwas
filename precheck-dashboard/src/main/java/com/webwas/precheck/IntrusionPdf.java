package com.webwas.precheck;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;

/**
 * 원본 리포트에서 [4] 침해 흔적 섹션만 발췌한 PDF 생성 (Apache PDFBox).
 * 한글 표시를 위해 나눔고딕(SIL OFL 1.1) 글꼴을 WAR 에 넣어 필요한 글자만 PDF 에 포함(subset)함.
 */
public final class IntrusionPdf {
    static final float MARGIN = 42f;
    static final float FOOTER = 28f;
    static final Color INK = new Color(0x0b, 0x0b, 0x0b);
    static final Color INK2 = new Color(0x52, 0x51, 0x4e);
    static final Color MUTED = new Color(0x89, 0x87, 0x81);
    static final Color CRITICAL = new Color(0xa3, 0x24, 0x24);
    static final Color WARN = new Color(0x7a, 0x53, 0x00);
    static final Color GOOD = new Color(0x00, 0x63, 0x00);
    static final Color BOX = new Color(0xf2, 0xf1, 0xed);

    private IntrusionPdf() {}

    /** 리포트 1건 PDF */
    public static byte[] single(Report r, String latest, String user) throws IOException {
        return build(List.of(r), latest, user, false);
    }

    /** 여러 리포트(침해 의심 서버 전체)를 한 PDF로. 첫 장은 목록 */
    public static byte[] combined(List<Report> reports, String latest, String user) throws IOException {
        return build(reports, latest, user, true);
    }

    private static byte[] build(List<Report> reports, String latest, String user, boolean cover) throws IOException {
        try (PDDocument doc = new PDDocument()) {
            Writer w = new Writer(doc);
            String now = now();
            PDDocumentInformation info = doc.getDocumentInformation();
            info.setTitle(cover ? "침해 의심 서버 점검 결과" : "침해 흔적 점검 결과 - " + reports.get(0).host);
            info.setCreator("precheck-dashboard");

            if (cover) {
                w.newPage();
                w.text(w.bold, 17, INK, "침해 의심 서버 점검 결과");
                w.gap(4);
                w.text(w.regular, 9.5f, INK2, "생성 " + now + " · " + user + " · 대상 " + reports.size() + "대 (인스턴스별 최신 점검 기준)");
                w.gap(10);
                w.text(w.regular, 9.5f, INK2, "판정 기준: 원본 리포트 [4] 침해 흔적 점검에 [위험] 항목이 있으면 '침해 의심'.");
                w.text(w.regular, 9.5f, INK2, "다음 장부터 서버별로 원본 리포트의 [4] 섹션만 원문 그대로 발췌했습니다.");
                w.gap(12);
                float[] cols = {0, 175, 250, 350, 410};
                w.row(w.bold, 9.5f, INK, cols, "호스트", "Apache 버전", "점검 일시", "[4] 위험", "수집");
                w.rule();
                for (Report r : reports) {
                    long risks = r.findings.stream().filter(f -> "4".equals(f.section) && "risk".equals(f.level)).count();
                    w.row(w.regular, 9.5f, INK, cols, hostLabel(r),
                            nz(r.version), nz(r.checkedAt), risks + "건", r.source != null ? "에이전트 " + r.source : "업로드");
                }
            }

            for (Report r : reports) {
                w.newPage();
                reportPages(w, r, latest, user, now);
            }
            return finish(doc, w, now, user);
        }
    }

    static String now() {
        return LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"));
    }

    /** 모든 쪽에 바닥글(생성 정보, 쪽 번호)을 쓰고 PDF 바이트로 저장 */
    static byte[] finish(PDDocument doc, Writer w, String now, String user) throws IOException {
        w.close();
        int total = doc.getNumberOfPages();
        for (int i = 0; i < total; i++) {
            PDPage page = doc.getPage(i);
            try (PDPageContentStream cs = new PDPageContentStream(doc, page, PDPageContentStream.AppendMode.APPEND, true, true)) {
                w.page = page;
                w.cs = cs;
                w.y = 16;
                w.draw(w.regular, 7.5f, MUTED, 0, "precheck-dashboard · 생성 " + now + " · " + user + " · 대외비");
                String pn = (i + 1) + " / " + total;
                w.draw(w.regular, 7.5f, MUTED, w.contentWidth() - w.width(w.regular, 7.5f, pn), pn);
            } finally {
                w.cs = null;
            }
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        doc.save(out);
        return out.toByteArray();
    }

    private static void reportPages(Writer w, Report r, String latest, String user, String now) throws IOException {
        String status = r.intrusionStatus();
        w.text(w.bold, 15, INK, "침해 흔적 점검 결과 (원본 리포트 발췌)");
        w.gap(6);
        switch (status) {
            case "compromise" -> w.text(w.bold, 12, CRITICAL, "판정: 침해 의심 — [4] 침해 흔적 점검에 [위험] 항목 있음");
            case "check" -> w.text(w.bold, 12, WARN, "판정: 확인 필요 — [4] 침해 흔적 점검에 [주의] 항목 있음");
            case "clean" -> w.text(w.bold, 12, GOOD, "판정: 알려진 침해 흔적 없음");
            default -> w.text(w.bold, 12, WARN, "판정: [4] 침해 흔적 점검 결과가 리포트에 없음 (스크립트 중단 가능성)");
        }
        w.gap(8);

        String ver = nz(r.version);
        if (r.version != null && latest != null) {
            ver += ReportParser.compareVersions(r.version, latest) < 0 ? "  (최신 " + latest + " 미만)" : "  (최신 " + latest + " 이상)";
        }
        String[][] meta = {
                {"호스트", r.host},
                {"서버 IP", ipText(r)},
                {"Apache 버전", ver},
                {"실행 파일", nz(r.binary)},
                {"점검 일시", nz(r.checkedAt)},
                {"수집 경로", r.source != null ? "에이전트 " + r.source : "수동 업로드"},
                {"원본 파일", r.id},
                {"원본 SHA-256", sha256(r.raw)},
        };
        for (String[] kv : meta) w.labeled(kv[0], kv[1]);
        if (!r.dataQuality.isEmpty()) {
            w.gap(4);
            w.text(w.bold, 9, WARN, "데이터 품질 경고 (결과가 불완전할 수 있음)");
            for (String d : r.dataQuality) w.wrapped(w.regular, 8.5f, WARN, "· " + d, 10);
        }
        w.gap(10);
        w.text(w.bold, 11, INK, "원본 리포트 [4] 침해 흔적 점검 — 원문 그대로");
        w.gap(4);

        if (r.section4Raw.isEmpty()) {
            w.text(w.regular, 9, MUTED, "(원본 리포트에 [4] 섹션이 없습니다)");
        } else {
            for (String line : r.section4Raw) {
                Color c = line.startsWith("[위험]") ? CRITICAL : line.startsWith("[주의]") ? WARN
                        : line.startsWith("[양호]") ? GOOD : line.startsWith(" [4]") ? INK : INK2;
                w.code(line, c);
            }
        }
        w.gap(12);
        w.wrapped(w.regular, 8, MUTED, "※ 이 문서는 apache_precheck.sh 원본 리포트에서 [4] 침해 흔적 섹션만 발췌한 것입니다. "
                + "원본 전체는 대시보드에서 받을 수 있으며, 위 SHA-256 값으로 원본 파일과 대조할 수 있습니다. "
                + "결과는 '알려진 패턴' 기준으로 침해 여부를 확정하지 않습니다. 침해 의심이면 설정 보완·패치보다 침해사고 대응(격리·증거 보존·분석)이 우선입니다.", 0);
    }

    /** "호스트 (IP)" 표시. IP 기록이 없으면 에이전트 접속 IP 를 "접속 IP"로 표시 */
    static String hostLabel(Report r) {
        String ip = r.displayIp();
        String s = ip == null ? r.host : r.host + " (" + ip + (r.ips.isEmpty() ? ", 접속 IP" : "") + ")";
        // 한 서버에 -f 로 설정 파일을 달리해 띄운 Apache 가 여러 개면 설정 파일로 구분
        return r.confArg == null ? s : s + " [" + shortPath(r.confArg) + "]";
    }

    static String shortPath(String p) {
        return p.length() <= 40 ? p : "…" + p.substring(p.length() - 39);
    }

    static String ipText(Report r) {
        if (!r.ips.isEmpty()) return String.join(", ", r.ips);
        if (r.fallbackIp != null) return r.fallbackIp + "  (리포트에 IP 기록 없음 — 에이전트 접속 IP)";
        return "-  (이전 스크립트 리포트라 IP 기록 없음)";
    }

    static String nz(String s) {
        return s == null || s.isBlank() ? "-" : s;
    }

    static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest((s == null ? "" : s).getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** 쪽 넘김·줄바꿈을 처리하며 위에서 아래로 글을 쓰는 도우미 (ConfigPdf 에서도 사용) */
    static final class Writer {
        final PDDocument doc;
        final PDType0Font regular, bold, mono;
        final PDType1Font spaceFont = new PDType1Font(Standard14Fonts.FontName.HELVETICA);
        final Map<PDType0Font, Map<Integer, Boolean>> glyphCache = new HashMap<>();
        PDPage page;
        PDPageContentStream cs;
        float y;

        Writer(PDDocument doc) throws IOException {
            this.doc = doc;
            this.regular = font("NanumGothic.ttf");
            this.bold = font("NanumGothicBold.ttf");
            this.mono = font("NanumGothicCoding.ttf");
        }

        private PDType0Font font(String name) throws IOException {
            try (InputStream in = IntrusionPdf.class.getResourceAsStream("/fonts/" + name)) {
                if (in == null) throw new IOException("글꼴 파일이 WAR 에 없습니다: " + name);
                return PDType0Font.load(doc, in, true);
            }
        }

        float contentWidth() {
            return page.getMediaBox().getWidth() - 2 * MARGIN;
        }

        void newPage() throws IOException {
            close();
            page = new PDPage(PDRectangle.A4);
            doc.addPage(page);
            cs = new PDPageContentStream(doc, page);
            y = page.getMediaBox().getHeight() - MARGIN;
        }

        void close() throws IOException {
            if (cs != null) {
                cs.close();
                cs = null;
            }
        }

        void ensure(float h) throws IOException {
            if (y - h < MARGIN + FOOTER) newPage();
        }

        void gap(float h) {
            y -= h;
        }

        /** 글꼴에 없는 글자(이모지 등)는 ? 로 바꿈. 탭은 공백 4칸 */
        String safe(PDType0Font f, String s) {
            Map<Integer, Boolean> cache = glyphCache.computeIfAbsent(f, k -> new HashMap<>());
            StringBuilder sb = new StringBuilder();
            s.replace("\t", "    ").codePoints().forEach(cp -> {
                if (cp < 0x20) return;
                boolean ok = cache.computeIfAbsent(cp, c -> {
                    try {
                        f.encode(new String(Character.toChars(c)));
                        return true;
                    } catch (IOException | IllegalArgumentException e) {
                        return false;
                    }
                });
                sb.append(ok ? new String(Character.toChars(cp)) : "?");
            });
            return sb.toString();
        }

        float width(PDType0Font f, float size, String s) throws IOException {
            return f.getStringWidth(safe(f, s)) / 1000f * size;
        }

        /**
         * 나눔 글꼴은 공백과 제어문자(U+0000~001F)가 같은 글리프라, 공백을 나눔 글꼴로 쓰면
         * PDF 에서 검색·복사할 때 공백이 NUL 로 나옴 → 공백만 표준 글꼴(Helvetica)로 써서 진짜 공백 문자로 기록.
         * 공백 폭은 원래 글꼴의 공백 폭에 맞춤.
         */
        void draw(PDType0Font f, float size, Color c, float x, String s) throws IOException {
            String t = safe(f, s);
            float want = f.getSpaceWidth() / 1000f;
            float helvSpace = spaceFont.getSpaceWidth() / 1000f;
            float spaceSize = want > 0 && helvSpace > 0 ? size * want / helvSpace : size;
            cs.setNonStrokingColor(c);
            cs.beginText();
            cs.newLineAtOffset(MARGIN + x, y);
            int i = 0, n = t.length();
            while (i < n) {
                int j = i;
                while (j < n && t.charAt(j) == ' ') j++;
                if (j > i) {
                    cs.setFont(spaceFont, spaceSize);
                    cs.showText(" ".repeat(j - i));
                }
                int k = j;
                while (k < n && t.charAt(k) != ' ') k++;
                if (k > j) {
                    cs.setFont(f, size);
                    cs.showText(t.substring(j, k));
                }
                i = k;
            }
            cs.endText();
        }

        void text(PDType0Font f, float size, Color c, String s) throws IOException {
            wrapped(f, size, c, s, 0);
        }

        /** 폭에 맞춰 줄바꿈 (indent = 둘째 줄부터 들여쓰기) */
        void wrapped(PDType0Font f, float size, Color c, String s, float indent) throws IOException {
            float lh = size * 1.45f;
            List<String> lines = split(f, size, s, contentWidth(), contentWidth() - indent);
            for (int i = 0; i < lines.size(); i++) {
                ensure(lh);
                y -= lh;
                draw(f, size, c, i == 0 ? 0 : indent, lines.get(i));
            }
        }

        void labeled(String label, String value) throws IOException {
            float size = 9.5f, lh = size * 1.5f, lw = 80;
            List<String> lines = split(regular, size, value, contentWidth() - lw, contentWidth() - lw);
            for (int i = 0; i < lines.size(); i++) {
                ensure(lh);
                y -= lh;
                if (i == 0) draw(bold, size, INK2, 0, label);
                draw(regular, size, INK, lw, lines.get(i));
            }
        }

        void row(PDType0Font f, float size, Color c, float[] cols, String... cells) throws IOException {
            float lh = size * 1.6f;
            ensure(lh);
            y -= lh;
            for (int i = 0; i < cells.length; i++) {
                float max = (i + 1 < cols.length ? cols[i + 1] : contentWidth()) - cols[i] - 6;
                draw(f, size, c, cols[i], ellipsize(f, size, cells[i], max));
            }
        }

        void rule() throws IOException {
            y -= 4;
            cs.setStrokingColor(MUTED);
            cs.setLineWidth(0.5f);
            cs.moveTo(MARGIN, y);
            cs.lineTo(MARGIN + contentWidth(), y);
            cs.stroke();
        }

        /** 원문 1줄: 고정폭 글꼴, 회색 바탕, 넘치면 줄바꿈해 이어지는 줄은 ↳ 표시 */
        void code(String line, Color c) throws IOException {
            float size = 8f, lh = 11.2f, pad = 6;
            List<String> parts = split(mono, size, line.isEmpty() ? " " : line, contentWidth() - 2 * pad, contentWidth() - 2 * pad - 10);
            for (int i = 0; i < parts.size(); i++) {
                ensure(lh);
                cs.setNonStrokingColor(BOX);
                cs.addRect(MARGIN, y - lh, contentWidth(), lh);
                cs.fill();
                y -= lh;
                float base = y;
                y = base + 3; // 글자 기준선을 바탕 안쪽으로
                if (i > 0) draw(mono, size, MUTED, pad, "↳");
                draw(mono, size, c, pad + (i > 0 ? 10 : 0), parts.get(i));
                y = base;
            }
        }

        String ellipsize(PDType0Font f, float size, String s, float max) throws IOException {
            if (width(f, size, s) <= max) return s;
            String t = s;
            while (!t.isEmpty() && width(f, size, t + "…") > max) t = t.substring(0, t.length() - 1);
            return t + "…";
        }

        /** 글자 단위 줄바꿈 (로그·경로처럼 공백 없는 긴 문자열도 잘림 없이) */
        List<String> split(PDType0Font f, float size, String s, float firstWidth, float restWidth) throws IOException {
            List<String> out = new ArrayList<>();
            String text = safe(f, s);
            StringBuilder cur = new StringBuilder();
            float curW = 0, limit = firstWidth;
            int lastSpace = -1;
            for (int i = 0; i < text.length(); ) {
                int cp = text.codePointAt(i);
                String ch = new String(Character.toChars(cp));
                float cw = f.getStringWidth(ch) / 1000f * size;
                if (curW + cw > limit && cur.length() > 0) {
                    // 가능하면 공백에서 끊기 (단, 너무 앞쪽이면 글자 단위)
                    if (lastSpace > cur.length() / 2) {
                        String rest = cur.substring(lastSpace + 1);
                        out.add(cur.substring(0, lastSpace));
                        cur = new StringBuilder(rest);
                        curW = f.getStringWidth(rest) / 1000f * size;
                    } else {
                        out.add(cur.toString());
                        cur = new StringBuilder();
                        curW = 0;
                    }
                    lastSpace = -1;
                    limit = restWidth;
                    continue;
                }
                if (cp == ' ') lastSpace = cur.length();
                cur.append(ch);
                curW += cw;
                i += Character.charCount(cp);
            }
            out.add(cur.toString());
            return out;
        }
    }
}
