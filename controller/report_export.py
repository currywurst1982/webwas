#!/usr/bin/env python3
"""
Export a report_week bundle (see report_store.get_report_bundle) to an
.xlsx workbook laid out like the original weekly-report template:
운영 현황 / 금주 진행 내역 / 차주 진행 내역 / 특이 사항.
"""
from io import BytesIO
from typing import Dict, List, Optional

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

TITLE_FILL  = PatternFill("solid", fgColor="305496")
HEADER_FILL = PatternFill("solid", fgColor="DDEBF7")
TOTAL_FILL  = PatternFill("solid", fgColor="F2F2F2")
THIN   = Side(style="thin", color="999999")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
CENTER = Alignment(horizontal="center", vertical="center", wrap_text=True)
LEFT   = Alignment(horizontal="left", vertical="center", wrap_text=True)

LAST_COL = 13  # sheet uses columns A..M (A left blank, matching the source template)


def _cell(ws, row: int, col: int, value, *, bold=False, fill=None,
          align=CENTER, font_color: Optional[str] = None, size: int = 11):
    c = ws.cell(row=row, column=col, value=value)
    c.font = Font(bold=bold, color=font_color, size=size)
    if fill:
        c.fill = fill
    c.alignment = align
    c.border = BORDER
    return c


def _merged(ws, row: int, col1: int, col2: int, value, **kw):
    ws.merge_cells(start_row=row, start_column=col1, end_row=row, end_column=col2)
    cell = _cell(ws, row, col1, value, **kw)
    # apply the border to every cell spanned by the merge so gridlines show up
    for col in range(col1, col2 + 1):
        ws.cell(row=row, column=col).border = BORDER
    return cell


def _row_height_for(text: str) -> float:
    lines = max(1, str(text or "").count("\n") + 1)
    return min(15 * lines + 6, 300)


def _set_column_widths(ws):
    widths = {1: 3, 2: 12, 3: 16, 4: 11, 5: 6, 6: 6, 7: 6, 8: 8,
              9: 6, 10: 6, 11: 6, 12: 6, 13: 8}
    for col, w in widths.items():
        ws.column_dimensions[get_column_letter(col)].width = w


def _write_operation_status(ws, row: int, ops: List[Dict]) -> int:
    _merged(ws, row, 1, LAST_COL, "운영 현황", bold=True, fill=TITLE_FILL,
            font_color="FFFFFF", size=13, align=LEFT)
    row += 1

    _merged(ws, row, 3, 6, "전주 운영 현황", bold=True, fill=HEADER_FILL)
    _merged(ws, row, 7, 10, "금주 운영 현황", bold=True, fill=HEADER_FILL)
    _merged(ws, row, 11, 13, "변동사항", bold=True, fill=HEADER_FILL)
    row += 1

    _cell(ws, row, 2, "분류", bold=True, fill=HEADER_FILL)
    for base in (3, 7, 11):
        _cell(ws, row, base, "WEB", bold=True, fill=HEADER_FILL)
        _cell(ws, row, base + 1, "WAS", bold=True, fill=HEADER_FILL)
        _cell(ws, row, base + 2, "개발", bold=True, fill=HEADER_FILL)
        _cell(ws, row, base + 3, "Total", bold=True, fill=HEADER_FILL)
    row += 1

    totals = {"last_web": 0, "last_was": 0, "last_dev": 0,
              "this_web": 0, "this_was": 0, "this_dev": 0}
    for r in ops:
        for k in totals:
            totals[k] += r[k]
        last_total = r["last_web"] + r["last_was"] + r["last_dev"]
        this_total = r["this_web"] + r["this_was"] + r["this_dev"]
        _cell(ws, row, 2, r["client_name"], align=LEFT)
        _cell(ws, row, 3, r["last_web"]); _cell(ws, row, 4, r["last_was"])
        _cell(ws, row, 5, r["last_dev"]); _cell(ws, row, 6, last_total)
        _cell(ws, row, 7, r["this_web"]); _cell(ws, row, 8, r["this_was"])
        _cell(ws, row, 9, r["this_dev"]); _cell(ws, row, 10, this_total)
        _cell(ws, row, 11, r["this_web"] - r["last_web"])
        _cell(ws, row, 12, r["this_was"] - r["last_was"])
        _cell(ws, row, 13, r["this_dev"] - r["last_dev"])
        row += 1

    if not ops:
        _merged(ws, row, 2, LAST_COL, "등록된 고객사가 없습니다.", align=CENTER)
        row += 1
    else:
        last_grand = totals["last_web"] + totals["last_was"] + totals["last_dev"]
        this_grand = totals["this_web"] + totals["this_was"] + totals["this_dev"]
        _cell(ws, row, 2, "총계", bold=True, fill=TOTAL_FILL, align=LEFT)
        _cell(ws, row, 3, totals["last_web"], bold=True, fill=TOTAL_FILL)
        _cell(ws, row, 4, totals["last_was"], bold=True, fill=TOTAL_FILL)
        _cell(ws, row, 5, totals["last_dev"], bold=True, fill=TOTAL_FILL)
        _cell(ws, row, 6, last_grand, bold=True, fill=TOTAL_FILL)
        _cell(ws, row, 7, totals["this_web"], bold=True, fill=TOTAL_FILL)
        _cell(ws, row, 8, totals["this_was"], bold=True, fill=TOTAL_FILL)
        _cell(ws, row, 9, totals["this_dev"], bold=True, fill=TOTAL_FILL)
        _cell(ws, row, 10, this_grand, bold=True, fill=TOTAL_FILL)
        _cell(ws, row, 11, totals["this_web"] - totals["last_web"], bold=True, fill=TOTAL_FILL)
        _cell(ws, row, 12, totals["this_was"] - totals["last_was"], bold=True, fill=TOTAL_FILL)
        _cell(ws, row, 13, totals["this_dev"] - totals["last_dev"], bold=True, fill=TOTAL_FILL)
        row += 1

    return row + 1


def _write_work_log(ws, row: int, title: str, start_date: Optional[str],
                     end_date: Optional[str], rows: List[Dict]) -> int:
    label = title + (f" ({start_date}~{end_date})" if start_date and end_date else "")
    _merged(ws, row, 1, LAST_COL, label, bold=True, fill=TITLE_FILL,
            font_color="FFFFFF", size=12, align=LEFT)
    row += 1

    web_sum = sum(r["web_count"] for r in rows)
    was_sum = sum(r["was_count"] for r in rows)
    etc_sum = sum(r["etc_count"] for r in rows)
    _merged(ws, row, 9, LAST_COL,
            f"전체 작업 수량   WEB {web_sum} / WAS {was_sum} / 기타 {etc_sum}",
            bold=True, align=LEFT)
    row += 1

    _cell(ws, row, 2, "번호", bold=True, fill=HEADER_FILL)
    _cell(ws, row, 3, "분류", bold=True, fill=HEADER_FILL)
    _cell(ws, row, 4, "요청 일자", bold=True, fill=HEADER_FILL)
    _cell(ws, row, 5, "요청자", bold=True, fill=HEADER_FILL)
    _cell(ws, row, 6, "작업 일자", bold=True, fill=HEADER_FILL)
    _merged(ws, row, 7, 10, "작업 내용", bold=True, fill=HEADER_FILL)
    _cell(ws, row, 11, "WEB", bold=True, fill=HEADER_FILL)
    _cell(ws, row, 12, "WAS", bold=True, fill=HEADER_FILL)
    _cell(ws, row, 13, "기타", bold=True, fill=HEADER_FILL)
    row += 1

    for i, r in enumerate(rows, start=1):
        _cell(ws, row, 2, i)
        _cell(ws, row, 3, r["category"], align=LEFT)
        _cell(ws, row, 4, r["request_date"])
        _cell(ws, row, 5, r["requester"])
        _cell(ws, row, 6, r["work_date"])
        _merged(ws, row, 7, 10, r["work_content"], align=LEFT)
        _cell(ws, row, 11, r["web_count"])
        _cell(ws, row, 12, r["was_count"])
        _cell(ws, row, 13, r["etc_count"])
        ws.row_dimensions[row].height = _row_height_for(r["work_content"])
        row += 1

    if not rows:
        _merged(ws, row, 2, LAST_COL, "등록된 작업 이력이 없습니다.", align=CENTER)
        row += 1

    return row + 1


def _write_special_notes(ws, row: int, rows: List[Dict]) -> int:
    _merged(ws, row, 1, LAST_COL, "특이 사항", bold=True, fill=TITLE_FILL,
            font_color="FFFFFF", size=12, align=LEFT)
    row += 1

    _cell(ws, row, 2, "번호", bold=True, fill=HEADER_FILL)
    _cell(ws, row, 3, "분류", bold=True, fill=HEADER_FILL)
    _cell(ws, row, 4, "일자", bold=True, fill=HEADER_FILL)
    _cell(ws, row, 5, "내용", bold=True, fill=HEADER_FILL)
    _cell(ws, row, 6, "서비스", bold=True, fill=HEADER_FILL)
    _merged(ws, row, 7, LAST_COL, "상세 내용", bold=True, fill=HEADER_FILL)
    row += 1

    for i, r in enumerate(rows, start=1):
        _cell(ws, row, 2, i)
        _cell(ws, row, 3, r["category"], align=LEFT)
        _cell(ws, row, 4, r["note_date"])
        _cell(ws, row, 5, r["title"], align=LEFT)
        _cell(ws, row, 6, r["service_name"], align=LEFT)
        _merged(ws, row, 7, LAST_COL, r["detail"], align=LEFT)
        ws.row_dimensions[row].height = _row_height_for(r["detail"])
        row += 1

    if not rows:
        _merged(ws, row, 2, LAST_COL, "등록된 특이 사항이 없습니다.", align=CENTER)
        row += 1

    return row


def build_workbook(bundle: Dict) -> BytesIO:
    week = bundle["week"]
    wb = Workbook()
    ws = wb.active
    ws.title = "운영보고서"
    _set_column_widths(ws)

    row = _write_operation_status(ws, 1, bundle["operation_status"])
    row = _write_work_log(ws, row, "금주 진행 내역", week["start_date"], week["end_date"],
                           bundle["work_log_current"])
    row = _write_work_log(ws, row, "차주 진행 내역", week.get("next_start_date"),
                           week.get("next_end_date"), bundle["work_log_next"])
    _write_special_notes(ws, row, bundle["special_notes"])

    buf = BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf
