#!/usr/bin/env python3
"""
Export a report_week bundle (see report_store.get_report_bundle) to an
.xlsx workbook laid out and styled like the original weekly-report template:
운영 현황 / 금주 진행 내역 / 차주 진행 내역 / 특이 사항.
"""
from io import BytesIO
from typing import Dict, List, Optional

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

FONT_NAME = "맑은 고딕"

GROUP_FILL  = PatternFill("solid", fgColor="808080")   # 전주/금주/변동사항 그룹 헤더
HEADER_FILL = PatternFill("solid", fgColor="F2F2F2")   # 운영 현황 열 헤더
DATA_FILL   = PatternFill("solid", fgColor="DEEBF7")   # 전주/금주 값 셀
TOTAL_FILL  = PatternFill("solid", fgColor="C5E0B4")   # 총계 / 전체 작업 수량

THIN = Side(style="thin", color="000000")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)

CENTER       = Alignment(horizontal="center", vertical="center", wrap_text=True)
CENTER_NOWRAP = Alignment(horizontal="center", vertical="center", wrap_text=False)
LEFT         = Alignment(horizontal="left", vertical="center", wrap_text=True)
TITLE_ALIGN  = Alignment(horizontal="left", vertical="center", wrap_text=False)

LAST_COL = 14  # sheet uses columns A..N (A is a thin blank spacer column)


def _cell(ws, row: int, col: int, value, *, bold=False, fill=None,
          align=CENTER_NOWRAP, border=True, color="000000", size: int = 11):
    c = ws.cell(row=row, column=col, value=value)
    c.font = Font(name=FONT_NAME, size=size, bold=bold, color=color)
    if fill:
        c.fill = fill
    c.alignment = align
    if border:
        c.border = BORDER
    return c


def _merged(ws, row: int, col1: int, col2: int, value, **kw):
    ws.merge_cells(start_row=row, start_column=col1, end_row=row, end_column=col2)
    cell = _cell(ws, row, col1, value, **kw)
    fill = kw.get("fill")
    for col in range(col1, col2 + 1):
        if kw.get("border", True):
            ws.cell(row=row, column=col).border = BORDER
        if fill:
            ws.cell(row=row, column=col).fill = fill
    return cell


def _row_height_for(text: str) -> float:
    lines = max(1, str(text or "").count("\n") + 1)
    return min(15 * lines + 6, 300)


def _set_column_widths(ws):
    widths = {1: 3.625, 2: 13.375, 3: 23.25, 4: 15.5, 6: 23.375,
              7: 16.25, 8: 15.5, 9: 16.625, 10: 12.625, 12: 11.0, 13: 15.125}
    for col, w in widths.items():
        ws.column_dimensions[get_column_letter(col)].width = w


def _write_operation_status(ws, row: int, ops: List[Dict]) -> int:
    _cell(ws, row, 1, "운영 현황", bold=True, border=False, align=TITLE_ALIGN)
    row += 1

    _merged(ws, row, 3, 6, "전주 운영 현황", bold=True, fill=GROUP_FILL,
            color="FFFFFF", border=False, align=CENTER_NOWRAP)
    _merged(ws, row, 7, 10, "금주 운영 현황", bold=True, fill=GROUP_FILL,
            color="FFFFFF", border=False, align=CENTER_NOWRAP)
    _merged(ws, row, 11, 14, "변동사항", bold=True, fill=GROUP_FILL,
            color="FFFFFF", border=False, align=CENTER_NOWRAP)
    row += 1
    ws.row_dimensions[row].height = 33.0

    _cell(ws, row, 2, "분류", bold=True, fill=HEADER_FILL, align=CENTER)
    for base in (3, 7, 11):
        _cell(ws, row, base, "WEB", bold=True, fill=HEADER_FILL, align=CENTER)
        _cell(ws, row, base + 1, "WAS", bold=True, fill=HEADER_FILL, align=CENTER)
        _cell(ws, row, base + 2, "개발\n(WEB/WAS)", bold=True, fill=HEADER_FILL, align=CENTER)
        _cell(ws, row, base + 3, "Total", bold=True, fill=HEADER_FILL, align=CENTER)
    row += 1

    totals = {"last_web": 0, "last_was": 0, "last_dev": 0,
              "this_web": 0, "this_was": 0, "this_dev": 0}
    for r in ops:
        for k in totals:
            totals[k] += r[k]
        last_total = r["last_web"] + r["last_was"] + r["last_dev"]
        this_total = r["this_web"] + r["this_was"] + r["this_dev"]
        ws.row_dimensions[row].height = 18.0
        _cell(ws, row, 2, r["client_name"], align=CENTER)
        _cell(ws, row, 3, r["last_web"], fill=DATA_FILL)
        _cell(ws, row, 4, r["last_was"], fill=DATA_FILL)
        _cell(ws, row, 5, r["last_dev"], fill=DATA_FILL)
        _cell(ws, row, 6, last_total)
        _cell(ws, row, 7, r["this_web"], fill=DATA_FILL)
        _cell(ws, row, 8, r["this_was"], fill=DATA_FILL)
        _cell(ws, row, 9, r["this_dev"], fill=DATA_FILL)
        _cell(ws, row, 10, this_total)
        _cell(ws, row, 11, r["this_web"] - r["last_web"])
        _cell(ws, row, 12, r["this_was"] - r["last_was"])
        _cell(ws, row, 13, r["this_dev"] - r["last_dev"])
        _cell(ws, row, 14, this_total - last_total)
        row += 1

    if not ops:
        _merged(ws, row, 2, LAST_COL, "등록된 고객사가 없습니다.", align=CENTER)
        row += 1
    else:
        last_grand = totals["last_web"] + totals["last_was"] + totals["last_dev"]
        this_grand = totals["this_web"] + totals["this_was"] + totals["this_dev"]
        ws.row_dimensions[row].height = 18.0
        _cell(ws, row, 2, "총계", bold=True, fill=TOTAL_FILL, align=CENTER)
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
        _cell(ws, row, 14, this_grand - last_grand, bold=True, fill=TOTAL_FILL)
        row += 1

    return row + 1


def _write_work_log(ws, row: int, title: str, start_date: Optional[str],
                     end_date: Optional[str], rows: List[Dict]) -> int:
    label = title + (f" ({start_date}~{end_date})" if start_date and end_date else "")
    _cell(ws, row, 1, label, bold=True, border=False, align=TITLE_ALIGN)
    row += 1

    web_sum = sum(r["web_count"] for r in rows)
    was_sum = sum(r["was_count"] for r in rows)
    etc_sum = sum(r["etc_count"] for r in rows)
    _merged(ws, row, 9, 10, "전체 작업 수량", bold=True, fill=TOTAL_FILL, align=CENTER)
    _cell(ws, row, 11, web_sum, bold=True, fill=TOTAL_FILL)
    _cell(ws, row, 12, was_sum, bold=True, fill=TOTAL_FILL)
    _cell(ws, row, 13, etc_sum, bold=True, fill=TOTAL_FILL)
    row += 1

    _cell(ws, row, 2, "번호", bold=True, align=CENTER_NOWRAP)
    _cell(ws, row, 3, "분류", bold=True, align=CENTER_NOWRAP)
    _cell(ws, row, 4, "요청 일자", bold=True, align=CENTER_NOWRAP)
    _cell(ws, row, 5, "요청자", bold=True, align=CENTER_NOWRAP)
    _cell(ws, row, 6, "작업 일자", bold=True, align=CENTER_NOWRAP)
    _merged(ws, row, 7, 10, "작업 내용", bold=True, align=CENTER_NOWRAP)
    _cell(ws, row, 11, "WEB", bold=True, align=CENTER_NOWRAP)
    _cell(ws, row, 12, "WAS", bold=True, align=CENTER_NOWRAP)
    _cell(ws, row, 13, "기타", bold=True, align=CENTER_NOWRAP)
    row += 1

    for i, r in enumerate(rows, start=1):
        _cell(ws, row, 2, i)
        _cell(ws, row, 3, r["category"], align=CENTER)
        _cell(ws, row, 4, r["request_date"], align=CENTER)
        _cell(ws, row, 5, r["requester"], align=CENTER)
        _cell(ws, row, 6, r["work_date"], align=CENTER)
        _merged(ws, row, 7, 10, r["work_content"], align=LEFT)
        _cell(ws, row, 11, r["web_count"], align=CENTER)
        _cell(ws, row, 12, r["was_count"], align=CENTER)
        _cell(ws, row, 13, r["etc_count"], align=CENTER)
        ws.row_dimensions[row].height = _row_height_for(r["work_content"])
        row += 1

    if not rows:
        _merged(ws, row, 2, LAST_COL, "등록된 작업 이력이 없습니다.", align=CENTER)
        row += 1

    return row + 1


def _write_special_notes(ws, row: int, rows: List[Dict]) -> int:
    _cell(ws, row, 1, "특이 사항", bold=True, border=False, align=TITLE_ALIGN)
    row += 1

    _cell(ws, row, 2, "번호", bold=True, align=CENTER_NOWRAP)
    _cell(ws, row, 3, "분류", bold=True, align=CENTER_NOWRAP)
    _cell(ws, row, 4, "일자", bold=True, align=CENTER_NOWRAP)
    _cell(ws, row, 5, "내용", bold=True, align=CENTER_NOWRAP)
    _cell(ws, row, 6, "서비스", bold=True, align=CENTER_NOWRAP)
    _merged(ws, row, 7, 10, "상세 내용", bold=True, align=CENTER_NOWRAP)
    row += 1

    for i, r in enumerate(rows, start=1):
        _cell(ws, row, 2, i)
        _cell(ws, row, 3, r["category"], align=CENTER)
        _cell(ws, row, 4, r["note_date"], align=CENTER)
        _cell(ws, row, 5, r["title"], align=CENTER)
        _cell(ws, row, 6, r["service_name"], align=CENTER)
        _merged(ws, row, 7, 10, r["detail"], align=LEFT)
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
    ws.sheet_format.defaultRowHeight = 16.5
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
