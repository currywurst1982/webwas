#!/usr/bin/env python3
"""
KISA 보호나라(boho.or.kr) "보안공지" 게시판을 확인하여 Apache/Tomcat/
WildFly(JBoss)/Nginx 관련 보안 업데이트 권고를 찾아 security_store에
저장한다.

게시판 전체를 페이지 순서대로 넘겨보는 대신, 게시판 자체의 검색 기능
(searchWrd=)을 제품 키워드별로 사용해서 "최근 N페이지"가 아니라
해당 키워드가 들어간 글 전체를 SCAN_SINCE_DATE 기준일까지 확인한다.
이미 저장된 글만 연속으로 나오거나, 기준일보다 오래된 글을 만나면
그 키워드는 더 이상 과거로 내려가지 않고 멈춘다 (최초 실행 시에는
기준일까지 내려가서 그 사이 과거 글을 전부 수집하고, 이후 매일
실행에서는 새 글이 있는 앞쪽 몇 페이지만 확인하게 된다).

이 모듈은 동기(blocking) 방식이다 — controller.py에서
asyncio.to_thread(run_check)로 호출해 이벤트 루프를 막지 않는다.

주의: boho.or.kr의 실제 게시판 HTML 마크업과 검색 파라미터(searchCnd 값의
의미 등)는 예고 없이 바뀔 수 있다. 이 파서는 "제목에 nttId가 담긴 링크가
있고, 같은 행에 날짜 형식의 셀이 있다"는 일반적인 게시판 구조만 가정하는
방어적인 방식으로 작성했다. 실제 운영 서버에서 최초 실행 후 결과가 비어
있거나 예상보다 훨씬 적다면 페이지/검색 구조가 달라진 것이므로 재확인이
필요하다.
"""
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from bs4 import BeautifulSoup

import security_store

logger = logging.getLogger("wildfly-controller.security_scan")

BASE = "https://www.boho.or.kr"
BBS_ID = "B0000133"       # 알림마당 > 보안공지
MENU_NO = "205020"
LIST_SEARCH_URL = (
    f"{BASE}/kr/bbs/list.do?bbsId={BBS_ID}&menuNo={MENU_NO}"
    f"&searchCnd=1&searchWrd={{keyword}}&pageIndex={{page}}"
)
VIEW_URL = f"{BASE}/kr/bbs/view.do?bbsId={BBS_ID}&menuNo={MENU_NO}&nttId={{ntt_id}}"

# 게시판 검색창에 넣을 키워드. KISA는 제품별 정확한 이름으로 공지를
# 올리기 때문에("Apache HTTP Server 보안 업데이트 권고", "NGINX Open
# Source 보안 업데이트 권고" 등), 짧은 "Apache"/"Nginx"보다 이 정확한
# 이름으로 검색해야 관련 없는 다른 Apache/Nginx 계열 프로젝트 공지가
# 섞이지 않는다.
SEARCH_KEYWORDS = ["Apache HTTP Server", "Tomcat", "WildFly", "JBoss", "NGINX Open Source"]

MAX_PAGES_PER_KEYWORD = 30   # 안전판: 검색 결과가 끝없이 나올 경우의 상한
STOP_AFTER_EMPTY_PAGES = 2   # 이미 다 아는 글만 연속 이 페이지 수만큼 나오면 중단
SCAN_SINCE_DATE = "2026-01-01"  # 이 날짜보다 오래된 공지는 수집/표시하지 않는다

REQUEST_TIMEOUT = 15
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# 순서 중요: 더 구체적인 제품을 먼저 매칭해서 "Apache Tomcat" 같은 글이
# apache(httpd)로 잘못 분류되지 않도록 한다.
PRODUCT_RULES = [
    ("tomcat",  re.compile(r"tomcat|톰캣", re.I)),
    ("wildfly", re.compile(r"wildfly|jboss|와일드플라이|제이보스", re.I)),
    ("nginx",   re.compile(r"nginx|엔진[\s-]?[xX엑]", re.I)),
    ("apache",  re.compile(r"apache|아파치", re.I)),
]
# "Apache Struts", "Apache Log4j" 처럼 httpd가 아닌 다른 Apache 프로젝트를
# 다루는 글은 apache(웹서버) 항목으로 잡히지 않도록 제외한다 (제목 기준).
APACHE_EXCLUDE = re.compile(
    r"struts|log4j|commons|kafka|solr|activemq|camel|airflow|superset|"
    r"james|ivy|maven|ant|cxf|karaf|shiro|ofbiz|nifi|"
    r"스트럿츠|커먼즈|카프카", re.I)

PRODUCT_LABELS = {
    "apache":  "Apache HTTP Server",
    "tomcat":  "Apache Tomcat",
    "wildfly": "WildFly / JBoss",
    "nginx":   "NGINX Open Source",
}

# KISA는 여러 제품을 한 번에 묶어 다루는 "번들형" 공지(예: OOO 리눅스
# 배포판 보안 업데이트 권고)도 올리는데, 게시판 검색이 제목뿐 아니라
# 본문까지 대상으로 해서 이런 글도 검색 결과에 걸려 나온다. 제목만으로는
# 걸러지지 않으므로, 상세 본문에 실제로 이 정확한 제품명이 있는지
# 확인한 뒤에만 저장한다 (제목이 아니라 "내용"을 기준으로 확정).
CONTENT_CONFIRM = {
    "apache":  re.compile(r"apache\s*http\s*server", re.I),
    "tomcat":  re.compile(r"tomcat", re.I),
    "wildfly": re.compile(r"wildfly|jboss", re.I),
    "nginx":   re.compile(r"nginx\s*open\s*source", re.I),
}

VERSION_RE = re.compile(
    r"(\d+(?:\.\d+){1,3})\s*(?:버전)?\s*(?:\s*이상|\s*이후|\s*또는\s*상위)")


def classify_product(title: str) -> Optional[str]:
    for product, pattern in PRODUCT_RULES:
        if not pattern.search(title):
            continue
        if product == "apache" and APACHE_EXCLUDE.search(title):
            return None
        return product
    return None


def _fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept-Language": "ko-KR,ko;q=0.9",
    })
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        raw = resp.read()
        charset = resp.headers.get_content_charset() or "utf-8"
        try:
            return raw.decode(charset, errors="replace")
        except LookupError:
            return raw.decode("utf-8", errors="replace")


def _list_candidates(keyword: str, page: int) -> List[Dict]:
    url = LIST_SEARCH_URL.format(keyword=urllib.parse.quote(keyword), page=page)
    html = _fetch(url)
    soup = BeautifulSoup(html, "html.parser")

    seen_ntt_ids = set()
    candidates = []
    for a in soup.select("a[href*='nttId=']"):
        href = a.get("href", "")
        m = re.search(r"nttId=(\d+)", href)
        if not m:
            continue
        ntt_id = m.group(1)
        if ntt_id in seen_ntt_ids:
            continue
        title = a.get_text(strip=True)
        if not title:
            continue

        product = classify_product(title)
        if not product:
            continue

        posted_date = None
        row = a.find_parent("tr")
        if row is not None:
            for td in row.find_all("td"):
                text = td.get_text(strip=True)
                if re.match(r"^\d{4}[.\-]\d{2}[.\-]\d{2}$", text):
                    posted_date = text.replace(".", "-")
                    break

        seen_ntt_ids.add(ntt_id)
        candidates.append({
            "ntt_id": ntt_id, "title": title, "product": product,
            "posted_date": posted_date,
        })
    return candidates


def _detail_text(detail_html: str) -> str:
    soup = BeautifulSoup(detail_html, "html.parser")
    text = soup.get_text(" ", strip=True)
    return re.sub(r"\s+", " ", text)


def _extract_recommendation(text: str, product: str) -> Tuple[Optional[str], Optional[str]]:
    """detail 페이지 본문 텍스트에서 product 키워드 주변 문장과, 그 문장에서
    'X.Y.Z 이상' 형태의 최소 권장 버전을 뽑아낸다. 못 찾으면 (None, None)."""
    product_pattern = dict(PRODUCT_RULES)[product]
    sentences = re.split(r"(?<=[.!?])\s+|\n", text)

    best_sentence = None
    best_version = None
    for sentence in sentences:
        if not product_pattern.search(sentence):
            continue
        version_match = VERSION_RE.search(sentence)
        if version_match:
            best_sentence = sentence.strip()
            best_version = version_match.group(1)
            break
        if best_sentence is None:
            best_sentence = sentence.strip()

    if best_sentence and len(best_sentence) > 300:
        best_sentence = best_sentence[:300] + "…"
    return best_sentence, best_version


def run_check() -> Dict:
    """전체 확인 사이클을 한 번 실행한다. 결과 요약 dict를 반환한다."""
    security_store.init_db()
    known_ntt_ids = {n["ntt_id"] for n in security_store.list_notices()}
    seen_this_run = set()
    found = 0
    new_count = 0
    errors: List[str] = []

    for keyword in SEARCH_KEYWORDS:
        empty_streak = 0
        for page in range(1, MAX_PAGES_PER_KEYWORD + 1):
            try:
                candidates = _list_candidates(keyword, page)
            except (urllib.error.URLError, TimeoutError) as e:
                errors.append(f"'{keyword}' 검색 {page}페이지 조회 실패: {e}")
                break

            if not candidates:
                break  # 검색 결과의 끝

            page_has_new = False
            hit_cutoff = False
            for c in candidates:
                if c["posted_date"] and c["posted_date"] < SCAN_SINCE_DATE:
                    # 게시판은 최신순 정렬이므로, 기준일보다 오래된 글을
                    # 만나면 이 키워드는 더 과거로 내려갈 필요가 없다.
                    hit_cutoff = True
                    continue

                if c["ntt_id"] in seen_this_run:
                    continue  # 다른 키워드 검색에서 이미 처리한 글
                seen_this_run.add(c["ntt_id"])

                try:
                    detail_text = _detail_text(_fetch(VIEW_URL.format(ntt_id=c["ntt_id"])))
                except (urllib.error.URLError, TimeoutError) as e:
                    errors.append(f"nttId={c['ntt_id']} 상세 조회 실패: {e}")
                    continue

                confirm = CONTENT_CONFIRM.get(c["product"])
                if confirm and not confirm.search(detail_text):
                    # 본문에서 정확한 제품명을 확인하지 못함 -> 여러 제품을
                    # 묶어 다루는 번들형 공지 등으로 보고 저장하지 않는다.
                    continue

                found += 1
                if c["ntt_id"] not in known_ntt_ids:
                    page_has_new = True

                recommendation, min_version = _extract_recommendation(detail_text, c["product"])

                is_new = security_store.upsert_notice(
                    ntt_id=c["ntt_id"],
                    product=c["product"],
                    title=c["title"],
                    posted_date=c["posted_date"],
                    recommendation=recommendation,
                    min_version=min_version,
                    url=VIEW_URL.format(ntt_id=c["ntt_id"]),
                )
                if is_new:
                    new_count += 1
                    known_ntt_ids.add(c["ntt_id"])

            if hit_cutoff:
                break  # 기준일 이전 -> 이 키워드는 여기서 중단

            if page_has_new:
                empty_streak = 0
            else:
                empty_streak += 1
                if empty_streak >= STOP_AFTER_EMPTY_PAGES:
                    break  # 이미 다 아는 글만 계속 나옴 -> 더 과거로 갈 필요 없음

    security_store.set_meta("last_checked_at", datetime.now().isoformat())
    security_store.set_meta("last_error", "; ".join(errors) if errors else "")
    security_store.set_meta("last_scanned_count", str(found))

    summary = {"scanned": found, "new": new_count, "errors": errors}
    logger.info("security_scan: scanned=%d new=%d errors=%d", found, new_count, len(errors))
    return summary


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(run_check())
