#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import sys

from scouter_monitor.client import ScouterClient
from scouter_monitor.config import load_config
from scouter_monitor.monitor import ScouterMonitor


def main() -> int:
    parser = argparse.ArgumentParser(description="ScouterAPM 기반 OOM / 응답지연 모니터링 도구")
    parser.add_argument("--config", default="config.yaml", help="설정 파일 경로 (기본: config.yaml)")
    parser.add_argument("--once", action="store_true", help="한 번만 점검하고 종료")
    parser.add_argument("--demo", action="store_true", help="실제 서버 없이 샘플 데이터로 동작 확인")
    parser.add_argument("--verbose", action="store_true", help="디버그 로그 출력")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    cfg = load_config(args.config)

    client = None
    if args.demo:
        from scouter_monitor.mock_client import MockScouterClient
        client = MockScouterClient(cfg.scouter)

    monitor = ScouterMonitor(cfg, client=client or ScouterClient(cfg.scouter))

    if args.once or args.demo:
        monitor.poll_once()
    else:
        monitor.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
