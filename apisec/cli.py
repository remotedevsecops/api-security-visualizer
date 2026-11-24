"""apisec — API 보안 가시화 툴킷 단일 CLI.

파이프라인을 하위 명령으로 묶는다. 각 단계는 독립 실행도 가능(python -m apisec.mN).

  apisec scan      M1 탐지 + M2 PII (+ 리포트)     → endpoints/enriched/report
  apisec verify    M3 가드레일 BOLA 검증            → findings, audit.log
  apisec report    M4 Markdown + 서비스맵 + report.html
  apisec all       scan → verify → report 일괄
  apisec capture   정상 트래픽 캡처(scripts/capture.sh 안내)

대상 교체는 config.yaml 하나로. 새 대상/프레임워크/게이트웨이는 adapters.md 참고.
"""
from __future__ import annotations

import argparse
import runpy
import sys
from pathlib import Path


def _run_module(mod: str, argv: list[str]) -> None:
    sys.argv = [mod, *argv]
    runpy.run_module(mod, run_name="__main__", alter_sys=True)


def cmd_scan(args) -> None:
    extra = ["--config", args.config] if args.config else []
    _run_module("apisec.m1", extra + (["--no-traffic"] if args.no_traffic else []))
    m2 = extra + (["--llm"] if args.llm else [])
    _run_module("apisec.m2", m2)
    if not args.no_report:
        _run_module("apisec.report", [])


def cmd_verify(args) -> None:
    extra = ["--config", args.config] if args.config else []
    _run_module("apisec.m3", extra + (["--dry-run"] if args.dry_run else []))


def cmd_report(args) -> None:
    _run_module("apisec.m4", [])
    _run_module("apisec.report", [])


def cmd_all(args) -> None:
    cmd_scan(args)
    cmd_verify(args)
    cmd_report(args)


def cmd_capture(args) -> None:
    sh = Path(__file__).resolve().parent.parent / "scripts" / "capture.sh"
    print(f"정상 트래픽 캡처는 아래를 실행하세요 (mitmproxy 리버스 프록시):\n  {sh}")
    print("완료 후: apisec scan")


def main() -> None:
    p = argparse.ArgumentParser(prog="apisec", description="API 보안 가시화 툴킷")
    p.add_argument("--config", help="config.yaml 경로")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="M1 탐지 + M2 PII")
    s.add_argument("--no-traffic", action="store_true")
    s.add_argument("--llm", action="store_true")
    s.add_argument("--no-report", action="store_true")
    s.set_defaults(func=cmd_scan)

    v = sub.add_parser("verify", help="M3 가드레일 BOLA 검증 (로컬 대상 전용)")
    v.add_argument("--dry-run", action="store_true")
    v.set_defaults(func=cmd_verify)

    r = sub.add_parser("report", help="M4 리포트 + 서비스맵 + report.html")
    r.set_defaults(func=cmd_report)

    a = sub.add_parser("all", help="scan → verify → report 일괄")
    a.add_argument("--no-traffic", action="store_true")
    a.add_argument("--llm", action="store_true")
    a.add_argument("--dry-run", action="store_true")
    a.add_argument("--no-report", action="store_true")
    a.set_defaults(func=cmd_all)

    c = sub.add_parser("capture", help="정상 트래픽 캡처 안내")
    c.set_defaults(func=cmd_capture)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
