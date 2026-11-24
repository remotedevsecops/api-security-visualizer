"""M4 실행: python -m apisec.m4

입력: enriched_endpoints.json(+ findings.json이 있으면 M3 반영)
출력:
  data/report.md       Markdown 리포트(확정 취약점·조치방안 포함)
  data/vuln_views.json  확정 취약점 시각화 데이터(홉 시퀀스 + 차분 매트릭스)
report.html에는 apisec.report가 이 시각화를 탭으로 함께 렌더한다.
"""
from __future__ import annotations

import json

from apisec.common import load_config, rel
from apisec.m4 import build, markdown, sequence
from apisec.report import _attach_m3


def main() -> None:
    cfg = load_config()
    out_dir = rel(cfg, cfg["output_dir"])
    enriched = out_dir / "enriched_endpoints.json"
    base = enriched if enriched.exists() else out_dir / "endpoints.json"
    data = json.loads(base.read_text(encoding="utf-8"))
    _attach_m3(cfg, data["endpoints"])

    findings_meta = None
    f = out_dir / "findings.json"
    if f.exists():
        findings_meta = json.loads(f.read_text(encoding="utf-8")).get("meta")

    summary = build.service_summary(data["endpoints"])
    graph = build.service_graph(cfg, data["endpoints"])  # markdown의 TLS 경고용
    matrix = build.auth_matrix(data["endpoints"])
    seqs = sequence.build_sequences(cfg, data["endpoints"])
    (out_dir / "vuln_views.json").write_text(
        json.dumps({"sequences": seqs, "matrix": matrix}, ensure_ascii=False, indent=2),
        encoding="utf-8")

    md = markdown.generate(data, graph, summary, findings_meta)
    (out_dir / "report.md").write_text(md, encoding="utf-8")

    print(f"[M4] 확정 취약점 시각화: 시퀀스 {len(seqs)}개, 매트릭스 행 {len(matrix)}개")
    print(f"     → {out_dir / 'report.md'}")
    print(f"     → {out_dir / 'vuln_views.json'}")
    print("     report.html 재생성: python -m apisec.report")


if __name__ == "__main__":
    main()
