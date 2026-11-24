"""M1 실행: python -m apisec.m1 [--config config.yaml] [--no-traffic]

출력: data/endpoints.json, data/attack_surface.html
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone

from apisec.common import load_config, rel
from apisec.m1 import code, codeql, gateway, merge, render, spec, traffic


def main() -> None:
    ap = argparse.ArgumentParser(description="M1: API 탐지와 공격면 지도")
    ap.add_argument("--config")
    ap.add_argument("--no-traffic", action="store_true", help="트래픽 출처 생략")
    args = ap.parse_args()
    cfg = load_config(args.config)

    code_routes = code.collect(cfg)
    spec_ops = spec.collect(cfg)
    locs = gateway.collect(cfg)
    templates = [(r["method"], r["path"]) for r in code_routes] + [(s["method"], s["path"]) for s in spec_ops]
    traffic_eps = [] if args.no_traffic else traffic.collect(cfg, templates)

    endpoints = merge.merge(cfg, code_routes, spec_ops, locs, traffic_eps)

    # CodeQL taint 결과(있으면)를 합친다. Java(식별자→repo 조회)와 Python(무인증→ORM→PII 직렬화) 둘 다.
    tainted = 0
    for sarif in ("codeql-bola.sarif", "codeql-bola-py.sarif"):
        tainted += codeql.attach(cfg, endpoints, sarif_name=sarif)
    # Java는 getter 체인으로 PII가 끊기므로, 응답 PII 단계를 구조 쿼리 결과로 흐름 끝에 덧붙임
    pii_steps = codeql.attach_pii_sink(cfg, endpoints, "codeql-pii-java.sarif")
    if tainted:
        print(f"[codeql] taint 경로로 확정된 흐름: {tainted}건 (TAINT_BOLA), 응답 PII 단계 +{pii_steps}")

    out_dir = rel(cfg, cfg["output_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": cfg["target"]["base_url"],
        "source_counts": {"code": len(code_routes), "spec": len(spec_ops),
                          "gateway_locations": len(locs), "traffic": len(traffic_eps)},
        "gateway_locations": locs,
    }
    (out_dir / "endpoints.json").write_text(
        json.dumps({"meta": meta, "endpoints": endpoints}, ensure_ascii=False, indent=2, default=list),
        encoding="utf-8")
    html = render.render(meta, endpoints)
    (out_dir / "attack_surface.html").write_text(html, encoding="utf-8")

    lc = Counter(e["lifecycle"] for e in endpoints)
    fl = Counter(f for e in endpoints for f in e["flags"])
    print(f"\n[M1] endpoints={len(endpoints)}")
    print("     lifecycle:", dict(lc.most_common()))
    print("     flags    :", dict(fl.most_common()))
    print(f"     → {out_dir / 'endpoints.json'}")
    print(f"     → {out_dir / 'attack_surface.html'}")


if __name__ == "__main__":
    main()
