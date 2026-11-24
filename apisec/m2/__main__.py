"""M2 실행: python -m apisec.m2 [--config config.yaml] [--llm]

입력: data/endpoints.json (M1), data/traffic.har (샘플 응답)
출력: data/enriched_endpoints.json  (+ M1 HTML에 PII 열이 추가로 렌더됨)

M1의 각 엔드포인트에 PII finding과 민감도/위험도를 붙인다.
무인증(NO_AUTH)인데 PII를 흘리면 risk를 critical로 승격.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlsplit

from apisec.common import canon, key, load_config, rel, template_regex
from apisec.m2 import detect
from apisec.m2 import llm as llm_mod


def _samples_by_endpoint(cfg, endpoints) -> dict[tuple[str, str], list[dict]]:
    """HAR의 응답을 M1 엔드포인트 템플릿에 매핑해 샘플로 모은다."""
    har_path = rel(cfg, cfg["sources"]["traffic_har"])
    if not har_path.exists():
        return {}
    entries = json.loads(har_path.read_text(encoding="utf-8"))["log"]["entries"]
    templates = sorted(
        ((e["method"], e["path"], template_regex(e["path"])) for e in endpoints if "{*}" not in e["path"]),
        key=lambda x: (x[1].count("{"), -len(x[1])),
    )
    out: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for e in entries:
        req, res = e["request"], e["response"]
        method = req["method"].upper()
        path = canon(urlsplit(req["url"]).path or "/")
        body = res.get("content", {}).get("text", "")
        if not body:
            continue
        for m, t, rx in templates:
            if (m == method or m == "ANY") and rx.match(path):
                k = key(m, t)
                if len(out[k]) < 3:
                    headers = {h["name"].lower(): h["value"] for h in req.get("headers", [])}
                    out[k].append({
                        "status": res["status"],
                        "had_auth": bool(headers.get("authorization")),
                        "body": body,
                    })
                break
    return out


def _risk(sensitivity: float, no_auth: bool, has_pii: bool) -> str:
    if not has_pii:
        return "none"
    if no_auth:
        return "critical"
    if sensitivity >= 8:
        return "high"
    if sensitivity >= 4:
        return "medium"
    return "low"


def main() -> None:
    ap = argparse.ArgumentParser(description="M2: 개인정보 흐름 탐지")
    ap.add_argument("--config")
    ap.add_argument("--llm", action="store_true", help="정규식으로 애매한 필드를 LLM으로 2차 판정")
    args = ap.parse_args()
    cfg = load_config(args.config)

    data = json.loads(rel(cfg, cfg["output_dir"] + "/endpoints.json").read_text(encoding="utf-8"))
    endpoints = data["endpoints"]
    samples = _samples_by_endpoint(cfg, endpoints)

    llm = llm_mod.get_adapter(cfg) if args.llm else None
    llm_calls = 0

    for e in endpoints:
        k = tuple(key(e["method"], e["path"]))
        ss = samples.get(k, [])
        findings: dict[tuple[str, str], dict] = {}
        for s in ss:
            for f in detect.detect(s["body"]):
                findings[(f["field"], f["type"])] = f
        flist = list(findings.values())

        # LLM 2차: 값 기반에서 못 잡았지만 field-name 힌트만 있는 애매한 필드
        if llm and ss:
            ambiguous = [f for f in flist if f["detector"] == "field-name"]
            if ambiguous:
                verdicts = llm.classify(e["method"], e["path"], ambiguous, ss[0]["body"])
                llm_calls += 1
                for f in flist:
                    v = verdicts.get(f["field"])
                    if v:
                        f["llm"] = v

        sensitivity = round(sum(f["weight"] for f in flist), 1)
        no_auth = "NO_AUTH" in e["flags"]
        risk = _risk(sensitivity, no_auth, bool(flist))
        e["pii_findings"] = flist
        e["sensitivity"] = sensitivity
        e["risk"] = risk
        e["sampled"] = len(ss)
        if risk == "critical":
            e["notes"].append("무인증 노출 + 개인정보 → critical")
        if flist and "PII_EXPOSURE" not in e["flags"]:
            e["flags"].append("PII_EXPOSURE")
            e["flags"].sort()

    data["meta"]["m2"] = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "llm": bool(llm), "llm_calls": llm_calls,
        "sampled_endpoints": sum(1 for e in endpoints if e["sampled"]),
    }
    out = rel(cfg, cfg["output_dir"] + "/enriched_endpoints.json")
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=list), encoding="utf-8")

    from collections import Counter
    rc = Counter(e["risk"] for e in endpoints)
    pii = sum(1 for e in endpoints if e["pii_findings"])
    print(f"[M2] PII 노출 엔드포인트={pii} (샘플 응답 있는 것 {data['meta']['m2']['sampled_endpoints']}개 중)")
    print(f"     risk: {dict(rc.most_common())}")
    if llm:
        print(f"     LLM 호출: {llm_calls}회")
    print("     상위 민감도:")
    for e in sorted(endpoints, key=lambda e: -e["sensitivity"])[:8]:
        if e["sensitivity"]:
            types = ",".join(sorted({f['type'] for f in e['pii_findings']}))
            print(f"       {e['risk']:<8} {e['sensitivity']:>4}  {e['method']:<5} {e['path'][:48]:<48} {types}")
    print(f"     → {out}")


if __name__ == "__main__":
    main()
