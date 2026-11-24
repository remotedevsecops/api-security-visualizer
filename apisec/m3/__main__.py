"""M3 실행: python -m apisec.m3 [--config config.yaml] [--dry-run]

입력: enriched_endpoints.json(M1/M2), config.m3
출력: data/findings.json, data/audit.log

흐름:
  1) 가드레일 구성 (스코프/행위/레이트/드라이런)
  2) A·B 로그인 → 토큰 확보 (로그인은 가드 통과: POST는 로그인 전용으로 예외 허용)
  3) 각 사용자의 객체 ID 수집 (차량 UUID, 주문 ID)
  4) M1/M2의 BOLA 후보 + 수집한 객체로 검증 케이스 생성
  5) 차분 테스트 실행 → findings.json
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

import httpx

from apisec.common import load_config, rel
from apisec.m3 import bola
from apisec.m3.guardrails import Guardrails
from apisec.m3.runner import GuardedRunner


def _login(base: str, user: dict) -> str | None:
    r = httpx.post(f"{base}/identity/api/auth/login",
                   json={"email": user["email"], "password": user["password"]}, timeout=15)
    return r.json().get("token") if r.status_code == 200 else None


def _collect_objects(base: str, token: str) -> dict[str, list[str]]:
    """소유자 토큰으로 자기 객체 ID 수집 (정상 사용 범위)."""
    h = {"Authorization": f"Bearer {token}"}
    out: dict[str, list[str]] = {"vehicle": [], "order": [], "service_request": []}
    v = httpx.get(f"{base}/identity/api/v2/vehicle/vehicles", headers=h, timeout=15)
    if v.status_code == 200:
        out["vehicle"] = [x["uuid"] for x in v.json() if x.get("uuid")]
    o = httpx.get(f"{base}/workshop/api/shop/orders/all", headers=h, timeout=15)
    if o.status_code == 200:
        out["order"] = [str(x["id"]) for x in o.json().get("orders", []) if x.get("id")]
    # mechanic service_request는 seed 데이터(타인 소유). ID를 1..N 순회로 탐침해 수집
    # — 이 '순회로 남의 객체가 보이는 것' 자체가 BOLA의 증거다.
    for i in range(1, 6):
        r = httpx.get(f"{base}/workshop/api/mechanic/service_request/{i}", headers=h, timeout=15)
        if r.status_code == 200 and '"owner"' in r.text:
            out["service_request"].append(str(i))
    return out


# 검증할 BOLA 템플릿 (읽기). M1/M2/CodeQL이 지목한 것 중 객체 매핑이 명확한 것.
TEMPLATES = [
    ("vehicle-location", "GET", "/identity/api/v2/vehicle/{obj}/location", "vehicle"),
    ("shop-order", "GET", "/workshop/api/shop/orders/{obj}", "order"),
    ("mechanic-service-request", "GET", "/workshop/api/mechanic/service_request/{obj}", "service_request"),
]


def main() -> None:
    ap = argparse.ArgumentParser(description="M3: 가드레일 BOLA 차분 검증 (로컬 crAPI 전용)")
    ap.add_argument("--config")
    ap.add_argument("--dry-run", action="store_true", help="실제 전송 없이 계획만")
    args = ap.parse_args()
    cfg = load_config(args.config)
    m3 = cfg["m3"]
    base = cfg["target"]["base_url"].rstrip("/")

    guards = Guardrails.from_config(cfg, m3)
    if args.dry_run:
        guards.dry_run = True

    # 로그인·객체수집은 '정상 사용'이라 가드 통과 전에 직접 수행(POST 로그인)
    tokens, objects = {}, {}
    for uid, u in m3["test_users"].items():
        tok = _login(base, u)
        if not tok:
            raise SystemExit(f"로그인 실패: {u['email']} — crAPI가 떠 있는지 확인")
        tokens[uid] = tok
        objects[uid] = _collect_objects(base, tok)
        print(f"[M3] {uid} 로그인 OK, 객체 {objects[uid]}")

    actor_tokens = {**tokens, "anon": ""}
    audit = rel(cfg, cfg["output_dir"] + "/audit.log")
    audit.unlink(missing_ok=True)
    runner = GuardedRunner(guards, audit, actor_tokens)

    cases = []
    seen_obj = set()
    for name, method, tmpl, kind in TEMPLATES:
        for owner in ("a", "b"):
            for oid in objects[owner].get(kind, []):
                # seed 객체(service_request)는 A/B 공통이므로 중복 제거
                key = (name, oid)
                if key in seen_obj:
                    continue
                seen_obj.add(key)
                cases.append(bola.BolaCase(name=name, method=method, url_template=tmpl,
                                           owner=owner, obj_id=oid))
    print(f"[M3] 검증 케이스 {len(cases)}건 (가드: 호스트={sorted(guards.allowed_hosts)}, "
          f"메서드={sorted(guards.allowed_methods)}, {guards.rate_per_sec}/s"
          f"{', DRY-RUN' if guards.dry_run else ''})")

    results = bola.verify(runner, base, cases)

    # 가드레일 데모: 범위 밖/파괴적 요청이 실제로 차단되는지 1건씩 시도(감사 로그에 남음)
    runner.request("a", "GET", "http://169.254.169.254/latest/meta-data/", note="가드 데모: 스코프 밖")
    if objects["a"].get("vehicle"):
        runner.request("a", "DELETE", f"{base}/identity/api/v2/user/videos/1", note="가드 데모: 파괴적 메서드")

    runner.close()

    findings = [r.__dict__ for r in results]
    out = rel(cfg, cfg["output_dir"] + "/findings.json")
    out.write_text(json.dumps({
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "target": base, "dry_run": guards.dry_run,
            "guardrails": {"allowed_hosts": sorted(guards.allowed_hosts),
                           "allowed_methods": sorted(guards.allowed_methods),
                           "rate_per_sec": guards.rate_per_sec},
            "request_counts": runner.counts,
        },
        "findings": findings,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    from collections import Counter
    vc = Counter(r.verdict for r in results)
    print(f"\n[M3] 요청: {runner.counts}")
    print(f"     판정: {dict(vc)}")
    for r in results:
        if r.verdict.startswith("vulnerable"):
            print(f"       [{r.verdict}] {r.method} {r.url}")
            print(f"         소유자={r.owner} 기준선={r.baseline_status} 교차={r.cross_status} 비로그인={r.anon_status} 유출={r.leaked_signals}")
    print(f"     → {out}")
    print(f"     → {audit}  (모든 시도·차단 기록)")


if __name__ == "__main__":
    main()
