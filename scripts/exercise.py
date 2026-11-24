"""정상 사용자 시나리오로 crAPI 트래픽을 만든다 (공격 요청 없음).

모든 앱 요청은 mitmproxy 리버스 프록시(config.target.proxy_url)를 거쳐 HAR로 기록된다.
메일함(mailhog)은 '사용자의 메일 클라이언트' 역할이라 프록시를 거치지 않고 직접 읽는다.

사용: python scripts/exercise.py [--users a b]
"""
from __future__ import annotations

import argparse
import quopri
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from apisec.common import load_config  # noqa: E402

MAILHOG = "http://127.0.0.1:8025"
USERS = {
    "a": {"name": "usera", "email": "usera@test.local", "number": "0100000001", "password": "Passw0rd!a"},
    "b": {"name": "userb", "email": "userb@test.local", "number": "0100000002", "password": "Passw0rd!b"},
}


class ScopedClient(httpx.Client):
    """스코프 가드: 허용 호스트·포트 밖으로는 요청 자체를 막는다."""

    def __init__(self, allowed: set[str], **kw):
        super().__init__(**kw)
        self.allowed = allowed

    def send(self, request, **kw):
        netloc = urlsplit(str(request.url)).netloc
        if netloc not in self.allowed:
            raise RuntimeError(f"scope violation: {request.url}")
        return super().send(request, **kw)


def log(user: str, r: httpx.Response) -> None:
    print(f"  [{user}] {r.request.method:<6} {r.request.url.path:<62} {r.status_code}")


def vehicle_mail(cli: httpx.Client, email: str) -> tuple[str, str] | None:
    for m in cli.get(f"{MAILHOG}/api/v1/messages").json():
        if email not in str(m["Content"]["Headers"].get("To")):
            continue
        text = quopri.decodestring(m["Raw"]["Data"].encode()).decode("utf-8", "replace")
        hit = re.search(r"VIN:\s*(?:<[^>]+>\s*)*([A-Z0-9]{17}).*?Pincode:\s*(?:<[^>]+>\s*)*(\d{4})", text, re.S)
        if hit:
            return hit.group(1), hit.group(2)
    return None


def run_user(cli: httpx.Client, base: str, uid: str) -> None:
    u = USERS[uid]
    r = cli.post(f"{base}/identity/api/auth/login", json={"email": u["email"], "password": u["password"]})
    if r.status_code != 200:
        log(uid, cli.post(f"{base}/identity/api/auth/signup", json=u))
        r = cli.post(f"{base}/identity/api/auth/login", json={"email": u["email"], "password": u["password"]})
    log(uid, r)
    h = {"Authorization": f"Bearer {r.json()['token']}"}

    log(uid, cli.get(f"{base}/identity/api/v2/user/dashboard", headers=h))

    # 차량: 없으면 메일의 VIN/PIN으로 등록
    vehicles = cli.get(f"{base}/identity/api/v2/vehicle/vehicles", headers=h)
    log(uid, vehicles)
    if not vehicles.json():
        vp = vehicle_mail(cli, u["email"])
        if vp:
            log(uid, cli.post(f"{base}/identity/api/v2/vehicle/add_vehicle", headers=h,
                              json={"vin": vp[0], "pincode": vp[1]}))
            vehicles = cli.get(f"{base}/identity/api/v2/vehicle/vehicles", headers=h)
            log(uid, vehicles)
    vin = None
    for v in vehicles.json() or []:
        vin = v.get("vin")
        log(uid, cli.get(f"{base}/identity/api/v2/vehicle/{v['uuid']}/location", headers=h))

    # 커뮤니티
    log(uid, cli.get(f"{base}/community/api/v2/community/posts/recent", headers=h))
    p = cli.post(f"{base}/community/api/v2/community/posts", headers=h,
                 json={"title": f"{u['name']} 첫 글", "content": "엔진 오일 교체 주기가 궁금합니다."})
    log(uid, p)
    if p.status_code < 300 and p.json().get("id"):
        pid = p.json()["id"]
        log(uid, cli.get(f"{base}/community/api/v2/community/posts/{pid}", headers=h))
        log(uid, cli.post(f"{base}/community/api/v2/community/posts/{pid}/comment", headers=h,
                          json={"content": "저도 궁금해요"}))
    log(uid, cli.get(f"{base}/community/api/v2/community/posts/search", headers=h, params={"title": "오일"}))
    log(uid, cli.post(f"{base}/community/api/v2/coupon/validate-coupon", headers=h, json={"coupon_code": "TRAC075"}))

    # 쇼핑
    prods = cli.get(f"{base}/workshop/api/shop/products", headers=h)
    log(uid, prods)
    items = (prods.json() or {}).get("products", [])
    if items:
        o = cli.post(f"{base}/workshop/api/shop/orders", headers=h,
                     json={"product_id": items[0]["id"], "quantity": 1})
        log(uid, o)
        log(uid, cli.get(f"{base}/workshop/api/shop/orders/all", headers=h))
        oid = (o.json() or {}).get("id") if o.status_code < 300 else None
        if oid:
            log(uid, cli.get(f"{base}/workshop/api/shop/orders/{oid}", headers=h))

    # 정비 요청
    mech = cli.get(f"{base}/workshop/api/mechanic/", headers=h)
    log(uid, mech)
    mlist = (mech.json() or {}).get("mechanics", [])
    if vin and mlist:
        cm = cli.post(f"{base}/workshop/api/merchant/contact_mechanic", headers=h, json={
            "mechanic_api": "http://localhost:8000/workshop/api/mechanic/receive_report",  # 워크숍 컨테이너 내부 기본값
            "mechanic_code": mlist[0]["mechanic_code"], "number_of_repeats": 1,
            "repeat_request_if_failed": False, "problem_details": "브레이크 소음", "vin": vin,
        })
        log(uid, cm)
        rid = (((cm.json() or {}).get("response_from_mechanic_api") or {}).get("id")) if cm.status_code < 300 else None
        if rid:
            log(uid, cli.get(f"{base}/workshop/api/mechanic/mechanic_report", headers=h, params={"report_id": rid}))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--users", nargs="+", default=["a", "b"])
    args = ap.parse_args()
    cfg = load_config()
    base = cfg["target"]["proxy_url"].rstrip("/")
    allowed = {urlsplit(base).netloc, urlsplit(MAILHOG).netloc}
    for host in allowed:
        if host.split(":")[0] not in cfg["scope"]["allowed_hosts"]:
            sys.exit(f"config scope 밖의 호스트: {host}")
    with ScopedClient(allowed, timeout=30) as cli:
        for uid in args.users:
            print(f"== user {uid}")
            run_user(cli, base, uid)


if __name__ == "__main__":
    main()
