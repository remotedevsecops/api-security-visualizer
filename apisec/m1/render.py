"""공격면 지도 (단일 HTML, 외부 의존성 없음)."""
from __future__ import annotations

import json
from typing import Any

from jinja2 import Template

LIFECYCLE = {
    "shadow": ("Shadow", "코드에 있고 외부에 노출됐지만 스펙에 없음"),
    "active": ("Active", "코드·스펙·노출·트래픽 모두 확인"),
    "unobserved": ("미관측", "문서화·노출됐지만 트래픽 없음 (Zombie 후보)"),
    "internal-only": ("내부 전용", "게이트웨이 접두사 밖 — 내부 신뢰 점검 대상"),
    "gateway-only": ("게이트웨이", "서비스가 아닌 게이트웨이 location 자체가 노출"),
    "stale-doc": ("문서만", "스펙에만 있고 코드에 없음"),
    "traffic-only": ("트래픽만", "코드·스펙 어디에도 없는 호출"),
}
FLAGS = {
    "NO_AUTH": "의도된 공개 목록에 없는데 인증이 없음",
    "BOLA_CANDIDATE": "경로에 객체 식별자 — 소유권 검사 필요",
    "AUTH_MISMATCH": "코드와 스펙의 인증 요구가 다름",
    "BODY_ID": "요청 바디로 객체를 참조",
    "ADMIN": "관리 기능",
    "DEBUG": "디버그·테스트용으로 보이는 경로",
    "OLD_VERSION": "상위 버전과 병존하는 구버전",
    "INTERNAL_TOOL": "내부 도구를 외부로 프록시",
    "UNSCANNED": "코드를 분석하지 않은 서비스",
}

TEMPLATE = Template(r"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>API 공격면 지도</title>
<style>
:root{
  --bg:#f7f7f5;--surface:#ffffff;--ink:#1d1d1b;--muted:#6b6b66;--line:#e4e3de;
  --accent:#2f5bd3;--crit:#c8372d;--crit-bg:#fbeceb;--warn:#b25e09;--warn-bg:#fcf1e3;
  --ok:#2d7a46;--ok-bg:#e7f3ea;--info:#2f5bd3;--info-bg:#e9effc;--violet:#6a4bc4;--violet-bg:#efebfa;
  --neutral-bg:#efefec;--dot:#1d1d1b;
}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){
  --bg:#151514;--surface:#1e1e1c;--ink:#ecece8;--muted:#a2a29b;--line:#34342f;
  --accent:#7d9cf0;--crit:#f0857b;--crit-bg:#3a1f1c;--warn:#e9a55a;--warn-bg:#382816;
  --ok:#7cc495;--ok-bg:#1d3324;--info:#7d9cf0;--info-bg:#1f2840;--violet:#b3a0f0;--violet-bg:#2a2340;
  --neutral-bg:#2a2a27;--dot:#ecece8;}}
:root[data-theme="dark"]{
  --bg:#151514;--surface:#1e1e1c;--ink:#ecece8;--muted:#a2a29b;--line:#34342f;
  --accent:#7d9cf0;--crit:#f0857b;--crit-bg:#3a1f1c;--warn:#e9a55a;--warn-bg:#382816;
  --ok:#7cc495;--ok-bg:#1d3324;--info:#7d9cf0;--info-bg:#1f2840;--violet:#b3a0f0;--violet-bg:#2a2340;
  --neutral-bg:#2a2a27;--dot:#ecece8;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Pretendard","Segoe UI",sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:28px 16px 64px}
h1{font-size:22px;margin:0 0 4px;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:13px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:22px 0 18px}
.kpi{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:12px 14px;cursor:pointer;text-align:left;color:inherit;font:inherit}
.kpi:hover{border-color:var(--muted)}
.kpi.on{outline:2px solid var(--accent);outline-offset:-1px}
.kpi .n{font-size:26px;font-weight:650;line-height:1.1}
.kpi .l{color:var(--muted);font-size:12.5px;margin-top:2px}
.kpi.crit .n{color:var(--crit)} .kpi.warn .n{color:var(--warn)} .kpi.violet .n{color:var(--violet)}
.bar{display:flex;height:10px;border-radius:5px;overflow:hidden;background:var(--neutral-bg);margin:6px 0 8px}
.bar span{display:block;height:100%}
.legend{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:12.5px;color:var(--muted)}
.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;vertical-align:0}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px;margin-top:14px}
.panel h2{font-size:15px;margin:0 0 4px}
.tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:4px 0 12px}
.tools input{flex:1 1 220px;min-width:0;padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);font:inherit}
.chip{-webkit-appearance:none;appearance:none;border:1px solid var(--line);background:var(--bg);color:var(--ink);border-radius:999px;padding:4px 10px;font:inherit;font-size:12.5px;cursor:pointer}
.chip.on{background:var(--ink);color:var(--surface);border-color:var(--ink)}
.tablewrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:900px}
th{font-size:12px;color:var(--muted);font-weight:600;text-align:left;padding:8px 8px;border-bottom:1px solid var(--line);white-space:nowrap}
th.src,td.src{text-align:center;width:54px}
td{padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
tr.row{cursor:pointer} tr.row:hover td{background:var(--bg)}
tr.svc td{background:var(--neutral-bg);font-weight:650;font-size:12.5px;padding:6px 8px;cursor:default}
.m{font:600 11.5px ui-monospace,SFMono-Regular,Menlo,monospace;padding:1px 6px;border-radius:4px;background:var(--neutral-bg)}
.p{font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;border:1.5px solid var(--dot)}
.dot.f{background:var(--dot)} .dot.e{opacity:.35}
.b{display:inline-block;font-size:11.5px;padding:1px 7px;border-radius:999px;margin:0 3px 3px 0;white-space:nowrap}
.lc-shadow{background:var(--warn-bg);color:var(--warn)} .lc-active{background:var(--ok-bg);color:var(--ok)}
.lc-unobserved{background:var(--neutral-bg);color:var(--muted)} .lc-internal-only{background:var(--info-bg);color:var(--info)}
.lc-gateway-only{background:var(--violet-bg);color:var(--violet)} .lc-stale-doc,.lc-traffic-only{background:var(--neutral-bg);color:var(--ink)}
.fl{background:transparent;border:1px solid var(--line);color:var(--muted)}
.fl-NO_AUTH{border-color:var(--crit);color:var(--crit);background:var(--crit-bg)}
.fl-BOLA_CANDIDATE{border-color:var(--violet);color:var(--violet)}
.fl-AUTH_MISMATCH,.fl-INTERNAL_TOOL,.fl-OLD_VERSION,.fl-DEBUG{border-color:var(--warn);color:var(--warn)}
.auth{font-size:12px} .auth.public{color:var(--crit);font-weight:600}
tr.detail td{background:var(--bg);font-size:12.5px;padding:10px 14px 14px}
.kv{display:grid;grid-template-columns:110px 1fr;gap:3px 12px}
.kv dt{color:var(--muted)} .kv dd{margin:0;word-break:break-all}
.note{color:var(--ink)}
.defs{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:6px 20px;font-size:12.5px;margin-top:8px}
.defs div{color:var(--muted)} .defs b{color:var(--ink);font-weight:600;margin-right:6px}
.empty{color:var(--muted);padding:20px;text-align:center}
.foot{color:var(--muted);font-size:12px;margin-top:18px}
</style>
</head>
<body>
<div class="wrap">
  <h1>API 공격면 지도</h1>
  <div class="sub">대상 {{ meta.target }} · 생성 {{ meta.generated_at }} · 출처: 코드 {{ meta.source_counts.code }}개 라우트, 스펙 {{ meta.source_counts.spec }}개 오퍼레이션, 게이트웨이 {{ meta.source_counts.gateway_locations }}개 location, 트래픽 {{ meta.source_counts.traffic }}개 엔드포인트</div>

  <div class="kpis" id="kpis"></div>

  <div class="panel">
    <h2>분류 분포</h2>
    <div class="bar" id="lcbar"></div>
    <div class="legend" id="lclegend"></div>
  </div>

  <div class="panel">
    <h2>출처 매트릭스</h2>
    <div class="sub" style="margin-bottom:8px">● 있음 ○ 없음 · 행을 누르면 근거(파일:라인, 인증 근거, 트래픽)가 펼쳐집니다</div>
    <div class="tools">
      <input id="q" type="search" placeholder="경로·핸들러 검색">
      <span id="chips"></span>
    </div>
    <div class="tablewrap">
      <table>
        <thead><tr>
          <th>메서드</th><th>경로</th>
          <th class="src">코드</th><th class="src">스펙</th><th class="src">노출</th><th class="src">트래픽</th>
          <th>인증</th><th>분류</th><th>플래그</th>
        </tr></thead>
        <tbody id="tb"></tbody>
      </table>
    </div>
    <div id="empty" class="empty" hidden>조건에 맞는 엔드포인트가 없습니다.</div>
  </div>

  <div class="panel">
    <h2>분류·플래그 기준</h2>
    <div class="defs" id="defs"></div>
  </div>
  <div class="foot">M1 결과는 정적 분석·설정·관측 트래픽 기반의 후보 목록입니다. 인증 우회와 BOLA는 M3에서 실제 요청으로 검증합니다.</div>
</div>

<script id="data" type="application/json">{{ payload }}</script>
<script>
const D = JSON.parse(document.getElementById('data').textContent);
const EP = D.endpoints, LC = D.lifecycle, FL = D.flags;
const LC_COLOR = {shadow:'var(--warn)',active:'var(--ok)',unobserved:'var(--muted)','internal-only':'var(--info)','gateway-only':'var(--violet)','stale-doc':'var(--ink)','traffic-only':'var(--ink)'};
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let filter = null, query = '';
const open = new Set();

const KPIS = [
  {k:null, n:EP.length, l:'전체 엔드포인트'},
  {k:'lc:shadow', n:EP.filter(e=>e.lifecycle==='shadow').length, l:'Shadow (문서에 없음)', c:'warn'},
  {k:'fl:NO_AUTH', n:EP.filter(e=>e.flags.includes('NO_AUTH')).length, l:'의도치 않은 무인증', c:'crit'},
  {k:'fl:BOLA_CANDIDATE', n:EP.filter(e=>e.flags.includes('BOLA_CANDIDATE')).length, l:'BOLA 후보', c:'violet'},
  {k:'fl:AUTH_MISMATCH', n:EP.filter(e=>e.flags.includes('AUTH_MISMATCH')).length, l:'코드·스펙 인증 불일치', c:'warn'},
  {k:'fl:OLD_VERSION', n:EP.filter(e=>e.flags.includes('OLD_VERSION')).length, l:'구버전 병존', c:'warn'},
];
function drawKpis(){
  document.getElementById('kpis').innerHTML = KPIS.map(x =>
    `<button class="kpi ${x.c||''} ${filter===x.k?'on':''}" data-k="${x.k??''}"><div class="n">${x.n}</div><div class="l">${x.l}</div></button>`).join('');
  document.querySelectorAll('.kpi').forEach(b => b.onclick = () => { const k=b.dataset.k||null; filter = (filter===k?null:k); draw(); });
}
function drawBar(){
  const cnt = {}; EP.forEach(e => cnt[e.lifecycle]=(cnt[e.lifecycle]||0)+1);
  const keys = Object.keys(LC).filter(k=>cnt[k]);
  document.getElementById('lcbar').innerHTML = keys.map(k=>`<span title="${LC[k][0]} ${cnt[k]}" style="width:${cnt[k]/EP.length*100}%;background:${LC_COLOR[k]}"></span>`).join('');
  document.getElementById('lclegend').innerHTML = keys.map(k=>`<span><i style="background:${LC_COLOR[k]}"></i>${LC[k][0]} ${cnt[k]}</span>`).join('');
}
function drawChips(){
  const used = new Set(EP.flatMap(e=>e.flags));
  const items = [...Object.keys(LC).filter(k=>EP.some(e=>e.lifecycle===k)).map(k=>['lc:'+k, LC[k][0]]),
                 ...Object.keys(FL).filter(f=>used.has(f)).map(f=>['fl:'+f, f])];
  document.getElementById('chips').innerHTML = items.map(([k,l]) => `<button class="chip ${filter===k?'on':''}" data-k="${k}">${esc(l)}</button>`).join(' ');
  document.querySelectorAll('.chip').forEach(b => b.onclick = () => { filter = (filter===b.dataset.k?null:b.dataset.k); draw(); });
}
const dot = on => `<span class="dot ${on?'f':'e'}"></span>`;
function srcTitle(e, s){
  const x = e.sources[s]; if(!x) return 'X';
  if(s==='code') return `${x.loc} · ${x.handler}`;
  if(s==='spec') return x.operation_id || 'spec';
  if(s==='gateway') return `location ${x.location||'-'} → ${x.upstream||x.kind||'-'}`;
  if(s==='traffic') return `${x.count}회 · ${JSON.stringify(x.statuses)}`;
}
function detail(e){
  const c=e.sources.code, s=e.sources.spec, g=e.sources.gateway, t=e.sources.traffic;
  const rows = [];
  if(c){ rows.push(['코드', `${esc(c.loc)} · <span class="p">${esc(c.handler)}</span>`]); rows.push(['인증 근거', esc(c.auth_evidence||'-')]); if(c.route_loc) rows.push(['라우트 선언', esc(c.route_loc)]); }
  if(s) rows.push(['스펙', `${esc(s.operation_id||'-')} · 인증 ${esc(s.auth)}${s.summary?' · '+esc(s.summary):''}`]);
  if(g) rows.push(['게이트웨이', `location <span class="p">${esc(g.location||'-')}</span> → ${esc(g.upstream||g.kind||'-')} · 외부 노출 ${g.exposed?'예':'아니오'}`]);
  if(t) rows.push(['트래픽', `${t.count}회 · 상태 ${esc(JSON.stringify(t.statuses))} · 호출자 ${esc(t.actors.join(', '))}<br><span class="p">${t.samples.map(esc).join('<br>')}</span>`]);
  if(e.notes.length) rows.push(['메모', `<span class="note">${e.notes.map(esc).join('<br>')}</span>`]);
  return `<dl class="kv">${rows.map(([k,v])=>`<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;
}
function draw(){
  drawKpis(); drawChips();
  const q = query.toLowerCase();
  const list = EP.filter(e => {
    if(filter){ const [t,v]=filter.split(':'); if(t==='lc' && e.lifecycle!==v) return false; if(t==='fl' && !e.flags.includes(v)) return false; }
    if(q && !(e.path.toLowerCase().includes(q) || (e.sources.code?.handler||'').toLowerCase().includes(q))) return false;
    return true;
  });
  let html = '', svc = null;
  for(const e of list){
    if(e.service !== svc){ svc = e.service; html += `<tr class="svc"><td colspan="9">${esc(svc||'기타')}</td></tr>`; }
    html += `<tr class="row" data-id="${e.id}">
      <td><span class="m">${esc(e.method)}</span></td>
      <td class="p">${esc(e.path)}</td>
      ${['code','spec','gateway','traffic'].map(s=>`<td class="src" title="${esc(srcTitle(e,s))}">${dot(s==='gateway'? !!(e.sources.gateway&&e.sources.gateway.exposed) : !!e.sources[s])}</td>`).join('')}
      <td class="auth ${e.auth==='public'?'public':''}">${esc(e.auth)}</td>
      <td><span class="b lc-${e.lifecycle}" title="${esc(LC[e.lifecycle][1])}">${esc(LC[e.lifecycle][0])}</span></td>
      <td>${e.flags.map(f=>`<span class="b fl fl-${f}" title="${esc(FL[f]||'')}">${f}</span>`).join('')}</td></tr>`;
    if(open.has(e.id)) html += `<tr class="detail"><td colspan="9">${detail(e)}</td></tr>`;
  }
  document.getElementById('tb').innerHTML = html;
  document.getElementById('empty').hidden = list.length>0;
  document.querySelectorAll('tr.row').forEach(r => r.onclick = () => { const id=r.dataset.id; open.has(id)?open.delete(id):open.add(id); draw(); });
}
document.getElementById('defs').innerHTML =
  Object.entries(LC).map(([k,[l,d]])=>`<div><b>${esc(l)}</b>${esc(d)}</div>`).join('') +
  Object.entries(FL).map(([k,d])=>`<div><b>${k}</b>${esc(d)}</div>`).join('');
document.getElementById('q').oninput = ev => { query = ev.target.value; draw(); };
drawBar(); draw();
</script>
</body>
</html>
""")


def render(meta: dict[str, Any], endpoints: list[dict[str, Any]]) -> str:
    payload = json.dumps({"endpoints": endpoints, "lifecycle": LIFECYCLE, "flags": FLAGS},
                         ensure_ascii=False, default=list).replace("</", "<\\/")
    return TEMPLATE.render(meta=meta, payload=payload)
