"""통합 리포트: 파이프라인 흐름 + M1 분류 + M2 PII/위험도를 한 HTML 페이지로.

python -m apisec.report  → data/report.html
입력은 enriched_endpoints.json(M2 산출). 없으면 endpoints.json(M1만).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Template

from apisec.common import load_config, rel

LIFECYCLE = {
    "shadow": ("Shadow", "코드에 있고 노출됐지만 스펙에 없음"),
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
    "PII_EXPOSURE": "응답에서 개인정보가 관측됨",
    "TAINT_BOLA": "CodeQL taint: 식별자가 소유권 검사 없이 DB 조회까지 흐름(코드 경로 확정)",
}
PII_TYPES = {
    "SSN_KR": "주민등록번호", "CARD": "카드번호", "JWT": "토큰", "EMAIL": "이메일",
    "PHONE": "전화번호", "VIN": "차대번호", "GEO": "위치좌표", "NAME": "이름",
    "ADDRESS": "주소", "VEHICLE": "차량정보", "FINANCIAL": "금융", "HEALTH": "건강", "OTHER": "기타",
}

TEMPLATE = Template(r"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>API 보안 가시화 리포트</title>
<style>
:root{
  --bg:#f7f7f5;--surface:#fff;--ink:#1d1d1b;--muted:#6b6b66;--line:#e4e3de;
  --accent:#2f5bd3;--crit:#c8372d;--crit-bg:#fbeceb;--warn:#b25e09;--warn-bg:#fcf1e3;
  --ok:#2d7a46;--ok-bg:#e7f3ea;--info:#2f5bd3;--info-bg:#e9effc;--violet:#6a4bc4;--violet-bg:#efebfa;
  --neutral-bg:#efefec;--dot:#1d1d1b;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
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
.wrap{max-width:1200px;margin:0 auto;padding:28px 16px 64px}
h1{font-size:22px;margin:0 0 4px;letter-spacing:-.01em}
h2{font-size:15px;margin:0 0 10px}
.sub{color:var(--muted);font-size:13px}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px;margin-top:14px}
/* pipeline */
.flow{overflow-x:auto}
.flow svg{display:block;min-width:720px;width:100%;height:auto}
/* kpis */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:22px 0 4px}
.kpi{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:12px 14px;cursor:pointer;text-align:left;color:inherit;font:inherit}
.kpi:hover{border-color:var(--muted)} .kpi.on{outline:2px solid var(--accent);outline-offset:-1px}
.kpi .n{font-size:26px;font-weight:650;line-height:1.1}
.kpi .l{color:var(--muted);font-size:12px;margin-top:2px}
.kpi.crit .n{color:var(--crit)} .kpi.warn .n{color:var(--warn)} .kpi.violet .n{color:var(--violet)} .kpi.ok .n{color:var(--ok)}
.tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:4px 0 12px}
.tools input{flex:1 1 220px;min-width:0;padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);font:inherit}
.chip{-webkit-appearance:none;appearance:none;border:1px solid var(--line);background:var(--bg);color:var(--ink);border-radius:999px;padding:4px 10px;font:inherit;font-size:12.5px;cursor:pointer}
.chip.on{background:var(--ink);color:var(--surface);border-color:var(--ink)}
.tablewrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:980px}
th{font-size:12px;color:var(--muted);font-weight:600;text-align:left;padding:8px;border-bottom:1px solid var(--line);white-space:nowrap}
th.src,td.src{text-align:center;width:46px}
td{padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
tr.row{cursor:pointer} tr.row:hover td{background:var(--bg)}
tr.svc td{background:var(--neutral-bg);font-weight:650;font-size:12.5px;padding:6px 8px;cursor:default}
.m{font:600 11.5px ui-monospace,Menlo,monospace;padding:1px 6px;border-radius:4px;background:var(--neutral-bg)}
.p{font:12.5px ui-monospace,Menlo,monospace;word-break:break-all}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;border:1.5px solid var(--dot)}
.dot.f{background:var(--dot)} .dot.e{opacity:.3}
.b{display:inline-block;font-size:11.5px;padding:1px 7px;border-radius:999px;margin:0 3px 3px 0;white-space:nowrap}
.lc-shadow{background:var(--warn-bg);color:var(--warn)} .lc-active{background:var(--ok-bg);color:var(--ok)}
.lc-unobserved{background:var(--neutral-bg);color:var(--muted)} .lc-internal-only{background:var(--info-bg);color:var(--info)}
.lc-gateway-only{background:var(--violet-bg);color:var(--violet)} .lc-stale-doc,.lc-traffic-only{background:var(--neutral-bg);color:var(--ink)}
.fl{background:transparent;border:1px solid var(--line);color:var(--muted)}
.fl-NO_AUTH,.fl-PII_EXPOSURE{border-color:var(--crit);color:var(--crit)}
.fl-BOLA_CANDIDATE,.fl-TAINT_BOLA{border-color:var(--violet);color:var(--violet)}
.fl-TAINT_BOLA{background:var(--violet-bg)}
.fl-AUTH_MISMATCH,.fl-INTERNAL_TOOL,.fl-OLD_VERSION,.fl-DEBUG{border-color:var(--warn);color:var(--warn)}
.auth{font-size:12px} .auth.public{color:var(--crit);font-weight:600}
.risk{font-weight:650;font-size:12px;padding:2px 8px;border-radius:6px}
.risk-critical{background:var(--crit-bg);color:var(--crit)} .risk-high{background:var(--warn-bg);color:var(--warn)}
.risk-medium{background:var(--info-bg);color:var(--info)} .risk-low{background:var(--neutral-bg);color:var(--muted)} .risk-none{color:var(--muted)}
.v{font-weight:650;font-size:11.5px;padding:2px 8px;border-radius:6px;white-space:nowrap}
.v-vulnerable_no_auth,.v-vulnerable_bola{background:var(--crit-bg);color:var(--crit)}
.v-not_vulnerable{background:var(--ok-bg);color:var(--ok)} .v-inconclusive{background:var(--neutral-bg);color:var(--muted)}
.pii{display:flex;gap:3px;flex-wrap:wrap}
.pii span{font-size:11px;padding:1px 6px;border-radius:4px;background:var(--crit-bg);color:var(--crit)}
tr.detail td{background:var(--bg);font-size:12.5px;padding:10px 14px 14px}
.kv{display:grid;grid-template-columns:120px 1fr;gap:3px 12px}
.kv dt{color:var(--muted)} .kv dd{margin:0;word-break:break-all}
.pfields{margin-top:6px}
.pfields table{min-width:0;width:auto}
.pfields td,.pfields th{padding:3px 10px 3px 0;border:0;font-size:12px}
.defs{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:4px 20px;font-size:12.5px;margin-top:8px}
.defs div{color:var(--muted)} .defs b{color:var(--ink);font-weight:600;margin-right:6px}
.empty{color:var(--muted);padding:20px;text-align:center}
.tabs{display:flex;gap:4px;margin:18px 0 0}
.tab{-webkit-appearance:none;appearance:none;border:1px solid var(--line);border-bottom:none;background:var(--bg);color:var(--muted);padding:8px 16px;border-radius:9px 9px 0 0;font:inherit;font-size:13px;cursor:pointer}
.tab.on{background:var(--surface);color:var(--ink);font-weight:600}
.tabpanel{margin-top:0;border-radius:0 12px 12px 12px}
.ghint{color:var(--muted);font-size:12.5px;margin-bottom:16px;line-height:1.6}
.vcard{border:1px solid var(--line);border-radius:12px;padding:0;margin-bottom:18px;overflow:hidden}
.vhead{display:flex;flex-wrap:wrap;align-items:center;gap:10px;padding:14px 16px;background:var(--neutral-bg);border-bottom:1px solid var(--line)}
.vhead .vm{font:600 11.5px ui-monospace,Menlo,monospace;padding:2px 7px;border-radius:5px;background:var(--surface);border:1px solid var(--line)}
.vhead .vp{font:13px ui-monospace,Menlo,monospace;color:var(--ink);word-break:break-all}
.vhead .vv{margin-left:auto;font-weight:650;font-size:12px;padding:3px 10px;border-radius:7px;background:var(--crit-bg);color:var(--crit)}
.vbody{display:grid;grid-template-columns:1.35fr 1fr;gap:0}
@media(max-width:760px){.vbody{grid-template-columns:1fr}}
.vseq{padding:16px;border-right:1px solid var(--line)}
@media(max-width:760px){.vseq{border-right:none;border-bottom:1px solid var(--line)}}
.vseq svg{display:block;width:100%;height:auto}
.vmx{padding:16px}
.vmx h4,.vseq h4{margin:0 0 12px;font-size:12.5px;color:var(--muted);font-weight:600}
.vmx table{width:100%;min-width:0;border-collapse:collapse}
.vmx th,.vmx td{padding:7px 6px;text-align:center;border-bottom:1px solid var(--line);font-size:12.5px}
.vmx th:first-child,.vmx td:first-child{text-align:left}
.vmx .st{font-weight:650;padding:2px 8px;border-radius:6px;font-size:12px}
.vmx .leak{color:var(--crit)} .vmx .okcell{color:var(--ok)}
.vmx .caption{color:var(--muted);font-size:11.5px;margin-top:10px;line-height:1.5}
.vfoot{padding:12px 16px;border-top:1px solid var(--line);font-size:12px;color:var(--muted)}
.vfoot b{color:var(--ink)}
.foot{color:var(--muted);font-size:12px;margin-top:18px}
</style>
</head>
<body>
<div class="wrap">
  <h1>API 보안 가시화 리포트</h1>
  <div class="sub">대상 {{ meta.target }} · 생성 {{ gen }}{% if has_m2 %} · PII 샘플 {{ meta.m2.sampled_endpoints }}개 엔드포인트{% if meta.m2.llm %} · LLM 2차 {{ meta.m2.llm_calls }}회{% endif %}{% endif %}</div>

  <div class="panel">
    <h2>파이프라인</h2>
    <div class="flow">
    <svg viewBox="0 0 980 232" role="img" aria-label="API 보안 가시화 파이프라인: 네 출처를 합쳐 분류하고 개인정보를 탐지한다">
      <defs><marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="var(--muted)"/></marker></defs>
      {% set srcs = [["소스코드","Semgrep 규칙 · 라우트+인증"],["API 스펙","OpenAPI 파싱"],["게이트웨이","nginx location · 노출범위"],["트래픽","mitmproxy HAR · 샘플응답"]] %}
      {% for s in srcs %}
      <g>
        <rect x="16" y="{{ 12 + loop.index0*54 }}" width="210" height="44" rx="8" fill="none" stroke="var(--line)" stroke-width="1.25"/>
        <text x="30" y="{{ 32 + loop.index0*54 }}" font-size="13" font-weight="600" fill="var(--ink)">{{ s[0] }}</text>
        <text x="30" y="{{ 48 + loop.index0*54 }}" font-size="11" fill="var(--muted)">{{ s[1] }}</text>
        <path d="M226 {{ 34 + loop.index0*54 }} H300 V116 H356" fill="none" stroke="var(--muted)" stroke-width="1.25" marker-end="url(#ar)"/>
      </g>
      {% endfor %}
      <rect x="356" y="86" width="150" height="60" rx="8" fill="var(--info-bg)" stroke="var(--info)" stroke-width="1.5"/>
      <text x="431" y="112" text-anchor="middle" font-size="13" font-weight="600" fill="var(--ink)">M1 병합·분류</text>
      <text x="431" y="130" text-anchor="middle" font-size="11" fill="var(--muted)">출처 겹쳐 lifecycle·flag</text>
      <path d="M506 116 H562" fill="none" stroke="var(--muted)" stroke-width="1.25" marker-end="url(#ar)"/>
      <rect x="562" y="86" width="150" height="60" rx="8" fill="var(--crit-bg)" stroke="var(--crit)" stroke-width="1.5"/>
      <text x="637" y="112" text-anchor="middle" font-size="13" font-weight="600" fill="var(--ink)">M2 PII 탐지</text>
      <text x="637" y="130" text-anchor="middle" font-size="11" fill="var(--muted)">응답 스캔·위험도</text>
      <path d="M712 116 H768" fill="none" stroke="var(--muted)" stroke-width="1.25" marker-end="url(#ar)"/>
      {% if has_m3 %}
      <rect x="768" y="86" width="196" height="60" rx="8" fill="var(--warn-bg)" stroke="var(--warn)" stroke-width="1.5"/>
      <text x="866" y="112" text-anchor="middle" font-size="13" font-weight="600" fill="var(--ink)">M3 가드레일 검증</text>
      <text x="866" y="130" text-anchor="middle" font-size="11" fill="var(--muted)">실제 요청으로 BOLA 확정</text>
      <text x="866" y="176" text-anchor="middle" font-size="11" fill="var(--muted)">모든 시도·차단 → audit.log</text>
      {% else %}
      <rect x="768" y="86" width="196" height="60" rx="8" fill="none" stroke="var(--line)" stroke-width="1.25"/>
      <text x="866" y="112" text-anchor="middle" font-size="13" font-weight="600" fill="var(--ink)">이 리포트</text>
      <text x="866" y="130" text-anchor="middle" font-size="11" fill="var(--muted)">공격면 + 개인정보 흐름</text>
      <text x="866" y="176" text-anchor="middle" font-size="11" fill="var(--muted)">다음: M3 인가 검증 → M4</text>
      {% endif %}
    </svg>
    </div>
  </div>

  <div class="kpis" id="kpis"></div>

  <div class="tabs">
    <button class="tab on" data-tab="list">엔드포인트 목록</button>
    {% if has_views %}<button class="tab" data-tab="vuln">확정 취약점 흐름</button>{% endif %}
  </div>

  <div class="panel tabpanel" id="tab-list">
    <div class="tools">
      <input id="q" type="search" placeholder="경로·핸들러 검색">
      <span id="chips"></span>
    </div>
    <div class="tablewrap">
      <table>
        <thead><tr>
          <th>메서드</th><th>경로</th>
          <th class="src">코드</th><th class="src">스펙</th><th class="src">노출</th><th class="src">트래픽</th>
          <th>인증</th><th>분류</th><th>위험</th><th>개인정보</th><th>M3 검증</th><th>플래그</th>
        </tr></thead>
        <tbody id="tb"></tbody>
      </table>
    </div>
    <div id="empty" class="empty" hidden>조건에 맞는 엔드포인트가 없습니다.</div>
    <div class="sub" style="margin-top:8px">행을 누르면 근거(파일:라인, 인증 근거, 트래픽, PII 필드)가 펼쳐집니다. ● 있음 ○ 없음.</div>
  </div>

  {% if has_views %}
  <div class="panel tabpanel" id="tab-vuln" hidden>
    <div class="ghint">M3에서 <b>실제 요청으로 확정</b>된 취약점의 호출 홉. 요청이 게이트웨이·서비스·저장소를 지나는 동안 <b>어느 홉에서 인가 검사가 빠졌는지</b>를 본다. 오른쪽 매트릭스는 같은 요청을 소유자·타인·비로그인으로 보냈을 때의 응답(차분 테스트).</div>
    <div id="vuln-root"></div>
  </div>
  {% endif %}

  <div class="panel">
    <h2>기준</h2>
    <div class="defs" id="defs"></div>
  </div>
  <div class="foot">정적 분석·설정·관측 트래픽 기반의 후보입니다. 인증 우회·BOLA의 실제 성립 여부는 M3에서 요청으로 검증합니다. 대상은 로컬 crAPI 실습 앱에 한정됩니다.</div>
</div>

<script id="data" type="application/json">{{ payload }}</script>
<script>
const D=JSON.parse(document.getElementById('data').textContent);
const EP=D.endpoints, LC=D.lifecycle, FL=D.flags, PT=D.pii_types, HAS_M2=D.has_m2, HAS_M3=D.has_m3;
const V_LABEL={vulnerable_no_auth:'무인증 확정',vulnerable_bola:'BOLA 확정',not_vulnerable:'안전 확인',inconclusive:'판정 불가'};
const LC_COLOR={shadow:'var(--warn)',active:'var(--ok)',unobserved:'var(--muted)','internal-only':'var(--info)','gateway-only':'var(--violet)','stale-doc':'var(--ink)','traffic-only':'var(--ink)'};
const RISK_ORDER={critical:0,high:1,medium:2,low:3,none:4};
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let filter=null, query='';
const open=new Set();

const KPIS=[
 {k:null,n:EP.length,l:'전체 엔드포인트'},
 {k:'lc:shadow',n:EP.filter(e=>e.lifecycle==='shadow').length,l:'Shadow',c:'warn'},
 {k:'fl:NO_AUTH',n:EP.filter(e=>e.flags.includes('NO_AUTH')).length,l:'의도치 않은 무인증',c:'crit'},
 {k:'fl:BOLA_CANDIDATE',n:EP.filter(e=>e.flags.includes('BOLA_CANDIDATE')).length,l:'BOLA 후보',c:'violet'},
];
if(HAS_M2){
 KPIS.push({k:'risk:critical',n:EP.filter(e=>e.risk==='critical').length,l:'Critical (무인증+PII)',c:'crit'});
 KPIS.push({k:'fl:PII_EXPOSURE',n:EP.filter(e=>e.flags.includes('PII_EXPOSURE')).length,l:'개인정보 노출',c:'crit'});
}
if(HAS_M3){
 KPIS.push({k:'m3:vuln',n:EP.filter(e=>e.m3&&e.m3.verdict.startsWith('vulnerable')).length,l:'M3 실제 확정',c:'crit'});
}
function drawKpis(){
 document.getElementById('kpis').innerHTML=KPIS.map(x=>`<button class="kpi ${x.c||''} ${filter===x.k?'on':''}" data-k="${x.k??''}"><div class="n">${x.n}</div><div class="l">${x.l}</div></button>`).join('');
 document.querySelectorAll('.kpi').forEach(b=>b.onclick=()=>{const k=b.dataset.k||null;filter=(filter===k?null:k);draw();});
}
function drawChips(){
 const used=new Set(EP.flatMap(e=>e.flags));
 const items=[...Object.keys(LC).filter(k=>EP.some(e=>e.lifecycle===k)).map(k=>['lc:'+k,LC[k][0]]),
              ...Object.keys(FL).filter(f=>used.has(f)).map(f=>['fl:'+f,f])];
 document.getElementById('chips').innerHTML=items.map(([k,l])=>`<button class="chip ${filter===k?'on':''}" data-k="${k}">${esc(l)}</button>`).join(' ');
 document.querySelectorAll('.chip').forEach(b=>b.onclick=()=>{filter=(filter===b.dataset.k?null:b.dataset.k);draw();});
}
const dot=on=>`<span class="dot ${on?'f':'e'}"></span>`;
function srcTitle(e,s){const x=e.sources[s];if(!x)return 'X';
 if(s==='code')return `${x.loc} · ${x.handler}`;
 if(s==='spec')return x.operation_id||'spec';
 if(s==='gateway')return `location ${x.location||'-'} → ${x.upstream||x.kind||'-'}`;
 if(s==='traffic')return `${x.count}회 · ${JSON.stringify(x.statuses)}`;}
function piiCell(e){if(!e.pii_findings||!e.pii_findings.length)return '';
 const types=[...new Set(e.pii_findings.map(f=>f.type))];
 return `<div class="pii">${types.map(t=>`<span>${esc(PT[t]||t)}</span>`).join('')}</div>`;}
function detail(e){
 const c=e.sources.code,s=e.sources.spec,g=e.sources.gateway,t=e.sources.traffic;const rows=[];
 if(c){rows.push(['코드',`${esc(c.loc)} · <span class="p">${esc(c.handler)}</span>`]);rows.push(['인증 근거',esc(c.auth_evidence||'-')]);if(c.route_loc)rows.push(['라우트 선언',esc(c.route_loc)]);}
 if(s)rows.push(['스펙',`${esc(s.operation_id||'-')} · 인증 ${esc(s.auth)}${s.summary?' · '+esc(s.summary):''}`]);
 if(g)rows.push(['게이트웨이',`location <span class="p">${esc(g.location||'-')}</span> → ${esc(g.upstream||g.kind||'-')} · 외부 노출 ${g.exposed?'예':'아니오'}`]);
 if(t)rows.push(['트래픽',`${t.count}회 · 상태 ${esc(JSON.stringify(t.statuses))} · 호출자 ${esc(t.actors.join(', '))}<br><span class="p">${t.samples.map(esc).join('<br>')}</span>`]);
 if(e.m3){const m=e.m3;const leaked=Object.entries({...m.evidence.cross_leaked,...m.evidence.anon_leaked});
   rows.push(['M3 검증',`<b>${esc(V_LABEL[m.verdict]||m.verdict)}</b> · 소유자 ${m.baseline} / 다른사용자 ${m.cross} / 비로그인 ${m.anon}`+
     (leaked.length?`<br>유출된 소유자 식별값: ${leaked.map(([k,v])=>esc(k)+'='+esc(v)).join(', ')}`:'')+
     `<br><span class="sub">실제 요청으로 확정. 증거·차단 기록은 audit.log 참조.</span>`]);}
 if(e.notes&&e.notes.length)rows.push(['메모',e.notes.map(esc).join('<br>')]);
 let h=`<dl class="kv">${rows.map(([k,v])=>`<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;
 if(e.pii_findings&&e.pii_findings.length){
   h+=`<div class="pfields"><table><thead><tr><th>필드</th><th>종류</th><th>탐지</th><th>표본(마스킹)</th>${e.pii_findings.some(f=>f.llm)?'<th>LLM</th>':''}</tr></thead><tbody>`+
      e.pii_findings.map(f=>`<tr><td class="p">${esc(f.field)}</td><td>${esc(PT[f.type]||f.type)}</td><td>${f.detector==='regex-value'?'정규식(값)':'필드명'}</td><td class="p">${esc(f.sample)}</td>${f.llm?`<td>${esc(f.llm.is_pii?('PII · '+(f.llm.rationale||'')):'아님')}</td>`:(e.pii_findings.some(x=>x.llm)?'<td>-</td>':'')}</tr>`).join('')+
      `</tbody></table></div>`;
 }
 return h;
}
function draw(){
 drawKpis();drawChips();
 const q=query.toLowerCase();
 const list=EP.filter(e=>{
   if(filter){const [t,v]=filter.split(':');
     if(t==='lc'&&e.lifecycle!==v)return false;
     if(t==='fl'&&!e.flags.includes(v))return false;
     if(t==='risk'&&e.risk!==v)return false;
     if(t==='m3'&&!(e.m3&&e.m3.verdict.startsWith('vulnerable')))return false;}
   if(q&&!(e.path.toLowerCase().includes(q)||(e.sources.code?.handler||'').toLowerCase().includes(q)))return false;
   return true;});
 let html='',svc=null;
 for(const e of list){
   if(e.service!==svc){svc=e.service;html+=`<tr class="svc"><td colspan="12">${esc(svc||'기타')}</td></tr>`;}
   html+=`<tr class="row" data-id="${e.id}">
     <td><span class="m">${esc(e.method)}</span></td>
     <td class="p">${esc(e.path)}</td>
     ${['code','spec','gateway','traffic'].map(s=>`<td class="src" title="${esc(srcTitle(e,s))}">${dot(s==='gateway'?!!(e.sources.gateway&&e.sources.gateway.exposed):!!e.sources[s])}</td>`).join('')}
     <td class="auth ${e.auth==='public'?'public':''}">${esc(e.auth)}</td>
     <td><span class="b lc-${e.lifecycle}" title="${esc(LC[e.lifecycle][1])}">${esc(LC[e.lifecycle][0])}</span></td>
     <td>${HAS_M2?`<span class="risk risk-${e.risk||'none'}">${esc(e.risk||'none')}</span>`:'-'}</td>
     <td>${piiCell(e)}</td>
     <td>${e.m3?`<span class="v v-${e.m3.verdict}" title="기준선 ${e.m3.baseline} · 교차 ${e.m3.cross} · 비로그인 ${e.m3.anon}">${esc(V_LABEL[e.m3.verdict]||e.m3.verdict)}</span>`:(HAS_M3?'<span class="sub">-</span>':'')}</td>
     <td>${e.flags.map(f=>`<span class="b fl fl-${f}" title="${esc(FL[f]||'')}">${f}</span>`).join('')}</td></tr>`;
   if(open.has(e.id))html+=`<tr class="detail"><td colspan="12">${detail(e)}</td></tr>`;
 }
 document.getElementById('tb').innerHTML=html;
 document.getElementById('empty').hidden=list.length>0;
 document.querySelectorAll('tr.row').forEach(r=>r.onclick=()=>{const id=r.dataset.id;open.has(id)?open.delete(id):open.add(id);draw();});
}
// 기본 정렬: 위험도 높은 순 유지(서비스 그룹 안에서는 원래 순서)
document.getElementById('defs').innerHTML=
 Object.entries(LC).map(([k,[l,d]])=>`<div><b>${esc(l)}</b>${esc(d)}</div>`).join('')+
 Object.entries(FL).map(([k,d])=>`<div><b>${k}</b>${esc(d)}</div>`).join('');
document.getElementById('q').oninput=ev=>{query=ev.target.value;draw();};

// ----- 탭 전환
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{
 document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('on',x===b));
 document.getElementById('tab-list').hidden=(b.dataset.tab!=='list');
 const vt=document.getElementById('tab-vuln'); if(vt)vt.hidden=(b.dataset.tab!=='vuln');
 if(b.dataset.tab==='vuln')drawVuln();
});

// ----- 확정 취약점 흐름 (홉 시퀀스 + 차분 매트릭스)
let vulnDrawn=false;
const VERDICT_LABEL={vulnerable_bola:'BOLA 확정 (소유권 미검증)',vulnerable_no_auth:'무인증 확정 (인증 누락)'};
const SCEN=[['owner','소유자(A)','기준선'],['cross','다른 사용자(B)','교차 접근'],['anon','비로그인','토큰 없음']];

function seqSVG(s){
 // 세로 생명선(열) + 홉(행). 취약 홉은 빨간색 + 라벨 강조.
 const actors=s.actors, n=actors.length;
 const padX=70, colW=Math.max(150,(640-padX*2)/(n-1)), topY=64, rowH=56;
 const W=padX*2+(n-1)*colW, H=topY+s.hops.length*rowH+30;
 const X=i=>padX+i*colW;
 const idx={}; actors.forEach((a,i)=>idx[a.id]=i);
 let defs=`<defs><marker id="sa" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 1L9 5L0 9z" fill="var(--muted)"/></marker>`+
          `<marker id="sar" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7.5" markerHeight="7.5" orient="auto-start-reverse"><path d="M0 1L9 5L0 9z" fill="var(--crit)"/></marker></defs>`;
 let head='', lines='';
 actors.forEach((a,i)=>{ const x=X(i);
   head+=`<text x="${x}" y="22" text-anchor="middle" font-size="12.5" font-weight="650" fill="var(--ink)">${esc(a.label)}</text>`+
         `<text x="${x}" y="38" text-anchor="middle" font-size="10" fill="var(--muted)">${esc(a.sub||'')}</text>`;
   lines+=`<line x1="${x}" y1="48" x2="${x}" y2="${H-18}" stroke="var(--line)" stroke-width="1.25"/>`;
 });
 let hops='';
 s.hops.forEach((h,i)=>{ const y=topY+i*rowH+24;
   const a=idx[h.from], b=idx[h.to];
   const vuln=!!h.vuln, col=vuln?'var(--crit)':'var(--muted)';
   if(a===b){ // self-call (서비스 내부 검사): 작은 루프
     const x=X(a);
     hops+=`<path d="M${x} ${y} c 34 0, 34 30, 0 30" fill="none" stroke="${col}" stroke-width="1.5" marker-end="url(#${vuln?'sar':'sa'})"/>`;
     hops+=`<text x="${x+42}" y="${y+12}" font-size="11" fill="var(--ink)">${esc(h.label)}</text>`;
     if(h.check_label) hops+=`<text x="${x+42}" y="${y+27}" font-size="10.5" fill="${vuln?'var(--crit)':'var(--muted)'}">${esc((vuln?'✗ ':'✓ ')+h.check_label.split('—').pop().trim())}</text>`;
   }else{
     const x1=X(a), x2=X(b), dir=x2>x1?1:-1;
     hops+=`<line x1="${x1+dir*4}" y1="${y}" x2="${x2-dir*8}" y2="${y}" stroke="${col}" stroke-width="1.5" ${vuln?'stroke-dasharray="6 4"':''} marker-end="url(#${vuln?'sar':'sa'})"/>`;
     const mx=(x1+x2)/2;
     hops+=`<text x="${mx}" y="${y-7}" text-anchor="middle" font-size="11" font-weight="${vuln?650:400}" fill="${vuln?'var(--crit)':'var(--ink)'}">${esc(h.label)}</text>`;
     if(h.check_label){ const cl=h.check_label; const good=h.check==='ok';
       hops+=`<text x="${mx}" y="${y+13}" text-anchor="middle" font-size="10.5" fill="${good?'var(--muted)':'var(--crit)'}">${esc((good?'✓ ':'✗ ')+cl.split(':').pop().split('—').pop().trim())}</text>`;
     }
   }
 });
 return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(s.title)} 호출 시퀀스">${defs}${lines}${head}${hops}</svg>`;
}

function mxTable(s){
 const stcell=(v)=>{ if(v==null)return '<td>-</td>';
   const ok=v>=200&&v<300, cls=ok?'':'okcell';
   return `<td><span class="st" style="background:${ok?'var(--crit-bg)':'var(--ok-bg)'};color:${ok?'var(--crit)':'var(--ok)'}">${v}</span></td>`; };
 let rows='';
 SCEN.forEach(([k,label,sub])=>{ const v=s.scenarios[k];
   const ok2xx=v>=200&&v<300;
   // 소유자 2xx는 정상, 타인/비로그인 2xx는 유출
   const good=(k==='owner')?ok2xx:!ok2xx;
   const mean=(k==='owner')?(ok2xx?'정상 조회':'차단'):(ok2xx?'타인 데이터 접근됨':'차단됨');
   rows+=`<tr><td>${esc(label)}<br><span style="color:var(--muted);font-size:11px">${esc(sub)}</span></td>${stcell(v)}<td style="color:${good?'var(--ok)':'var(--crit)'}">${esc(mean)}</td></tr>`;
 });
 return `<table><thead><tr><th>요청 주체</th><th>응답</th><th>의미</th></tr></thead><tbody>${rows}</tbody></table>`+
        `<div class="caption">같은 요청을 주체만 바꿔 보냈을 때의 실제 응답(M3). 유출된 소유자 식별값: ${s.leaked.map(x=>`<span class="leak">${esc(x)}</span>`).join(', ')}</div>`;
}

function drawVuln(){
 if(vulnDrawn||!D.views)return; vulnDrawn=true;
 const seqs=D.views.sequences||[];
 let html='';
 for(const s of seqs){
   html+=`<div class="vcard">`;
   html+=`<div class="vhead"><span class="vm">${esc(s.title.split(' ')[0])}</span><span class="vp">${esc(s.title.split(' ').slice(1).join(' '))}</span><span class="vv">${esc(VERDICT_LABEL[s.verdict]||s.verdict)}</span></div>`;
   html+=`<div class="vbody"><div class="vseq"><h4>호출 홉 — 인가가 빠진 지점(빨강)</h4>${seqSVG(s)}</div>`;
   html+=`<div class="vmx"><h4>차분 테스트 결과</h4>${mxTable(s)}</div></div>`;
   if(s.code_loc) html+=`<div class="vfoot">근본 원인: <b>${esc(s.code_loc)}</b>${s.handler?' · <code>'+esc(s.handler)+'</code>':''} — 조치방안은 report.md 참조</div>`;
   if(s.codeql&&s.codeql.length&&s.codeql[0].steps&&s.codeql[0].steps.length){
     html+=`<div class="vfoot" style="border-top:none;padding-top:0">`+
       `<b style="color:var(--violet)">CodeQL taint 경로</b> (식별자가 소유권 검사 없이 DB 조회까지): `+
       `<span class="p" style="color:var(--ink)">${s.codeql[0].steps.map(esc).join('  →  ')}</span></div>`;
   }
   html+=`</div>`;
 }
 document.getElementById('vuln-root').innerHTML=html;
}
draw();
</script>
</body>
</html>
""")


def _attach_m3(cfg, endpoints: list[dict]) -> bool:
    """M3 findings(실제 검증 결과)를 엔드포인트에 매핑. 있으면 confirmed 필드 추가."""
    f = rel(cfg, cfg["output_dir"] + "/findings.json")
    if not f.exists():
        return False
    from apisec.common import key, template_regex
    from urllib.parse import urlsplit
    fd = json.loads(f.read_text(encoding="utf-8"))
    tmpls = [(e, template_regex(e["path"])) for e in endpoints if "{*}" not in e["path"]]
    for e in endpoints:
        e["m3"] = None
    for finding in fd["findings"]:
        path = urlsplit(finding["url"]).path
        for e, rx in tmpls:
            if (e["method"] == finding["method"]) and rx.match(path):
                prev = e.get("m3")
                # 같은 엔드포인트에 여러 케이스면 더 심각한 판정 유지
                sev = {"vulnerable_no_auth": 3, "vulnerable_bola": 2, "not_vulnerable": 1, "inconclusive": 0}
                if not prev or sev.get(finding["verdict"], 0) > sev.get(prev["verdict"], 0):
                    e["m3"] = {"verdict": finding["verdict"], "leaked": finding["leaked_signals"],
                               "baseline": finding["baseline_status"], "cross": finding["cross_status"],
                               "anon": finding["anon_status"], "evidence": finding["evidence"]}
                break
    return True


def main() -> None:
    cfg = load_config()
    out_dir = rel(cfg, cfg["output_dir"])
    enriched = out_dir / "enriched_endpoints.json"
    base = enriched if enriched.exists() else out_dir / "endpoints.json"
    data = json.loads(base.read_text(encoding="utf-8"))
    has_m2 = "m2" in data.get("meta", {})
    has_m3 = _attach_m3(cfg, data["endpoints"])
    # M4 확정 취약점 시각화(홉 시퀀스 + 차분 매트릭스)
    views = None
    vpath = out_dir / "vuln_views.json"
    if vpath.exists():
        views = json.loads(vpath.read_text(encoding="utf-8"))
    has_views = bool(views and views.get("sequences"))
    payload = json.dumps({
        "endpoints": data["endpoints"], "lifecycle": LIFECYCLE, "flags": FLAGS,
        "pii_types": PII_TYPES, "has_m2": has_m2, "has_m3": has_m3, "views": views,
    }, ensure_ascii=False, default=list).replace("</", "<\\/")
    html = TEMPLATE.render(
        meta=data["meta"], gen=data["meta"].get("m2", {}).get("generated_at", data["meta"]["generated_at"]),
        has_m2=has_m2, has_m3=has_m3, has_views=has_views, payload=payload,
    )
    out = out_dir / "report.html"
    out.write_text(html, encoding="utf-8")
    stages = "+".join(["M1"] + (["M2"] if has_m2 else []) + (["M3"] if has_m3 else []))
    print(f"[report] {stages} → {out}")


if __name__ == "__main__":
    main()
