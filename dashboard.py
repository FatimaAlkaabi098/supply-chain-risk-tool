"""
BOMShield dashboard generator.

Emits a single self-contained HTML file: no server, no build step, no CDN.
Open it by double-clicking.

The scoring model is implemented twice - once in score.py (Python, the engine)
and once in the dashboard's JavaScript, because the what-if simulator has to
recalculate live in the browser and browsers cannot run Python.

Two implementations of one model is a correctness risk, so the dashboard
RE-SCORES the baseline on load and compares it against the values Python
computed. If they disagree by more than 0.1 the page shows a warning banner.
That check is visible to anyone opening the file.
"""

import json
import os

CSS = """
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 "Segoe UI",Helvetica,Arial,sans-serif;background:#0e1621;color:#e6edf3}
a{color:#5fb3f0}
.wrap{max-width:1500px;margin:0 auto;padding:0 20px 80px}
header{background:#131f2e;border-bottom:1px solid #24354a;padding:14px 0;margin-bottom:20px}
header .wrap{padding-bottom:0;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.brand{font-size:20px;font-weight:700;letter-spacing:.5px}
.brand span{color:#4ea3e0}
.tagline{color:#8fa3b8;font-size:12px}
.spacer{flex:1}
button,label.btn{background:#1d2d40;border:1px solid #2f455e;color:#dbe7f2;padding:7px 13px;
  border-radius:6px;cursor:pointer;font-size:13px}
button:hover,label.btn:hover{background:#26394f}
button.on{background:#1f5c8b;border-color:#2d7cb8;color:#fff}
h2{font-size:13px;text-transform:uppercase;letter-spacing:1px;color:#8fa3b8;
  margin:26px 0 10px;font-weight:600}
.banner{padding:16px 20px;border-radius:8px;margin-bottom:18px;font-weight:600;font-size:16px}
.banner small{display:block;font-weight:400;font-size:13px;opacity:.9;margin-top:5px}
.v-REJECT{background:#5c1a1a;border:1px solid #8e2b2b}
.v-APPROVEWITHCONDITIONS{background:#5c4310;border:1px solid #8e6a1c}
.v-APPROVE{background:#14502e;border:1px solid #1f7a46}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));gap:12px}
.kpi{background:#16233300;background:#162333;border:1px solid #24354a;border-radius:8px;padding:12px 14px}
.kpi .n{font-size:22px;font-weight:700}
.kpi .l{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:#8fa3b8;margin-top:2px}
.dims{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.dim{background:#162333;border:1px solid #24354a;border-radius:8px;padding:12px 14px;cursor:pointer}
.dim:hover{border-color:#3d6a94}
.dim.sel{border-color:#4ea3e0;background:#1a2c40}
.dim .n{font-size:20px;font-weight:700}
.dim .l{font-size:12px;color:#a8bccf}
.dim .w{font-size:11px;color:#7d92a8}
.bar{height:5px;background:#22323f;border-radius:3px;margin-top:8px;overflow:hidden}
.bar i{display:block;height:100%}
.cols{display:grid;grid-template-columns:1fr 380px;gap:18px;align-items:start}
@media(max-width:1100px){.cols{grid-template-columns:1fr}}
.panel{background:#162333;border:1px solid #24354a;border-radius:8px;padding:14px 16px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:7px 9px;border-bottom:1px solid #22303f;text-align:left;vertical-align:top}
th{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#8fa3b8;cursor:pointer;
  user-select:none;white-space:nowrap;position:sticky;top:0;background:#131f2e}
th:hover{color:#cfe0ee}
tbody tr{cursor:pointer}
tbody tr:hover{background:#1b2b3d}
tbody tr.sel{background:#1f3purple}
tbody tr.sel{background:#1f3a55}
.pill{display:inline-block;padding:2px 8px;border-radius:11px;font-size:11px;font-weight:700}
.b-CRITICAL{background:#8e2b2b;color:#fff}
.b-HIGH{background:#a85d1c;color:#fff}
.b-MEDIUM{background:#8a7318;color:#fff}
.b-LOW{background:#2c5f45;color:#dff5e8}
.b-UNKNOWN{background:#3a4756;color:#c8d6e2;border:1px dashed #6b7f94}
.mono{font-family:Consolas,ui-monospace,monospace;font-size:12px;color:#9fb4c8}
.muted{color:#8fa3b8}
.filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
select,input[type=search]{background:#101b28;border:1px solid #2f455e;color:#dbe7f2;
  padding:6px 9px;border-radius:6px;font-size:13px}
.finding{border-left:3px solid #8e2b2b;padding:8px 0 8px 11px;margin-bottom:11px}
.finding b{display:block}
.finding .act{color:#7fc4a0;font-size:12px;margin-top:3px}
.matrix{border-collapse:collapse;font-size:11px;width:100%}
.matrix td,.matrix th{border:1px solid #24354a;text-align:center;padding:6px 4px}
.matrix .cell{cursor:pointer;min-width:40px;height:34px}
.matrix .cell:hover{outline:1px solid #4ea3e0}
.drawer{position:fixed;top:0;right:0;width:440px;max-width:94vw;height:100vh;background:#132030;
  border-left:1px solid #2c4055;overflow-y:auto;padding:18px;z-index:50;
  box-shadow:-14px 0 34px rgba(0,0,0,.5);display:none}
.drawer.open{display:block}
.drawer h3{margin:0 0 3px;font-size:17px}
.close{position:absolute;top:14px;right:16px;cursor:pointer;color:#8fa3b8;font-size:20px}
.note{background:#1a2c40;border-left:3px solid #4ea3e0;padding:9px 12px;margin:9px 0;font-size:13px}
.warn{background:#4a2a10;border-left:3px solid #c8801e}
.ok{background:#14331f;border-left:3px solid #2f9e5e}
.simrow{display:flex;gap:9px;align-items:flex-start;padding:8px 0;border-bottom:1px solid #22303f}
.simrow input{margin-top:3px}
.big{font-size:30px;font-weight:700}
.delta{font-size:15px;font-weight:700}
.up{color:#f08c8c}.down{color:#7fdca8}
"""

JS = r"""
// ---------------------------------------------------------------------------
// Scoring model, mirrored from score.py so the what-if simulator can
// recalculate in the browser. Any change here must be made in score.py too.
// The self-check below proves the two agree.
// ---------------------------------------------------------------------------
const M = DATA.meta, W = M.weights, CRIT = M.criticality;
const DIMS = ["vulnerability","policy","lifecycle","geopolitical","operational"];
const UNK = new Set(["unknown","","n/a","none","-","tbd"]);
const EPSS_MOD = 0.30, KEV_FLOOR = 90, COVERAGE_TARGET = M.coverage_target;
const POLICY_SCORES = {restricted:100, review:60};
const TIER = {"1":10,"2":40,"3":70}, UNDECLARED = 70;
const EOL = {yes:80, unknown:40, no:0};
const CRITICAL_CATS = new Set(["bmc","firmware","cpu","gpu"]);
// Vulnerability and Policy describe conditions true NOW, so either can floor a
// component's score on its own; a weighted mean would average them away.
const DOMINANT = ["vulnerability","policy"], DOMINANCE = 0.85;
// A BOM is not acceptable because most of it is fine.
const WORST_FLOOR = 0.70;

const low = v => (v==null?"":String(v)).trim().toLowerCase();
const isUnk = v => UNK.has(low(v));
const num = v => { const n = parseFloat(v); return isNaN(n)?null:n; };

function vtuple(v){
  if(isUnk(v)) return null;
  const out=[];
  for(const p of low(v).split(/[._-]/)){
    if(/^\d+$/.test(p)) out.push(parseInt(p,10));
    else { const m=/^(\d+)/.exec(p); if(!m) return null; out.push(parseInt(m[1],10)); }
  }
  return out.length?out:null;
}
function cmpV(a,b){
  const ta=vtuple(a), tb=vtuple(b); if(!ta||!tb) return null;
  const n=Math.max(ta.length,tb.length);
  for(let i=0;i<n;i++){ const x=ta[i]||0, y=tb[i]||0; if(x!==y) return x>y?1:-1; }
  return 0;
}
function inRange(version,range){
  if(!range||isUnk(range)||low(range)==="unspecified") return false;
  for(const tok of range.split(/\s+/)){
    const m=/^(>=|<=|>|<)(.+)$/.exec(tok); if(!m) return false;
    const c=cmpV(version,m[2]); if(c===null) return false;
    if(m[1]===">="&&c<0) return false;
    if(m[1]===">"&&c<=0) return false;
    if(m[1]==="<="&&c>0) return false;
    if(m[1]==="<"&&c>=0) return false;
  }
  return true;
}
const identifiable = c => !(isUnk(c.vendor)||isUnk(c.model)||isUnk(c.version));
function band(s){ for(const [t,n] of M.bands){ if(s>=t) return n; } return "LOW"; }

function singleSourceCats(bom){
  const map={};
  bom.forEach(c=>{ (map[c.category]=map[c.category]||new Set()).add(c.vendor); });
  return new Set(Object.keys(map).filter(k=>map[k].size===1));
}

function dimVuln(c, cves){
  const hits = cves.filter(v => low(c.vendor)===low(v.vendor) && low(c.model)===low(v.product)
                                && inRange(c.version, v.version_affected));
  if(!hits.length) return {score:0, cves:[], reasons:[]};
  hits.sort((a,b)=>(num(b.cvss_score)||0)-(num(a.cvss_score)||0) || a.cve_id.localeCompare(b.cve_id));
  const worst=hits[0], cvss=num(worst.cvss_score)||0; let s=cvss*10; const reasons=[];
  const pct=num(worst.epss_percentile);
  if(pct===null){ reasons.push(`CVSS ${cvss} with no EPSS data - severity used unmodulated`); }
  else { s = s*((1-EPSS_MOD)+EPSS_MOD*pct);
         reasons.push(`CVSS ${cvss} modulated by EPSS percentile ${pct.toFixed(2)} (exploitation likelihood)`); }
  if(hits.some(h=>low(h.kev).startsWith("y"))){
    s=Math.max(s,KEV_FLOOR);
    reasons.push("Listed in the CISA Known Exploited Vulnerabilities catalogue - exploitation is observed, not predicted");
  }
  return {score:Math.min(100,s), cves:hits, reasons};
}
function dimPolicy(c, policy){
  const r=policy.vendors[low(c.vendor)];
  if(!r) return {score:0, reasons:[], blocking:false};
  const tier=low(r.risk_tier);
  return {score:POLICY_SCORES[tier]??50,
          reasons:[`Vendor '${c.vendor}' is ${tier}: ${r.justification}`],
          blocking:low(r.action)==="block"};
}
function dimLifecycle(c){
  const e=low(c.end_of_life), s=EOL[e]??EOL.unknown;
  if(e==="yes") return {score:s,reasons:["End of life - will receive no further security updates"]};
  if(e!=="no") return {score:s,reasons:["Lifecycle status not declared by the supplier"]};
  return {score:s,reasons:[]};
}
function dimGeo(c, policy){
  if(isUnk(c.country_of_origin))
    return {score:UNDECLARED,reasons:["Country of origin not declared - provenance cannot be verified"]};
  const r=policy.countries[low(c.country_of_origin)];
  if(!r) return {score:TIER["3"],reasons:[`Origin '${c.country_of_origin}' is not covered by the policy file`]};
  const s=TIER[r.risk_tier]??40;
  return {score:s, reasons: s<=10?[]:[`Origin ${c.country_of_origin} is tier ${r.risk_tier}: ${r.justification}`]};
}
function dimOps(c, ssc){
  let s=0; const reasons=[]; const alt=low(c.validated_alternative);
  if(alt==="no"){ s+=50; reasons.push("No validated alternative supplier has been qualified"); }
  else if(UNK.has(alt)){ s+=30; reasons.push("Whether an alternative supplier exists has not been established"); }
  if(ssc.has(c.category)){ s+=30; reasons.push(`Single-source dependency - '${c.category}' is supplied only by ${c.vendor}`); }
  const w=num(c.lead_time_weeks);
  if(w!==null){ if(w>=26){ s+=30; reasons.push(`Very long lead time - ${w} weeks`); }
                else if(w>=16){ s+=20; reasons.push(`Long lead time - ${w} weeks`); } }
  return {score:Math.min(100,s), reasons};
}

function firstFixed(range){
  if(!range) return null;
  const toks=range.split(/\s+/);
  for(const t of toks){ const m=/^<(?!=)(.+)$/.exec(t); if(m) return m[1]; }
  for(const t of toks){ const m=/^<=(.+)$/.exec(t); if(m){
    const parts=m[1].split("."); const n=parseInt(parts[parts.length-1],10);
    if(isNaN(n)) return null; parts[parts.length-1]=String(n+1); return parts.join("."); } }
  return null;
}
function suggestMitigation(c, cves, blocking, bom, reasons){
  if(cves.length){
    let t = M.cwe_mitigations[String(cves[0].cwe||"").trim()] || M.default_mitigation;
    if(low(cves[0].fix_available).startsWith("y")){
      const f=firstFixed(cves[0].version_affected);
      if(f) t += ` Upgrade to ${f} or later.`;
    }
    return t;
  }
  if(blocking){
    const alts=[...new Set(bom.filter(x=>x.category===c.category&&x.vendor!==c.vendor).map(x=>x.vendor))].sort();
    return alts.length
      ? "Vendor is blocked by policy. Substitute an approved supplier already in this BOM for the same category: "+alts.join(", ")+"."
      : "Vendor is blocked by policy and no alternative appears in this BOM. Re-tender this line item.";
  }
  if(!identifiable(c))
    return "Obtain vendor, model and version from the supplier before purchase. Provenance that cannot be established cannot be assessed.";
  if(reasons.operational.length)
    return "Qualify and validate a second supplier to remove the single-source dependency.";
  if(reasons.lifecycle.length)
    return "Plan replacement before end of support and confirm the successor part now.";
  return "No action required. Re-assess if the component version changes.";
}

function scoreComponent(c, cves, policy, ssc, bom){
  const ident=identifiable(c), d={}, reasons={};
  const v = ident ? dimVuln(c,cves) : {score:0,cves:[],reasons:[]};
  d.vulnerability=v.score; reasons.vulnerability=v.reasons;
  const p=dimPolicy(c,policy); d.policy=p.score; reasons.policy=p.reasons;
  const l=dimLifecycle(c);     d.lifecycle=l.score; reasons.lifecycle=l.reasons;
  const g=dimGeo(c,policy);    d.geopolitical=g.score; reasons.geopolitical=g.reasons;
  const o=dimOps(c,ssc);       d.operational=o.score; reasons.operational=o.reasons;
  const mult=CRIT[c.category]??1.0;
  const base=DIMS.reduce((a,k)=>a+W[k]*d[k],0);
  const weighted=base*mult;
  const floor=Math.max(...DOMINANT.map(k=>d[k]*DOMINANCE));
  const final=Math.min(100, Math.max(weighted, floor));
  const driver = weighted>=floor ? "weighted profile"
                 : DOMINANT.reduce((a,b)=>d[a]>=d[b]?a:b);
  DIMS.forEach(k=>d[k]=Math.round(d[k]*10)/10);
  return {component:c, identifiable:ident, dimensions:d, reasons,
          base:Math.round(base*10)/10, weighted:Math.round(weighted*10)/10,
          floor:Math.round(floor*10)/10, driver,
          multiplier:mult, cves:v.cves, blocking:p.blocking,
          score: ident?Math.round(final*10)/10:null,
          normalised: ident?Math.round(final)/100:null,
          band: ident?band(final):"UNKNOWN",
          status: ident?"SCORED":"NOT SCORED",
          mitigation: suggestMitigation(c, v.cves, p.blocking, bom||[], reasons)};
}

function scoreAll(bom, cves, policy){
  const ssc=singleSourceCats(bom);
  const scored=bom.map(c=>scoreComponent(c,cves,policy,ssc,bom));
  const rated=scored.filter(r=>r.identifiable);
  const wsum=rated.reduce((a,r)=>a+r.score*r.multiplier,0);
  const wtot=rated.reduce((a,r)=>a+r.multiplier,0)||1;
  const mean=wsum/wtot;

  let penalty=0; const conc=[]; const total=bom.length;
  const counts={}; bom.forEach(c=>counts[c.country_of_origin]=(counts[c.country_of_origin]||0)+1);
  const top=Object.entries(counts).sort((a,b)=>b[1]-a[1])[0];
  const share=top[1]/total;
  if(share>0.40){ penalty+=Math.min(15,(share-0.40)*50);
    conc.push(`BREACH: ${top[1]} of ${total} components (${Math.round(share*100)}%) originate in ${top[0]} - above the 40% threshold`); }
  else conc.push(`Largest single origin is ${top[0]} at ${top[1]} of ${total} (${Math.round(share*100)}%) - within the 40% threshold`);
  const undecl=bom.filter(c=>isUnk(c.country_of_origin)).length;
  if(undecl) conc.push(`${undecl} of ${total} components (${Math.round(undecl/total*100)}%) do not declare an origin, so true concentration may be higher`);
  const vend={}; bom.forEach(c=>(vend[c.category]=vend[c.category]||new Set()).add(c.vendor));
  Object.keys(vend).filter(k=>CRITICAL_CATS.has(k)).sort().forEach(k=>{
    if(vend[k].size===1){ penalty+=5;
      conc.push(`All '${k}' components come from a single vendor (${[...vend[k]][0]}) - no second source`); }
  });
  penalty=Math.min(15,penalty);

  const worst=rated.length?Math.max(...rated.map(r=>r.score)):0;
  const portfolio=mean+penalty;
  const overall=Math.min(100, Math.max(portfolio, worst*WORST_FLOOR));
  const coverage=total?rated.length/total:0;
  const blocked=rated.filter(r=>r.blocking);
  const criticals=rated.filter(r=>r.band==="CRITICAL");
  let verdict,banner,rationale;
  if(blocked.length){ verdict="REJECT"; banner="PROCUREMENT REVIEW REQUIRED";
    rationale=`${blocked.length} component(s) come from a vendor blocked by procurement policy. A restricted supplier is a compliance decision, not a risk trade-off.`; }
  else if(criticals.length||coverage<COVERAGE_TARGET){ verdict="APPROVE WITH CONDITIONS"; banner="ACCEPTABLE WITH MITIGATIONS";
    const parts=[]; if(criticals.length) parts.push(`${criticals.length} component(s) score CRITICAL and must be remediated before deployment`);
    if(coverage<COVERAGE_TARGET) parts.push(`provenance could not be established for ${total-rated.length} component(s)`);
    rationale=parts.join("; ")+"."; }
  else { verdict="APPROVE"; banner="ACCEPTABLE";
    rationale="No blocking policy findings, no critical components, and provenance established for at least 90% of the BOM."; }

  const dmeans={}; DIMS.forEach(d=>dmeans[d]= rated.length?Math.round(rated.reduce((a,r)=>a+r.dimensions[d],0)/rated.length*10)/10:0);
  const bandCounts={}; scored.forEach(r=>bandCounts[r.band]=(bandCounts[r.band]||0)+1);
  return {scored, rated, overall:Math.round(overall*10)/10, mean:Math.round(mean*10)/10,
          worst:Math.round(worst*10)/10, portfolio:Math.round(portfolio*10)/10,
          overall_driver: worst*WORST_FLOOR>portfolio?"worst component":"portfolio profile",
          penalty:Math.round(penalty*10)/10, concentration:conc, coverage, blocked, criticals,
          verdict, banner, rationale, dimension_means:dmeans, band_counts:bandCounts,
          countries:counts, total};
}

// --------------------------------------------------------------------------
// State
// --------------------------------------------------------------------------
let RAW = JSON.parse(JSON.stringify(DATA.raw));
let applied = new Set();     // what-if: indices into DATA.plan.candidates
let live = null;             // current scoreAll result
let selected = null;         // component id in the drawer
let sortKey = "score", sortDir = -1;
let filters = {band:"", category:"", vendor:"", country:"", status:"", q:"", actionable:false, dim:""};

function currentBom(){
  const changes={};
  [...applied].forEach(i=>{ const a=DATA.plan.candidates[i];
    changes[a.component_id]=Object.assign(changes[a.component_id]||{}, a.change); });
  return RAW.bom.map(c=>Object.assign({},c,changes[c.component_id]||{}));
}
function recompute(){ live = scoreAll(currentBom(), RAW.cves, RAW.policy); render(); }

const esc = s => String(s??"").replace(/[&<>"]/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[m]));
const el = id => document.getElementById(id);
function barColour(v){ return v>=75?"#c04141":v>=50?"#c9761f":v>=25?"#b09a1e":"#2f9e5e"; }

// --------------------------------------------------------------------------
// Render
// --------------------------------------------------------------------------
function render(){
  const s = live;
  el("banner").className = "banner v-"+s.verdict.replace(/ /g,"");
  el("banner").innerHTML = `${esc(s.banner)} &middot; ${esc(s.verdict)}<small>${esc(s.rationale)}</small>`;

  const kpi=[["Overall BOM risk", `${s.overall}/100`, band(s.overall)],
             ["Normalised", (s.overall/100).toFixed(2), ""],
             ["Worst component", s.worst, ""],
             ["Components", s.total, ""],
             ["Critical", s.band_counts.CRITICAL||0, ""],
             ["High", s.band_counts.HIGH||0, ""],
             ["Not scored", s.total-s.rated.length, ""],
             ["Data confidence", Math.round(s.coverage*100)+"%", ""],
             ["Restricted vendors", new Set(s.blocked.map(r=>r.component.vendor)).size, ""],
             ["Known CVEs", s.scored.reduce((a,r)=>a+r.cves.length,0), ""]];
  el("kpis").innerHTML = kpi.map(([l,n,b])=>
    `<div class="kpi"><div class="n">${esc(n)}${b?` <span class="pill b-${b}" style="font-size:10px">${b}</span>`:""}</div><div class="l">${esc(l)}</div></div>`).join("");

  el("dims").innerHTML = DIMS.map(d=>{
    const v=s.dimension_means[d];
    return `<div class="dim ${filters.dim===d?"sel":""}" onclick="toggleDim('${d}')">
      <div class="n">${v}</div><div class="l">${esc(M.dimension_labels[d])}</div>
      <div class="w">weight ${W[d]} &middot; click to sort</div>
      <div class="bar"><i style="width:${v}%;background:${barColour(v)}"></i></div></div>`;
  }).join("");

  // filter option lists
  const opts=(key,label)=>{
    const vals=[...new Set(RAW.bom.map(c=>c[key]))].sort();
    return `<select onchange="setFilter('${label}',this.value)">
      <option value="">${label[0].toUpperCase()+label.slice(1)}: all</option>
      ${vals.map(v=>`<option ${filters[label]===v?"selected":""}>${esc(v)}</option>`).join("")}</select>`;
  };
  el("filters").innerHTML = `
    <input type="search" placeholder="Search component, vendor or CVE" value="${esc(filters.q)}"
      oninput="setFilter('q',this.value)" style="min-width:260px">
    <select onchange="setFilter('band',this.value)">
      <option value="">Risk: all</option>
      ${["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"].map(b=>`<option ${filters.band===b?"selected":""}>${b}</option>`).join("")}
    </select>
    ${opts("category","category")}${opts("vendor","vendor")}${opts("country_of_origin","country")}
    <button class="${filters.actionable?"on":""}" onclick="setFilter('actionable',!filters.actionable)">Actionable only</button>
    <button onclick="clearFilters()">Clear</button>`;

  const rows = visible();
  const H=(k,t)=>`<th onclick="sortBy('${k}')">${t}${sortKey===k?(sortDir<0?" ▼":" ▲"):""}</th>`;
  el("table").innerHTML = `<thead><tr>
      ${H("id","ID")}${H("name","Component")}${H("vendor","Vendor")}${H("version","Version")}
      ${H("country","Origin")}${H("score","Risk")}
      ${DIMS.map(d=>H(d, M.dimension_labels[d].split(" ")[0])).join("")}
      ${H("band","Status")}</tr></thead><tbody>${
    rows.map(r=>{const c=r.component; return `<tr onclick="openDrawer('${c.component_id}')" class="${selected===c.component_id?"sel":""}">
      <td class="mono">${esc(c.component_id)}</td><td>${esc(c.component_name)}</td>
      <td>${esc(c.vendor)}</td><td class="mono">${esc(c.version)}</td><td class="mono">${esc(c.country_of_origin)}</td>
      <td><b>${r.score===null?"&mdash;":r.score}</b></td>
      ${DIMS.map(d=>`<td class="mono">${r.dimensions[d]}</td>`).join("")}
      <td><span class="pill b-${r.band}">${r.band}</span></td></tr>`;}).join("")
    }</tbody>`;
  el("rowcount").textContent = `${rows.length} of ${s.total} components`;

  // priority findings
  const top = s.scored.filter(r=>r.score!==null).sort((a,b)=>b.score-a.score).slice(0,4);
  el("findings").innerHTML = top.map((r,i)=>{
    const c=r.component, why=r.cves.length?`${r.cves[0].cve_id} &middot; CVSS ${r.cves[0].cvss_score}`
      :(r.blocking?"Restricted vendor":DIMS.map(d=>r.reasons[d][0]).filter(Boolean)[0]||"");
    return `<div class="finding" style="border-left-color:${barColour(r.score)}">
      <b>#${i+1} ${esc(c.component_name)} &mdash; ${r.score}/100</b>
      <span class="mono">${esc(c.vendor)} ${esc(c.model)}</span><br>
      <span class="muted">${esc(why)}</span>
      <div class="act">&rarr; ${esc(r.mitigation.split(".")[0])}.</div></div>`;
  }).join("");

  renderMatrix(s); renderGeo(s); renderOps(s); renderConfidence(s); renderSim(s);
}

function visible(){
  let rows = live.scored.slice();
  const f=filters, q=f.q.toLowerCase();
  if(f.band) rows=rows.filter(r=>r.band===f.band);
  if(f.category) rows=rows.filter(r=>r.component.category===f.category);
  if(f.vendor) rows=rows.filter(r=>r.component.vendor===f.vendor);
  if(f.country) rows=rows.filter(r=>r.component.country_of_origin===f.country);
  if(f.actionable) rows=rows.filter(r=>r.band==="CRITICAL"||r.band==="HIGH"||r.band==="UNKNOWN"||r.blocking);
  if(q) rows=rows.filter(r=>{const c=r.component;
    return (c.component_name+" "+c.vendor+" "+c.model+" "+c.component_id+" "+
            r.cves.map(x=>x.cve_id).join(" ")).toLowerCase().includes(q);});
  const key=sortKey;
  rows.sort((a,b)=>{
    let x,y;
    if(DIMS.includes(key)){ x=a.dimensions[key]; y=b.dimensions[key]; }
    else if(key==="score"){ x=a.score===null?-1:a.score; y=b.score===null?-1:b.score; }
    else if(key==="id"){ x=a.component.component_id; y=b.component.component_id; }
    else if(key==="name"){ x=a.component.component_name; y=b.component.component_name; }
    else if(key==="vendor"){ x=a.component.vendor; y=b.component.vendor; }
    else if(key==="version"){ x=a.component.version; y=b.component.version; }
    else if(key==="country"){ x=a.component.country_of_origin; y=b.component.country_of_origin; }
    else { x=a.band; y=b.band; }
    if(typeof x==="string") return sortDir*x.localeCompare(y);
    return sortDir*((x>y)-(x<y));
  });
  return rows;
}
function sortBy(k){ if(sortKey===k) sortDir=-sortDir; else {sortKey=k; sortDir=-1;} render(); }
function setFilter(k,v){ filters[k]=v; render(); }
function toggleDim(d){ filters.dim = filters.dim===d?"":d; if(filters.dim){sortKey=d;sortDir=-1;} render(); }
function clearFilters(){ filters={band:"",category:"",vendor:"",country:"",status:"",q:"",actionable:false,dim:""}; render(); }

// severity x likelihood
function renderMatrix(s){
  const sevBands=[["Low",0,4],["Medium",4,7],["High",7,9],["Critical",9,10.1]];
  const likBands=[["Very high",.75,1.01],["High",.5,.75],["Medium",.25,.5],["Low",0,.25]];
  const cells={};
  s.scored.forEach(r=>r.cves.forEach(v=>{
    const cvss=parseFloat(v.cvss_score)||0, pct=parseFloat(v.epss_percentile);
    const si=sevBands.findIndex(b=>cvss>=b[1]&&cvss<b[2]);
    const li=likBands.findIndex(b=>!isNaN(pct)&&pct>=b[1]&&pct<b[2]);
    if(si<0||li<0) return;
    (cells[li+"_"+si]=cells[li+"_"+si]||[]).push({id:r.component.component_id,cve:v.cve_id});
  }));
  let h=`<table class="matrix"><tr><th></th><th colspan="4">SEVERITY (CVSS)</th></tr>
    <tr><th>LIKELIHOOD<br><span class="muted" style="font-weight:400">(EPSS pct)</span></th>${sevBands.map(b=>`<th>${b[0]}</th>`).join("")}</tr>`;
  likBands.forEach((lb,li)=>{
    h+=`<tr><th>${lb[0]}</th>`;
    sevBands.forEach((sb,si)=>{
      const c=cells[li+"_"+si]||[];
      const bg=c.length?barColour(Math.min(100,(si+1)*22+(3-li)*12)):"transparent";
      h+=`<td class="cell" style="background:${c.length?bg:"#101b28"}"
           title="${esc(c.map(x=>x.id+" "+x.cve).join(", "))}"
           onclick="${c.length?`openDrawer('${c[0].id}')`:""}">${c.length||""}</td>`;
    });
    h+="</tr>";
  });
  el("matrix").innerHTML = h+"</table><div class='muted' style='font-size:12px;margin-top:7px'>"+
    "Severity from CVSS, likelihood from the EPSS percentile. Click a populated cell to open the component.</div>";
}

function renderGeo(s){
  const total=s.total, rows=Object.entries(s.countries).sort((a,b)=>b[1]-a[1]);
  const tierOf=c=>{ const r=RAW.policy.countries[low(c)]; return isUnk(c)?"undeclared":(r?("tier "+r.risk_tier):"not in policy"); };
  el("geo").innerHTML = `<table><tr><th>Origin</th><th>Components</th><th>Share</th><th>Policy</th></tr>${
    rows.map(([c,n])=>`<tr><td>${esc(c)}</td><td class="mono">${n}</td>
      <td class="mono">${Math.round(n/total*100)}%</td><td class="mono">${esc(tierOf(c))}</td></tr>`).join("")}</table>
    ${s.concentration.map(f=>`<div class="note ${f.startsWith("BREACH")?"warn":""}">${esc(f)}</div>`).join("")}`;
}

function renderOps(s){
  const bom=currentBom();
  const noAlt=bom.filter(c=>low(c.validated_alternative)==="no");
  const unkAlt=bom.filter(c=>UNK.has(low(c.validated_alternative)));
  const longLead=bom.filter(c=>{const w=num(c.lead_time_weeks); return w!==null&&w>=16;});
  const eol=bom.filter(c=>low(c.end_of_life)==="yes");
  const ssc=singleSourceCats(bom);
  const inSS=bom.filter(c=>ssc.has(c.category));
  const critical=s.scored.filter(r=>r.band==="CRITICAL"||r.band==="HIGH").map(r=>r.component);
  const critNoAlt=critical.filter(c=>low(c.validated_alternative)!=="yes").length;
  const idx = critical.length?Math.round(critNoAlt/critical.length*100):0;
  el("ops").innerHTML = `
    <table>
      <tr><td>Single-source components</td><td class="mono"><b>${inSS.length}</b></td></tr>
      <tr><td>No validated alternative</td><td class="mono"><b>${noAlt.length}</b></td></tr>
      <tr><td>Alternative status unknown</td><td class="mono"><b>${unkAlt.length}</b></td></tr>
      <tr><td>Long lead time (&ge;16 weeks)</td><td class="mono"><b>${longLead.length}</b></td></tr>
      <tr><td>End of life</td><td class="mono"><b>${eol.length}</b></td></tr>
    </table>
    <div class="note ${idx>=50?"warn":""}"><b>Supply Concentration Index: ${idx}%</b><br>
      ${critNoAlt} of ${critical.length} high or critical components have no validated alternative supplier.</div>`;
}

function renderConfidence(s){
  const unknown=s.scored.filter(r=>!r.identifiable);
  el("confidence").innerHTML = `
    <div class="big">${Math.round(s.coverage*100)}%</div>
    <div class="muted" style="margin-bottom:9px">data confidence &middot; ${s.rated.length} scored, ${unknown.length} not scored</div>
    <div class="note warn"><b>Unknown components are excluded from automatic "safe" classification.</b><br>
      A component whose identity cannot be established is reported as <b>NOT SCORED</b>, never as 0.</div>
    ${unknown.length?`<table><tr><th>ID</th><th>Component</th><th>Missing</th></tr>${
      unknown.map(r=>{const c=r.component; const miss=["vendor","model","version"].filter(f=>isUnk(c[f]));
        return `<tr onclick="openDrawer('${c.component_id}')" style="cursor:pointer">
          <td class="mono">${esc(c.component_id)}</td><td>${esc(c.component_name)}</td>
          <td class="mono">${miss.join(", ")}</td></tr>`;}).join("")}</table>`:""}`;
}

// --------------------------------------------------------------------------
// What-if procurement simulator
// --------------------------------------------------------------------------
function renderSim(s){
  const base=DATA.summary.overall;
  const delta=Math.round((s.overall-base)*10)/10;
  const cands=DATA.plan?DATA.plan.candidates:[];
  el("simhead").innerHTML = `
    <div style="display:flex;gap:26px;align-items:baseline;flex-wrap:wrap">
      <div><div class="muted">Original BOM risk</div><div class="big">${base}</div></div>
      <div><div class="muted">After selected changes</div><div class="big">${s.overall}</div></div>
      <div><div class="muted">Change</div>
        <div class="delta ${delta>0?"up":(delta<0?"down":"")}">${delta>0?"+":""}${delta} points</div></div>
      <div><div class="muted">Data confidence</div><div class="delta">${Math.round(s.coverage*100)}%</div></div>
      <div><div class="muted">Verdict</div><div class="delta">${esc(s.verdict)}</div></div>
      <div class="spacer"></div>
      <button onclick="applyPlan()">Apply recommended plan</button>
      <button onclick="clearSim()">Reset</button>
    </div>`;
  el("simlist").innerHTML = cands.map((a,i)=>`
    <label class="simrow">
      <input type="checkbox" ${applied.has(i)?"checked":""} onchange="toggleAction(${i})">
      <span><span class="pill b-LOW">${esc(a.type)}</span> ${esc(a.label)}<br>
        <span class="mono">${esc(a.component_id)} &middot; ${esc(a.detail)} &middot; effort ${esc(a.effort)}
        &middot; alone: -${a.saving}</span></span></label>`).join("");
}
function toggleAction(i){ applied.has(i)?applied.delete(i):applied.add(i); recompute(); }
function clearSim(){ applied.clear(); recompute(); }
function applyPlan(){
  applied.clear();
  (DATA.plan?DATA.plan.steps:[]).forEach(st=>{
    const i=DATA.plan.candidates.findIndex(c=>c.component_id===st.component_id&&c.type===st.type);
    if(i>=0) applied.add(i);
  });
  recompute();
}

// --------------------------------------------------------------------------
// Drill-down drawer
// --------------------------------------------------------------------------
function openDrawer(id){
  const r=live.scored.find(x=>x.component.component_id===id); if(!r) return;
  selected=id; const c=r.component;
  const rows=DIMS.map(d=>`<tr><td>${esc(M.dimension_labels[d])}</td>
      <td class="mono">${r.dimensions[d]}</td><td class="mono">${W[d]}</td>
      <td>${r.reasons[d].length?r.reasons[d].map(esc).join("<br>"):'<span class="muted">no finding</span>'}</td></tr>`).join("");
  const ev=r.cves.map(v=>`<div class="note">
      <b>${esc(v.cve_id)}</b> &middot; CVSS ${esc(v.cvss_score)} ${esc(v.severity)} (${esc(v.score_source)})
      &middot; ${esc(v.cwe)}<br>
      <span class="mono">KEV: ${esc(v.kev)} &middot; EPSS: ${esc(v.epss)} (percentile ${esc(v.epss_percentile)})</span><br>
      ${esc(v.description)}</div>`).join("") || '<div class="muted">No matching CVE in the dataset.</div>';
  el("drawer").innerHTML = `<span class="close" onclick="closeDrawer()">&times;</span>
    <h3>${esc(c.component_name)}</h3>
    <div class="mono" style="margin-bottom:6px">${esc(c.component_id)} &middot; ${esc(c.vendor)} ${esc(c.model)} ${esc(c.version)}</div>
    <div style="margin-bottom:12px"><span class="pill b-${r.band}">${r.band}</span>
      <b style="font-size:20px;margin-left:8px">${r.score===null?"NOT SCORED":r.score+"/100"}</b>
      ${r.score!==null?`<span class="muted">(${(r.score/100).toFixed(2)} normalised)</span>`:""}</div>
    <h2>Why this score</h2>
    <table><tr><th>Dimension</th><th>Score</th><th>Weight</th><th>Reason</th></tr>${rows}</table>
    <div class="mono" style="margin-top:7px">weighted base ${r.base} &times; ${r.multiplier} (${esc(c.category)} criticality) = ${r.weighted}
      <br>dominance floor ${r.floor} (highest of Vulnerability / Policy &times; ${DOMINANCE})
      <br><b>score = ${r.score===null?"not scored":r.score}</b>, set by the ${esc(r.driver)}</div>
    <h2>Procurement data</h2>
    <table>
      <tr><td>Origin</td><td class="mono">${esc(c.country_of_origin)}</td></tr>
      <tr><td>Quantity</td><td class="mono">${esc(c.quantity)}</td></tr>
      <tr><td>Lead time</td><td class="mono">${esc(c.lead_time_weeks)} weeks</td></tr>
      <tr><td>Validated alternative</td><td class="mono">${esc(c.validated_alternative)}</td></tr>
      <tr><td>End of life</td><td class="mono">${esc(c.end_of_life)}</td></tr>
    </table>
    <h2>Evidence</h2>${ev}
    <h2>Recommended action</h2><div class="note ok">${esc(r.mitigation)}</div>`;
  el("drawer").classList.add("open"); render();
}
function closeDrawer(){ selected=null; el("drawer").classList.remove("open"); render(); }

// --------------------------------------------------------------------------
// CSV upload - score a different BOM in the browser
// --------------------------------------------------------------------------
function parseCSV(text){
  const rows=[]; let row=[], field="", q=false;
  text=text.replace(/^﻿/,"");
  for(let i=0;i<text.length;i++){
    const ch=text[i];
    if(q){ if(ch==='"'){ if(text[i+1]==='"'){field+='"';i++;} else q=false; } else field+=ch; }
    else if(ch==='"') q=true;
    else if(ch===","){ row.push(field); field=""; }
    else if(ch==="\n"){ row.push(field); rows.push(row); row=[]; field=""; }
    else if(ch!=="\r") field+=ch;
  }
  if(field.length||row.length){ row.push(field); rows.push(row); }
  if(!rows.length) return [];
  const head=rows[0].map(h=>h.trim());
  return rows.slice(1).filter(r=>r.some(v=>v.trim()))
             .map(r=>Object.fromEntries(head.map((h,i)=>[h,(r[i]||"").trim()])));
}
function uploadBom(input){
  const file=input.files[0]; if(!file) return;
  const reader=new FileReader();
  reader.onload=e=>{
    try{
      const rows=parseCSV(e.target.result);
      const need=["component_id","component_name","category","vendor","model","version",
                  "country_of_origin","quantity","end_of_life","lead_time_weeks","validated_alternative"];
      const miss=need.filter(c=>!(c in (rows[0]||{})));
      if(!rows.length) throw new Error("the file has headers but no data rows");
      if(miss.length) throw new Error("missing required column(s): "+miss.join(", "));
      RAW.bom=rows; applied.clear(); selected=null;
      el("uploadmsg").innerHTML=`<span class="mono">Loaded ${esc(file.name)} - ${rows.length} components. `+
        `The remediation list below still reflects the original BOM.</span>`;
      recompute();
    }catch(err){
      el("uploadmsg").innerHTML=`<span style="color:#f08c8c">Cannot read ${esc(file.name)}: ${esc(err.message)}</span>`;
    }
  };
  reader.readAsText(file);
}
function resetBom(){ RAW=JSON.parse(JSON.stringify(DATA.raw)); applied.clear(); selected=null;
  el("uploadmsg").textContent=""; recompute(); }

// --------------------------------------------------------------------------
// Self-check: does the browser model agree with the Python engine?
// --------------------------------------------------------------------------
function selfCheck(){
  const check=scoreAll(JSON.parse(JSON.stringify(DATA.raw.bom)), DATA.raw.cves, DATA.raw.policy);
  const diffs=[];
  if(Math.abs(check.overall-DATA.summary.overall)>0.1)
    diffs.push(`overall ${check.overall} vs ${DATA.summary.overall}`);
  DATA.components.forEach(pc=>{
    const jc=check.scored.find(r=>r.component.component_id===pc.id);
    if(!jc) return diffs.push(pc.id+" missing");
    if(pc.score===null){ if(jc.score!==null) diffs.push(pc.id+" scored in JS but not Python"); return; }
    if(Math.abs((jc.score??-1)-pc.score)>0.1) diffs.push(`${pc.id} ${jc.score} vs ${pc.score}`);
  });
  const box=el("selfcheck");
  if(diffs.length){ box.className="note warn";
    box.innerHTML=`<b>Model mismatch:</b> the dashboard's scoring disagrees with the Python engine on ${diffs.length} value(s): ${esc(diffs.slice(0,4).join("; "))}`; }
  else { box.className="note ok";
    box.innerHTML=`<b>Model verified.</b> The dashboard re-scored all ${DATA.components.length} components in the browser and matched the Python engine exactly, including the overall score of ${DATA.summary.overall}/100.`; }
}

recompute(); selfCheck();
document.addEventListener("keydown",e=>{ if(e.key==="Escape") closeDrawer(); });
"""


def _body():
    return """
<header><div class="wrap">
  <div><div class="brand">BOM<span>SHIELD</span></div>
       <div class="tagline">AI Server Supply-Chain Risk Assessment</div></div>
  <div class="spacer"></div>
  <span class="mono" id="rowcount"></span>
  <label class="btn">Upload BOM (CSV)
    <input type="file" accept=".csv" onchange="uploadBom(this)" style="display:none"></label>
  <button onclick="resetBom()">Demo BOM</button>
  <button onclick="window.print()">Print</button>
</div></header>

<div class="wrap">
  <div id="banner" class="banner"></div>
  <div id="uploadmsg" style="margin-bottom:10px"></div>
  <div id="kpis" class="kpis"></div>

  <h2>Risk dimensions &mdash; adaptive scoring</h2>
  <div id="dims" class="dims"></div>

  <div class="cols" style="margin-top:22px">
    <div>
      <h2>Component risk</h2>
      <div id="filters" class="filters"></div>
      <div class="panel" style="padding:0;max-height:560px;overflow:auto">
        <table id="table"></table>
      </div>
    </div>
    <div>
      <h2>Priority findings</h2>
      <div class="panel" id="findings"></div>
      <h2>Data confidence</h2>
      <div class="panel" id="confidence"></div>
    </div>
  </div>

  <h2>What-if procurement simulator</h2>
  <div class="panel">
    <div id="simhead"></div>
    <div style="max-height:290px;overflow:auto;margin-top:10px" id="simlist"></div>
  </div>

  <div class="cols" style="margin-top:22px">
    <div>
      <h2>Risk matrix &mdash; severity &times; likelihood</h2>
      <div class="panel" id="matrix"></div>
      <h2>Geopolitical exposure</h2>
      <div class="panel" id="geo"></div>
    </div>
    <div>
      <h2>Operational dependency</h2>
      <div class="panel" id="ops"></div>
      <h2>Model verification</h2>
      <div id="selfcheck" class="note"></div>
    </div>
  </div>
</div>
<div id="drawer" class="drawer"></div>
"""


def write_dashboard(payload, path):
    html = (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>BOMShield Risk Dashboard</title><style>{CSS}</style></head><body>"
            f"{_body()}"
            f"<script>const DATA = {json.dumps(payload)};\n{JS}</script></body></html>")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return path


# ---------------------------------------------------------------------------
# Static report - a plain, printable summary that needs no JavaScript
# ---------------------------------------------------------------------------
STATIC_CSS = """
body{font-family:Segoe UI,Helvetica,Arial,sans-serif;margin:0;background:#f4f6f8;color:#1c2733}
.wrap{max-width:1000px;margin:0 auto;padding:30px 22px 60px}
h1{margin:0 0 4px}h2{margin:30px 0 10px;font-size:17px;border-bottom:2px solid #d7dee5;padding-bottom:5px}
.sub{color:#5b6b7a;margin:0 0 20px}
.verdict{padding:16px 20px;border-radius:8px;color:#fff;margin-bottom:20px}
.REJECT{background:#8e1b1b}.APPROVEWITHCONDITIONS{background:#9a6212}.APPROVE{background:#1d6b3a}
.verdict b{display:block;font-size:19px;margin-bottom:5px}
table{width:100%;border-collapse:collapse;background:#fff;font-size:13px}
th,td{padding:8px 10px;border-bottom:1px solid #e6ebef;text-align:left;vertical-align:top}
th{background:#eef2f5;font-size:11px;text-transform:uppercase;letter-spacing:.4px;color:#44535f}
.mono{font-family:Consolas,monospace;font-size:12px;color:#44535f}
.note{background:#fff;border-left:4px solid #9a6212;padding:10px 14px;margin:9px 0;font-size:13px}
"""


def _e(v):
    return (str(v).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def write_static_report(payload, path):
    s, comps = payload["summary"], payload["components"]
    labels = payload["meta"]["dimension_labels"]
    dims = list(labels.keys())
    rated = sorted([c for c in comps if c["score"] is not None],
                   key=lambda c: (-c["score"], c["id"]))
    unknown = [c for c in comps if c["score"] is None]

    p = [f"<!doctype html><html><head><meta charset='utf-8'><title>BOMShield report</title>"
         f"<style>{STATIC_CSS}</style></head><body><div class='wrap'>",
         "<h1>BOMShield &mdash; Supply Chain Risk Assessment</h1>",
         f"<p class='sub'>{_e(os.path.basename(payload['meta']['sources']['bom']))} &middot; "
         f"{s['total']} components &middot; {s['rated']} scored, {len(unknown)} not scored</p>",
         f"<div class='verdict {s['verdict'].replace(' ','')}'><b>{_e(s['banner'])} &middot; "
         f"{_e(s['verdict'])}</b>{_e(s['rationale'])}</div>",
         "<h2>Summary</h2><table><tr>"
         "<th>Overall risk</th><th>Normalised</th><th>Band</th><th>Data confidence</th>"
         "<th>Critical</th><th>High</th><th>Not scored</th></tr>"
         f"<tr><td><b>{s['overall']}/100</b></td><td>{s['normalised']}</td><td>{_e(s['band'])}</td>"
         f"<td>{s['coverage']:.0%}</td><td>{s['counts']['CRITICAL']}</td>"
         f"<td>{s['counts']['HIGH']}</td><td>{s['counts']['UNKNOWN']}</td></tr></table>",
         "<h2>Risk dimensions</h2><table><tr><th>Dimension</th><th>Weight</th><th>Mean score</th></tr>"]
    for d in dims:
        p.append(f"<tr><td>{_e(labels[d])}</td><td class='mono'>{payload['meta']['weights'][d]}</td>"
                 f"<td class='mono'>{s['dimension_means'][d]}</td></tr>")
    p.append("</table>")

    p.append("<h2>Concentration risk</h2>")
    for f in s["concentration"]:
        p.append(f"<div class='note'>{_e(f)}</div>")

    p.append("<h2>Findings, highest risk first</h2><table><tr><th>Risk</th><th>Component</th>"
             + "".join(f"<th>{_e(labels[d]).split(' ')[0]}</th>" for d in dims)
             + "<th>Evidence</th><th>Mitigation</th></tr>")
    for c in rated:
        ev = "<br>".join(
            f"<b>{_e(v['id'])}</b> CVSS {_e(v['cvss'])} {_e(v['severity'])} &middot; KEV {_e(v['kev'])}"
            f" &middot; EPSS {_e(v['epss'])}" for v in c["cves"])
        reasons = [r for d in dims for r in c["reasons"][d]]
        if not ev:
            ev = "<br>".join(_e(r) for r in reasons[:2]) or "-"
        p.append(f"<tr><td><b>{c['score']}</b><br><span class='mono'>{_e(c['band'])}</span></td>"
                 f"<td><b>{_e(c['id'])}</b> {_e(c['name'])}<br><span class='mono'>{_e(c['vendor'])} "
                 f"{_e(c['model'])} {_e(c['version'])}</span></td>"
                 + "".join(f"<td class='mono'>{c['dimensions'][d]}</td>" for d in dims)
                 + f"<td>{ev}</td><td>{_e(c['mitigation'])}</td></tr>")
    p.append("</table>")

    p.append("<h2>Components that could not be verified</h2>"
             "<p class='sub'>Reported as NOT SCORED, never as zero. An absence of known "
             "vulnerabilities for a component we cannot identify is an absence of evidence.</p>")
    if unknown:
        p.append("<table><tr><th>ID</th><th>Component</th><th>Vendor</th><th>Version</th><th>Origin</th></tr>")
        for c in unknown:
            p.append(f"<tr><td class='mono'>{_e(c['id'])}</td><td>{_e(c['name'])}</td>"
                     f"<td>{_e(c['vendor'])}</td><td class='mono'>{_e(c['version'])}</td>"
                     f"<td>{_e(c['country'])}</td></tr>")
        p.append("</table>")
    else:
        p.append("<p>All components were identifiable.</p>")

    plan = payload.get("plan")
    if plan and plan["steps"]:
        p.append("<h2>Remediation plan</h2>")
        p.append(f"<p class='sub'>{len(plan['steps'])} action(s) take this BOM from "
                 f"<b>{_e(plan['baseline_verdict'])}</b> at {plan['baseline_score']} to "
                 f"<b>{_e(plan['final_verdict'])}</b> at {plan['final_score']}.</p>")
        p.append("<table><tr><th>Step</th><th>Action</th><th>Component</th><th>Effort</th>"
                 "<th>Score after</th><th>Verdict after</th></tr>")
        for i, st in enumerate(plan["steps"], 1):
            p.append(f"<tr><td class='mono'>{i}</td><td><b>{_e(st['type'])}</b> {_e(st['label'])}<br>"
                     f"<span class='mono'>{_e(st['detail'])}</span></td>"
                     f"<td class='mono'>{_e(st['component_id'])}</td><td class='mono'>{_e(st['effort'])}</td>"
                     f"<td class='mono'>{st['score']}</td><td class='mono'>{_e(st['verdict'])}</td></tr>")
        p.append("</table>")

    p.append("<p class='sub' style='margin-top:24px'>Scores are a prioritisation index on a 0-100 "
             "scale, not a probability of compromise.</p></div></body></html>")

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(p))
    return path
