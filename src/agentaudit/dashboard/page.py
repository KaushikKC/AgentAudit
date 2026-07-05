"""The dashboard single-page app (self-contained HTML/CSS/JS, no external deps).

Design concept: a digital notary's evidence ledger. Events render as a literal
chain of custody (cards connected by hash links that illuminate as verification
cascades down), and the verdict is a circular seal that stamps intact, or breaks
when tampering is detected. Ships a dark "ink" theme and a light "paper" theme,
toggleable and persisted, defaulting to the OS preference.
"""

INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentAudit · evidence ledger</title>
<style>
  :root{
    --ink:#06080d; --dot:#131a26; --panel:#0d121b; --panel2:#0a0e16;
    --line:#1b2433; --line2:#27334a;
    --text:#e9edf4; --muted:#8a97ab; --faint:#5a6779;
    --gold:#d4a843; --gold-soft:#8a6f2f; --gold-glow:rgba(212,168,67,.14);
    --ok:#3ecf8e; --ok-bg:#0b241a; --ok-line:#1d5c41;
    --bad:#e5484d; --bad-bg:#2a1113; --bad-line:#6b2226; --bad-hover:#3a1518;
    --amber:#e0a34e; --amber-line:#6b5426; --amber-bg:#211a0e;
    --chip-bg:#151d2b; --chip-text:#a9b6c9; --gold-chip-bg:#1c1912;
    --btn-bg:#141c2b; --btn-bg-hover:#1a2436;
    --field-text:#c6d1e0; --meter-bg:#1c2637;
    --case-a:#101725; --case-b:#0c1220; --node-bad:#241014;
    --verd-pass-a:#0c2119; --verd-pass-b:#0a1720;
    --verd-fail-a:#2a1113; --verd-fail-b:#160d12;
    --verd-sheen:rgba(255,255,255,.05);
    --topbar-a:rgba(10,14,22,.97); --topbar-b:rgba(10,14,22,.92);
    --hairline:rgba(212,168,67,.28); --topbar-shadow:rgba(0,0,0,.35);
    --seal-fill:rgba(0,0,0,.3); --seal-shadow:rgba(0,0,0,.45);
    --sel:#3a3117;
    --serif:Georgia,'Iowan Old Style','Times New Roman',serif;
    --mono:ui-monospace,'SF Mono',SFMono-Regular,Menlo,Consolas,monospace;
    --sans:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
  }
  body.light{
    --ink:#f5f2ea; --dot:#e6dfd0; --panel:#ffffff; --panel2:#faf8f2;
    --line:#e2dccc; --line2:#cfc7b1;
    --text:#252b38; --muted:#67717f; --faint:#979fa9;
    --gold:#96700f; --gold-soft:#c8a84d; --gold-glow:rgba(150,112,15,.10);
    --ok:#188a58; --ok-bg:#e6f4ec; --ok-line:#b8dfc9;
    --bad:#c23237; --bad-bg:#fbecec; --bad-line:#ecc4c4; --bad-hover:#f6dcdb;
    --amber:#94650e; --amber-line:#dcc48d; --amber-bg:#f8f0da;
    --chip-bg:#f1ecdf; --chip-text:#5b6472; --gold-chip-bg:#f6efd8;
    --btn-bg:#efeadb; --btn-bg-hover:#e7e0cc;
    --field-text:#39424f; --meter-bg:#e8e1d0;
    --case-a:#ffffff; --case-b:#fbf8f1; --node-bad:#fdeeee;
    --verd-pass-a:#e9f5ee; --verd-pass-b:#f4f6ec;
    --verd-fail-a:#fbebeb; --verd-fail-b:#f8f1e9;
    --verd-sheen:rgba(255,255,255,.45);
    --topbar-a:rgba(250,248,242,.97); --topbar-b:rgba(250,248,242,.92);
    --hairline:rgba(150,112,15,.25); --topbar-shadow:rgba(80,64,20,.10);
    --seal-fill:rgba(255,255,255,.55); --seal-shadow:rgba(90,72,20,.20);
    --sel:#efe2b8;
  }
  *{box-sizing:border-box}
  html,body{margin:0}
  body{
    background:var(--ink) radial-gradient(circle at 1px 1px, var(--dot) 1px, transparent 0);
    background-size:26px 26px;
    color:var(--text);font:14px/1.55 var(--sans);-webkit-font-smoothing:antialiased;
  }
  a{color:var(--gold)} ::selection{background:var(--sel)}
  .mono{font-family:var(--mono)}
  button{font-family:inherit;border:0;cursor:pointer;border-radius:9px;font-weight:650;font-size:13px}
  button:focus-visible,[tabindex]:focus-visible{outline:2px solid var(--gold);outline-offset:2px}

  /* ---- top bar ---- */
  .topbar{
    display:flex;align-items:center;gap:15px;padding:14px 24px;position:sticky;top:0;z-index:9;
    background:linear-gradient(180deg,var(--topbar-a),var(--topbar-b));
    backdrop-filter:blur(6px);
    border-bottom:1px solid var(--line);
    box-shadow:0 1px 0 var(--hairline), 0 8px 24px var(--topbar-shadow);
  }
  .sealmark{width:38px;height:38px;flex:none}
  .sealmark svg{width:100%;height:100%;display:block}
  .s-ring{stroke:var(--gold);animation:spin 26s linear infinite;transform-origin:48px 48px}
  .s-core{fill:var(--gold-chip-bg);stroke:var(--gold-soft)}
  .s-tick{stroke:var(--gold)}
  .wordmark h1{margin:0;font:600 19px/1 var(--serif);letter-spacing:.4px}
  .wordmark h1 em{font-style:normal;color:var(--gold)}
  .wordmark .sub{font-size:11.5px;color:var(--muted);margin-top:3px;letter-spacing:.02em}
  .livewrap{margin-left:auto;display:flex;align-items:center;gap:8px;
    font:11px var(--mono);color:var(--muted);padding:6px 12px;border:1px solid var(--line);
    border-radius:20px;background:var(--panel2)}
  .livedot{width:7px;height:7px;border-radius:50%;background:var(--ok);animation:pulse 2s infinite}
  @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(62,207,142,.45)}70%{box-shadow:0 0 0 7px rgba(62,207,142,0)}100%{box-shadow:0 0 0 0 rgba(62,207,142,0)}}
  .themebtn{width:34px;height:34px;border-radius:50%;background:var(--panel2);
    border:1px solid var(--line);color:var(--muted);font-size:15px;line-height:1;flex:none}
  .themebtn:hover{border-color:var(--gold-soft);color:var(--gold)}

  /* ---- layout ---- */
  .layout{display:grid;grid-template-columns:318px 1fr;min-height:calc(100vh - 67px)}
  @media(max-width:900px){.layout{grid-template-columns:1fr}}

  /* ---- case-file rail ---- */
  .rail{border-right:1px solid var(--line);background:var(--panel2);display:flex;flex-direction:column}
  .rail h2{font:600 10.5px var(--sans);text-transform:uppercase;letter-spacing:.14em;
    color:var(--faint);margin:0;padding:18px 18px 10px;display:flex;justify-content:space-between;align-items:center}
  .rail h2 .count{font-family:var(--mono);color:var(--muted);text-transform:none;letter-spacing:0}
  #sessions{overflow:auto;padding:4px 12px 12px;display:flex;flex-direction:column;gap:9px}
  .case{
    position:relative;padding:13px 14px 12px;border:1px solid var(--line);border-radius:12px;
    background:linear-gradient(180deg,var(--case-a),var(--case-b));cursor:pointer;
    transition:transform .15s,border-color .15s,box-shadow .15s;
  }
  .case:hover{transform:translateY(-1px);border-color:var(--line2)}
  .case.active{border-color:var(--gold-soft);box-shadow:0 0 0 1px var(--gold-soft),0 6px 20px var(--topbar-shadow)}
  .case.active::before{content:"";position:absolute;inset:10px auto 10px -1px;width:3px;
    border-radius:3px;background:var(--gold)}
  .case .row1{display:flex;align-items:baseline;justify-content:space-between;gap:8px}
  .case .agent{font-weight:650;font-size:13.5px}
  .case .stamp{font:600 9.5px var(--sans);text-transform:uppercase;letter-spacing:.1em;
    padding:2.5px 8px;border-radius:4px}
  .stamp.sealed{color:var(--ok);background:var(--ok-bg);border:1px solid var(--ok-line)}
  .stamp.open{color:var(--muted);background:var(--chip-bg);border:1px solid var(--line)}
  .case .meta{color:var(--muted);font-size:11.5px;margin-top:3px}
  .case .root{font:10.5px var(--mono);color:var(--faint);margin-top:8px;
    display:flex;align-items:center;gap:6px}
  .case .root::before{content:"⬡";color:var(--gold-soft)}
  .railfoot{margin-top:auto;padding:14px 18px;border-top:1px solid var(--line);
    font-size:11px;color:var(--faint);line-height:1.6}
  .empty{color:var(--faint);text-align:center;padding:36px 18px;font-size:13px}

  /* ---- main ---- */
  main{padding:26px 30px 48px;overflow:auto;max-width:1060px}

  /* verdict */
  .verdict{display:flex;align-items:center;gap:22px;padding:20px 24px;border-radius:16px;
    margin-bottom:20px;border:1px solid;position:relative;overflow:hidden}
  .verdict.pass{border-color:var(--ok-line);background:linear-gradient(135deg,var(--verd-pass-a) 0%,var(--verd-pass-b) 70%)}
  .verdict.fail{border-color:var(--bad-line);background:linear-gradient(135deg,var(--verd-fail-a) 0%,var(--verd-fail-b) 70%)}
  .verdict::after{content:"";position:absolute;inset:0;pointer-events:none;
    background:radial-gradient(420px 140px at 12% 0%,var(--verd-sheen),transparent)}
  .seal{width:88px;height:88px;flex:none;filter:drop-shadow(0 4px 14px var(--seal-shadow))}
  .seal svg{width:100%;height:100%}
  .seal .ring{animation:spin 26s linear infinite;transform-origin:48px 48px}
  @keyframes spin{to{transform:rotate(360deg)}}
  .verdict .eyebrow{font:600 10px var(--sans);letter-spacing:.18em;text-transform:uppercase;color:var(--faint)}
  .verdict h2{margin:4px 0 5px;font:600 24px/1.15 var(--serif);letter-spacing:.2px;text-wrap:balance}
  .verdict.pass h2{color:var(--ok)} .verdict.fail h2{color:var(--bad)}
  .verdict .note{color:var(--muted);font-size:12.5px}
  .counter{margin-left:auto;text-align:center;font-family:var(--mono);flex:none;
    padding:10px 18px;border-left:1px solid var(--line)}
  .counter b{display:block;font-size:30px;font-weight:600}
  .verdict.pass .counter b{color:var(--ok)} .verdict.fail .counter b{color:var(--bad)}
  .counter span{font-size:10px;color:var(--faint);letter-spacing:.12em;text-transform:uppercase}

  /* toolbar */
  .toolbar{display:flex;gap:10px;margin:0 0 22px;flex-wrap:wrap}
  .btn-danger{background:var(--bad-bg);color:var(--bad);padding:10px 16px;
    box-shadow:0 0 0 1px var(--bad-line) inset}
  .btn-danger:hover{background:var(--bad-hover)}
  .btn-ghost{background:var(--btn-bg);color:var(--text);padding:10px 16px;
    box-shadow:0 0 0 1px var(--line2) inset}
  .btn-ghost:hover{background:var(--btn-bg-hover)}

  /* info grid */
  .cards{display:grid;grid-template-columns:1.35fr 1fr;gap:16px;margin-bottom:26px}
  @media(max-width:820px){.cards{grid-template-columns:1fr}}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px 18px}
  .card h3{margin:0 0 12px;font:600 10px var(--sans);text-transform:uppercase;
    letter-spacing:.15em;color:var(--faint)}
  .roothash{
    font:15px/1.7 var(--mono);letter-spacing:.06em;word-break:break-all;cursor:copy;
    padding:12px 14px;border-radius:10px;background:var(--panel2);border:1px solid var(--line);
    color:var(--gold);transition:border-color .15s;
  }
  .roothash:hover{border-color:var(--gold-soft)}
  .roothash small{display:block;color:var(--faint);font-size:10px;letter-spacing:.1em;
    margin-top:6px;font-family:var(--sans);text-transform:uppercase}
  .kv{display:flex;justify-content:space-between;gap:14px;padding:7px 0;
    border-bottom:1px dashed var(--line);font-size:13px}
  .kv:last-child{border-bottom:0}
  .kv .k{color:var(--muted)} .kv .v{text-align:right}
  .chips{display:flex;gap:7px;flex-wrap:wrap}
  .chip{font:600 10.5px var(--mono);padding:4px 10px;border-radius:6px;cursor:default;
    background:var(--chip-bg);color:var(--chip-text);border:1px solid var(--line2)}
  .chip:hover{border-color:var(--gold-soft);color:var(--gold)}

  /* ---- the chain of custody ---- */
  .chain-h{display:flex;align-items:center;gap:12px;margin:0 0 16px}
  .chain-h h3{margin:0;font:600 10px var(--sans);letter-spacing:.15em;text-transform:uppercase;color:var(--faint)}
  .chain-h::after{content:"";flex:1;height:1px;background:linear-gradient(90deg,var(--line),transparent)}
  .chain{display:flex;flex-direction:column;max-width:760px}
  .node{
    display:grid;grid-template-columns:52px 1fr;gap:14px;
    animation:rise .45s cubic-bezier(.2,.7,.3,1) both;
  }
  @keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
  .node .gutter{display:flex;flex-direction:column;align-items:center}
  .seqbadge{
    width:40px;height:40px;border-radius:50%;flex:none;display:grid;place-items:center;
    font:600 13px var(--mono);color:var(--gold);background:var(--panel2);
    border:1.5px solid var(--gold-soft);box-shadow:0 0 0 4px var(--gold-glow);
  }
  .node.bad .seqbadge{color:var(--bad);border-color:var(--bad-line);box-shadow:0 0 0 4px rgba(229,72,77,.12)}
  .linkline{flex:1;width:2px;min-height:26px;margin:6px 0;border-radius:2px;
    background:linear-gradient(180deg,var(--gold-soft),var(--line))}
  .linkline.lit{background:linear-gradient(180deg,var(--ok),var(--ok-line))}
  .linkline.severed{
    background:repeating-linear-gradient(180deg,var(--bad) 0 5px,transparent 5px 10px);
  }
  .evcard{
    background:var(--panel);border:1px solid var(--line);border-radius:13px;
    padding:14px 16px;margin-bottom:14px;transition:border-color .15s,transform .15s;
  }
  .evcard:hover{border-color:var(--line2)}
  .node.bad .evcard{border-color:var(--bad-line);background:linear-gradient(135deg,var(--node-bad),var(--panel) 55%)}
  .evtop{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .etype{font:600 10px var(--sans);text-transform:uppercase;letter-spacing:.1em;
    padding:3px 9px;border-radius:5px;background:var(--chip-bg);color:var(--chip-text);border:1px solid var(--line2)}
  .etype.decision{color:var(--gold);border-color:var(--gold-soft);background:var(--gold-chip-bg)}
  .etype.human_override{color:var(--amber);border-color:var(--amber-line);background:var(--amber-bg)}
  .evtop .actor{font-size:12.5px;color:var(--muted)}
  .evtop .policy{margin-left:auto;font:11px var(--mono);color:var(--faint)}
  .evtop .policy b{color:var(--muted);font-weight:600}
  .evbody{margin-top:10px;display:flex;gap:18px;flex-wrap:wrap;align-items:center}
  .field{font:12.5px var(--mono);color:var(--field-text)}
  .field .fk{color:var(--faint)}
  .decision-val{font-weight:700}
  .decision-val.approve{color:var(--ok)} .decision-val.route_to_human{color:var(--amber)}
  .decision-val.TAMPERED{color:var(--bad)}
  .redpill{font:600 10px var(--sans);letter-spacing:.08em;text-transform:uppercase;
    color:var(--amber);background:var(--amber-bg);border:1px solid var(--amber-line);border-radius:5px;padding:3px 9px}
  .meter{width:110px;height:5px;border-radius:3px;background:var(--meter-bg);overflow:hidden}
  .meter i{display:block;height:100%;background:linear-gradient(90deg,var(--gold-soft),var(--gold))}
  .hashline{margin-top:10px;font:10.5px var(--mono);color:var(--faint);
    display:flex;align-items:center;gap:6px;cursor:copy}
  .hashline:hover{color:var(--gold)}
  .hashline::before{content:"⬡"}
  .linktag{align-self:center;font:10px var(--mono);color:var(--faint);margin:-6px 0 8px 66px}
  .linktag.lit{color:var(--ok)}
  .linktag.severed{color:var(--bad);font-weight:700}

  /* tamper diff card */
  .diff{border:1px solid var(--bad-line);border-radius:13px;background:var(--bad-bg);
    padding:14px 18px;margin-bottom:22px}
  .diff h3{margin:0 0 10px;font:600 10px var(--sans);letter-spacing:.14em;
    text-transform:uppercase;color:var(--bad)}
  .diff .kv{border-color:var(--bad-line)}

  /* checks */
  details{margin-top:22px;border:1px solid var(--line);border-radius:12px;
    background:var(--panel);overflow:hidden;max-width:760px}
  summary{padding:13px 17px;cursor:pointer;color:var(--muted);font-size:12.5px;list-style:none}
  summary::-webkit-details-marker{display:none}
  summary::before{content:"▸ ";color:var(--gold-soft)}
  details[open] summary::before{content:"▾ "}
  .checks{padding:2px 17px 15px}
  .chk{font:12px var(--mono);padding:3.5px 0;color:var(--muted)}
  .chk.pass::before{content:"✓  ";color:var(--ok)}
  .chk.fail{color:var(--bad)} .chk.fail::before{content:"✗  ";color:var(--bad)}

  .flash{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(6px);
    background:var(--panel);border:1px solid var(--gold-soft);color:var(--gold);
    border-radius:9px;padding:9px 16px;font:12px var(--mono);opacity:0;
    transition:.22s;pointer-events:none;z-index:20}
  .flash.show{opacity:1;transform:translateX(-50%)}

  @media(prefers-reduced-motion:reduce){
    *{animation:none!important;transition:none!important}
  }
</style>
</head>
<body>

<header class="topbar">
  <div class="sealmark">
    <svg viewBox="0 0 96 96" aria-hidden="true">
      <circle cx="48" cy="48" r="42" fill="none" stroke-width="2.5"
              stroke-dasharray="5 7" class="s-ring"/>
      <circle cx="48" cy="48" r="30" stroke-width="1.5" class="s-core"/>
      <path d="M34 49 l10 10 l19 -21" fill="none" stroke-width="5.5"
            stroke-linecap="round" stroke-linejoin="round" class="s-tick"/>
    </svg>
  </div>
  <div class="wordmark">
    <h1>Agent<em>Audit</em></h1>
    <div class="sub">Evidence ledger · every verdict re-derived live from the raw record</div>
  </div>
  <div class="livewrap"><span class="livedot"></span><span id="livecount">…</span></div>
  <button id="themebtn" class="themebtn" onclick="toggleTheme()" title="Toggle light/dark theme"
          aria-label="Toggle light or dark theme">☀</button>
</header>

<div class="layout">
  <aside class="rail">
    <h2>Case files <span class="count" id="railcount"></span></h2>
    <div id="sessions"></div>
    <div class="railfoot">Each case is hash-chained, Merkle-committed and Ed25519-sealed.
      Nothing on this page is taken on trust: every status is recomputed from the raw entries.</div>
  </aside>
  <main id="main"><div class="empty">Select a case file to examine its chain of custody.</div></main>
</div>
<div class="flash" id="flash"></div>

<script>
const $ = (s,el=document)=>el.querySelector(s);
const esc = s => String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const short = h => h ? h.slice(0,16)+"…" : "n/a";
const groupHash = h => h ? h.replace(/(.{8})/g,"$1 ").trim() : "n/a";
let current = null, tampering = false, lastSig = "", lastCounts = {};

/* ---------- theme ---------- */
function applyTheme(t){
  document.body.classList.toggle("light", t==="light");
  const b = $("#themebtn"); if(b) b.textContent = t==="light" ? "☾" : "☀";
  try{ localStorage.setItem("aa-theme", t); }catch(e){}
}
function toggleTheme(){
  applyTheme(document.body.classList.contains("light") ? "dark" : "light");
}
(function(){
  let saved = null; try{ saved = localStorage.getItem("aa-theme"); }catch(e){}
  applyTheme(saved || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"));
})();

async function get(url){ const r = await fetch(url); if(!r.ok) throw new Error(r.status); return r.json(); }

function flash(msg){
  const f = $("#flash"); f.textContent = msg; f.classList.add("show");
  clearTimeout(f._t); f._t = setTimeout(()=>f.classList.remove("show"), 1200);
}
function copyText(t, label){ navigator.clipboard?.writeText(t).then(()=>flash("copied "+(label||short(t)))); }

function anchorHtml(a){
  if(!a) return '<span style="color:var(--faint)">not anchored</span>';
  if(a.backend==="rekor" && a.log_index!=null)
    return `Sigstore Rekor · <a href="https://search.sigstore.dev/?logIndex=${a.log_index}" target="_blank" rel="noopener">logIndex ${a.log_index}</a>`;
  return `independent witness <span style="color:var(--faint)">· cosigned</span>`;
}

/* ---------- seal SVG for verdicts ---------- */
function sealSvg(ok){
  const col = ok ? "var(--ok)" : "var(--bad)";
  const soft = ok ? "var(--ok-line)" : "var(--bad-line)";
  const glyph = ok
    ? '<path d="M33 49 l11 11 l20 -23" fill="none" style="stroke:'+col+'" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>'
    : '<path d="M36 36 l24 24 M60 36 l-24 24" fill="none" style="stroke:'+col+'" stroke-width="6" stroke-linecap="round"/>';
  return `<div class="seal"><svg viewBox="0 0 96 96" aria-hidden="true">
    <circle cx="48" cy="48" r="43" fill="none" style="stroke:${col}" stroke-width="2"
            stroke-dasharray="${ok ? "4 6" : "2 9"}" class="ring"/>
    <circle cx="48" cy="48" r="31" style="fill:var(--seal-fill);stroke:${soft}" stroke-width="1.5"/>
    ${glyph}
  </svg></div>`;
}

function verdictHtml(v, note){
  const ok = v.ok;
  return `<section class="verdict ${ok?'pass':'fail'}">
    ${sealSvg(ok)}
    <div>
      <div class="eyebrow">Independent verification</div>
      <h2>${ok ? "Evidence intact: seal holds" : "Seal broken: tampering detected"}</h2>
      <div class="note">${v.passed} checks re-derived from the raw record${v.failed?`, <b style="color:var(--bad)">${v.failed} failed</b>`:""}${note?" · "+esc(note):""}</div>
    </div>
    <div class="counter"><b>${ok? v.passed : v.failed}</b><span>${ok?"checks passed":"checks failed"}</span></div>
  </section>`;
}

/* ---------- case-file rail ---------- */
async function loadSessions(initial){
  const rows = await get("/api/sessions");
  const sig = rows.map(s=>s.session_id+":"+s.event_count).join("|");
  if(sig !== lastSig){
    lastSig = sig;
    $("#sessions").innerHTML = rows.map(s=>`
      <div class="case ${s.session_id===current?'active':''}" role="option" tabindex="0"
           aria-selected="${s.session_id===current}" data-id="${esc(s.session_id)}">
        <div class="row1">
          <span class="agent">${esc(s.agent_id)}</span>
          <span class="stamp ${s.signed?'sealed':'open'}">${s.signed?'sealed':'open'}</span>
        </div>
        <div class="meta">${s.event_count} events · ${esc(s.framework||"unknown")}${s.anchor?` · anchored (${esc(s.anchor.backend)})`:''}</div>
        <div class="root">${esc(short(s.root_hash))}</div>
      </div>`).join("") ||
      '<div class="empty">No case files yet.<br>Run an agent that logs to this ledger.</div>';
    document.querySelectorAll(".case").forEach(el=>{
      const pick = ()=>{ current = el.dataset.id; tampering = false;
        document.querySelectorAll(".case").forEach(x=>{
          const on = x.dataset.id===current; x.classList.toggle("active",on); x.setAttribute("aria-selected",on);});
        loadSession(current); };
      el.onclick = pick;
      el.onkeydown = e=>{ if(e.key==="Enter"||e.key===" "){e.preventDefault();pick();} };
    });
  }
  if(initial && rows[0] && !current){
    current = rows[0].session_id;
    document.querySelector(`.case[data-id="${current}"]`)?.classList.add("active");
    loadSession(current);
  }
  $("#livecount").textContent = "live · " + rows.length + " case" + (rows.length===1?"":"s");
  $("#railcount").textContent = rows.length || "";
  return rows;
}

/* ---------- chain of custody ---------- */
function fieldHtml(out){
  if(!out) return '<span class="field" style="color:var(--faint)">no payload</span>';
  const parts = [];
  for(const [k,v] of Object.entries(out)){
    if(k==="decision"||k==="intent"){
      parts.push(`<span class="field"><span class="fk">${esc(k)}:</span> <span class="decision-val ${esc(v)}">${esc(v)}</span></span>`);
    }else if(k==="confidence" && typeof v==="number"){
      parts.push(`<span class="field"><span class="fk">confidence:</span> ${v.toFixed(2)}</span>
        <span class="meter"><i style="width:${Math.round(v*100)}%"></i></span>`);
    }else{
      parts.push(`<span class="field"><span class="fk">${esc(k)}:</span> ${esc(JSON.stringify(v))}</span>`);
    }
  }
  return parts.join(" ");
}

function chainHtml(entries, brokenSeq){
  const n = entries.length;
  return `<div class="chain-h"><h3>Chain of custody · ${n} link${n===1?"":"s"}</h3></div>
  <div class="chain">` + entries.map((e,i)=>{
    const bad = e.seq === brokenSeq;
    const severed = brokenSeq !== -1 && e.seq === brokenSeq;
    const litClass = brokenSeq === -1 ? "lit" : (e.seq < brokenSeq ? "lit" : (severed ? "severed" : ""));
    const pol = e.policy_ref ? `<span class="policy"><b>${esc(e.policy_ref.policy_id)}</b> v${esc(e.policy_ref.version)}</span>` : "";
    const red = e.input && e.input.__redacted__ ? '<span class="redpill">PII sealed</span>' : "";
    const link = i < n-1 ? `<div class="linkline ${litClass}"></div>` : "";
    const tag = i < n-1
      ? `<div class="linktag ${litClass}">${severed ? "✂ chain severed: downstream hashes orphaned" : "⬡ "+esc(e.entry_hash.slice(0,12))+"… links entry "+(e.seq+1)}</div>`
      : "";
    return `<div class="node ${bad?'bad':''}" style="animation-delay:${Math.min(i*70,700)}ms">
      <div class="gutter"><div class="seqbadge">${e.seq}</div>${link}</div>
      <div>
        <div class="evcard">
          <div class="evtop">
            <span class="etype ${esc(e.event_type)}">${esc(e.event_type.replace(/_/g," "))}</span>
            <span class="actor">${esc(e.actor.agent_id)}${e.actor.model?" · "+esc(e.actor.model):""}</span>
            ${pol}
          </div>
          <div class="evbody">${fieldHtml(e.output)} ${red}</div>
          <div class="hashline" onclick="copyText('${esc(e.entry_hash)}','entry hash')"
               title="click to copy">${esc(short(e.entry_hash))}</div>
        </div>
        ${tag}
      </div>
    </div>`;
  }).join("") + `</div>`;
}

/* ---------- views ---------- */
async function loadSession(id){
  tampering = false;
  const d = await get("/api/session?id="+encodeURIComponent(id));
  const cp = d.checkpoint, v = d.verification;
  lastCounts[id] = d.entries.length;
  $("#main").innerHTML = `
    ${verdictHtml(v)}
    <div class="toolbar">
      <button class="btn-danger" onclick="tamper('${esc(id)}')">✂ Test the seal (simulate tampering)</button>
      <button class="btn-ghost" onclick="loadSession('${esc(id)}')">↻ Re-verify now</button>
    </div>
    <div class="cards">
      <div class="card"><h3>Sealed checkpoint</h3>
        <div class="roothash" onclick="copyText('${esc(cp.root_hash)}','merkle root')" title="click to copy">
          ${esc(groupHash(cp.root_hash))}
          <small>Merkle root · commits all ${cp.tree_size} entries in 32 bytes</small>
        </div>
        <div style="height:10px"></div>
        <div class="kv"><span class="k">Signature</span><span class="v">${cp.signature?'Ed25519 ✓':'not signed'}</span></div>
        <div class="kv"><span class="k">External anchor</span><span class="v">${anchorHtml(d.anchor)}</span></div>
        <div class="kv"><span class="k">Sealed at</span><span class="v mono">${esc((cp.timestamp||"").replace("T"," ").slice(0,19))}</span></div>
      </div>
      <div class="card"><h3>Regulatory coverage</h3>
        <div class="chips">${(d.controls||[]).map(c=>`<span class="chip" title="${esc(c.title)}: ${esc(c.relevance)}">${esc(c.id)}</span>`).join("") || '<span style="color:var(--faint)">none mapped</span>'}</div>
        <div style="margin-top:12px;color:var(--muted);font-size:12px">${[...new Set((d.controls||[]).map(c=>c.framework))].join("  ·  ")||""}</div>
      </div>
    </div>
    ${chainHtml(d.entries, -1)}
    <details><summary>All ${v.passed} verification checks</summary>
      <div class="checks">${v.checks.map(c=>`<div class="chk pass">${esc(c)}</div>`).join("")}</div>
    </details>`;
}

async function tamper(id){
  tampering = true;
  const t = await get("/api/tamper?id="+encodeURIComponent(id)+"&seq=0");
  const d = await get("/api/session?id="+encodeURIComponent(id));
  const v = t.verification;
  $("#main").innerHTML = `
    ${verdictHtml(v, "entry #"+t.tampered_seq+" was altered after sealing")}
    <div class="toolbar">
      <button class="btn-ghost" onclick="loadSession('${esc(id)}')">↺ Restore the record &amp; re-verify</button>
    </div>
    <div class="diff">
      <h3>Simulated post-hoc edit (in memory only; the ledger on disk is untouched)</h3>
      <div class="kv"><span class="k">entry #${t.tampered_seq} · before</span>
        <span class="v mono">${esc(JSON.stringify(t.before))}</span></div>
      <div class="kv"><span class="k">after</span>
        <span class="v mono" style="color:var(--bad)">${esc(JSON.stringify(t.after))}</span></div>
    </div>
    ${chainHtml(d.entries, t.tampered_seq)}
    <details open><summary>Failing check</summary>
      <div class="checks">
        ${(v.errors||[]).map(c=>`<div class="chk fail">${esc(c)}</div>`).join("")}
        <div class="chk" style="color:var(--faint);margin-top:8px">Altering one field changes its hash,
        which was the next entry's prev_hash, so the break cascades all the way to the signed Merkle root.</div>
      </div>
    </details>`;
}

/* ---------- live polling ---------- */
async function poll(){
  try{
    const rows = await loadSessions(false);
    if(current && !tampering){
      const cur = rows.find(r=>r.session_id===current);
      if(cur && lastCounts[current] !== cur.event_count){
        lastCounts[current] = cur.event_count;
        loadSession(current);
      }
    }
  }catch(e){/* server busy; next tick */}
}
loadSessions(true);
setInterval(poll, 2000);
</script>
</body>
</html>"""
