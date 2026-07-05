"""The dashboard single-page app (self-contained HTML/CSS/JS, no external deps)."""

INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentAudit — evidence dashboard</title>
<style>
  :root{
    --bg:#0b0f14; --panel:#121821; --panel2:#0e141c; --line:#1e2937;
    --text:#e6edf3; --muted:#8b98a9; --accent:#4aa8ff;
    --ok:#2ecc71; --okbg:#0f2a1c; --bad:#ff5c69; --badbg:#2a1013;
    --chip:#182230; --warn:#f4c15d;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
    font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
  a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
  code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  header{display:flex;align-items:center;gap:14px;padding:16px 22px;
    border-bottom:1px solid var(--line);background:var(--panel2)}
  header .logo{width:30px;height:30px;border-radius:8px;
    background:linear-gradient(135deg,#4aa8ff,#7b5cff);display:grid;place-items:center;font-weight:800}
  header h1{font-size:16px;margin:0}
  header .tag{color:var(--muted);font-size:12.5px}
  .wrap{display:grid;grid-template-columns:320px 1fr;min-height:calc(100vh - 63px)}
  .side{border-right:1px solid var(--line);background:var(--panel2);overflow:auto}
  .side h2{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
    margin:0;padding:16px 18px 8px}
  .sess{padding:12px 18px;border-bottom:1px solid var(--line);cursor:pointer}
  .sess:hover{background:var(--panel)} .sess.active{background:var(--panel);border-left:3px solid var(--accent)}
  .sess .name{font-weight:600} .sess .meta{color:var(--muted);font-size:12px;margin-top:2px}
  .badges{margin-top:6px;display:flex;gap:6px;flex-wrap:wrap}
  .badge{font-size:11px;padding:2px 8px;border-radius:20px;background:var(--chip);color:var(--muted)}
  .badge.ok{color:var(--ok)} .badge.anchor{color:var(--accent)}
  main{padding:22px 26px;overflow:auto}
  .empty{color:var(--muted);margin-top:80px;text-align:center}
  .banner{border-radius:12px;padding:16px 18px;margin-bottom:18px;display:flex;
    align-items:center;gap:14px;font-weight:600;border:1px solid transparent}
  .banner.ok{background:var(--okbg);color:var(--ok);border-color:#1c5138}
  .banner.bad{background:var(--badbg);color:var(--bad);border-color:#5a2026}
  .banner .big{font-size:22px}
  .banner .sub{font-weight:400;color:var(--muted);font-size:12.5px}
  .cards{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:18px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
  .card h3{margin:0 0 10px;font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
  .kv{display:flex;justify-content:space-between;gap:12px;padding:4px 0;border-bottom:1px dashed var(--line)}
  .kv:last-child{border-bottom:0} .kv .k{color:var(--muted)} .kv .v{text-align:right;word-break:break-all}
  .toolbar{display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap}
  button{background:var(--accent);color:#03121f;border:0;border-radius:8px;padding:9px 14px;
    font-weight:700;cursor:pointer} button:hover{filter:brightness(1.08)}
  button.ghost{background:var(--chip);color:var(--text)}
  table{width:100%;border-collapse:collapse;background:var(--panel);
    border:1px solid var(--line);border-radius:12px;overflow:hidden}
  th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
  th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);background:var(--panel2)}
  tr:last-child td{border-bottom:0}
  tr.tampered{background:var(--badbg)}
  .etype{font-size:11px;padding:2px 8px;border-radius:6px;background:var(--chip)}
  .redacted{color:var(--warn)} .chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}
  .check{font-size:12.5px;padding:3px 0;color:var(--muted)}
  .check.pass::before{content:"✓ ";color:var(--ok)} .check.fail::before{content:"✗ ";color:var(--bad)}
  details summary{cursor:pointer;color:var(--muted);font-size:12px}
  .muted{color:var(--muted)}
  .live{float:right;font-size:10px;color:var(--muted);display:inline-flex;align-items:center;gap:5px}
  .livedot{width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 0 var(--ok);animation:pulse 1.8s infinite}
  @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(46,204,113,.5)}70%{box-shadow:0 0 0 6px rgba(46,204,113,0)}100%{box-shadow:0 0 0 0 rgba(46,204,113,0)}}
  @media(prefers-reduced-motion:reduce){.livedot{animation:none}}
</style>
</head>
<body>
<header>
  <div class="logo">A</div>
  <div>
    <h1>AgentAudit</h1>
    <div class="tag">Tamper-evident evidence — verified live, not cached</div>
  </div>
</header>
<div class="wrap">
  <aside class="side">
    <h2>Sessions <span class="live"><span class="livedot"></span><span id="livecount">…</span></span></h2>
    <div id="sessions"></div>
  </aside>
  <main id="main"><div class="empty">Select a session to inspect its evidence.</div></main>
</div>
<script>
const $ = (s,el=document)=>el.querySelector(s);
const esc = s => String(s??"").replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
const short = h => h ? h.slice(0,16)+"…" : "—";
let current = null;

async function get(url){ const r = await fetch(url); return r.json(); }

function anchorHtml(a){
  if(!a) return '<span class="muted">not anchored</span>';
  if(a.backend==="rekor" && a.log_index!=null)
    return `Rekor · <a href="https://search.sigstore.dev/?logIndex=${a.log_index}" target="_blank">logIndex ${a.log_index}</a>`;
  return `${esc(a.backend)} · <span class="muted">${esc(a.anchored_at||"")}</span>`;
}

let tampering = false;
let lastSig = "";   // fingerprint of the session list, to detect changes

async function loadSessions(initial){
  const rows = await get("/api/sessions");
  const sig = rows.map(s=>s.session_id+":"+s.event_count).join("|");
  if(sig !== lastSig){                      // only re-render when something changed
    lastSig = sig;
    $("#sessions").innerHTML = rows.map(s=>`
      <div class="sess ${s.session_id===current?'active':''}" data-id="${esc(s.session_id)}">
        <div class="name">${esc(s.agent_id)}</div>
        <div class="meta">${s.event_count} events · ${esc(short(s.root_hash))}</div>
        <div class="badges">
          ${s.signed?'<span class="badge ok">signed</span>':'<span class="badge">unsigned</span>'}
          ${s.anchor?`<span class="badge anchor">${esc(s.anchor.backend)}</span>`:''}
          ${s.framework?`<span class="badge">${esc(s.framework)}</span>`:''}
        </div>
      </div>`).join("") || '<div class="empty" style="margin-top:20px">No sessions yet — run an agent that logs to this DB.</div>';
    document.querySelectorAll(".sess").forEach(el=>
      el.onclick=()=>{ current=el.dataset.id; tampering=false;
        document.querySelectorAll(".sess").forEach(x=>x.classList.toggle("active",x.dataset.id===current));
        loadSession(current); });
  }
  if(initial && rows[0] && !current){
    current = rows[0].session_id;
    document.querySelector(`.sess[data-id="${current}"]`)?.classList.add("active");
    loadSession(current);
  }
  document.getElementById("livecount").textContent = rows.length + " session" + (rows.length===1?"":"s");
  return rows;
}

function banner(v, note){
  const cls = v.ok ? "ok":"bad";
  const head = v.ok ? "VERIFIED":"TAMPER DETECTED";
  return `<div class="banner ${cls}"><span class="big">${v.ok?"✓":"✗"}</span>
    <div><div>${head}</div><div class="sub">${v.passed} checks passed, ${v.failed} failed${note?" · "+esc(note):""}</div></div></div>`;
}

function renderEntries(entries, tamperedSeq){
  return `<table><thead><tr><th>#</th><th>type</th><th>actor</th><th>policy</th><th>output</th></tr></thead>
    <tbody>${entries.map((e,i)=>{
      const pol = e.policy_ref ? `${esc(e.policy_ref.policy_id)} v${esc(e.policy_ref.version)}`:'<span class="muted">—</span>';
      const inp = e.input && e.input.__redacted__ ? '<span class="redacted">redacted</span>':'';
      const out = e.output ? esc(JSON.stringify(e.output)) : '<span class="muted">—</span>';
      return `<tr class="${i===tamperedSeq?'tampered':''}">
        <td class="mono">${e.seq}</td><td><span class="etype">${esc(e.event_type)}</span></td>
        <td>${esc(e.actor.agent_id)}<div class="muted" style="font-size:11px">${esc(e.actor.framework||"")}</div></td>
        <td>${pol}</td><td class="mono">${out} ${inp}</td></tr>`;
    }).join("")}</tbody></table>`;
}

async function loadSession(id){
  tampering = false;
  const d = await get("/api/session?id="+encodeURIComponent(id));
  const cp = d.checkpoint, v = d.verification;
  $("#main").innerHTML = `
    ${banner(v)}
    <div class="toolbar">
      <button onclick="tamper('${esc(id)}')">▶ Simulate tamper</button>
      <button class="ghost" onclick="loadSession('${esc(id)}')">↻ Re-verify</button>
    </div>
    <div class="cards">
      <div class="card"><h3>Sealed checkpoint</h3>
        <div class="kv"><span class="k">Merkle root</span><span class="v mono">${esc(short(cp.root_hash))}</span></div>
        <div class="kv"><span class="k">Tree size</span><span class="v">${cp.tree_size}</span></div>
        <div class="kv"><span class="k">Signature</span><span class="v">${cp.signature?"Ed25519 ✓":"—"}</span></div>
        <div class="kv"><span class="k">Anchor</span><span class="v">${anchorHtml(d.anchor)}</span></div>
      </div>
      <div class="card"><h3>Regulatory coverage</h3>
        <div class="chips">${(d.controls||[]).map(c=>`<span class="badge" title="${esc(c.title)}">${esc(c.id)}</span>`).join("") || '<span class="muted">none mapped</span>'}</div>
        <div class="muted" style="margin-top:10px;font-size:12px">${[...new Set((d.controls||[]).map(c=>c.framework))].join(" · ")}</div>
      </div>
    </div>
    <h3 class="muted" style="text-transform:uppercase;letter-spacing:.06em;font-size:11px">Events</h3>
    ${renderEntries(d.entries, -1)}
    <details style="margin-top:16px"><summary>Verification checks (${v.passed})</summary>
      <div style="margin-top:8px">${v.checks.map(c=>`<div class="check pass">${esc(c)}</div>`).join("")}</div></details>`;
}

async function tamper(id){
  tampering = true;
  const t = await get("/api/tamper?id="+encodeURIComponent(id)+"&seq=0");
  const d = await get("/api/session?id="+encodeURIComponent(id));
  const v = t.verification;
  $("#main").innerHTML = `
    ${banner(v, `entry #${t.tampered_seq} output altered`)}
    <div class="toolbar"><button class="ghost" onclick="loadSession('${esc(id)}')">↻ Restore & re-verify</button></div>
    <div class="card" style="margin-bottom:16px"><h3>Simulated edit (in-memory only — the log is untouched)</h3>
      <div class="kv"><span class="k">entry #${t.tampered_seq} before</span><span class="v mono">${esc(JSON.stringify(t.before))}</span></div>
      <div class="kv"><span class="k">after</span><span class="v mono">${esc(JSON.stringify(t.after))}</span></div>
    </div>
    ${renderEntries(d.entries, t.tampered_seq)}
    <details open style="margin-top:16px"><summary>Failing checks</summary>
      <div style="margin-top:8px">${(v.errors||[]).map(c=>`<div class="check fail">${esc(c)}</div>`).join("")}</div></details>`;
}
// Live: poll for new sessions/events; refresh the open detail unless the user
// is looking at a tamper result.
let lastCounts = {};
async function poll(){
  try{
    const rows = await loadSessions(false);
    if(current && !tampering){
      const cur = rows.find(r=>r.session_id===current);
      if(cur && lastCounts[current] !== cur.event_count){  // detail changed -> refresh
        lastCounts[current] = cur.event_count;
        loadSession(current);
      }
    }
  }catch(e){/* server momentarily busy; try again next tick */}
}
loadSessions(true);
setInterval(poll, 2000);
</script>
</body>
</html>"""
