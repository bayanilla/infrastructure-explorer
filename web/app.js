import {servicesHTML, servicesCSV} from "./render/services.js";
import {runJob} from "./render/jobs.js";
import {esc, pct, asLabel, nf, plural, stamp} from "./render/format.js";
import {targetLabel, targetContext, asEvidenceHTML, adjacencyTable, evidenceHTML, scopeText, traceHTML, drillMapContextHTML} from "./render/lookup.js";
import {resolutionCSV, adjacencyCSV, inputsLine, rejectedHTML, unmappedHTML, statusLine, sourcesHTML, confirmHTML, sortValue, sortedNeighbors, neighborsTableHTML, footprintGraphSVG, perAsnHTML, footprintReportHTML} from "./render/footprint.js";
import {chartSVG} from "./render/chart.js";
import {reportHTML} from "./render/report.js";

"use strict";
const $ = s => document.querySelector(s);

let jobId = null, result = null, resolution = null, footprint = null;
const layers = {data:true, cp:true};
let fpSort = {key: null, dir: -1};

const THEME_IDS = new Set(["soc", "nord", "contrast", "matrix", "mucaro", "notebook", "amber"]);
const THEME_STORAGE = "mucaro-exposure-probe-theme";
function applyTheme(value){
  const selected = THEME_IDS.has(value) ? value : "soc";
  document.documentElement.dataset.probeTheme = selected;
  $("#theme").value = selected;
  try { localStorage.setItem(THEME_STORAGE, selected); } catch {}
}
let savedTheme = "soc";
try { savedTheme = localStorage.getItem(THEME_STORAGE) || "soc"; } catch {}
applyTheme(savedTheme);
$("#theme").addEventListener("change", ev => applyTheme(ev.target.value));

let shodanRequested = false;
async function settingsRequest(path, body){
 const res=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
 const data=await res.json(); if(!res.ok) throw new Error(data.error || "Settings request failed."); return data;
}
function openSettings(){ $("#settingsDrawer").showModal(); }
$("#settingsOpen").addEventListener("click",openSettings);
$("#configureShodan").addEventListener("click",openSettings);
$("#settingsClose").addEventListener("click",()=>$("#settingsDrawer").close());
for(const [id,path,body] of [["shodanSave","/api/settings/shodan",()=>({key:$("#shodanKey").value.trim()})],["shodanRemove","/api/settings/shodan",()=>({key:null})],["shodanCheck","/api/settings/shodan/check",()=>({})]]){
 $("#"+id).addEventListener("click",async()=>{try{const b=body();$("#shodanKey").value="";const d=await settingsRequest(path,b);$("#shodanStatus").textContent=d.message || (d.configured ? "Shodan configured for this server session." : "Shodan not configured.");}catch(e){$("#shodanStatus").textContent=e.message;}});
}
fetch("/api/settings/shodan").then(r=>r.json()).then(d=>{$("#shodanStatus").textContent=d.configured ? "Shodan configured for this server session." : "Shodan not configured.";}).catch(()=>{});
async function enrichServices(r, resources, done){
 const unique=[...new Set(resources)];
 for(const [requested,provider,field] of [[shodanRequested,"shodan","service_observations"]]){
  if(!requested) continue;
  if(unique.length>20){r[field]={limits:"Service observations were not requested: footprint exceeds the 20-resource limit. Split the footprint to include observations.",records:[]};continue;}
  try{r[field]=await runJob("/api/"+provider,{resources:unique},{onStarted:id=>{jobId=id;$("#cancel").hidden=false;$("#run").disabled=true;},onProgress:st=>{$("#now").textContent=st.progress;}});}
  catch(e){r[field]={limits:e.message,records:[]};}
 }
 stopPolling(); done(r);
}
function toast(msg){ const t=$("#toast"); t.textContent=msg; t.classList.add("on"); setTimeout(()=>t.classList.remove("on"),1800); }
function show(id){ for (const s of ["empty","running","error","report"]) $("#"+s).hidden = s !== id; }

const EMPTY = {
  footprint: ["See the networks observed next to yours.",
    "Start with one public IP or prefix, or upload your external footprint. Pathfinder maps each entry to its announced prefix and origin ASN, you confirm which ASNs are yours, and it reads the neighbors RIS observes for them.",
    [["Origin ASNs", "Which ASNs announce the space in your footprint, and how much of it each one holds."],
     ["Adjacent networks", "Every network observed next to the ASNs you confirm, with RIPE's position, route and path counts."],
     ["A point-in-time record", "Inputs, resolution, your confirmation and the adjacency result, saved as JSON and CSV."]]],
  ip: ["Public routing context for one IP.",
    "Look up its covering prefix and origin ASN, review public routing observations, then explore the ASN for broader context.",
    [["Identity context", "Prefix, origin ASN and reported holder. These do not identify the person behind a connection."],
     ["Routing evidence", "Collector-observed BGP advertisements and existing Atlas samples, kept distinct."],
     ["Explore ASN", "Optional wider context with explicit sample and coverage limits."]]],
};
EMPTY.asn = ["Explore the ASN’s broader routing context.",
  "Review observed prefixes, BGP advertisements and existing Atlas samples. This is incomplete routing context, not a reconstruction of an observed connection.", EMPTY.ip[2]];
function setEmpty(mode){
  const [h, p, items] = EMPTY[mode];
  $("#empty h2").textContent = h; $("#empty > p").textContent = p;
  $("#empty dl").innerHTML = items.map(([t, d]) => `<dt>${esc(t)}</dt><dd>${esc(d)}</dd>`).join("");
}
function lookupMode(){ return $('input[name=lookup]:checked').value; }
function isAsTarget(){ return /^(?:AS)?[0-9]{1,10}$/i.test($("#target").value.trim()); }
function updateTargetMode(){
  const footprintMode = lookupMode() === "footprint";
  $("#shodanFields").hidden = lookupMode() === "asn";
  $("#footprintFields").hidden = !footprintMode;
  $("#singleFields").hidden = footprintMode;
  if (footprintMode) { $("#run").textContent = "Resolve footprint"; setEmpty("footprint"); return; }
  const value = $("#target").value.trim();
  const asn = isAsTarget() || (!value && lookupMode() === "asn");
  $(`input[name=lookup][value=${asn ? "asn" : "ip"}]`).checked = true;
  $("#target-label").textContent = asn ? "ASN" : "Public IP address";
  $("#target").placeholder = asn ? "AS3333 or 3333" : "Public IP address";
  $("#target-hint").textContent = asn ? "Optional broader context. Enter AS3333 or 3333. The first lookup may take several minutes." : "Review public routing context for an externally observed IP. Public data only; no probes are scheduled. RIPE requests are paced, so a run can take several minutes.";
  $("#asn-note").hidden = !asn;
  $("#shodanFields").hidden = asn;
  $("#run").textContent = asn ? "Explore ASN" : "Analyze public routing context";
  setEmpty(asn ? "asn" : "ip");
  $("#publicFields .hint").textContent = asn ? "Leave empty to search existing public traceroutes classified under this ASN. Samples cover particular addresses, not the whole AS." : "Leave empty to search existing traceroutes to this address, then other addresses in its origin ASN. Supplied IDs are checked against the target. Sample destinations are shown in the report.";
}
document.querySelectorAll('input[name=lookup]').forEach(radio => radio.addEventListener("change", () => {
  if (radio.value !== "footprint" && $("#target").value.trim() && (radio.value === "asn") !== isAsTarget()) $("#target").value = "";
  updateTargetMode();
}));
$("#target").addEventListener("input", updateTargetMode);
updateTargetMode();

async function postJob(url, body, done){
  $("#log").textContent = ""; $("#now").textContent = "Starting";
  show("running"); $("#run").disabled = true; $("#cancel").hidden = false;
  try {
    const report = await runJob(url, body, {
      onStarted: id => { jobId = id; },
      onProgress: state => {
        $("#now").textContent = state.progress || "";
        const log = $("#log"); log.textContent = (state.log || []).join("\n"); log.scrollTop = log.scrollHeight;
      }
    });
    stopPolling(); done(report);
  } catch (error) { fail(error.message || "The local server isn't responding."); }
}

async function submitFootprint(){
  const single = $("#fpSingle").value.trim();
  const file = $("#fpFile").files[0];
  if (single && file) return fail("Enter one IP or prefix, or choose a file, not both.");
  if (!single && !file) return fail("Enter one IP or prefix, or choose a CSV or text file.");
  if (file && file.size > 1024 * 1024) return fail("The file is larger than 1 MB. Split it into smaller files.");
  let text;
  if (single) text = single;
  else try { text = await file.text(); } catch { return fail("The file couldn't be read."); }
  postJob("/api/footprint/resolve", {csv: text, org_keywords: $("#fpKeywords").value,
    include_low_visibility: $("#fpLowVis").checked}, res => renderConfirm(res));
}

$("#plan").addEventListener("submit", ev => {
  ev.preventDefault();
  shodanRequested = lookupMode() !== "asn" && $("#includeShodan").checked;
  if (lookupMode() === "footprint") return submitFootprint();
  postJob("/api/analyze", {target: $("#target").value.trim(), tier: "public",
    measurement_ids: $("#msm").value, control_plane: $("#cp").checked}, r => enrichServices(r, [r.meta.target_resource], enriched => {result=enriched;render(enriched);}));
});

$("#openRun").addEventListener("click", () => $("#openFile").click());
$("#openFile").addEventListener("change", async ev => {
  const f = ev.target.files[0]; ev.target.value = "";
  shodanRequested = false;
  if (!f) return;
  let r;
  if (f.size > 16 * 1024 * 1024) return fail("The saved report exceeds the 16 MB import limit.");
  try {
    const response = await fetch("/api/import", {method: "POST", headers: {"Content-Type": "application/json"}, body: await f.text()});
    r = await response.json();
    if (!response.ok) return fail(r.error || "The report couldn't be opened.");
  } catch { return fail("The saved report couldn't be read by the local server."); }
  try {
    if (r && r.kind === "footprint_run" && r.adjacency) renderFootprint(r);
    else if (r && r.kind === "footprint_resolution" && r.origins) renderConfirm(r, {fromFile: true});
    else if (r && r.meta && ["ip", "asn"].includes(r.meta.target_kind) && r.graph) { result = r; render(r); }
    else fail("That file isn't a Pathfinder export.");
  } catch (e) { fail(`The file couldn't be displayed: ${e.message}`); }
});

$("#cancel").addEventListener("click", async () => {
  if (!jobId) return;
  await fetch(`/api/job/${jobId}/cancel`, {method:"POST"}).catch(()=>{});
  $("#now").textContent = "Cancelling after the current request";
});

function stopPolling(){ jobId=null; $("#run").disabled=false; $("#cancel").hidden=true; }
function fail(msg){ stopPolling(); $("#error").innerHTML = `<h2>Analysis didn't finish</h2><p>${esc(msg)}</p>`; show("error"); }

function render(r){
  const isAs = r.meta.target_kind === "asn";
  $("#report").innerHTML = `<div class="brief"><h2>${isAs ? "ASN routing context" : "IP infrastructure context"}</h2>
    <p class="target">${targetContext(r)}</p><p class="lede">${r.summary.map(x=>`<span>${esc(x)}</span>`).join("")}</p>
    ${!isAs ? `<button type="button" class="quiet" id="exploreOrigin">Explore AS${esc(r.meta.origin.asn)}</button><p class="hint">Optional broader context. This does not identify the path the observed IP took.</p>` : ""}</div>
    <section class="block"><h2>Adjacent network context</h2>${adjacencyTable(r, {collapsible: true})}</section>
    <section class="block"><h2>${isAs ? "Observed BGP paths" : "Routing observations and inferred mappings"}</h2>
      <p class="sub">${isAs ? "This graph shows BGP advertisements only; Atlas hop-to-AS mapping is not performed." : "Dashed edges are BGP advertisements. Solid edges are inferred from reply-address prefix origins in existing Atlas samples."} Neither reconstructs an observed perimeter connection.</p>
      <p class="sub">A compact five-hop routing overview. Select a network to inspect it. Up to three networks per hop are emphasized; a small number of lower-frequency networks are faded for context. The evidence section and exports retain their documented path subsets.</p>
      <div class="chartbar">
        ${!isAs ? `<label class="key"><input type="checkbox" id="lyData" ${layers.data ? "checked" : ""}>Inferred hop mappings</label>` : ""}
        <label class="key"><input type="checkbox" id="lyCp" ${layers.cp ? "checked" : ""}>Observed BGP paths</label>
      </div><div class="chartwrap"><div id="chart"></div></div><div class="nodecard" id="nodecard"></div></section>
    ${servicesHTML(r,{interactive:true})}<section class="block"><h2>Evidence and coverage</h2>${evidenceHTML(r)}
      <div class="exports"><button type="button" id="exHtml">Download report</button><button type="button" class="quiet" id="exJson">JSON evidence</button><button type="button" class="quiet" id="exPrint">Print or save PDF</button></div></section>`;
  show("report"); wireServices(r); drawChart();
  if ($("#lyData")) $("#lyData").addEventListener("change",ev=>{layers.data=ev.target.checked;drawChart();});
  $("#lyCp").addEventListener("change",ev=>{layers.cp=ev.target.checked;drawChart();});
  if ($("#exploreOrigin")) $("#exploreOrigin").addEventListener("click",()=>{
    $("#target").value = `AS${r.meta.origin.asn}`; $("#msm").value = ""; updateTargetMode();
    $("#plan").scrollIntoView(); $("#target").focus();
  });
  $("#exJson").addEventListener("click",()=>download(`infrastructure-${fileStamp(r)}.json`,JSON.stringify(r,null,2),"application/json"));
  $("#exHtml").addEventListener("click",()=>download(`infrastructure-${fileStamp(r)}.html`,reportHTML(r),"text/html"));
  $("#exPrint").addEventListener("click",()=>{document.querySelectorAll("details").forEach(d=>d.open=true);window.print();});
}

function renderConfirm(res, opts = {}){
  resolution = res;
  $("#report").innerHTML = confirmHTML(res, opts);
  show("report");
  const boxes = () => [...document.querySelectorAll(".confirm-asn")];
  const sync = () => {
    const n = boxes().filter(b => b.checked).length;
    $("#readAdj").disabled = !n;
    $("#readAdj").textContent = n ? `Read adjacency for ${plural(n, "ASN")}` : "Select at least one ASN";
  };
  boxes().forEach(b => b.addEventListener("change", sync)); sync();
  $("#selAll").addEventListener("click", () => { boxes().forEach(b => b.checked = true); sync(); });
  $("#selNone").addEventListener("click", () => { boxes().forEach(b => b.checked = false); sync(); });
  $("#readAdj").addEventListener("click", () => postJob("/api/footprint/adjacency",
    {resolution_job: res.meta.job_id, asns: boxes().filter(b => b.checked).map(b => Number(b.value))},
    rec => enrichServices(rec, res.resolution.map(x=>x.input), renderFootprint)));
  $("#resJson").addEventListener("click", () => download(`pathfinder-resolution-${stamp(res)}.json`, JSON.stringify(res, null, 2), "application/json"));
  $("#resCsv").addEventListener("click", () => download(`pathfinder-resolution-${stamp(res)}.csv`, resolutionCSV(res), "text/csv"));
}

function wireSort(rec){
  document.querySelectorAll("#neighborTable .sortbtn").forEach(btn => btn.addEventListener("click", () => {
    const key = btn.dataset.sort;
    fpSort = fpSort.key === key ? {key, dir: -fpSort.dir} : {key, dir: (key === "name" || key === "positions" || key === "asn") ? 1 : -1};
    $("#neighborTable").innerHTML = neighborsTableHTML(rec, fpSort);
    wireSort(rec);
    const again = document.querySelector(`#neighborTable .sortbtn[data-sort="${key}"]`); if (again) again.focus();
  }));
}

function renderFootprint(rec){
  footprint = rec; fpSort = {key: null, dir: -1};
  $("#report").innerHTML = footprintReportHTML(rec, {interactive: true});
  show("report");
  wireSort(rec); wireServices(rec);
  document.querySelectorAll(".drill").forEach(btn => btn.addEventListener("click", () => drillDown(Number(btn.dataset.asn), btn)));
  $("#fpJson").addEventListener("click", () => download(`pathfinder-footprint-${stamp(rec)}.json`, JSON.stringify(rec, null, 2), "application/json"));
  $("#fpAdjCsv").addEventListener("click", () => download(`pathfinder-adjacency-${stamp(rec)}.csv`, adjacencyCSV(rec), "text/csv"));
  $("#fpResCsv").addEventListener("click", () => download(`pathfinder-resolution-${stamp(rec)}.csv`, resolutionCSV(rec), "text/csv"));
  $("#fpPrint").addEventListener("click", () => { document.querySelectorAll("details").forEach(d => d.open = true); window.print(); });
}

async function drillDown(asn, btn){
  const box = $("#footprintPathMap");
  const buttons = [...document.querySelectorAll(".drill")];
  buttons.forEach(b => { b.disabled = true; b.setAttribute("aria-pressed", "false"); });
  box.innerHTML = `<p class="hint">Loading observed BGP paths for AS${esc(asn)}…</p>`;
  try {
    const r = await runJob("/api/analyze", {target: `AS${asn}`, tier: "public", measurement_ids: "", control_plane: true}, {
      onProgress: state => { box.innerHTML = `<p class="hint">AS${esc(asn)}: ${esc(state.progress || "Working")}</p>`; }
    });
    if (!box.isConnected) return;
    box.innerHTML = drillMapContextHTML(r, {interactive: true, heading: false}) + `<p class="sub">${r.summary.map(esc).join(" ")}</p><div class="chartwrap"><div class="routing-chart"></div></div><div class="nodecard no-print"></div>`;
    drawChart(r, box.querySelector(".routing-chart"), box.querySelector(".nodecard"), {data: false, cp: true});
    buttons.forEach(b => b.setAttribute("aria-pressed", String(b === btn)));
  } catch (error) { if (box.isConnected) box.innerHTML = `<p class="error">${esc(error.message)}</p>`; }
  finally { buttons.forEach(b => { b.disabled = false; }); }
}

function drawChart(r = result, host = $("#chart"), card = $("#nodecard"), selectedLayers = layers){
  host.classList.add("routing-chart");
  host.innerHTML = chartSVG(r, {layers: selectedLayers});
  card.innerHTML = "";
  host.querySelectorAll(".node").forEach(g => {
    const act = () => focusNode(Number(g.dataset.asn), r, host, card);
    g.addEventListener("click", act);
    g.addEventListener("keydown", ev => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); act(); } });
  });
}

function focusNode(asn, r, host, card){
  const linked = new Set([asn]);
  host.querySelectorAll(".edge").forEach(p => {
    const on = Number(p.dataset.a) === asn || Number(p.dataset.b) === asn;
    p.classList.toggle("dim", !on);
    if (on) { linked.add(Number(p.dataset.a)); linked.add(Number(p.dataset.b)); }
  });
  host.querySelectorAll(".node").forEach(g => g.classList.toggle("dim", !linked.has(Number(g.dataset.asn))));
  const n = r.graph.nodes.find(x => x.asn === asn) || {};
  const adjacent = r.routing_context.adjacencies.find(x=>x.asn===asn);
  card.innerHTML = `<p>${asLabel(asn,n.name)}</p><p>${n.cp || 0} retained BGP records; ${r.meta.target_kind === "asn" ? "Atlas hop-to-AS mapping not performed" : `${n.data || 0} inferred Atlas mappings`}. Nearest displayed position: ${n.depth} AS hops before the selected origin. Counts describe samples, not traffic or confidence.</p>
    ${adjacent ? `<p>${esc(adjacent.interpretation)}</p>` : ""}
    <p>Provider relationship and router ownership are unverified.</p><p><button type="button" class="quiet clear-focus">Show all paths</button></p>`;
  card.querySelector(".clear-focus").addEventListener("click", () => { host.querySelectorAll(".dim").forEach(x => x.classList.remove("dim")); card.innerHTML = ""; });
}

/* ---------- Exports ---------- */
function fileStamp(r){ return `AS${r.meta.origin.asn}-${r.meta.generated_utc.replace(/[:]/g, "").replace("T", "-").replace("Z", "")}`; }

function download(name, text, type){
  const url = URL.createObjectURL(new Blob([text], {type}));
  const a = Object.assign(document.createElement("a"), {href: url, download: name});
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const serviceDisplayPages = new WeakMap();
function wireServices(r){
 for(const [provider,field] of [["shodan","service_observations"]]){
 const observations=r[field];if(!observations)continue;
 const section=document.querySelector(`#report [data-service-provider="${provider}"]`);
 if(!section)continue;
 const name="Shodan";
 // Renderer exports retain every fetched row; only the live table is paginated.
 section.querySelectorAll(".service-disclosure").forEach(btn=>btn.addEventListener("click",()=>{
  const expanded=btn.getAttribute("aria-expanded")!=="true";
  btn.setAttribute("aria-expanded",String(expanded));btn.querySelector("span").textContent=expanded ? "▾" : "▸";
  document.getElementById(btn.getAttribute("aria-controls")).hidden=!expanded;
 }));
 const selectors=section.querySelectorAll("[data-service-nav]");
 for(const nav of selectors){
  const index=nav.dataset.serviceNav, record=observations.records[Number(index)];
  let page=serviceDisplayPages.get(record) || 1;
  const showPage=()=>{
   serviceDisplayPages.set(record,page);
   const count=Math.max(1,Math.ceil(record.services.length/20));
   section.querySelectorAll(`[data-service-row="${index}"]`).forEach(row=>{row.hidden=Math.floor(Number(row.dataset.row)/20)+1!==page;});
   section.querySelectorAll(`[data-service-detail="${index}"]`).forEach(row=>{const btn=section.querySelector(`[aria-controls="${row.id}"]`);row.hidden=Math.floor(Number(row.dataset.row)/20)+1!==page || btn?.getAttribute("aria-expanded")!=="true";});
   nav.replaceChildren();
   const button=(label,action,disabled=false)=>{const b=document.createElement("button");b.type="button";b.className="quiet";b.textContent=label;b.disabled=disabled;b.addEventListener("click",action);nav.append(b);return b;};
   button("Previous",()=>{page--;showPage();},page===1);
   const start=Math.max(1,Math.min(page-3,count-6));
   if(start>1) button("1",()=>{page=1;showPage();});
   for(let n=start;n<=Math.min(count,start+6);n++){const b=button(String(n),()=>{page=n;showPage();});if(n===page)b.setAttribute("aria-current","page");}
   if(start+6<count) button(String(count),()=>{page=count;showPage();});
   button("Next",()=>{page++;showPage();},page===count);
   const latest=Math.max(...(record.pages || [1]));
   if(record.truncated && record.resource.includes("/") && latest<100){
    const load=button("Load next 100 records from Shodan (uses credits)",async()=>{
     load.disabled=true;
     const message=section.querySelector(`[data-service-message="${index}"]`);message.textContent=`Reading the next ${name} page…`;
     try{
      const next=await runJob("/api/shodan/page",{resources:[record.resource],page:latest+1});
      const batch=next.records[0];
      if(batch.status==="failed")throw new Error(batch.error || `${name} page unavailable.`);
      const identity=v=>JSON.stringify([v.ip,v.port,v.transport,v.service,v.observed_at,v.source_record_id,v.host,v.path]);
      const previousLength=record.services.length;
      const seen=new Set(record.services.map(identity));
      for(const row of batch.services)if(!seen.has(identity(row))){record.services.push(row);seen.add(identity(row));}
      record.pages=[...(record.pages || [1]),batch.page];record.page_sources=[...(record.page_sources || []),...batch.page_sources];
      record.coverage_unknown=batch.coverage_unknown;record.total=batch.total;record.truncated=batch.truncated;record.rejected_records+=batch.rejected_records;
      record.retrieved_at=batch.retrieved_at;record.status=record.truncated || record.rejected_records || record.coverage_unknown ? "partial" : record.services.length ? "available" : "empty";
      if(record.services.length>previousLength)serviceDisplayPages.set(record,Math.floor(previousLength/20)+1);
      if(section.isConnected){if(footprint===r)renderFootprint(r);else render(r);}
     }catch(e){record.page_failures=[...(record.page_failures || []),{page:latest+1,error:e.message}];message.textContent=e.message+" Existing records are retained.";load.disabled=false;}
    });
   }
   const msg=section.querySelector(`[data-service-message="${index}"]`);msg.textContent=`Page ${page} of ${count}, 20 rows per display page. ${record.services.length} fetched service records.`+(record.truncated && latest>=100 ? " Retrieval limit of 100 source pages reached." : "");
  };
  showPage();
 }
 const btn=document.createElement("button");btn.type="button";btn.className="quiet no-print";btn.textContent="Service observations CSV";
 btn.addEventListener("click",()=>download(`pathfinder-services-${stamp(r)}.csv`,servicesCSV({[field]:observations}),"text/csv"));section.append(btn);
 }
}
// Print/PDF includes all fetched observations, regardless of the selected display page.
window.addEventListener("beforeprint",()=>document.querySelectorAll("[data-service-row],[data-service-detail]").forEach(row=>{row.dataset.wasHidden=String(row.hidden);row.hidden=false;}));
window.addEventListener("afterprint",()=>document.querySelectorAll("[data-service-row],[data-service-detail]").forEach(row=>{row.hidden=row.dataset.wasHidden==="true";}));
