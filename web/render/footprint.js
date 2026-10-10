import {servicesHTML} from "./services.js";
import {esc, pct, asLabel, nf, plural, csvCell, toCSV, stamp} from "./format.js";
const STATUS_TEXT = {announced: "announced", partially_announced: "not announced as a whole; contains announcements",
  not_announced: "no covering announcement seen", lookup_failed: "lookup failed", not_resolved: "not resolved (lookup limit)"};
const POSITION_TEXT = {left: "left", right: "right", uncertain: "uncertain"};
const MAX_TABLE_ROWS = 1000;
const DEFAULT_SORT = {key: null, dir: -1};

// CSV cells are quoted, and cells that a spreadsheet would run as a formula are prefixed with an apostrophe.
export function resolutionCSV(res){
  return toCSV(["line", "input", "kind", "status", "covering_prefix", "origin_asns", "origin_holders",
                "more_specific_announcements", "method", "filtered_routes", "error"],
    res.resolution.map(r => [r.line, r.input, r.kind, r.status, r.covering_prefix || "",
      r.origins.map(o => o.asn).join(" "), r.origins.map(o => o.holder || "").join(" | "),
      r.more_specifics.map(p => `${p.prefix}=${p.origins.map(o => "AS" + o.asn).join("+") || "none"}`).join(" "),
      r.method || "", r.filtered_routes, r.error || ""]));
}
export function adjacencyCSV(rec){
  const holders = new Map(rec.origins.map(o => [o.asn, o.holder]));
  const rows = [];
  for (const p of rec.adjacency.per_asn) for (const n of p.neighbors) {
    const agg = rec.adjacency.neighbors.find(x => x.asn === n.asn) || {};
    rows.push([p.asn, holders.get(p.asn) || "", n.asn, agg.name || "", agg.is_confirmed_asn ? "yes" : "no",
               n.type, n.power, n.v4_peers, n.v6_peers, p.source.query_starttime || "", p.source.url]);
  }
  return toCSV(["your_asn", "your_asn_holder", "neighbor_asn", "neighbor_holder", "neighbor_is_confirmed_asn",
                "position", "power", "v4_peers", "v6_peers", "query_starttime", "source_url"], rows);
}

export function inputsLine(inp){
  return `${plural(inp.rows_read, "row")} read · ${nf(inp.accepted)} accepted · ${plural(inp.duplicates, "duplicate")} removed · ${nf(inp.rejected_total)} rejected${inp.header ? ` · header “${esc(inp.header)}” skipped` : ""}`;
}
export function rejectedHTML(inp){
  if (!inp.rejected_total) return "";
  return `<details><summary>Rejected rows (${nf(inp.rejected_total)}${inp.rejected_truncated ? `; first ${inp.rejected.length} listed` : ""})</summary>
    <div class="tablewrap"><table><thead><tr><th>Line</th><th>Value</th><th>Reason</th></tr></thead><tbody>
    ${inp.rejected.map(r => `<tr><td class="num">${esc(r.line)}</td><td class="mono">${esc(r.value)}</td><td>${esc(r.reason)}</td></tr>`).join("")}</tbody></table></div></details>`;
}
export function unmappedHTML(res){
  const rows = res.resolution.filter(r => !r.origins.length && !r.more_specifics.some(p => p.origins.length));
  if (!rows.length) return "";
  return `<details><summary>Entries with no origin ASN (${nf(rows.length)})</summary>
    <div class="tablewrap"><table><thead><tr><th>Line</th><th>Entry</th><th>Result</th></tr></thead><tbody>
    ${rows.map(r => `<tr><td class="num">${esc(r.line)}</td><td class="mono">${esc(r.input)}</td><td>${esc(STATUS_TEXT[r.status] || r.status)}${r.error ? ` · ${esc(r.error)}` : ""}</td></tr>`).join("")}</tbody></table></div></details>`;
}
export function statusLine(res){
  const c = res.status_counts || {};
  return Object.keys(STATUS_TEXT).filter(k => c[k]).map(k => `${nf(c[k])} ${STATUS_TEXT[k]}`).join(" · ");
}
export function sourcesHTML(rec){
  const po = rec.sources.prefix_overview, an = rec.sources.asn_neighbors, st = rec.settings;
  return `<p class="sub">Resolution: ${esc(po.name)} · ${plural(po.lookups, "lookup")} · ${nf(po.reused)} answered from an already-read covering prefix · data time ${esc(po.query_times.join(", ") || "not supplied")}.</p>
    <p class="sub">Visibility: ${st.include_low_visibility ? "low-visibility routes included (min_peers_seeing=1)" : `RIPE default threshold${st.visibility_threshold ? ` (${st.visibility_threshold} RIS peers)` : ""}`} · ${plural(po.filtered_routes, "route")} left out by that threshold.${st.org_keywords.length ? ` Holder-name keywords: ${st.org_keywords.map(k => `“${esc(k)}”`).join(", ")}.` : ""}</p>
    ${an ? `<p class="sub">Adjacency: ${esc(an.name)} · data time ${esc(an.query_times.join(", ") || "not supplied")}.</p>` : ""}
    ${po.messages.length ? `<details><summary>RIPE response messages (${po.messages.length})</summary><ul class="notes">${po.messages.map(m => `<li>${esc(m.message)} <span class="counts">× ${nf(m.count)}</span></li>`).join("")}</ul></details>` : ""}`;
}

export function confirmHTML(res, opts = {}){
  const total = res.inputs.accepted;
  const rows = res.origins.map(o => `<tr>
      <td class="check-cell"><input type="checkbox" class="confirm-asn" value="${esc(o.asn)}" ${o.default_selected ? "checked" : ""} aria-label="Treat AS${esc(o.asn)} as yours"></td>
      <td>${asLabel(o.asn, o.holder)}${o.matched_keyword ? `<span class="nm">Pre-checked: holder contains “${esc(o.matched_keyword)}”</span>` : ""}</td>
      <td class="num">${nf(o.entries)} · ${pct(o.share)}</td>
      <td class="mono">${o.prefixes.slice(0, 4).map(esc).join("<br>")}${o.prefixes.length > 4 ? `<br><span class="nm">+${nf(o.prefixes.length - 4)} more</span>` : ""}</td>
      <td>${o.multi_origin_entries ? `${plural(o.multi_origin_entries, "entry", "entries")} also announced by another origin` : ""}</td></tr>`).join("");
  return `<div class="brief"><h2>Confirm which origin ASNs are yours</h2>
    <p class="target">${inputsLine(res.inputs)}. Resolved ${esc(res.meta.generated_utc)}.</p>
    <p class="lede"><span>${plural(total, "entry", "entries")} map to ${plural(res.origins.length, "origin ASN")}.</span><span class="counts">${statusLine(res)}</span></p>
    ${opts.fromFile ? `<p class="hint">Opened from a file. Reading adjacency needs this resolution to still be held by the server (one hour after it finished); otherwise upload the CSV again.</p>` : ""}</div>
    <section class="block"><h2>Origin ASNs in your footprint</h2>
      <p class="sub">Checked ASNs are treated as yours: Pathfinder reads their observed neighbors. Unchecked ASNs stay in the record and are not queried. For entries in cloud, CDN or hosting space, the origin and its neighbors belong to the provider. Ordered by footprint entries, then ASN.</p>
      ${res.origins.length ? `<div class="tablewrap"><table><thead><tr><th><span class="sr-only">Yours</span></th><th>Origin ASN</th><th>Footprint entries</th><th>Announced prefixes</th><th>Notes</th></tr></thead><tbody>${rows}</tbody></table></div>` : "<p>No entry resolved to an origin ASN.</p>"}
      <div class="actions"><button type="button" id="readAdj">Read adjacency</button><button type="button" class="quiet" id="selAll">Select all</button><button type="button" class="quiet" id="selNone">Clear</button></div>
      <p class="hint">One RIPE request per checked ASN, plus holder-name lookups for up to 150 neighbors, paced at least one second apart.</p>
      ${unmappedHTML(res)}${rejectedHTML(res.inputs)}</section>
    <section class="block"><h2>Evidence and coverage</h2>${sourcesHTML(res)}
      ${res.warnings.length ? `<h3>Warnings and limits</h3><ul class="notes">${res.warnings.map(w => `<li>${esc(w)}</li>`).join("")}</ul>` : ""}
      <div class="exports"><button type="button" class="quiet" id="resJson">Resolution JSON</button><button type="button" class="quiet" id="resCsv">Resolution CSV</button></div></section>`;
}

export function sortValue(n, key){
  if (key === "name") return (n.name || "").toLowerCase();
  if (key === "positions") return n.positions.join(",");
  return n[key];
}
export function sortedNeighbors(rows, sort){
  if (!sort.key) return rows;
  return [...rows].sort((a, b) => {
    const va = sortValue(a, sort.key), vb = sortValue(b, sort.key);
    return ((va < vb ? -1 : va > vb ? 1 : 0) * sort.dir) || a.asn - b.asn;
  });
}
const NEIGHBOR_COLUMNS = [["asn", "Neighbor"], ["name", "Holder"], ["your_asn_count", "Your ASNs"], ["positions", "Position"],
  ["max_v4_peers", "IPv4 routes"], ["max_v6_peers", "IPv6 routes"], ["max_power", "AS paths"]];
export function neighborsTableHTML(rec, sort = DEFAULT_SORT){
  const rows = sortedNeighbors(rec.adjacency.neighbors, sort);
  const shown = rows.slice(0, MAX_TABLE_ROWS);
  const head = NEIGHBOR_COLUMNS.map(([key, label]) => {
    const state = sort.key === key ? (sort.dir > 0 ? "ascending" : "descending") : "none";
    return `<th class="sortable" aria-sort="${state}"><button type="button" class="sortbtn" data-sort="${key}">${label}</button></th>`;
  }).join("");
  const body = shown.map(n => `<tr>
      <td>${asLabel(n.asn, null)}${n.is_confirmed_asn ? `<span class="nm">Your confirmed ASN</span>` : ""}</td>
      <td>${esc(n.name || "")}</td>
      <td>${n.relations.map(r => `<span class="rel">AS${esc(r.your_asn)} · ${esc(POSITION_TEXT[r.type])} · ${nf(r.v4_peers)} v4 / ${nf(r.v6_peers)} v6 routes · ${nf(r.power)} paths</span>`).join("")}</td>
      <td>${n.positions.map(p => esc(POSITION_TEXT[p])).join(", ")}</td>
      <td class="num">${nf(n.max_v4_peers)}</td><td class="num">${nf(n.max_v6_peers)}</td><td class="num">${nf(n.max_power)}</td></tr>`).join("");
  return `<div class="tablewrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>
    ${rows.length > shown.length ? `<p class="hint">Showing ${nf(shown.length)} of ${nf(rows.length)} neighbors. The JSON and CSV exports include all of them.</p>` : ""}`;
}

export function footprintGraphSVG(rec){
  const mine = rec.adjacency.per_asn.filter(p => p.source.status === "available").map(p => p.asn);
  const holders = new Map(rec.origins.map(o => [o.asn, o.holder]));
  const external = rec.adjacency.neighbors.filter(n => !n.is_confirmed_asn);
  const internal = rec.adjacency.neighbors.filter(n => n.is_confirmed_asn);
  const left = external.filter(n => n.relations.some(r => r.type !== "right"));
  const right = external.filter(n => n.relations.every(r => r.type === "right"));
  const W = 1100, top = 64, rowH = 58, cx = {left: 230, mid: 550, right: 870}, half = 92;
  const rowsN = Math.max(left.length, right.length, mine.length, 3);
  const H = top + rowsN * rowH + 24;
  const place = (list, x) => new Map(list.map((n, i) => [n.asn ?? n, {x, y: top + (rowsN - list.length) * rowH / 2 + i * rowH + rowH / 2}]));
  const pos = new Map([...place(left, cx.left), ...place(right, cx.right), ...place(mine, cx.mid)]);
  const routes = r => r.v4_peers + r.v6_peers;
  const maxR = Math.max(1, ...rec.adjacency.neighbors.flatMap(n => n.relations.map(routes)));
  const width = r => (1 + 5 * Math.sqrt(routes(r) / maxR)).toFixed(2);
  const short = (t, n = 26) => (t || "").length > n ? t.slice(0, n - 1) + "…" : (t || "");
  const title = (n, r) => `<title>AS${n.asn} ${esc(POSITION_TEXT[r.type])} of AS${r.your_asn}: ${nf(r.v4_peers)} IPv4 / ${nf(r.v6_peers)} IPv6 routes, ${nf(r.power)} AS paths</title>`;
  let s = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Observed BGP neighbors of ${mine.length} confirmed ASNs" font-family="system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif">`;
  s += `<rect x="${cx.mid - half - 18}" y="0" width="${2 * half + 36}" height="${H}" fill="var(--perimeter)"/>`;
  [["Left of your ASNs", cx.left], ["Your confirmed ASNs", cx.mid], ["Right of your ASNs", cx.right]]
    .forEach(([t, x]) => { s += `<text x="${x}" y="26" font-size="13" fill="var(--muted)" text-anchor="middle">${t}</text>`; });
  for (const n of external) for (const r of n.relations) {
    const a = pos.get(n.asn), b = pos.get(r.your_asn); if (!a || !b) continue;
    const bx = a.x < cx.mid ? b.x - half : b.x + half, mx = (a.x + bx) / 2;
    s += `<path d="M${a.x},${a.y} C${mx},${a.y} ${mx},${b.y} ${bx},${b.y}" fill="none" stroke="var(--observed)" stroke-opacity=".7" stroke-width="${width(r)}"${r.type === "uncertain" ? ` stroke-dasharray="4 4"` : ""}>${title(n, r)}</path>`;
  }
  for (const n of internal) for (const r of n.relations) {
    const a = pos.get(n.asn), b = pos.get(r.your_asn); if (!a || !b) continue;
    const ex = cx.mid + half, bend = ex + 26 + Math.abs(a.y - b.y) / 4;
    s += `<path d="M${ex},${a.y} C${bend},${a.y} ${bend},${b.y} ${ex},${b.y}" fill="none" stroke="var(--accent)" stroke-opacity=".85" stroke-width="${width(r)}"${r.type === "uncertain" ? ` stroke-dasharray="4 4"` : ""}>${title(n, r)}</path>`;
  }
  for (const asn of mine) {
    const p = pos.get(asn);
    s += `<rect x="${p.x - half}" y="${p.y - 20}" width="${2 * half}" height="40" rx="5" fill="var(--surface)" stroke="var(--text-strong)" stroke-width="1.5"/>`;
    s += `<text x="${p.x}" y="${p.y - 3}" font-size="13" font-weight="600" text-anchor="middle" fill="var(--text-strong)">AS${asn}</text>`;
    s += `<text x="${p.x}" y="${p.y + 12}" font-size="10.5" text-anchor="middle" fill="var(--muted)">${esc(short(holders.get(asn), 25))}</text>`;
  }
  for (const [list, side] of [[left, "left"], [right, "right"]]) for (const n of list) {
    const p = pos.get(n.asn), rad = 5 + 3 * (n.your_asn_count - 1);
    const tx = side === "left" ? p.x - rad - 8 : p.x + rad + 8, anchor = side === "left" ? "end" : "start";
    s += `<circle cx="${p.x}" cy="${p.y}" r="${rad}" fill="var(--surface)" stroke="var(--text-strong)" stroke-width="${n.your_asn_count > 1 ? 2.5 : 1.5}"/>`;
    s += `<text x="${tx}" y="${p.y - 2}" font-size="12" font-weight="600" text-anchor="${anchor}" fill="var(--text-strong)">AS${n.asn}</text>`;
    s += `<text x="${tx}" y="${p.y + 12}" font-size="11" text-anchor="${anchor}" fill="var(--muted)">${esc(short(n.name))}</text>`;
  }
  return s + `</svg>`;
}

export function perAsnHTML(rec, interactive){
  const origins = new Map(rec.origins.map(o => [o.asn, o]));
  return rec.adjacency.per_asn.map(p => {
    const o = origins.get(p.asn) || {}, src = p.source;
    const counts = ["left", "right", "uncertain"].map(t => `${p.neighbors.filter(n => n.type === t).length} ${t}`).join(" / ");
    const names = new Map(rec.adjacency.neighbors.map(n => [n.asn, n.name]));
    const rows = [...p.neighbors].sort((a, b) => (b.v4_peers + b.v6_peers) - (a.v4_peers + a.v6_peers) || a.asn - b.asn);
    return `<details class="asn-section"><summary>${asLabel(p.asn, null)}<span>${esc(o.holder || "")}</span><span class="counts">${src.status === "available" ? `${plural(p.neighbors.length, "neighbor")} (${counts})` : "neighbor data unavailable"} · ${plural(o.entries || 0, "footprint entry", "footprint entries")}</span></summary>
      <div class="inner">
        <p class="sub">Source: ${esc(src.name)} · status ${esc(src.status)} · data time ${esc(src.query_starttime || "not supplied")} · retrieved ${esc(src.retrieved_at || "not retrieved")}${src.version ? ` · data call version ${esc(src.version)}` : ""}${src.error ? ` · ${esc(src.error)}` : ""}.</p>
        ${src.messages && src.messages.length ? `<p class="sub">RIPE: ${src.messages.map(esc).join(" · ")}</p>` : ""}
        ${rows.length ? `<div class="tablewrap"><table><thead><tr><th>Neighbor</th><th>Position</th><th>IPv4 routes</th><th>IPv6 routes</th><th>AS paths</th></tr></thead><tbody>
          ${rows.map(n => `<tr><td>${asLabel(n.asn, names.get(n.asn))}</td><td>${esc(POSITION_TEXT[n.type])}</td><td class="num">${nf(n.v4_peers)}</td><td class="num">${nf(n.v6_peers)}</td><td class="num">${nf(n.power)}</td></tr>`).join("")}</tbody></table></div>
          <p class="hint">Ordered by IPv4 plus IPv6 routes, then ASN.</p>` : ""}
        <details class="footprint-mapping"><summary><span>Footprint entries and announced prefixes</span><span class="summary-meta">Expand to compare ${nf(o.entries || 0)} footprint ${o.entries === 1 ? "entry" : "entries"} with ${nf((o.prefixes || []).length)} announced ${(o.prefixes || []).length === 1 ? "prefix" : "prefixes"}</span></summary>
          <p class="mono">${(o.inputs || []).map(esc).join(", ")}${o.inputs_truncated ? ` … first ${o.inputs.length} listed` : ""}</p>
          <p class="mono">${(o.prefixes || []).map(esc).join(", ")}</p></details>

      </div></details>`;
  }).join("");
}

export function footprintReportHTML(rec, opts = {}){
  const interactive = !!opts.interactive;
  const confirmed = rec.origins.filter(o => o.confirmed), others = rec.origins.filter(o => !o.confirmed);
  const neighbors = rec.adjacency.neighbors;
  const graphable = rec.confirmed_asns.length <= 5 && neighbors.length <= 40 && neighbors.length > 0;
  const defs = rec.adjacency.field_definitions;
  return `<div class="brief"><h2>Footprint adjacency</h2>
      <p class="target">${inputsLine(rec.inputs)}. Resolved ${esc(rec.meta.resolution_generated_utc)}; adjacency read ${esc(rec.meta.generated_utc)}.</p>
      <p class="lede">${rec.summary.map(x => `<span>${esc(x)}</span>`).join("")}</p></div>
    <section class="block"><h2>Your confirmed ASNs</h2>
      <div class="tablewrap"><table><thead><tr><th>ASN</th><th>Footprint entries</th><th>Observed neighbors</th><th>Data time</th></tr></thead><tbody>
      ${rec.adjacency.per_asn.map(p => { const o = confirmed.find(c => c.asn === p.asn) || {}; return `<tr><td>${asLabel(p.asn, p.holder)}</td><td class="num">${nf(o.entries)} · ${pct(o.share)}</td><td class="num">${p.source.status === "available" ? nf(p.neighbors.length) : "unknown"}</td><td class="mono">${esc(p.source.query_starttime || "not supplied")}</td></tr>`; }).join("")}
      </tbody></table></div></section>
    <section class="block"><h2>Networks adjacent to your footprint</h2>
      <p class="sub">Every network RIS observes next to a confirmed ASN, one row per network. ${interactive ? "Select a column heading to sort. " : ""}Default order: number of your ASNs, then IPv4 plus IPv6 routes, then ASN.</p>
      <p class="sub">Position: ${esc(defs.position)}</p>
      <p class="sub">Route and path counts are RIPE's v4_peers, v6_peers and power fields. ${esc(defs.v4_peers.split(". ").slice(1).join(". "))} They don't measure traffic.</p>
      <div id="neighborTable">${neighbors.length ? neighborsTableHTML(rec, opts.sort || DEFAULT_SORT) : "<p>No neighbors were observed for the confirmed ASNs. Review source status below.</p>"}</div></section>
    <section class="block"><h2>Combined view</h2>
      <p class="sub">Left and right describe positions in RIPE-observed BGP advertisements. Left is toward the route collector; right is toward the network originating the advertised route. A right-side neighbor is not necessarily that origin. These positions do not identify incoming or outgoing traffic, or establish a provider or customer relationship.</p>
      <p class="sub"><strong>Question for network operations:</strong> For a right-side neighbor, “Do we expect routes toward this ASN, and any origin ASNs beyond it, to be advertised through our ASN?” If the neighbor is the final ASN in a specific observed path, ask, “Do we expect routes originating from that ASN to be advertised through our ASN?” Validate against router state, routing policy, and provider records.</p>
      ${graphable ? `<p class="sub">All confirmed ASNs and their observed neighbors. Line width follows IPv4 plus IPv6 routes; dashed lines are uncertain positions; arcs on the right join two of your own ASNs. A thicker circle is adjacent to more than one of your ASNs.</p><div class="chartwrap">${footprintGraphSVG(rec)}</div>`
        : `<p class="sub">The combined view is drawn for up to 5 confirmed ASNs and 40 neighbors. This run has ${plural(rec.confirmed_asns.length, "confirmed ASN")} and ${plural(neighbors.length, "neighbor")}; use the per-ASN sections below.</p>`}</section>
    <section class="block"><h2>Per-ASN detail</h2>
      ${interactive ? `<div class="footprint-path-context"><h3>Observed BGP path context</h3>
        <p class="hint">Choose a confirmed ASN to load its interactive path map. Select a network on the map to inspect it and highlight adjacent displayed edges. Each lookup is a separate run; its evidence is not added to the footprint JSON or CSV exports.</p>
        <div class="chartbar no-print">${rec.adjacency.per_asn.map(p => `<button type="button" class="quiet drill" aria-pressed="false" data-asn="${esc(p.asn)}">Load observed BGP paths for AS${esc(p.asn)}</button>`).join("")}</div>
        <div class="drillbox" id="footprintPathMap" aria-live="polite"><p class="hint">No BGP path context loaded. Choose an ASN above.</p></div></div>` : ""}
      <p class="hint">Select an ASN row below to expand its source record, observed-neighbor table, and footprint mapping.</p>${perAsnHTML(rec, interactive)}</section>
    ${others.length ? `<section class="block"><h2>Origin ASNs not treated as yours</h2>
      <p class="sub">In your footprint but not confirmed, so their neighbors were not read. Listed for completeness.</p>
      <div class="tablewrap"><table><thead><tr><th>Origin ASN</th><th>Footprint entries</th><th>Announced prefixes</th></tr></thead><tbody>
      ${others.map(o => `<tr><td>${asLabel(o.asn, o.holder)}</td><td class="num">${nf(o.entries)} · ${pct(o.share)}</td><td class="mono">${o.prefixes.slice(0, 4).map(esc).join("<br>")}${o.prefixes.length > 4 ? `<br><span class="nm">+${nf(o.prefixes.length - 4)} more</span>` : ""}</td></tr>`).join("")}
      </tbody></table></div></section>` : ""}
    ${servicesHTML(rec,{interactive:opts.interactive})}<section class="block"><h2>Evidence and coverage</h2>
      <p class="sub">${statusLine(rec)}. RIPE requests: ${nf(rec.requests.resolution)} for resolution, ${nf(rec.requests.adjacency)} for adjacency.</p>
      ${sourcesHTML(rec)}${unmappedHTML(rec)}${rejectedHTML(rec.inputs)}
      ${rec.warnings.length ? `<h3>Warnings and limits</h3><ul class="notes">${rec.warnings.map(w => `<li>${esc(w)}</li>`).join("")}</ul>` : ""}
      <h3>How to read this</h3><ul class="notes">${rec.methodology.map(x => `<li>${esc(x)}</li>`).join("")}</ul>
      ${interactive ? `<div class="exports"><button type="button" id="fpJson">Download JSON record</button><button type="button" class="quiet" id="fpAdjCsv">Adjacency CSV</button><button type="button" class="quiet" id="fpResCsv">Resolution CSV</button><button type="button" class="quiet" id="fpPrint">Print or save PDF</button></div>` : ""}</section>`;
}
