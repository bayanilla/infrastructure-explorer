import {esc, pct, asLabel, nf, plural, csvCell, toCSV, stamp} from "./format.js";
export function targetLabel(m){ return m.target_resource || m.target_ip || m.target_input; }
export function targetContext(r){
  const m=r.meta, o=m.origin;
  if (m.target_kind === "asn") return `${esc(targetLabel(m))} · ASN holder: ${esc(o.name || "unavailable")} · ${o.prefix_count == null ? "prefix count unknown" : `${o.prefix_count} prefixes in retained BGP observations`}. Generated ${esc(m.generated_utc)}.`;
  const originLabel = asLabel(o.asn,o.name).replace('class="nm"','class="nm" style="display:inline;margin-left:.35em"');
  return `${esc(m.target_ip)} maps to ${esc(o.prefix || "an unknown prefix")}, with selected origin ${originLabel}. Generated ${esc(m.generated_utc)}.`;
}
export function asEvidenceHTML(r){
  const source=r.control_plane.source || {}, o=r.meta.origin;
  return `<p class="sub">BGP source: ${esc(source.name || "unavailable")} · Status: ${esc(source.status || "unknown")} · Observed at: ${esc(source.observed_at || "not supplied")} · Retrieved at: ${esc(source.retrieved_at || "not retrieved")}.</p>
    ${(o.prefixes || []).length ? `<details><summary>Prefixes in retained BGP observations (${o.prefixes.length}${o.prefixes_truncated ? "; list limited" : ""})</summary><ul class="notes mono">${o.prefixes.map(p=>`<li>${esc(p)}</li>`).join("")}</ul></details>` : ""}
    <p class="sub">${r.control_plane.distinct_peers == null ? "Peer count unknown" : `${r.control_plane.distinct_peers} distinct peers in retained BGP observations`}. Counts describe the captured sample, not traffic share or complete AS coverage.</p>
    ${(r.control_plane.other_origins || []).length ? `<h3>Other origins in the covering prefix</h3><p class="sub">BGP records for ${esc((source.query_parameters || {}).resource || "the queried resource")} that end at an AS other than the selected origin. Multiple origins can be legitimate or a misorigination; this view does not decide which.${r.control_plane.other_origins_truncated ? " List limited; see the JSON export." : ""}</p>
      <div class="tablewrap"><table><thead><tr><th>Prefix</th><th>Origin</th><th>Peers</th></tr></thead><tbody>${r.control_plane.other_origins.map(x=>`<tr><td class="mono">${esc(x.prefix)}</td><td>${asLabel(x.asn,x.name)}</td><td class="num">${esc(x.peers)}</td></tr>`).join("")}</tbody></table></div>` : ""}`;
}

/* ---------- Shared report sections: UI and exports use identical context ---------- */
export function adjacencyTable(r, opts = {}){
  const rows = r.routing_context.adjacencies;
  const mapped = r.meta.target_kind !== "asn" && r.traces.length > 0;
  const calculation = r.routing_context.calculations;
  const table = displayed => `<div class="tablewrap"><table><thead><tr><th>Network</th>${mapped ? "<th>Inferred samples</th>" : ""}<th>BGP records</th><th>Interpretation</th></tr></thead><tbody>
    ${displayed.map(x=>`<tr><td>${asLabel(x.asn,x.name)}</td>${mapped ? `<td class="num">${x.data_paths} · ${x.data_share == null ? "unknown" : pct(x.data_share)}</td>` : ""}<td class="num">${x.cp_routes == null ? "unknown" : x.cp_routes} · ${x.cp_share == null ? "unknown" : pct(x.cp_share)}</td><td>${esc(x.interpretation)}</td></tr>`).join("")}</tbody></table></div>`;
  const top = rows.slice(0, 5), remaining = rows.slice(5);
  const display = opts.collapsible && remaining.length
    ? `${table(top)}<details><summary>Show ${remaining.length} more adjacent network${remaining.length === 1 ? "" : "s"}</summary>${table(remaining)}</details>`
    : table(rows);
  return `<p class="sub">${r.meta.target_kind === "asn" ? "Preceding ASNs in retained BGP observations." : "Preceding ASNs in retained BGP observations or inferred hop mappings."} Adjacency does not confirm a provider relationship. Fractions describe sample records, never traffic share.</p>
    <p class="sub">Ordered by retained BGP records, then inferred samples, with ASN as the tie-breaker. BGP denominator: ${calculation.bgp_fraction.denominator == null ? "unknown" : calculation.bgp_fraction.denominator} records with a preceding ASN.${mapped ? ` Inferred-sample denominator: ${calculation.mapped_sample_fraction.denominator} samples with a preceding mapped ASN.` : ""} Percentages are displayed to the nearest whole percent; JSON retains fractions rounded to four decimal places.</p>
    ${rows.length ? display : "<p>No adjacency is available from the retained evidence. Review source status and warnings.</p>"}`;
}
export function evidenceHTML(r){
  const cp = r.control_plane;
  return `<p class="sub">Measurements: ${esc(scopeText(r.meta))}. ${r.meta.requests ?? 0} RIPE requests in this run.</p>
    ${asEvidenceHTML(r)}
    ${r.warnings.length ? `<h3>Warnings and limits</h3><ul class="notes">${r.warnings.map(w=>`<li>${esc(w)}</li>`).join("")}</ul>` : ""}
    ${r.traces.length ? `<details><summary>Existing Atlas samples (${r.traces.length})</summary>${r.traces.map(traceHTML).join("")}</details>` : ""}
    ${cp.paths.length ? `<details><summary>BGP paths (${cp.routes}${cp.truncated ? "; first " + cp.paths.length + " retained" : ""})</summary><div class="tablewrap"><table><thead><tr><th>Prefix</th><th>Collector peer</th><th>Observed AS path</th></tr></thead><tbody>${cp.paths.map(p=>`<tr><td class="mono">${esc(p.prefix)}</td><td class="mono">${esc(p.source_id)}</td><td class="path">${p.path.map(a=>"AS"+esc(a)).join(" → ")}</td></tr>`).join("")}</tbody></table></div></details>` : ""}
    <h3>How to read this</h3><ul class="notes">${r.methodology.map(x=>`<li>${esc(x)}</li>`).join("")}</ul>`;
}
export function scopeText(m){
  return ({supplied:`measurements you supplied (${(m.measurement_ids||[]).join(", ")})`,
           target:"public traceroutes to the requested target",
           origin_as:"public traceroutes to other addresses in the selected origin ASN",
           asn_samples:"existing Atlas traceroute samples to specific addresses classified under the selected ASN"})[m.data_scope] || "no traceroutes; routing observations only";
}

export function traceHTML(t){
  const hops = t.hops.map(h => h.ip
    ? `<li>${esc(h.hop)}  ${esc(h.ip)}${h.asn ? "  AS" + esc(h.asn) : h.scope ? "  (" + esc(h.scope) + ")" : ""}${h.rtt != null ? "  " + esc(h.rtt) + " ms" : ""}</li>`
    : `<li class="gap">${esc(h.hop)}  no reply</li>`).join("");
  const asSample = t.mapping_status === "not_performed";
  const when = t.timestamp ? new Date(t.timestamp * 1000).toISOString().replace(".000","") : "";
  return `<details><summary class="path">Probe ${esc(t.probe_id)}${t.probe_asn ? " in AS" + esc(t.probe_asn) : ""}${t.probe_country ? " (" + esc(t.probe_country) + ")" : ""}:
    ${asSample ? "existing traceroute to " + esc(t.dst) : t.as_path.length ? "inferred mapping: " + t.as_path.map(a => "AS" + a).join(" → ") : "no mapped hops"}${asSample ? " · hop-to-AS mapping not performed" : t.reached_origin_as ? "" : "  · no hop mapped to the selected origin"}</summary>
    <p class="nm">Measurement ${esc(t.msm_id)} · ${esc(when)} · to ${esc(t.dst)}${t.as_loop ? " · AS loop seen" : ""}</p>
    <ol class="hops" style="list-style:none">${hops}</ol></details>`;
}

/* ---------- Footprint: upload, confirm, adjacency ---------- */
export function drillMapContextHTML(r, opts = {}){
  const source = r.control_plane.source || {};
  const observed = source.observed_at;
  const retrieved = source.retrieved_at;
  const provenance = observed
    ? `Source: ${esc(source.name || "RIPE RIS via RIPEstat")} · BGP observation time: ${esc(observed)}${retrieved ? ` · retrieved by Pathfinder: ${esc(retrieved)}` : ""}.`
    : `Source: ${esc(source.name || "RIPE RIS via RIPEstat")} · RIPE did not provide a BGP observation time for this response.${retrieved ? ` Pathfinder retrieved it at ${esc(retrieved)}, which is not an observation time.` : ""}`;
  return `${opts.heading === false ? "" : "<h4>Observed BGP path context</h4>"}
    <p class="sub">This ${opts.interactive ? "interactive" : "static"} map is a filtered presentation of collector-observed BGP advertisements ending at AS${esc(r.meta.origin.asn)}. It is not a packet path, physical topology, provider relationship, or traffic-flow diagram. Retained Atlas traceroute samples are separate evidence and are not plotted here.</p>
    <p class="hint">${provenance} ${opts.interactive ? "Select a network to inspect its retained counts and nearest displayed hop position. Use Explore ASN for this lookup’s own exports." : "Use Explore ASN for the interactive map and its own exports."}</p>`;
}

/* ---------- Approach chart ---------- */
