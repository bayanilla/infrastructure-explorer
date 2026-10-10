import {servicesHTML} from "./services.js";
import {esc} from "./format.js";
import {chartSVG} from "./chart.js";
import {targetLabel, targetContext, scopeText, adjacencyTable, evidenceHTML} from "./lookup.js";
export function reportHTML(r){
  const m = r.meta, o = m.origin;
  const svg = chartSVG(r, {static: true});
  const nm = (a, n) => `AS${esc(a)}${n ? " " + esc(n) : ""}`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Infrastructure context: ${esc(targetLabel(m))} (AS${esc(o.asn)})</title>
<style>
:root{--perimeter:#ebe1cc;--muted:#53676a;--border-subtle:#cbbda5;--observed:#006d77;--measured:#31434a;--caution:#a15c00;--text-strong:#172125;--surface:#fffaf0}
body{font:14px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#17212C;max-width:1040px;margin:32px auto;padding:0 24px;background:#fff}
h1,h2{font-family:inherit;font-weight:600;line-height:1.4}
h1{font-size:26px;margin:0;border-bottom:1px solid #C8CDC2;padding-bottom:16px} h2{font-size:16px;margin:28px 0 8px;padding-top:16px;border-top:1px solid #C8CDC2}
.meta{color:#5A6571} .lede{font-size:17px} table{border-collapse:collapse;width:100%;font-size:14px}
th{text-align:left;color:#5A6571;border-bottom:1px solid #17212C;padding:5px 10px 5px 0} td{border-bottom:1px solid #C8CDC2;padding:7px 10px 7px 0;vertical-align:top}
pre{font:12.5px ui-monospace,Menlo,Consolas,monospace;background:#F6F7F2;border:1px solid #C8CDC2;padding:10px;white-space:pre-wrap}
.chart{overflow-x:auto;border:1px solid #17212C;padding:8px} li{margin:.3rem 0}
@media print{.chart{overflow:visible} svg{max-width:100%;height:auto}}
</style></head><body>
<h1>${m.target_kind === "asn" ? "ASN routing context" : "IP infrastructure context"}: ${esc(targetLabel(m))}</h1>
<p class="meta">${targetContext(r)} Measurement: ${esc(scopeText(m))}.</p>
<div class="lede">${r.summary.map(s => `<p>${esc(s)}</p>`).join("")}</div>
<h2>Adjacent network context</h2>${adjacencyTable(r)}
<h2>Routing context visualization</h2><p class="meta">${m.target_kind === "asn" ? "BGP advertisements only; Atlas hop-to-AS mapping is not performed." : "Dashed: observed BGP advertisements. Solid: inferred hop prefix-origin mappings."} These do not reconstruct an observed connection.</p><div class="chart">${svg}</div>
${servicesHTML(r)}
<h2>Evidence and coverage</h2>${evidenceHTML(r)}
<script type="application/json" id="evidence">${JSON.stringify(r).replace(/</g, "\\u003c")}<\/script>
</body></html>`;
}
