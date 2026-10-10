import {esc} from "./format.js";
export function chartSVG(r, opts = {}){
  const layers = opts.layers || {data: true, cp: true};
  const o = r.meta.origin.asn;
  const activeEdges = r.graph.edges.filter(e => (layers.data && e.data) || (layers.cp && e.cp));
  const live = new Set([o]); activeEdges.forEach(e => { live.add(e.from); live.add(e.to); });
  const allNodes = r.graph.nodes.filter(n => live.has(n.asn));
  const nodeByAsn = new Map(allNodes.map(n => [n.asn, n]));
  const MAX_HOPS = 5;
  const weight = n => (layers.data ? n.data * 4 : 0) + (layers.cp ? n.cp : 0);
  const byDepth = {};
  allNodes.forEach(n => { if (n.asn !== o) { const c = Math.min(n.depth, MAX_HOPS); (byDepth[c] ||= []).push(n); } });
  Object.values(byDepth).forEach(list => list.sort((a,b) => weight(b) - weight(a) || a.asn - b.asn));

  // The graph is an overview: preserve the strongest representative paths and
  // a few faded alternatives, while the report retains every captured record.
  const emphasized = new Set([o]), MAX_EMPHASIZED = 3, MAX_CONTEXT = 2;
  Object.values(byDepth).forEach(list => list.slice(0, MAX_EMPHASIZED).forEach(n => emphasized.add(n.asn)));
  const queue = [...emphasized];
  while (queue.length) {
    const from = queue.pop();
    const next = activeEdges.filter(e => e.from === from && nodeByAsn.has(e.to))
      .sort((a,b) => ((b.data * 4 + b.cp) - (a.data * 4 + a.cp)) || a.to - b.to)[0];
    if (next && !emphasized.has(next.to)) { emphasized.add(next.to); queue.push(next.to); }
  }
  const context = new Set();
  Object.values(byDepth).forEach(list => list.filter(n => !emphasized.has(n.asn)).slice(0, MAX_CONTEXT)
    .forEach(n => context.add(n.asn)));
  const visible = new Set([...emphasized, ...context]);
  const nodes = allNodes.filter(n => visible.has(n.asn));
  const edges = activeEdges.filter(e => visible.has(e.from) && visible.has(e.to));
  const cols = {};
  nodes.forEach(n => { const c = Math.min(n.depth, MAX_HOPS); (cols[c] ||= []).push(n); });
  Object.values(cols).forEach(c => c.sort((a, b) => (emphasized.has(b.asn) - emphasized.has(a.asn)) || weight(b) - weight(a) || a.asn - b.asn));
  const ncol = MAX_HOPS;
  const rowH = 58, top = 46, padL = 60, originBand = 190, W = 1100;
  const maxRows = Math.max(...Object.values(cols).map(c => c.length), 1);
  const displayRows = Math.max(maxRows, 5);
  const originX = W - originBand + 30;
  const laneW = (originX - padL - 40) / ncol;
  const H = top + displayRows * rowH + 30;
  const pos = {};
  for (const [c, list] of Object.entries(cols)) {
    const x = originX - Number(c) * laneW;
    const y0 = top + (displayRows - list.length) * rowH / 2;
    list.forEach((n, i) => pos[n.asn] = {x, y: y0 + i * rowH + rowH / 2});
  }
  pos[o] = {x: originX, y: top + displayRows * rowH / 2};
  const maxDE = Math.max(1, ...edges.map(e => e.data)), maxCE = Math.max(1, ...edges.map(e => e.cp));
  const maxDN = Math.max(1, ...nodes.map(n => n.data)), maxCN = Math.max(1, ...nodes.map(n => n.cp));
  const curve = (a, b, off) => {
    const mx = (a.x + b.x) / 2;
    return `M${a.x},${a.y + off} C${mx},${a.y + off} ${mx},${b.y + off} ${b.x},${b.y + off}`;
  };
  let s = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="${r.meta.target_kind === "asn" ? "Observed BGP advertisements ending at" : "Inferred mappings and BGP observations ending at"} AS${o}" font-family="system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif">`;
  s += `<rect x="${originX - 10}" y="0" width="${W - originX + 10}" height="${H}" fill="var(--perimeter)"/>`;
  s += `<text x="${originX + 14}" y="22" font-size="13" fill="var(--muted)">${r.meta.target_kind === "asn" ? "Selected AS" : "Selected origin"}</text>`;
  for (let c = 1; c <= ncol; c++) {
    const x = originX - c * laneW;
    s += `<line x1="${x}" y1="34" x2="${x}" y2="${H - 8}" stroke="var(--border-subtle)"/>`;
    s += `<text x="${x}" y="22" font-size="13" fill="var(--muted)" text-anchor="middle">${c === 1 ? "Adjacent" : c === MAX_HOPS ? `${c}+ AS hops` : `${c} AS hops`}</text>`;
  }
  s += `<g class="edges">`;
  for (const e of edges) {
    const a = pos[e.from], b = pos[e.to]; if (!a || !b) continue;
    const faded = context.has(e.from) || context.has(e.to), opacity = faded ? ".14" : ".78";
    if (layers.cp && e.cp) s += `<path class="edge${faded ? " context" : ""}" data-a="${e.from}" data-b="${e.to}" d="${curve(a, b, 2)}" fill="none" stroke="var(--observed)" stroke-opacity="${opacity}" stroke-dasharray="6 4" stroke-width="${(1 + 4 * Math.sqrt(e.cp / maxCE)).toFixed(2)}"><title>AS${e.from} → AS${e.to}: ${e.cp} RIS routes</title></path>`;
    if (layers.data && e.data) s += `<path class="edge${faded ? " context" : ""}" data-a="${e.from}" data-b="${e.to}" d="${curve(a, b, -2)}" fill="none" stroke="var(--measured)" stroke-opacity="${faded ? ".2" : ".9"}" stroke-width="${(1.5 + 6 * Math.sqrt(e.data / maxDE)).toFixed(2)}"><title>AS${e.from} → AS${e.to}: ${e.data} inferred sample mappings</title></path>`;
  }
  s += `</g><g class="nodes">`;
  for (const n of nodes) {
    const p = pos[n.asn]; if (!p) continue;
    const isO = n.roles.includes("origin"), isE = n.roles.includes("adjacent");
    const faded = context.has(n.asn);
    const w = Math.max(layers.data ? n.data / maxDN : 0, layers.cp ? n.cp / maxCN : 0);
    const rad = isO ? 0 : 6 + 9 * Math.sqrt(w);
    const stroke = isE ? "var(--observed)" : "var(--text-strong)";
    const fill = "var(--surface)";
    const name = (n.name || "").length > 22 ? n.name.slice(0, 21) + "…" : (n.name || "");
    const interaction = opts.static ? "" : ` tabindex="0" role="button" aria-label="AS${n.asn} ${esc(n.name || "")}"`;
    s += `<g class="node${faded ? " context" : ""}" data-priority="${faded ? "context" : "emphasized"}" data-asn="${n.asn}"${interaction} opacity="${faded ? ".18" : "1"}">`;
    if (isO) {
      s += `<rect x="${p.x}" y="${p.y - 32}" width="14" height="64" fill="var(--text-strong)"/>`;
      s += `<text x="${p.x + 24}" y="${p.y - 4}" font-size="16" font-weight="600" fill="var(--text-strong)">AS${n.asn}</text>`;
      s += `<text x="${p.x + 24}" y="${p.y + 14}" font-size="12" fill="var(--muted)">${esc(name)}</text>`;
    } else {
      s += `<circle cx="${p.x}" cy="${p.y}" r="${rad.toFixed(1)}" fill="${fill}" stroke="${stroke}" stroke-width="${isE ? 3 : 1.6}"/>`;
      s += `<text x="${p.x}" y="${p.y - rad - 6}" font-size="13" font-weight="600" text-anchor="middle" fill="var(--text-strong)" paint-order="stroke" stroke="var(--surface)" stroke-width="3">AS${n.asn}</text>`;
      if (name) s += `<text x="${p.x}" y="${p.y + rad + 14}" font-size="11.5" text-anchor="middle" fill="var(--muted)" paint-order="stroke" stroke="var(--surface)" stroke-width="3">${esc(name)}</text>`;
    }
    s += `</g>`;
  }
  return s + `</g></svg>`;
}
