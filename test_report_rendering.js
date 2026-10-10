// Offline renderer verification against the same fixture reports as the backend.
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(__dirname, 'web/index.html'), 'utf8') + fs.readFileSync(path.join(__dirname, 'web/styles.css'), 'utf8') + fs.readFileSync(path.join(__dirname, 'web/app.js'), 'utf8');
assert.match(html, /id="chart"/);
assert.doesNotMatch(html, /id="staticMap"/);
assert.doesNotMatch(html, /id="interactiveMap"/);
assert.match(html, /class="coqui-background"/);
assert.doesNotMatch(html, /class="coqui-mark"/);
assert.match(html, /href="\/assets\/mucaro-mark\.svg(?:\?[^\"]*)?"/);
import * as format from './web/render/format.js';
import * as lookup from './web/render/lookup.js';
import * as footprint from './web/render/footprint.js';
import * as chart from './web/render/chart.js';
import * as report from './web/render/report.js';
const context = vm.createContext({...format, ...lookup, ...footprint, ...chart, ...report});
const fixtures = JSON.parse(fs.readFileSync(process.argv[2] || 'report_fixtures.json', 'utf8'));
for (const report of fixtures) {
  context.fixture = report;
  const rendered = vm.runInContext('reportHTML(fixture)', context);
  assert.match(rendered, /Adjacent network context/);
  assert.match(rendered, /Evidence and coverage/);
  assert.doesNotMatch(rendered, /Enforcement brief|Ask this network|Perimeter blocklist|Block at perimeter|single point of failure/);
  assert.match(rendered, /&lt;script&gt;untrusted&lt;\/script&gt;/);
  const embedded = rendered.match(/<script type="application\/json" id="evidence">([\s\S]*?)<\/script>/);
  assert.ok(embedded);
  assert.deepEqual(JSON.parse(embedded[1]), report); // Exports retain the canonical evidence.
  assert.equal(report.enforcement, undefined);
  if (report.meta.target_kind === 'asn') {
    assert.match(rendered, /ASN routing context/);
    assert.doesNotMatch(rendered, /<th>Inferred samples<\/th>/);
  } else {
    assert.match(rendered, /IP infrastructure context/);
    assert.match(rendered, /inferred mapping:/);
  }
}
context.crowded = {
  meta: {origin: {asn: 64500}, target_kind: 'asn'},
  graph: {
    nodes: [{asn: 64500, depth: 0, data: 0, cp: 1, name: 'Selected', roles: ['origin']}]
      .concat(Array.from({length: 8}, (_, i) => ({asn: 64501 + i, depth: 1, data: 0, cp: 8 - i, name: `Adjacent ${i}`, roles: ['adjacent']}))),
    edges: Array.from({length: 8}, (_, i) => ({from: 64501 + i, to: 64500, data: 0, cp: 8 - i})),
  },
};
const crowdedSvg = vm.runInContext('chartSVG(crowded)', context);
assert.match(crowdedSvg, /data-priority="context"/);
assert.doesNotMatch(crowdedSvg, /AS64508/); // The overview limits low-frequency peers; captured paths remain in the report data.
assert.match(crowdedSvg, /5\+ AS hops/); // The overview always reserves five horizontal hop columns.
assert.match(crowdedSvg, /viewBox="0 0 1100 /); // The columns use a full-width, stable diagram frame.
const staticCrowdedSvg = vm.runInContext('chartSVG(crowded, {static:true})', context);
assert.doesNotMatch(staticCrowdedSvg, /role="button"/); // Static diagrams do not expose inactive controls.
context.longAdjacencies = JSON.parse(JSON.stringify(fixtures[0]));
context.longAdjacencies.routing_context.adjacencies = Array.from({length: 6}, (_, i) => ({
  asn: 64501 + i, name: `Adjacent ${i + 1}`, data_paths: 0, data_share: null,
  cp_routes: 6 - i, cp_share: 0.1, interpretation: "Context only.",
}));
const expandableAdjacencies = vm.runInContext('adjacencyTable(longAdjacencies, {collapsible:true})', context);
assert.match(expandableAdjacencies, /Show 1 more adjacent network/);
assert.match(expandableAdjacencies, /AS64501/);
assert.match(expandableAdjacencies, /AS64506/);
const fullAdjacencies = vm.runInContext('adjacencyTable(longAdjacencies)', context);
assert.doesNotMatch(fullAdjacencies, /Show 1 more adjacent network/); // Exports retain the complete table.
console.log('IP and ASN HTML exports preserve canonical evidence, escape names, and contain no action recommendations. UI syntax passed.');
