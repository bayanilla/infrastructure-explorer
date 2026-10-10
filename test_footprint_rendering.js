// Offline checks for the footprint views: escaping, CSV safety, sorting, layout limits and wording.
// Runs the complete page script against a stub DOM, so the functions tested are exactly what ships.
//   node test_footprint_rendering.js footprint_fixtures.json
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
import assert from 'node:assert/strict';

const html = fs.readFileSync(path.join(__dirname, 'web/index.html'), 'utf8') + fs.readFileSync(path.join(__dirname, 'web/styles.css'), 'utf8') + fs.readFileSync(path.join(__dirname, 'web/app.js'), 'utf8');
for (const id of ['fpSingle', 'fpFile', 'fpKeywords', 'fpLowVis', 'footprintFields', 'singleFields', 'openRun', 'openFile']) {
  assert.match(html, new RegExp(`id="${id}"`), id);
}
assert.match(html, /name="lookup" value="footprint" checked/); // Footprint is the primary mode.
assert.match(html, /Enter one IP or prefix, or upload a list/);
assert.match(html, /Public routing context/);
import * as format from './web/render/format.js';
import * as lookup from './web/render/lookup.js';
import * as footprint from './web/render/footprint.js';
import * as chart from './web/render/chart.js';
import * as reportModule from './web/render/report.js';
const context = vm.createContext({...format, ...lookup, ...footprint, ...chart, ...reportModule});
const run = (code, vars = {}) => { Object.assign(context, vars); return vm.runInContext(code, context); };
const {resolution: fxResolution, run: fxRecord} = JSON.parse(fs.readFileSync(process.argv[2] || 'footprint_fixtures.json', 'utf8'));
const forbidden = /suspicious|risky|unexpected|should block|malicious|threat/i;

// Confirmation screen
const confirm = run('confirmHTML(fxResolution)', {fxResolution});
assert.doesNotMatch(confirm, /<script>untrusted/);
assert.match(confirm, /&lt;script&gt;untrusted&lt;\/script&gt;/);
assert.match(confirm, /value="3333" checked/);
assert.match(confirm, /value="5555" checked/);
assert.match(confirm, /value="16509" (?!checked)/);
assert.match(confirm, /value="4200" (?!checked)/);
assert.match(confirm, /header “ip” skipped/);
assert.match(confirm, /Rejected rows \(2\)/);
assert.match(confirm, /Entries with no origin ASN \(1\)/);
assert.match(confirm, /Pre-checked: holder contains “example org”/);
assert.doesNotMatch(confirm, forbidden);

// Footprint report
const report = run('footprintReportHTML(fxRecord, {interactive: true})', {fxRecord});
assert.doesNotMatch(report, /<script>untrusted/);
assert.match(report, /&lt;script&gt;untrusted&lt;\/script&gt;/);
assert.match(report, /<svg[^>]+aria-label="Observed BGP neighbors of 2 confirmed ASNs"/);
assert.match(report, /<span class="nm">Your confirmed ASN<\/span>/);
assert.match(report, /Despite the field name, this counts routes, not distinct peers\./);
assert.equal((report.match(/class="asn-section"/g) || []).length, 2);
assert.equal((report.match(/class="quiet drill"/g) || []).length, 2);
assert.match(report, /Select an ASN row below to expand/);
assert.ok(report.indexOf('id="footprintPathMap"') < report.indexOf('class="asn-section"'));
assert.match(report, /class="quiet drill" aria-pressed="false"/);
assert.doesNotMatch(run('perAsnHTML(fxRecord, true)', {fxRecord}), /class="quiet drill"|drillbox/);
assert.match(report, /class="footprint-mapping"/);
assert.match(report, /Expand to compare 3 footprint entries with 2 announced prefixes/);
assert.match(report, /Origin ASNs not treated as yours/);
assert.match(report, /id="fpAdjCsv"/);
assert.doesNotMatch(report, forbidden);
const printable = run('footprintReportHTML(fxRecord)', {fxRecord});
for (const output of [report, printable]) {
  assert.match(output, /right is toward the network originating the advertised route/);
  assert.match(output, /A right-side neighbor is not necessarily that origin/);
  assert.match(output, /Question for network operations:/);
  assert.match(output, /Do we expect routes originating from that ASN to be advertised through our ASN/);
}
assert.doesNotMatch(printable, /class="quiet drill"|id="fpJson"/); // Static rendering has no live controls.
assert.match(html, /summary::before\{content:"▸"/);
assert.match(html, /details\[open\]>summary::before\{content:"▾"/);

// Per-ASN drill-down maps name their evidence source and retain the distinction
// between a source observation time and a local retrieval time.
const drillWithTime = run('drillMapContextHTML(drillEvidence)', {drillEvidence: {
  meta: {origin: {asn: 3333}},
  control_plane: {source: {name: "RIPE RIS via RIPEstat", observed_at: "2026-10-05T00:00:00", retrieved_at: "2026-10-05T00:02:00Z"}}
}});
assert.match(drillWithTime, /collector-observed BGP advertisements/);
assert.match(drillWithTime, /not a packet path, physical topology, provider relationship, or traffic-flow diagram/);
assert.match(drillWithTime, /BGP observation time: 2026-10-05T00:00:00/);
assert.match(drillWithTime, /Retained Atlas traceroute samples are separate evidence and are not plotted here/);
const drillWithoutTime = run('drillMapContextHTML(drillEvidence)', {drillEvidence: {
  meta: {origin: {asn: 3333}},
  control_plane: {source: {name: "RIPE RIS via RIPEstat", retrieved_at: "2026-10-05T00:02:00Z"}}
}});
assert.match(drillWithoutTime, /did not provide a BGP observation time/);
assert.match(drillWithoutTime, /which is not an observation time/);
const interactiveContext = run('drillMapContextHTML(drillEvidence, {interactive: true, heading: false})', {drillEvidence: {
  meta: {origin: {asn: 3333}}, control_plane: {source: {}}
}});
assert.match(interactiveContext, /This interactive map/);
assert.doesNotMatch(interactiveContext, /<h4>|This static map/);
assert.match(interactiveContext, /Select a network to inspect/);


// The combined view stops at 5 ASNs or 40 neighbors.
const crowded = JSON.parse(JSON.stringify(fxRecord));
crowded.confirmed_asns = [1, 2, 3, 4, 5, 6];
assert.match(run('footprintReportHTML(crowded)', {crowded}), /drawn for up to 5 confirmed ASNs and 40 neighbors/);

// Sorting is analyst-driven and stable on ASN.
const byName = run('sortedNeighbors(fxRecord.adjacency.neighbors, {key: "name", dir: 1}).map(n => n.asn)', {fxRecord});
assert.deepEqual([...byName], [64999, 5555, 174, 1299]); // "" < "<script…" < "=hyperlink…" < "holder…"
const byRoutes = run('sortedNeighbors(fxRecord.adjacency.neighbors, {key: "max_v4_peers", dir: -1}).map(n => n.asn)', {fxRecord});
assert.deepEqual([...byRoutes], [1299, 174, 5555, 64999]);
const sorted = run('neighborsTableHTML(fxRecord, {key: "max_power", dir: -1})', {fxRecord});
assert.match(sorted, /aria-sort="descending"><button type="button" class="sortbtn" data-sort="max_power"/);

// Large tables are capped on screen, never in exports.
const big = JSON.parse(JSON.stringify(fxRecord));
big.adjacency.neighbors = Array.from({length: 1005}, (_, i) => ({...fxRecord.adjacency.neighbors[0], asn: 70000 + i}));
assert.match(run('neighborsTableHTML(big)', {big}), /Showing 1,000 of 1,005 neighbors/);

// CSV exports: every relation, formula-safe cells, doubled quotes.
const adjacency = run('adjacencyCSV(fxRecord)', {fxRecord}).trim().split('\r\n');
const relations = fxRecord.adjacency.per_asn.reduce((n, p) => n + p.neighbors.length, 0);
assert.equal(adjacency.length, relations + 1);
assert.match(adjacency[0], /^"your_asn","your_asn_holder","neighbor_asn"/);
const formulaRow = adjacency.find(l => l.includes('HYPERLINK'));
assert.match(formulaRow, /"'=HYPERLINK\(""http:\/\/evil\.example"",""x""\)"/);
assert.doesNotMatch(adjacency.join('\n'), /(^|,)"=/m);
const resolutionRows = run('resolutionCSV(fxResolution)', {fxResolution}).trim().split('\r\n');
assert.equal(resolutionRows.length, fxResolution.resolution.length + 1);
assert.ok(resolutionRows.some(l => l.includes('"193.0.4.4"') && l.includes('"4200"')));
assert.equal(run('csvCell("-1+2")'), '"\'-1+2"');
assert.equal(run('csvCell("@SUM(A1)")'), '"\'@SUM(A1)"');
assert.equal(run('csvCell(42)'), '"42"');

// Graph text is escaped too.
const graph = run('footprintGraphSVG(fxRecord)', {fxRecord});
assert.doesNotMatch(graph, /<script>/);
assert.match(graph, /AS1299/);

console.log('Footprint confirmation, report, graph, sorting and CSV exports render safely with no editorial wording.');
