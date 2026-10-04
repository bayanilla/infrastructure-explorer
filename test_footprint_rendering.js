// Offline checks for the footprint views: escaping, CSV safety, sorting, layout limits and wording.
// Runs the complete page script against a stub DOM, so the functions tested are exactly what ships.
//   node test_footprint_rendering.js footprint_fixtures.json
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const assert = require('node:assert/strict');

const html = fs.readFileSync(path.join(__dirname, 'probe_web/index.html'), 'utf8');
for (const id of ['fpSingle', 'fpFile', 'fpKeywords', 'fpLowVis', 'footprintFields', 'singleFields', 'openRun', 'openFile']) {
  assert.match(html, new RegExp(`id="${id}"`), id);
}
assert.match(html, /name="lookup" value="footprint" checked/); // Footprint is the primary mode.
assert.match(html, /Enter one IP or prefix, or upload a list/);
assert.match(html, /Public routing context/);
const script = html.split('<script>')[1].split('</script>')[0];

const stub = () => new Proxy(function () {}, {
  get(_, key) {
    if (key === 'value' || key === 'textContent' || key === 'innerHTML') return '';
    if (key === 'files') return [];
    if (key === 'dataset') return {};
    if (key === 'classList') return {add() {}, remove() {}, toggle() {}};
    if (key === Symbol.toPrimitive) return () => '';
    return stub();
  },
  set() { return true; },
  apply() { return stub(); },
});
const document = {querySelector: () => stub(), querySelectorAll: () => [], documentElement: {dataset: {}},
                  getElementById: () => stub(), createElement: () => stub(), body: stub()};
const context = vm.createContext({document, localStorage: {getItem: () => null, setItem() {}}, console,
                                  setTimeout, clearTimeout, setInterval, clearInterval, URL, Blob: function () {}});
vm.runInContext(script, context);
const run = (code, vars = {}) => { Object.assign(context, vars); return vm.runInContext(code, context); };

const {resolution: fxResolution, run: fxRecord} = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
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
assert.match(report, /<svg[^>]+aria-label="Observed BGP neighbours of 2 confirmed ASNs"/);
assert.match(report, /<span class="nm">Your confirmed ASN<\/span>/);
assert.match(report, /Despite the field name, this counts routes, not distinct peers\./);
assert.equal((report.match(/class="asn-section"/g) || []).length, 2);
assert.equal((report.match(/class="quiet drill"/g) || []).length, 2);
assert.match(report, /Origin ASNs not treated as yours/);
assert.match(report, /id="fpAdjCsv"/);
assert.doesNotMatch(report, forbidden);
const printable = run('footprintReportHTML(fxRecord)', {fxRecord});
assert.doesNotMatch(printable, /class="quiet drill"|id="fpJson"/); // Static rendering has no live controls.

// The combined view stops at 5 ASNs or 40 neighbours.
const crowded = JSON.parse(JSON.stringify(fxRecord));
crowded.confirmed_asns = [1, 2, 3, 4, 5, 6];
assert.match(run('footprintReportHTML(crowded)', {crowded}), /drawn for up to 5 confirmed ASNs and 40 neighbours/);

// Sorting is analyst-driven and stable on ASN.
const byName = run('sortedNeighbours(fxRecord.adjacency.neighbours, {key: "name", dir: 1}).map(n => n.asn)', {fxRecord});
assert.deepEqual([...byName], [64999, 5555, 174, 1299]); // "" < "<script…" < "=hyperlink…" < "holder…"
const byRoutes = run('sortedNeighbours(fxRecord.adjacency.neighbours, {key: "max_v4_peers", dir: -1}).map(n => n.asn)', {fxRecord});
assert.deepEqual([...byRoutes], [1299, 174, 5555, 64999]);
const sorted = run('neighboursTableHTML(fxRecord, {key: "max_power", dir: -1})', {fxRecord});
assert.match(sorted, /aria-sort="descending"><button type="button" class="sortbtn" data-sort="max_power"/);

// Large tables are capped on screen, never in exports.
const big = JSON.parse(JSON.stringify(fxRecord));
big.adjacency.neighbours = Array.from({length: 1005}, (_, i) => ({...fxRecord.adjacency.neighbours[0], asn: 70000 + i}));
assert.match(run('neighboursTableHTML(big)', {big}), /Showing 1,000 of 1,005 neighbours/);

// CSV exports: every relation, formula-safe cells, doubled quotes.
const adjacency = run('adjacencyCSV(fxRecord)', {fxRecord}).trim().split('\r\n');
const relations = fxRecord.adjacency.per_asn.reduce((n, p) => n + p.neighbours.length, 0);
assert.equal(adjacency.length, relations + 1);
assert.match(adjacency[0], /^"your_asn","your_asn_holder","neighbour_asn"/);
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
