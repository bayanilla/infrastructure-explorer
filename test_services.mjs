import assert from 'node:assert/strict';
import {servicesHTML,servicesCSV} from './web/render/services.js';
const r={service_observations:{limits:'bounded',records:[{resource:'8.8.8.8',status:'partial',source:'Shodan',query:'8.8.8.8',retrieved_at:'2026-10-10T00:00:00Z',total:101,truncated:true,rejected_records:1,services:[{ip:'8.8.8.8',port:443,transport:'tcp',service:'<script>bad</script>',observed_at:'2026-10-01T00:00:00'}]}]}};
assert.equal(servicesHTML({}),'');
const html=servicesHTML(r); assert.ok(html.includes('&lt;script&gt;'));assert.ok(html.includes('More Shodan records remain unfetched'));assert.ok(html.includes('2026-10-01'));
r.service_observations.records[0].services[0].service='=unsafe';assert.ok(servicesCSV(r).includes("'=unsafe"));
console.log('Shodan observations render safely and CSV formulas are neutralized.');

const live=servicesHTML(r,{interactive:true});assert.ok(live.includes('data-service-nav="0"'));assert.ok(live.includes('data-service-row="0"'));assert.ok(!html.includes('data-service-row'));

r.service_observations.records[0].services[0].details={product:'<script>bad</script>',banner:'<img src=https://untrusted.invalid>'};
const detailed=servicesHTML(r,{interactive:true});assert.ok(detailed.includes('aria-expanded="false"'));assert.ok(detailed.includes('data-service-detail="0"'));assert.ok(detailed.includes('&lt;img'));assert.ok(!detailed.includes('<img src='));assert.ok(detailed.includes('Not reported'));
const denied={service_observations:{records:[{resource:'8.8.8.0/24',source:'Shodan',status:'failed',services:[],error:'HTTP 403'}]}};
const deniedHtml=servicesHTML(denied,{interactive:true});assert.ok(deniedHtml.includes('HTTP 403'));assert.ok(!deniedHtml.includes('data-service-nav='));
const empty={service_observations:{records:[{resource:'8.8.8.0/24',source:'Shodan',status:'empty',services:[]}]}};assert.ok(!servicesHTML(empty,{interactive:true}).includes('data-service-nav='));
