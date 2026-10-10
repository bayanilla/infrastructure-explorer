import assert from 'node:assert/strict';
import {runJob} from './web/render/jobs.js';
const id = 'a'.repeat(32);
const response = (body, ok=true, status=200) => ({ok,status,json:async()=>body});
let active=0, peak=0, calls=0;
const events=[response({job_id:id}),response({status:'running',progress:'Reading'}),response({status:'done',result:{value:42}})];
const result=await runJob('/api/analyze',{}, {interval:0,wait:async()=>{},fetcher:async()=>{
  active++; peak=Math.max(peak,active); calls++;
  await Promise.resolve(); active--; return events.shift();
}});
assert.deepEqual(result,{value:42}); assert.equal(peak,1); assert.equal(calls,3);
await assert.rejects(runJob('/api/analyze',{}, {wait:async()=>{},fetcher:async(url)=>url==='/api/analyze'?response({job_id:id}):response({error:'Expired'},false,404)}),/Expired/);
const controller=new AbortController();
await assert.rejects(runJob('/api/analyze',{}, {signal:controller.signal,wait:async()=>{},onStarted:()=>controller.abort(),fetcher:async()=>response({job_id:id})}),{name:'AbortError'});
let attempts=0;
await assert.rejects(runJob('/api/analyze',{}, {wait:async()=>{},fetcher:async(url)=>{
  if(url==='/api/analyze') return response({job_id:id});
  attempts++; throw new Error('Unavailable');
}}),/Unavailable/);
assert.equal(attempts,3);
console.log('Shared job polling is sequential, bounded on failures, and cancellation-aware.');
