// One sequential poller for every workflow; no overlapping interval requests.
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

export async function runJob(url, body, {
  fetcher = globalThis.fetch, onStarted = () => {}, onProgress = () => {},
  signal, wait = delay, interval = 1500,
} = {}) {
  const started = await fetcher(url, {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body), signal});
  const record = await started.json();
  if (!started.ok) throw new Error(record.error || `Request failed (${started.status}).`);
  if (!/^[0-9a-f]{32}$/.test(record.job_id || '')) throw new Error('The server returned an invalid run reference.');
  onStarted(record.job_id);
  let errors = 0;
  while (true) {
    if (signal?.aborted) throw new DOMException('Cancelled', 'AbortError');
    await wait(interval);
    let response, state;
    try {
      response = await fetcher(`/api/job/${record.job_id}`, {signal});
      state = await response.json();
    } catch (error) {
      if (signal?.aborted || ++errors >= 3) throw error;
      continue;
    }
    if (!response.ok) throw new Error(state.error || `Request failed (${response.status}).`);
    errors = 0;
    onProgress(state);
    if (state.status === 'done') return state.result;
    if (state.status === 'failed') throw new Error(state.error || 'Analysis failed.');
    if (state.status === 'cancelled') throw new Error('Cancelled. No measurements were scheduled.');
    if (state.status !== 'running') throw new Error('The server returned an unknown run state.');
  }
}
