import { verifyDemoTrace } from './trace-verifier.mjs';

const summary = document.querySelector('#trace-summary');
const status = document.querySelector('#verification-status');
const results = document.querySelector('#trace-results');
const json = document.querySelector('#trace-json');
const originalButton = document.querySelector('#verify-original');
const tamperButton = document.querySelector('#tamper-fixture');
const retryButton = document.querySelector('#retry-fixture');
const target = document.querySelector('#tamper-target');
const badge = document.querySelector('#result-badge');
const count = document.querySelector('#check-count');
const experiment = document.querySelector('#experiment-status');
let originalTrace;
let running = false;

function setBusy(busy) {
  running = busy;
  results.setAttribute('aria-busy', String(busy));
  originalButton.disabled = busy || !originalTrace;
  tamperButton.disabled = busy || !originalTrace;
  target.disabled = busy || !originalTrace;
  retryButton.disabled = busy;
}
function setStatus(state, message) {
  status.textContent = message;
  status.dataset.state = state;
  badge.textContent = state;
  badge.className = `badge ${state === 'VERIFIED' ? '' : state === 'INVALID' || state === 'ERROR' ? 'danger' : state === 'PARTIAL' ? 'warn' : 'neutral'}`;
}
function setSummary(trace) {
  summary.replaceChildren();
  const rows = [
    ['Action ID', trace.action_id],
    ['Action', trace.intent.action_type],
    ['Resource', trace.intent.resource],
    ['Decision', trace.authorization.decision],
    ['Outcome', trace.execution.outcome.status],
  ];
  for (const [label, value] of rows) {
    const row = document.createElement('div');
    row.className = 'metric';
    const name = document.createElement('span');
    const detail = document.createElement('strong');
    name.textContent = label;
    detail.textContent = value;
    row.append(name, detail);
    summary.append(row);
  }
}
function renderResult(result) {
  const message = result.status === 'VERIFIED'
    ? 'All checks passed. The sample’s hashes, signatures and record links match.'
    : result.status === 'PARTIAL'
      ? 'Hashes and record links passed. This browser could not verify every Ed25519 signature.'
      : 'Evidence mismatch detected. At least one bound record, hash or signature does not match.';
  setStatus(result.status, message);
  const totals = { pass: 0, fail: 0, warn: 0 };
  const states = { pass: ['✓', 'PASS'], fail: ['×', 'FAIL'], warn: ['!', 'UNSUPPORTED'] };
  results.replaceChildren();
  for (const check of result.checks) {
    totals[check.status]++;
    const item = document.createElement('div');
    item.className = `check ${check.status}`;
    const icon = document.createElement('span');
    icon.className = 'check-icon';
    icon.textContent = states[check.status][0];
    icon.setAttribute('aria-hidden', 'true');
    const copy = document.createElement('div');
    const title = document.createElement('strong');
    const detail = document.createElement('span');
    title.textContent = check.title;
    detail.textContent = check.detail;
    detail.className = 'check-detail';
    const state = document.createElement('span');
    state.className = 'check-state';
    state.textContent = states[check.status][1];
    copy.append(title, detail);
    item.append(icon, copy, state);
    results.append(item);
  }
  count.textContent = `${totals.pass} passed · ${totals.fail} failed · ${totals.warn} unsupported`;
}
async function run(trace, description) {
  if (running) return;
  setBusy(true);
  setStatus('CHECKING', 'Running local cryptographic checks…');
  results.replaceChildren();
  count.textContent = '';
  experiment.textContent = description;
  setSummary(trace);
  json.textContent = JSON.stringify(trace, null, 2);
  try {
    renderResult(await verifyDemoTrace(trace));
  } catch {
    setStatus('ERROR', 'The checks could not finish. Restore the original sample and try again.');
  } finally {
    setBusy(false);
  }
}
async function initialize() {
  if (running) return;
  setBusy(true);
  retryButton.hidden = true;
  setStatus('LOADING', 'Loading the signed demonstration fixture…');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch('data/demo-trace.json', { signal: controller.signal });
    if (!response.ok) throw new Error('Sample unavailable');
    const trace = await response.json();
    if (trace?.schema_version !== 'tempus.site-demo-trace.v1' || !trace.intent || !trace.authorization || !trace.execution?.outcome || !trace.execution?.receipt) throw new Error('Invalid sample');
    originalTrace = trace;
    clearTimeout(timeout);
    setBusy(false);
    await run(structuredClone(originalTrace), 'Original sample. No fields have been changed.');
  } catch {
    originalTrace = undefined;
    summary.textContent = 'The demonstration sample could not be loaded.';
    setStatus('ERROR', 'Could not load the sample. Check your connection and retry.');
    experiment.textContent = 'No sample loaded. Verification has not run.';
    retryButton.hidden = false;
  } finally {
    clearTimeout(timeout);
    setBusy(false);
  }
}
originalButton.addEventListener('click', () => {
  if (originalTrace && !running) run(structuredClone(originalTrace), 'Original sample restored. No fields have been changed.');
});
tamperButton.addEventListener('click', () => {
  if (!originalTrace || running) return;
  const altered = structuredClone(originalTrace);
  let description;
  if (target.value === 'decision') {
    altered.authorization.decision = altered.authorization.decision === 'ALLOWED' ? 'BLOCKED' : 'ALLOWED';
    description = 'Changed authorization.decision. All signatures remain unchanged.';
  } else if (target.value === 'outcome') {
    altered.execution.outcome.status = altered.execution.outcome.status === 'SUCCEEDED' ? 'FAILED' : 'SUCCEEDED';
    description = 'Changed execution.outcome.status. All signatures remain unchanged.';
  } else {
    altered.intent.resource = 'example-org/production-admin';
    description = 'Changed intent.resource to example-org/production-admin. All signatures remain unchanged.';
  }
  run(altered, description);
});
retryButton.addEventListener('click', initialize);
initialize();
