// Public evidence verifier. Everything runs in this page: the verifier is the wasm32
// build of the Tempus crate (assets/wasm/), the gate public key is pinned by the reader,
// and nothing is sent anywhere. The only fetches are same-origin sample files.
import init, * as verifier from './wasm/tempus_verifier.js';

const form = document.querySelector('#verify-form');
const fileInput = document.querySelector('#evidence-file');
const evidenceText = document.querySelector('#evidence-text');
const keyInput = document.querySelector('#gate-key');
const executorInput = document.querySelector('#executor-keys');
const anchorFileInput = document.querySelector('#anchor-file');
const anchorTextInput = document.querySelector('#anchor-text');
const rekorKeysInput = document.querySelector('#rekor-keys');
const tsaRootsInput = document.querySelector('#tsa-roots');
const verifyButton = document.querySelector('#verify-button');
const sampleButton = document.querySelector('#load-sample');
const tamperedButton = document.querySelector('#load-tampered');
const clearButton = document.querySelector('#clear-form');
const badge = document.querySelector('#result-badge');
const status = document.querySelector('#verification-status');
const summary = document.querySelector('#evidence-summary');
const checks = document.querySelector('#evidence-checks');
const errors = document.querySelector('#evidence-errors');
const notChecked = document.querySelector('#not-checked');
const linkPanel = document.querySelector('#link-panel');
const engine = document.querySelector('#engine-version');
const resultJson = document.querySelector('#result-json');

const CHECK_TITLES = {
  authorization: ['Permit', 'The gate signed this exact permit (intent hash, decision, policy digest, expiry) with the pinned key, and the agent signed the intent.'],
  execution: ['Outcome', 'The gate signed this exact outcome receipt with the pinned key, bound to the permit, and the executor signed the outcome.'],
  checkpoint: ['Ledger inclusion', 'A gate-signed checkpoint covers an event stream that contains this permit and outcome, with no gaps or rollback.'],
  anchor: ['Checkpoint date', 'Proofs from outside the gate, checked against the roots you pinned, date this checkpoint. Neither the operator nor Tempus could have backdated it.'],
};
const CHECK_DETAILS = {
  anchor: {
    NOT_PRESENT: 'No anchor was loaded, so every date in this file is the gate’s own claim.',
    NOT_CHECKED: 'The anchor is about this checkpoint, but nothing you pinned says who signed its proofs, so it claims no date.',
    FAILED: 'At least one proof in the anchor does not verify, however good the others are.',
  },
};
const BACKEND_TITLES = { rekor: 'Rekor log', rfc3161: 'Timestamp authority' };
const CHECK_STATES = {
  VERIFIED: ['pass', '✓', 'PASS'],
  FAILED: ['fail', '×', 'FAIL'],
  INVALID: ['fail', '×', 'FAIL'],
  NOT_PRESENT: ['neutral', '–', 'NOT PRESENT'],
  NOT_CHECKED: ['warn', '!', 'NOT CHECKED'],
};
const NOT_CHECKED = {
  AGENT_REGISTRATION_AT_ISSUE: 'Whether the agent was registered and active when the permit was issued. The gate attests it with its signature; this page does not re-check the registry.',
  SINGLE_USE_CONSUMPTION: 'That this permit produced exactly one outcome. No document can show that; only the gate’s ledger can.',
  EXECUTOR_IDENTITY: 'Which executor carried out the action. The gate attests it; pin the executor public key above to check it here.',
  LEDGER_INCLUSION: 'That these events are in the gate’s signed ledger. This file carries no checkpoint, so inclusion is not shown.',
  COMPLETENESS: 'That nothing else happened: other actions, retries or outcomes. No single file can show that; compare against the ledger or a checkpoint.',
  CHECKPOINT_TIME: 'When this checkpoint was made. Without a verified anchor, every date in this file is the gate’s own claim.',
  ANCHOR_NOT_PINNED: 'A proof in the anchor was not checked. Pin its log key or authority root above to check it.',
  TSA_REVOCATION: 'Whether the timestamp certificates were later revoked. That takes a network, and this page stays offline.',
};
const ERROR_TEXT = {
  AUTHORIZATION_ID_MISMATCH: 'The permit’s content no longer matches its own identifier: a signed field was edited after signing.',
  AUTHORIZATION_SIGNATURE_INVALID: 'The gate signature on the permit does not verify with the pinned key.',
  AUTHORIZATION_GATE_KEY_NOT_PINNED: 'The permit was signed by a different gate than the key you pinned.',
  INTENT_HASH_MISMATCH: 'The intent in the file is not the intent the permit was issued for.',
  AGENT_SIGNATURE_INVALID: 'The agent signature on the intent does not verify.',
  RECEIPT_ID_MISMATCH: 'The outcome receipt’s content no longer matches its own identifier.',
  EXECUTION_SIGNATURE_INVALID: 'The gate signature on the outcome receipt does not verify with the pinned key.',
  EXECUTION_GATE_KEY_NOT_PINNED: 'The outcome receipt was signed by a different gate than the key you pinned.',
  EXECUTOR_SIGNATURE_INVALID: 'The executor signature on the outcome does not verify.',
  EXECUTOR_KEY_NOT_PINNED: 'The executor that signed is not one of the executor keys you pinned.',
  OUTCOME_HASH_MISMATCH: 'The outcome in the file is not the outcome the receipt was issued for.',
  BUNDLE_VERIFY_URL_MISMATCH: 'The verify link inside the file names a different bundle: the file changed after the link was written, or the link belongs to another file.',
  BUNDLE_VERIFY_URL_INVALID: 'The verify link inside the file is not a verifier address with a bundle digest.',
  BUNDLE_ACTION_ID_MISMATCH: 'The bundle’s action identifier differs from the permit’s.',
  TRACE_ACTION_ID_MISMATCH: 'The trace’s action identifier differs from the signed one.',
  POLICY_DIGEST_MISMATCH: 'The policy bundle in the file is not the policy the permit cites.',
  POLICY_SIGNATURE_INVALID: 'The policy bundle’s gate signature does not verify.',
  DUPLICATE_JSON_KEY: 'The file repeats a JSON key, so different readers would see different values. Refused.',
  NON_EXACT_NUMBER: 'The file holds a number that is not an exact integer, so its hash is ambiguous. Refused.',
  AUTHORIZATION_POLICY_DECISION_MISMATCH: 'Running the signed policy again, rules included, gives a different decision from the one on the permit.',
  AUTHORIZATION_DECISION_NOT_REPRODUCIBLE: 'The decision on the permit cannot be reproduced from its intent and its signed policy.',
  AUTHORIZATION_REASON_CODES_NOT_REPRODUCIBLE: 'The reasons on the permit cannot be reproduced from its intent and its signed policy.',
  ANCHOR_NO_CHECKPOINT: 'An anchor dates a checkpoint, and this bundle holds none.',
  ANCHOR_CHECKPOINT_MISMATCH: 'The anchor names a different checkpoint from the one in this bundle.',
  ANCHOR_BEFORE_CHECKPOINT: 'A proof is dated before the checkpoint says it was created. One of the two dates is wrong.',
  ANCHOR_REKOR_LOG_UNKNOWN: 'The proof comes from a log you did not pin.',
  ANCHOR_REKOR_SET_INVALID: 'The log’s signature over the entry and its time does not verify: one of them was edited.',
  ANCHOR_REKOR_ENTRY_MISMATCH: 'The logged entry is about something other than this checkpoint.',
  ANCHOR_REKOR_INCLUSION_INVALID: 'The log’s proof that it holds this entry does not verify.',
  ANCHOR_REKOR_NOTE_INVALID: 'The log’s signed tree head does not verify, or is about another tree.',
  ANCHOR_TSA_TOKEN_MALFORMED: 'The timestamp token is not one this verifier can read.',
  ANCHOR_TSA_IMPRINT_MISMATCH: 'The timestamp token is about another hash, not this checkpoint.',
  ANCHOR_TSA_SIGNATURE_INVALID: 'The signature on the timestamp token does not verify.',
  ANCHOR_TSA_ATTRIBUTES_INVALID: 'The signed attributes of the timestamp token are missing or do not match its content.',
  ANCHOR_TSA_SIGNER_INVALID: 'The certificate that signed the token is not one allowed to sign timestamps.',
  ANCHOR_TSA_CHAIN_INVALID: 'The token’s certificate does not lead to a root you pinned, or was not valid at the time it names.',
  ANCHOR_TSA_ALGORITHM_UNSUPPORTED: 'The timestamp token uses an algorithm this verifier does not accept.',
};

let ready = false;
let fragment = parseFragment();

function parseFragment() {
  const params = new URLSearchParams(location.hash.replace(/^#/, ''));
  return {
    action: params.get('action'),
    bundle: params.get('bundle'),
    gate: params.get('gate'),
  };
}

function setBadge(state) {
  badge.textContent = state;
  badge.className = `badge ${state === 'VERIFIED' ? '' : state === 'INVALID' || state === 'ERROR' ? 'danger' : state === 'READY' || state === 'LOADING' ? 'neutral' : 'warn'}`;
}
function setStatus(state, message) {
  status.textContent = message;
  status.dataset.state = state;
  setBadge(state);
}
function row(label, value, mono = true) {
  const item = document.createElement('div');
  item.className = 'metric';
  const name = document.createElement('span');
  const detail = document.createElement('strong');
  name.textContent = label;
  detail.textContent = value ?? '—';
  if (!mono) detail.style.fontFamily = 'inherit';
  item.append(name, detail);
  return item;
}
function listItem(title, detail, state) {
  const item = document.createElement('div');
  item.className = `check ${state}`;
  const icon = document.createElement('span');
  icon.className = 'check-icon';
  icon.setAttribute('aria-hidden', 'true');
  icon.textContent = state === 'pass' ? '✓' : state === 'fail' ? '×' : state === 'warn' ? '!' : '–';
  const copy = document.createElement('div');
  const strong = document.createElement('strong');
  strong.textContent = title;
  const span = document.createElement('span');
  span.className = 'check-detail';
  span.textContent = detail;
  copy.append(strong, span);
  item.append(icon, copy);
  return item;
}

function normalizeKey(raw, label) {
  const text = raw.trim();
  if (!text) return '';
  if (text.startsWith('{')) {
    let parsed;
    try { parsed = JSON.parse(text); } catch { throw new Error(`${label}: not a public key (64 hex characters) and not valid JSON.`); }
    if (parsed && typeof parsed === 'object' && 'private_key' in parsed) {
      throw new Error(`${label}: that text contains a PRIVATE key. Never paste a key file here; paste only the public_key value. Nothing was sent, but rotate that key if it has left your machine.`);
    }
    const candidate = parsed?.public_key ?? parsed?.gate_public_key ?? parsed?.gate_id;
    if (typeof candidate !== 'string') throw new Error(`${label}: JSON has no public_key field.`);
    return normalizeKey(candidate, label);
  }
  if (!/^[0-9a-fA-F]{64}$/.test(text)) throw new Error(`${label}: a public key is exactly 64 hexadecimal characters.`);
  return text.toLowerCase();
}
function normalizeExecutorKeys(raw) {
  const parts = raw.split(/[\s,]+/).filter(Boolean);
  return parts.map((part, index) => normalizeKey(part, `Executor key ${index + 1}`));
}

function detectKind(document) {
  switch (document?.schema_version) {
    case 'tempus.evidence-bundle.v1': return 'bundle';
    case 'tempus.action-trace.v1': return 'trace';
    case 'tempus.authorization-result.v1': return 'authorization';
    case 'tempus.execution-result.v1': return 'execution';
    default: return null;
  }
}

function formatMicros(micros) {
  return new Date(Math.floor(micros / 1000)).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function renderResult(result, evidence, kind) {
  const verdict = result.status;
  const phaseText = { AUTHORIZED: 'permit issued, no outcome in this file', COMPLETED: 'permit issued and outcome recorded', EXPIRED: 'permit expired without an outcome in this file', BLOCKED: 'the gate signed a denial' };
  const dated = result.anchor?.status === 'VERIFIED' ? ` This checkpoint existed no later than ${formatMicros(result.anchor.anchored_at)}.` : '';
  const message = verdict === 'VERIFIED'
    ? `Every signed document in this file checks out against the pinned gate key. Phase: ${result.phase} (${phaseText[result.phase] ?? result.phase}).${dated}`
    : 'This file is not valid evidence. At least one signed document does not match, or the file was changed after signing.';
  setStatus(verdict, message);

  summary.replaceChildren(
    row('Document', kind === 'bundle' ? 'Evidence bundle' : kind === 'trace' ? 'Action trace' : kind === 'authorization' ? 'Permit' : 'Outcome', false),
    row('Action ID', result.action_id),
    row('Decision', result.decision ?? '—'),
    row('Phase', result.phase ?? '—'),
    row('Outcome', result.execution_status ?? 'not in file'),
    row('Gate key (pinned)', result.trust.gate_public_key),
    row('Executor keys pinned', String(result.trust.executor_keys_pinned ?? 0)),
  );
  if (result.bundle_digest) summary.append(row('Bundle digest', result.bundle_digest));
  if (dated) summary.append(row('Existed no later than', formatMicros(result.anchor.anchored_at)));

  checks.replaceChildren();
  for (const [name, [title, detail]] of Object.entries(CHECK_TITLES)) {
    const value = result.checks?.[name];
    if (value === undefined) continue;
    const [state, , label] = CHECK_STATES[value] ?? ['warn', '!', value];
    const specific = CHECK_DETAILS[name]?.[value];
    checks.append(listItem(`${title} · ${label}`, specific ?? (value === 'NOT_PRESENT' ? `${title.toLowerCase()} is not in this file.` : detail), state));
  }
  for (const proof of result.anchor?.proofs ?? []) {
    const [state, , label] = CHECK_STATES[proof.status] ?? ['warn', '!', proof.status];
    const proofDetail = proof.status === 'VERIFIED'
      ? `Says the checkpoint existed no later than ${formatMicros(proof.anchored_at)}.`
      : proof.status === 'NOT_CHECKED'
        ? 'Nothing you pinned can check this proof.'
        : `Does not verify: ${(proof.errors ?? []).join(', ')}.`;
    checks.append(listItem(`${BACKEND_TITLES[proof.backend] ?? proof.backend} · ${label}`, proofDetail, state));
  }
  if (result.output_degraded === true) {
    checks.append(listItem('Executor output was degraded', 'The executor could not represent its full result; the receipt says so and the verifier reports it.', 'warn'));
  }

  errors.replaceChildren();
  errors.hidden = !(result.errors?.length);
  for (const code of result.errors ?? []) {
    const key = code.split(' ')[0];
    errors.append(listItem(key, ERROR_TEXT[key] ?? `Reported by the verifier as ${code}.`, 'fail'));
  }

  notChecked.replaceChildren();
  for (const entry of result.trust?.not_checked ?? []) {
    const code = String(entry).split(' ')[0];
    notChecked.append(listItem(code.replaceAll('_', ' ').toLowerCase().replace(/^tsa /, 'timestamp ').replace(/^\w/, (c) => c.toUpperCase()), NOT_CHECKED[code] ?? String(entry), 'neutral'));
  }

  renderLink(result, evidence, kind);
  resultJson.textContent = JSON.stringify(result, null, 2);
}

function renderLink(result, evidence, kind) {
  linkPanel.replaceChildren();
  const items = [];
  if (fragment.bundle) {
    const match = result.bundle_digest && fragment.bundle.toLowerCase() === result.bundle_digest;
    items.push(listItem(
      match ? 'This link names the loaded file' : 'This link names a different file',
      match
        ? `The link you followed carries bundle digest ${fragment.bundle.slice(0, 16)}…, and the loaded bundle has that digest.`
        : `The link carries bundle digest ${fragment.bundle.slice(0, 16)}… but the loaded ${kind === 'bundle' ? 'bundle has digest ' + (result.bundle_digest ?? '?').slice(0, 16) + '…' : 'document is not a bundle'}. Ask for the file this link was issued for.`,
      match ? 'pass' : 'fail',
    ));
  }
  if (fragment.action) {
    const match = fragment.action === result.action_id;
    items.push(listItem(
      match ? 'This link is for the loaded action' : 'This link is for another action',
      match ? 'The action identifier in the link equals the signed action identifier in the file.' : `The link names action ${fragment.action.slice(0, 16)}… and the file is about ${String(result.action_id).slice(0, 16)}….`,
      match ? 'pass' : 'fail',
    ));
  }
  const embedded = evidence?.verify_url ?? evidence?.authorization?.verify_url ?? evidence?.authorization?.authorization?.verify_url ?? evidence?.receipt?.verify_url;
  if (embedded) {
    items.push(listItem('Verifier named by the file', `${embedded.split('#')[0]} — if that is not this page, the issuer points at another verifier; both must agree on the same spec.`, 'neutral'));
  }
  linkPanel.hidden = items.length === 0;
  linkPanel.append(...items);
}

async function readEvidenceText() {
  const file = fileInput.files?.[0];
  if (file) return file.text();
  return evidenceText.value;
}

async function readAnchorText() {
  const file = anchorFileInput.files?.[0];
  if (file) return file.text();
  return anchorTextInput.value;
}

function trustRootsJson() {
  const roots = {};
  if (rekorKeysInput.value.trim()) roots.rekor_public_keys = [rekorKeysInput.value];
  if (tsaRootsInput.value.trim()) roots.tsa_roots = [tsaRootsInput.value];
  return JSON.stringify(roots);
}

async function runVerification(event) {
  event?.preventDefault();
  if (!ready) return;
  errors.hidden = true;
  let text;
  try {
    text = (await readEvidenceText()).trim();
    if (!text) throw new Error('Choose an evidence file or paste its JSON.');
    const gate = normalizeKey(keyInput.value, 'Gate public key');
    if (!gate) throw new Error('Paste the gate PUBLIC key you obtained out of band (64 hex characters). Without a pinned key nothing here is independent.');
    const executors = normalizeExecutorKeys(executorInput.value);
    let parsed;
    try { parsed = JSON.parse(text); } catch { parsed = null; }
    const kind = detectKind(parsed);
    const anchor = (await readAnchorText()).trim();
    if (anchor && kind !== 'bundle') throw new Error('An anchor dates the checkpoint in an evidence bundle. Load the bundle, not a single permit or trace.');
    const raw = kind === 'bundle'
      ? verifier.verify_bundle_anchored(text, gate, JSON.stringify(executors), anchor, trustRootsJson())
      : verifier.verify_receipt(text, gate, JSON.stringify(executors));
    const result = JSON.parse(raw);
    renderResult(result, parsed, kind ?? result.kind);
  } catch (error) {
    const message = String(error?.message ?? error);
    setStatus('ERROR', message.replace(/^Error:\s*/, ''));
    summary.replaceChildren();
    checks.replaceChildren();
    notChecked.replaceChildren();
    linkPanel.hidden = true;
    resultJson.textContent = '';
  }
}

async function loadSample(name, anchored = false) {
  const sample = (file) => fetch(`data/evidence/${file}`).then((response) => { if (!response.ok) throw new Error(`Sample ${file} unavailable (${response.status}).`); return response.text(); });
  try {
    const [bundle, key, anchor, roots] = await Promise.all([
      sample(name),
      sample('gate_public_key.txt'),
      anchored ? sample('anchor.json') : '',
      anchored ? sample('anchor_roots.json') : '{}',
    ]);
    fileInput.value = '';
    evidenceText.value = bundle.trim();
    keyInput.value = key.trim();
    executorInput.value = '';
    const pinned = JSON.parse(roots);
    anchorFileInput.value = '';
    anchorTextInput.value = anchor.trim();
    rekorKeysInput.value = (pinned.rekor_public_keys ?? []).join('\n');
    tsaRootsInput.value = (pinned.tsa_roots ?? []).join('\n');
    await runVerification();
  } catch (error) {
    setStatus('ERROR', String(error?.message ?? error));
  }
}

function clearForm() {
  form.reset();
  summary.replaceChildren();
  checks.replaceChildren();
  errors.replaceChildren();
  errors.hidden = true;
  notChecked.replaceChildren();
  linkPanel.hidden = true;
  resultJson.textContent = '';
  setStatus('READY', 'Load a file and pin the gate public key to verify.');
}

form.addEventListener('submit', runVerification);
sampleButton.addEventListener('click', () => loadSample('bundle.json', true));
tamperedButton.addEventListener('click', () => loadSample('bundle_tampered_decision.json'));
clearButton.addEventListener('click', clearForm);
fileInput.addEventListener('change', () => { if (fileInput.files?.length) evidenceText.value = ''; });
anchorFileInput.addEventListener('change', () => { if (anchorFileInput.files?.length) anchorTextInput.value = ''; });
window.addEventListener('hashchange', () => { fragment = parseFragment(); describeFragment(); });

function describeFragment() {
  const intro = document.querySelector('#link-intro');
  if (fragment.bundle) {
    intro.hidden = false;
    intro.textContent = `This link was issued for one evidence bundle (digest ${fragment.bundle.slice(0, 16)}…). Load that file and the gate public key you were given; the page checks that they belong together.`;
  } else if (fragment.action) {
    intro.hidden = false;
    intro.textContent = `This link was issued for action ${fragment.action.slice(0, 16)}…. Load the permit, outcome, trace or bundle for it and the gate public key you were given.`;
  } else {
    intro.hidden = true;
  }
  if (fragment.gate && !keyInput.value) {
    try { keyInput.value = normalizeKey(fragment.gate, 'Gate public key'); } catch { /* ignore a malformed hint */ }
  }
}

try {
  setStatus('LOADING', 'Loading the verifier…');
  await init(new URL('./wasm/tempus_verifier_bg.wasm', import.meta.url));
  ready = true;
  engine.textContent = `Verifier: tempus-ddb ${verifier.version()} (WebAssembly, this page only)`;
  verifyButton.disabled = false;
  sampleButton.disabled = false;
  tamperedButton.disabled = false;
  describeFragment();
  setStatus('READY', 'Load a file and pin the gate public key to verify.');
} catch (error) {
  setStatus('ERROR', `The verifier could not load in this browser (${String(error?.message ?? error)}). Use the CLI: tempus verify-bundle --bundle evidence.json --gate-public-key <hex>.`);
}
