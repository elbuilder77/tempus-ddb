import { verifyDemoTrace } from "./trace-verifier.mjs";

const summary = document.querySelector("#trace-summary");
const status = document.querySelector("#verification-status");
const results = document.querySelector("#trace-results");
const json = document.querySelector("#trace-json");
const originalButton = document.querySelector("#verify-original");
const tamperButton = document.querySelector("#tamper-fixture");
let originalTrace;

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function setSummary(trace) {
  summary.replaceChildren();
  const rows = [
    ["Action", trace.action_id],
    ["Requested resource", trace.intent.resource],
    ["Decision", trace.authorization.decision],
    ["Outcome", trace.execution.outcome.status],
  ];
  for (const [label, value] of rows) {
    const row = document.createElement("div");
    row.className = "metric";
    const name = document.createElement("span");
    const detail = document.createElement("strong");
    name.textContent = label;
    detail.textContent = value;
    row.append(name, detail);
    summary.append(row);
  }
}

function renderResult(result, trace) {
  const message = result.status === "VERIFIED"
    ? "VERIFIED — all browser checks passed for this synthetic fixture."
    : result.status === "PARTIAL"
      ? "PARTIAL — record and hash checks passed, but this browser could not verify every Ed25519 signature."
      : "INVALID — at least one bound record, hash or signature no longer matches.";
  status.textContent = message;
  results.replaceChildren();
  for (const check of result.checks) {
    const item = document.createElement("div");
    item.className = `check ${check.status}`;
    const icon = document.createElement("span");
    icon.className = "check-icon";
    icon.setAttribute("aria-hidden", "true");
    const copy = document.createElement("div");
    const title = document.createElement("strong");
    const detail = document.createElement("span");
    title.textContent = check.title;
    detail.textContent = check.detail;
    copy.append(title, detail);
    item.append(icon, copy);
    results.append(item);
  }
  setSummary(trace);
  json.textContent = JSON.stringify(trace, null, 2);
}

async function run(trace) {
  status.textContent = "Running local checks…";
  results.replaceChildren();
  try {
    renderResult(await verifyDemoTrace(trace), trace);
  } catch (error) {
    status.textContent = "INVALID — the browser could not process this fixture.";
    results.textContent = error.message;
  }
}

async function initialize() {
  try {
    const response = await fetch("data/demo-trace.json", { cache: "no-store" });
    if (!response.ok) throw new Error(`Fixture request failed with HTTP ${response.status}`);
    originalTrace = await response.json();
    await run(clone(originalTrace));
  } catch (error) {
    summary.textContent = "The demonstration fixture could not be loaded.";
    status.textContent = `INVALID — ${error.message}`;
  }
}

originalButton.addEventListener("click", () => run(clone(originalTrace)));
tamperButton.addEventListener("click", () => {
  const altered = clone(originalTrace);
  altered.intent.resource = "github.com/example-org/production-admin";
  run(altered);
});

initialize();
