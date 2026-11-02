// Runs the browser verifier (the wasm32 build of the crate, as published on the site)
// against the conformance evidence fixtures, in Node and with no network.
//
//   node scripts/test_wasm_verifier.mjs
//
// Requires site/assets/wasm/ (see scripts/build_wasm_verifier.sh) and
// conformance/evidence/ (see scripts/generate_conformance_evidence.py).

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const projectRoot = resolve(import.meta.dirname, "..");
const wasmDir = resolve(projectRoot, "site", "assets", "wasm");
const evidenceDir = resolve(projectRoot, "conformance", "evidence");

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const glue = await import(pathToFileURL(resolve(wasmDir, "tempus_verifier.js")).href);
const bytes = await readFile(resolve(wasmDir, "tempus_verifier_bg.wasm"));
glue.initSync({ module: bytes });

const expected = JSON.parse(await readFile(resolve(evidenceDir, "expected.json"), "utf8"));
assert(expected.schema_version === "tempus.conformance-evidence.v1", "unknown expected.json schema");
const gateKey = (await readFile(resolve(evidenceDir, expected.gate_public_key_file), "utf8")).trim();
const executorKey = (await readFile(resolve(evidenceDir, expected.executor_public_key_file), "utf8")).trim();

const version = glue.version();
assert(/^\d+\.\d+\.\d+/.test(version), `version() must be a semver string, got ${version}`);

let checked = 0;
for (const testCase of expected.cases) {
  const text = await readFile(resolve(evidenceDir, testCase.file), "utf8");
  const raw = testCase.kind === "bundle"
    ? glue.verify_bundle(text, gateKey, "")
    : glue.verify_receipt(text, gateKey, "");
  const result = JSON.parse(raw);
  const where = `${testCase.file}:`;
  assert(result.schema_version === "tempus.trace-verification.v1", `${where} unexpected result schema ${result.schema_version}`);
  assert(result.kind === testCase.kind, `${where} kind ${result.kind} != ${testCase.kind}`);
  assert(result.status === testCase.status, `${where} status ${result.status} != ${testCase.status}: ${raw}`);
  if (testCase.phase) assert(result.phase === testCase.phase, `${where} phase ${result.phase} != ${testCase.phase}`);
  if (testCase.phase_any) assert(testCase.phase_any.includes(result.phase), `${where} phase ${result.phase} not in ${testCase.phase_any}`);
  for (const [name, value] of Object.entries(testCase.checks ?? {})) {
    assert(result.checks[name] === value, `${where} checks.${name} ${result.checks[name]} != ${value}`);
  }
  if (testCase.errors) {
    assert(JSON.stringify(result.errors) === JSON.stringify(testCase.errors), `${where} errors ${JSON.stringify(result.errors)}`);
  }
  for (const code of testCase.errors_include ?? []) {
    assert(result.errors.includes(code), `${where} missing error ${code} in ${JSON.stringify(result.errors)}`);
  }
  assert(result.trust.independent === true, `${where} browser verification must be independent`);
  assert(result.trust.gate_public_key === gateKey, `${where} pinned key must be reported`);
  checked++;
}

// Anchors: alone, and alongside the bundle whose checkpoint they prove.
const anchorBundleText = await readFile(resolve(evidenceDir, expected.anchor_bundle), "utf8");
const anchorCheckpoint = JSON.stringify(JSON.parse(anchorBundleText).checkpoint.checkpoint);
const bundleChecks = { VERIFIED: "VERIFIED", NOT_CHECKED: "NOT_CHECKED", INVALID: "FAILED" };
let anchorsChecked = 0;
for (const testCase of expected.anchor_cases) {
  const anchorText = await readFile(resolve(evidenceDir, testCase.anchor), "utf8");
  const roots = testCase.roots ? await readFile(resolve(evidenceDir, testCase.roots), "utf8") : "";
  const where = `${testCase.anchor} (${testCase.roots ?? "nothing pinned"}):`;
  const alone = JSON.parse(glue.verify_anchor(anchorText, anchorCheckpoint, roots));
  assert(alone.schema_version === "tempus.anchor-verification.v1", `${where} unexpected schema ${alone.schema_version}`);
  assert(alone.status === testCase.status, `${where} status ${alone.status} != ${testCase.status}: ${JSON.stringify(alone)}`);
  assert(JSON.stringify(alone.proofs.map((proof) => proof.status)) === JSON.stringify(testCase.proofs), `${where} proofs ${JSON.stringify(alone.proofs)}`);
  assert(JSON.stringify(alone.errors) === JSON.stringify(testCase.errors), `${where} errors ${JSON.stringify(alone.errors)}`);
  assert((alone.anchored_at !== null) === (testCase.status === "VERIFIED"), `${where} anchored_at ${alone.anchored_at}`);
  const inBundle = JSON.parse(glue.verify_bundle_anchored(anchorBundleText, gateKey, "", anchorText, roots));
  assert(inBundle.checks.anchor === bundleChecks[testCase.status], `${where} checks.anchor ${inBundle.checks.anchor}`);
  assert(inBundle.status === (testCase.status === "INVALID" ? "INVALID" : "VERIFIED"), `${where} bundle status ${inBundle.status}`);
  for (const code of testCase.errors) {
    assert(inBundle.errors.includes(code), `${where} bundle is missing ${code}`);
  }
  anchorsChecked++;
}
// No anchor argument is the plain verification, and it says what it cannot show.
const unanchored = JSON.parse(glue.verify_bundle_anchored(anchorBundleText, gateKey, "", "", ""));
assert(unanchored.status === "VERIFIED" && unanchored.checks.anchor === "NOT_PRESENT", "an empty anchor argument must mean no anchor");
assert(JSON.stringify(unanchored.trust.not_checked).includes("CHECKPOINT_TIME"), "the checkpoint's date must be listed as not checked");
// A root that cannot be read is a thrown error: silently dropping it would look like no pin.
let refusedRoots = false;
try {
  glue.verify_anchor("{}", anchorCheckpoint, '{"tsa_roots":["AQID"]}');
} catch (error) {
  refusedRoots = String(error).includes("not an X.509 certificate");
}
assert(refusedRoots, "an unreadable trust root must be refused");

// Pinning the executor key is accepted in every documented form.
const bundleText = await readFile(resolve(evidenceDir, "bundle.json"), "utf8");
for (const keys of [executorKey, `["${executorKey}"]`, ` ${executorKey},\n`]) {
  const result = JSON.parse(glue.verify_bundle(bundleText, gateKey, keys));
  assert(result.status === "VERIFIED", `pinned executor (${JSON.stringify(keys)}) must verify: ${result.errors}`);
  assert(result.trust.executor_keys_pinned === 1, "one executor key must be reported as pinned");
}
// The wrong gate key is INVALID, not an exception: a reader sees the verdict.
const wrongKey = JSON.parse(glue.verify_bundle(bundleText, executorKey, ""));
assert(wrongKey.status === "INVALID", "a bundle verified with the wrong gate key must be INVALID");

// bundle_digest matches what the gate wrote into verify_url, and ignores verify_url itself.
assert(glue.bundle_digest(bundleText) === expected.bundle_digest, "bundle_digest must match expected.json");
assert(JSON.parse(bundleText).verify_url.endsWith(`#bundle=${expected.bundle_digest}`), "verify_url must carry the digest");

// Malformed input is a thrown error with the protocol's code, never a VERIFIED verdict.
for (const [input, needle] of [
  ['{"a":1,"a":2}', "DUPLICATE_JSON_KEY"],
  ["not json", "valid JSON"],
]) {
  let threw = false;
  try {
    glue.bundle_digest(input);
  } catch (error) {
    threw = true;
    assert(String(error).includes(needle), `expected ${needle} in ${String(error)}`);
  }
  assert(threw, `bundle_digest(${JSON.stringify(input)}) must throw`);
}

console.log(`wasm verifier ${version}: ${checked} conformance cases, ${anchorsChecked} anchor cases, executor pinning, wrong-key, digest and malformed-input checks passed.`);
