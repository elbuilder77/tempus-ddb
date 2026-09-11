import { webcrypto } from "node:crypto";
import { access, readFile, readdir } from "node:fs/promises";
import { dirname, extname, resolve } from "node:path";
import { verifyDemoTrace } from "../site/assets/trace-verifier.mjs";

const projectRoot = resolve(import.meta.dirname, "..");
const siteRoot = resolve(projectRoot, "site");
const requiredPages = ["index.html", "docs.html", "trace.html", "404.html"];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

function localReference(value) {
  return value
    && !value.startsWith("#")
    && !value.startsWith("https://")
    && !value.startsWith("http://")
    && !value.startsWith("mailto:")
    && !value.startsWith("tel:")
    && !value.startsWith("data:");
}

async function assertReferencesExist(file, html) {
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
  assert(new Set(ids).size === ids.length, `${file} contains duplicate IDs`);
  for (const match of html.matchAll(/\b(?:href|src)="([^"]+)"/g)) {
    const reference = match[1];
    if (reference.startsWith("#")) {
      assert(ids.includes(reference.slice(1)), `${file} references missing anchor ${reference}`);
      continue;
    }
    if (!localReference(reference)) continue;
    const cleanReference = reference.split(/[?#]/, 1)[0];
    let target = resolve(dirname(file), cleanReference);
    if (extname(target) === "" && await exists(target)) target = resolve(target, "index.html");
    assert(await exists(target), `${file.replace(projectRoot, ".")} references missing local asset ${reference}`);
    if (reference.includes("#") && extname(target) === ".html") {
      const targetHtml = await readFile(target, "utf8");
      assert(targetHtml.includes(`id="${reference.split("#")[1]}"`), `${file} references missing destination anchor ${reference}`);
    }
  }
}

for (const page of requiredPages) {
  const path = resolve(siteRoot, page);
  assert(await exists(path), `Missing required page ${page}`);
  const html = await readFile(path, "utf8");
  assert(html.includes('href="assets/site.css"'), `${page} must use the shared stylesheet`);
  assert(html.includes('href="#main-content"'), `${page} must include a skip link`);
  assert(html.includes('<main id="main-content">'), `${page} must expose a main landmark`);
  assert(/<meta name="description" content="[^"]+">/.test(html), `${page} needs a description`);
  assert(html.includes('src="assets/site.mjs"'), `${page} must load shared navigation and copy behavior`);
  assert((html.match(/<h1[ >]/g) ?? []).length === 1, `${page} needs one primary heading`);
  assert(!html.includes("PyPI publishing pending"), `${page} must not claim PyPI publishing is pending`);
  await assertReferencesExist(path, html);
}

const assets = await readdir(resolve(siteRoot, "assets"));
for (const asset of ["site.css", "site.mjs", "trace-verifier.mjs", "trace-page.mjs"]) assert(assets.includes(asset), `Missing shared asset ${asset}`);

const readme = await readFile(resolve(projectRoot, "README.md"), "utf8");
assert(!readme.includes("Install the published beta from PyPI"), "README must not present PyPI as the beta installation source");

const fixture = JSON.parse(await readFile(resolve(siteRoot, "data", "demo-trace.json"), "utf8"));
const original = await verifyDemoTrace(fixture, webcrypto);
assert(original.status === "VERIFIED", `Expected verified browser fixture, received ${original.status}`);

const altered = structuredClone(fixture);
altered.intent.resource = "example-org/production-admin";
const alteredResult = await verifyDemoTrace(altered, webcrypto);
assert(alteredResult.status === "INVALID", "A changed intent must invalidate the browser fixture");

const hashOnlyCrypto = { subtle: { digest: webcrypto.subtle.digest.bind(webcrypto.subtle) } };
const fallback = await verifyDemoTrace(fixture, hashOnlyCrypto);
assert(fallback.status === "PARTIAL", "Missing Ed25519 support must be reported as a partial result");

for (const [name, mutate] of [
  ["decision", (trace) => { trace.authorization.decision = "BLOCKED"; }],
  ["outcome", (trace) => { trace.execution.outcome.status = "FAILED"; }],
  ["malformed signature", (trace) => { trace.agent_signature = "not-hex"; }],
  ["invalid public key", (trace) => { trace.authorization.gate_id = "aa"; }],
]) {
  const tampered = structuredClone(fixture);
  mutate(tampered);
  const result = await verifyDemoTrace(tampered, webcrypto);
  assert(result.status === "INVALID", `Tampered ${name} must be INVALID, received ${result.status}`);
}
const unsupportedCrypto = {
  subtle: {
    digest: webcrypto.subtle.digest.bind(webcrypto.subtle),
    importKey: () => { throw new DOMException("Unavailable", "NotSupportedError"); },
    verify: webcrypto.subtle.verify.bind(webcrypto.subtle),
  },
};
assert((await verifyDemoTrace(fixture, unsupportedCrypto)).status === "PARTIAL", "Unsupported Ed25519 must stay PARTIAL");
assert((await verifyDemoTrace(altered, hashOnlyCrypto)).status === "INVALID", "A known hash mismatch must not become PARTIAL without Ed25519");

console.log(`Validated ${requiredPages.length} pages, local assets and anchors, metadata, all tamper scenarios and signature fallback states.`);
