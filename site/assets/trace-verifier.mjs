const encoder = new TextEncoder();

export function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  throw new TypeError(`Unsupported value in canonical JSON: ${typeof value}`);
}

export function hexToBytes(hex) {
  if (typeof hex !== "string" || !/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) throw new TypeError("Expected an even-length hexadecimal string");
  return Uint8Array.from(hex.match(/.{1,2}/g), (pair) => Number.parseInt(pair, 16));
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

async function sha256(value, cryptoImpl) {
  const digest = await cryptoImpl.subtle.digest("SHA-256", encoder.encode(value));
  return bytesToHex(new Uint8Array(digest));
}

function without(object, fields) {
  return Object.fromEntries(Object.entries(object).filter(([key]) => !fields.includes(key)));
}

async function verifyEd25519(publicKeyHex, message, signatureHex, cryptoImpl) {
  const key = await cryptoImpl.subtle.importKey("raw", hexToBytes(publicKeyHex), { name: "Ed25519" }, false, ["verify"]);
  return cryptoImpl.subtle.verify({ name: "Ed25519" }, key, hexToBytes(signatureHex), message);
}

export async function verifyDemoTrace(trace, cryptoImpl = globalThis.crypto) {
  const checks = [];
  const add = (status, title, detail) => checks.push({ status, title, detail });
  const fail = (title, detail) => add("fail", title, detail);
  const pass = (title, detail) => add("pass", title, detail);
  const warn = (title, detail) => add("warn", title, detail);

  if (!cryptoImpl?.subtle?.digest) {
    fail("Web Crypto is unavailable", "This browser cannot calculate the fixture hashes.");
    return { status: "INVALID", checks };
  }

  if (trace?.schema_version !== "tempus.site-demo-trace.v1") fail("Fixture schema", "The browser fixture schema is not recognized.");
  else pass("Fixture schema", "The fixture identifies itself as a non-production site demo.");

  const intent = trace?.intent;
  const authorization = trace?.authorization;
  const execution = trace?.execution;
  const outcome = execution?.outcome;
  const receipt = execution?.receipt;
  if (!intent || !authorization || !outcome || !receipt) {
    fail("Trace structure", "The fixture is missing one or more required evidence records.");
    return { status: "INVALID", checks };
  }

  const intentHash = await sha256(canonicalize(intent), cryptoImpl);
  if (intentHash === authorization.intent_hash) pass("Intent hash", "The signed request matches the permit's bound intent hash.");
  else fail("Intent hash", "The requested action no longer matches the permit.");

  const authorizationId = await sha256(canonicalize(without(authorization, ["authorization_id", "gate_signature"])), cryptoImpl);
  if (authorizationId === authorization.authorization_id) pass("Permit identifier", "The permit identifier matches its canonical authorization body.");
  else fail("Permit identifier", "The permit identifier does not match its authorization body.");

  const receiptId = await sha256(canonicalize(without(receipt, ["receipt_id", "gate_signature"])), cryptoImpl);
  if (receiptId === receipt.receipt_id) pass("Receipt identifier", "The receipt identifier matches its canonical receipt body.");
  else fail("Receipt identifier", "The receipt identifier does not match its receipt body.");

  const linksMatch = authorization.action_id === trace.action_id
    && outcome.action_id === trace.action_id
    && receipt.action_id === trace.action_id
    && outcome.authorization_id === authorization.authorization_id
    && receipt.authorization_id === authorization.authorization_id
    && receipt.intent_hash === authorization.intent_hash
    && receipt.status === outcome.status;
  if (linksMatch) pass("Record bindings", "Intent, permit, outcome and receipt point to the same action.");
  else fail("Record bindings", "One or more records point to a different action, permit or outcome.");

  const canVerifySignatures = Boolean(cryptoImpl?.subtle?.importKey && cryptoImpl?.subtle?.verify);
  if (!canVerifySignatures) {
    warn("Ed25519 signatures", "This browser cannot run Ed25519 checks. Hash and binding checks still ran.");
  } else {
    try {
      const agentValid = await verifyEd25519(intent.agent_id, encoder.encode(canonicalize(intent)), trace.agent_signature, cryptoImpl);
      agentValid ? pass("Agent signature", "The requesting workload signed the canonical intent.") : fail("Agent signature", "The intent signature does not verify with the agent public key.");

      const authorizationValid = await verifyEd25519(authorization.gate_id, hexToBytes(authorization.authorization_id), authorization.gate_signature, cryptoImpl);
      authorizationValid ? pass("Permit signature", "The gate signed the permit identifier.") : fail("Permit signature", "The gate signature does not verify for this permit.");

      const unsignedOutcome = without(outcome, ["executor_signature"]);
      const outcomeValid = await verifyEd25519(outcome.executor_id, encoder.encode(canonicalize(unsignedOutcome)), outcome.executor_signature, cryptoImpl);
      outcomeValid ? pass("Executor signature", "The executor signed the canonical outcome.") : fail("Executor signature", "The executor signature does not verify for this outcome.");

      const receiptValid = await verifyEd25519(receipt.gate_id, hexToBytes(receipt.receipt_id), receipt.gate_signature, cryptoImpl);
      receiptValid ? pass("Receipt signature", "The gate signed the execution receipt identifier.") : fail("Receipt signature", "The gate signature does not verify for this receipt.");
    } catch (error) {
      if (error.name === "NotSupportedError") {
        warn("Ed25519 signatures", "This browser does not support Ed25519. Hash and binding checks still ran.");
      } else {
        fail("Signature data", "A signature or public key is malformed or could not be verified.");
      }
    }
  }

  const status = checks.some((check) => check.status === "fail") ? "INVALID" : checks.some((check) => check.status === "warn") ? "PARTIAL" : "VERIFIED";
  return { status, checks };
}
