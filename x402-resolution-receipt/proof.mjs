import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";

const STATES = ["SURVIVED", "NARROWED", "FAILED", "UNRESOLVED"];
const T0 = 1787749200;

function canon(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canon).join(",")}]`;
  return `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${canon(v[k])}`).join(",")}}`;
}
function digest(v) { return `sha256:${createHash("sha256").update(canon(v)).digest("hex")}`; }
function keypair() { return generateKeyPairSync("ed25519"); }
function pub(k) { return k.export({format:"der",type:"spki"}).toString("base64url"); }
function sig(k,v) { return sign(null, Buffer.from(canon(v)), k).toString("base64url"); }
function check(k,v,s) { return verify(null, Buffer.from(canon(v)), k, Buffer.from(s,"base64url")); }

// One x402 v2 exact-payment path. This proof consumes settlement; it does not reimplement EIP-3009/RPC validation.
const paymentRequired = {
  x402Version: 2,
  resource: { url:"https://api.example.com/premium-data", mimeType:"application/json" },
  accepts: [{ scheme:"exact", network:"eip155:84532", amount:"10000", asset:"0x036CbD53842c5426634e7929541eC2318f3dCF7e", payTo:"0x209693Bc6afc0C5328bA36FaF03C514EF312287C", maxTimeoutSeconds:60 }],
  extensions: {}
};
const paymentPayload = {
  x402Version: 2,
  resource: paymentRequired.resource,
  accepted: paymentRequired.accepts[0],
  payload: { signature:`0x${"11".repeat(65)}`, authorization:{ from:"0x857b06519E91e3A54538791bDbb0E22373e36b66", to:paymentRequired.accepts[0].payTo, value:"10000", validAfter:String(T0), validBefore:String(T0+60), nonce:`0x${"22".repeat(32)}` } },
  extensions: {}
};
const settlementResponse = { success:true, transaction:`0x${"33".repeat(32)}`, network:"eip155:84532", payer:paymentPayload.payload.authorization.from, amount:"10000", extensions:{} };

function exactBinding() {
  const r = paymentRequired.accepts[0], a = paymentPayload.accepted, x = paymentPayload.payload.authorization;
  return paymentRequired.x402Version === 2 && paymentPayload.x402Version === 2 &&
    a.scheme === "exact" && ["network","amount","asset","payTo","maxTimeoutSeconds"].every(k => String(a[k]) === String(r[k])) &&
    x.to === r.payTo && x.value === r.amount && settlementResponse.success && settlementResponse.network === r.network && settlementResponse.payer === x.from;
}
assert.equal(exactBinding(), true);

// 1) Preserve issuance-time authority evidence rather than depending on current mutable DID/DNS state.
const authority = keypair();
const issuanceSigner = keypair();
const rotatedSigner = keypair();
const authorityPayload = {
  type:"x402-resolution-authority/v1",
  service:paymentRequired.resource.url,
  signerKeyId:"did:web:api.example.com#receipt-2026-08",
  signerPublicKey:pub(issuanceSigner.publicKey),
  observedAt:T0,
  validFrom:T0-60,
  validUntil:T0+86400,
  source:{ method:"did:web", locator:"did:web:api.example.com", documentDigest:digest({verificationMethod:[pub(issuanceSigner.publicKey)]}) }
};
const authorityEvidence = { ...authorityPayload, proof:{ authorityPublicKey:pub(authority.publicKey), signature:sig(authority.privateKey, authorityPayload) } };
const currentDid = { verificationMethod:[pub(rotatedSigner.publicKey)] }; // issuance key is gone after rotation
assert.notEqual(currentDid.verificationMethod[0], authorityEvidence.signerPublicKey);
assert.equal(check(authority.publicKey, authorityPayload, authorityEvidence.proof.signature), true);

const evidence = {
  x402:{ paymentRequiredDigest:digest(paymentRequired), paymentPayloadDigest:digest(paymentPayload), settlementResponseDigest:digest(settlementResponse) },
  execution:{ requestDigest:digest({method:"GET",url:"/premium-data?symbol=ETH"}), responseDigest:digest({status:200,body:{symbol:"ETH",price:"4600.00"}}) },
  authorityEvidence
};
const evidenceRoot = digest(evidence);
const receiptId = digest({ evidenceRoot, transaction:settlementResponse.transaction });

// 2) Preserve independently signed verifier findings. Four states are reference semantics, not mandatory x402 policy.
function finding(verifierId, keys, ruleset, result, reason, observedAt) {
  assert.ok(STATES.includes(result));
  const payload = { type:"x402-resolution-verification/v1", verifierId, verifierPublicKey:pub(keys.publicKey), rulesetDigest:digest(ruleset), evidenceRoot, result, reason, observedAt };
  return { ...payload, signature:sig(keys.privateKey,payload) };
}
// avoid serialized-key reconstruction in this tiny proof: verify with the known independent key below.
const verifierA = keypair();
const f0 = finding("independent-A", verifierA, {checks:["exact-binding","issuance-authority","response-digest"]}, "SURVIVED", "Replay passed under ruleset v1.", T0+10);
const {signature:f0sig,...f0payload}=f0;
assert.equal(check(verifierA.publicKey,f0payload,f0sig),true);

// 3) Corrections are append-only: a new conclusion links to, but never overwrites, the old one.
const resolver = keypair();
function resolution(sequence, previousResolutionId, findings, state, correctionReason, issuedAt) {
  const payload = { type:"x402-resolution-receipt/v1", receiptId, evidenceRoot, sequence, previousResolutionId, findingDigests:findings.map(digest), state, correctionReason, issuedAt, resolverPublicKey:pub(resolver.publicKey) };
  const resolutionId = digest(payload);
  return { ...payload, resolutionId, signature:sig(resolver.privateKey,{...payload,resolutionId}), findings };
}
function validResolution(r) {
  const {signature,findings,...signed}=r;
  const {resolutionId,...payload}=signed;
  return resolutionId === digest(payload) && check(resolver.publicKey,signed,signature) && canon(r.findingDigests) === canon(findings.map(digest));
}
const r0 = resolution(0,null,[f0],"SURVIVED",null,T0+11);
const f1 = finding("independent-A", verifierA, {checks:["exact-binding","issuance-authority","response-preimage"]}, "FAILED", "Later audit found the retained response preimage does not match the committed digest.", T0+3600);
const {signature:f1sig,...f1payload}=f1;
assert.equal(check(verifierA.publicKey,f1payload,f1sig),true);
const r1 = resolution(1,r0.resolutionId,[f1],"FAILED","Superseding audit result; r0 remains immutable.",T0+3601);
assert.equal(validResolution(r0),true);
assert.equal(validResolution(r1),true);
assert.equal(r1.previousResolutionId,r0.resolutionId);
assert.equal(r0.state,"SURVIVED");
assert.equal(r1.state,"FAILED");

console.log(JSON.stringify({
  exactPaymentBinding:true,
  historicalAuthoritySurvivesRotation:true,
  signedIndependentFinding:true,
  originalResolution:{id:r0.resolutionId,state:r0.state},
  correction:{id:r1.resolutionId,state:r1.state,previousResolutionId:r1.previousResolutionId},
  correctionChainValid:r1.previousResolutionId===r0.resolutionId
},null,2));
