// Smoke test for the JavaScript port. Run: node test.js (Node >= 18, stdlib only).
import assert from "node:assert/strict";
import {
  normalizeAddress, parseAmount, classifyAllowance, scoreApproval,
  auditApprovals, loadApprovals, fromRecord,
} from "./index.js";

const NOW = 1749340800; // 2026-06-08, matches the Python suite
let n = 0;
const ok = (name, fn) => { fn(); n++; console.log(`ok ${name}`); };

ok("normalize lowercases", () =>
  assert.equal(normalizeAddress("0x" + "Ab".repeat(20)), "0x" + "ab".repeat(20)));
ok("normalize rejects garbage", () =>
  assert.throws(() => normalizeAddress("nope")));
ok("parse max sentinel", () =>
  assert.equal(parseAmount("max"), (1n << 256n) - 1n));
ok("parse hex", () => assert.equal(parseAmount("0x10"), 16n));
ok("parse zero", () => assert.equal(parseAmount("0"), 0n));

const infinite = fromRecord({ token: "0x" + "11".repeat(20), symbol: "USDC", spender: "0x" + "22".repeat(20), amount: "max" });
ok("classify infinite", () => assert.equal(classifyAllowance(infinite), "infinite"));

const finite = fromRecord({ token: "0x" + "11".repeat(20), symbol: "W", spender: "0x" + "22".repeat(20), amount: "1000000000000000000" });
ok("classify finite", () => assert.equal(classifyAllowance(finite), "finite"));

const blanket = fromRecord({ token: "0x" + "11".repeat(20), symbol: "BAYC", spender: "0x" + "22".repeat(20), standard: "ERC721", is_approval_for_all: true });
ok("classify blanket", () => assert.equal(classifyAllowance(blanket), "blanket"));

const zero = fromRecord({ token: "0x" + "11".repeat(20), symbol: "Z", spender: "0x" + "22".repeat(20), amount: "0" });
ok("classify zero", () => assert.equal(classifyAllowance(zero), "zero"));

const drainer = fromRecord({ token: "0x" + "11".repeat(20), symbol: "X", spender: "0x" + "22".repeat(20), standard: "ERC721", is_approval_for_all: true, spender_label: "Pink-Drainer", spender_verified: false });
ok("drainer label is critical", () => {
  const f = scoreApproval(drainer, NOW);
  assert.equal(f.severity, "critical");
  assert.ok(f.score >= 80);
});

ok("finite is low", () => assert.equal(scoreApproval(finite, NOW).severity, "low"));
ok("zero is not scored", () => assert.equal(scoreApproval(zero, NOW).score, 0));

ok("address denylist escalates", () => {
  const dl = new Set([finite.spender]);
  const f = scoreApproval(finite, NOW, dl);
  assert.equal(f.severity, "critical");
  assert.ok(f.reasons.some((r) => r.includes("deny-list")));
});

const recs = loadApprovals(JSON.stringify({
  approvals: [
    { token: "0x" + "11".repeat(20), symbol: "USDC", spender: "0x" + "22".repeat(20), amount: "max", last_updated: 1735689600 },
    { token: "0x" + "33".repeat(20), symbol: "BAYC", spender: "0x" + "44".repeat(20), standard: "ERC721", is_approval_for_all: true, spender_label: "Inferno", spender_verified: false },
    { token: "0x" + "55".repeat(20), symbol: "Z", spender: "0x" + "66".repeat(20), amount: "0" },
  ],
}));
ok("load approvals count", () => assert.equal(recs.length, 3));

const report = auditApprovals(recs, NOW);
ok("report total", () => assert.equal(report.total_approvals, 3));
ok("report active drops zero", () => assert.equal(report.active_approvals, 2));
ok("report risk critical", () => assert.equal(report.risk_level, "critical"));
ok("findings sorted worst-first", () => {
  const scores = report.findings.map((f) => f.score);
  assert.deepEqual(scores, [...scores].sort((a, b) => b - a));
});

const cleanReport = auditApprovals(loadApprovals(JSON.stringify([
  { token: "0x" + "11".repeat(20), symbol: "OK", spender: "0x" + "22".repeat(20), amount: "0" },
])), NOW);
ok("clean wallet", () => {
  assert.equal(cleanReport.clean, true);
  assert.equal(cleanReport.risk_level, "clean");
});

const csv = "token,symbol,spender,amount,spender_verified\n0x" + "33".repeat(20) + ",FOO,0x" + "44".repeat(20) + ",max,false\n";
ok("csv parse", () => {
  const a = loadApprovals(csv, "csv");
  assert.equal(a.length, 1);
  assert.equal(a[0].amount, (1n << 256n) - 1n);
  assert.equal(a[0].spender_verified, false);
});

console.log(`\n${n} assertions passed`);
