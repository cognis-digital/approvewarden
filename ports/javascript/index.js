#!/usr/bin/env node
// JavaScript port of the approvewarden approval-audit core.
// Mirrors the Python CLI: read a JSON/CSV approval export, classify each
// allowance, score drainer exposure 0-100, and emit an aggregate report.
// Pure Node stdlib, no network access.
import { readFileSync } from "fs";
import { argv } from "process";
import { fileURLToPath } from "url";

const UINT256_MAX = (1n << 256n) - 1n;
const UINT96_MAX = (1n << 96n) - 1n;
const EFFECTIVE_INFINITE_RAW = 10n ** 33n; // 10^(15+18)
const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
export const SEVERITY_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const DRAINER_LABELS = [
  "drainer", "phishing", "inferno", "pink-drainer", "angel-drainer",
  "monkey-drainer", "venom-drainer", "ms-drainer", "scam", "malicious",
  "fake-permit", "approval-farming", "wallet-drainer",
];

export function normalizeAddress(v) {
  if (v == null) throw new Error("address is missing");
  const s = String(v).trim();
  if (!ADDR_RE.test(s)) throw new Error(`invalid address: ${v}`);
  return s.toLowerCase();
}

export function parseAmount(v) {
  if (v == null) return 0n;
  if (typeof v === "boolean") throw new Error("amount cannot be a boolean");
  if (typeof v === "number") return BigInt(Math.trunc(v));
  let s = String(v).trim().toLowerCase().replace(/[_,]/g, "");
  if (s === "" || s === "none" || s === "null") return 0n;
  if (["max", "unlimited", "infinite", "inf"].includes(s)) return UINT256_MAX;
  if (s.startsWith("0x")) return BigInt(s);
  if (s.includes("e") || s.includes(".")) return BigInt(Math.trunc(Number(s)));
  return BigInt(s);
}

export function fromRecord(d) {
  const standard = String(d.standard ?? "ERC20").toUpperCase().trim() || "ERC20";
  let afa = d.is_approval_for_all ?? d.approval_for_all ?? false;
  if (typeof afa === "string") afa = ["1", "true", "yes", "y"].includes(afa.trim().toLowerCase());
  afa = Boolean(afa);
  let verified = d.spender_verified ?? true;
  if (typeof verified === "string")
    verified = !["0", "false", "no", "n", ""].includes(verified.trim().toLowerCase());
  let last = d.last_updated;
  if (last === "" || last == null) last = null;
  else last = Number.parseInt(String(last), 10);
  if (Number.isNaN(last)) last = null;
  const amount = afa ? UINT256_MAX : parseAmount(d.amount ?? d.allowance ?? 0);
  return {
    token: normalizeAddress(d.token ?? d.contract),
    token_symbol: String(d.token_symbol ?? d.symbol ?? "").trim(),
    spender: normalizeAddress(d.spender),
    amount,
    standard,
    is_approval_for_all: afa,
    spender_label: String(d.spender_label ?? d.label ?? "").trim(),
    spender_verified: Boolean(verified),
    last_updated: last,
  };
}

export function classifyAllowance(a) {
  if (a.is_approval_for_all) return "blanket";
  const amt = a.amount;
  if (amt <= 0n) return "zero";
  if (amt === UINT256_MAX || amt === UINT96_MAX) return "infinite";
  if (amt >= EFFECTIVE_INFINITE_RAW) return "effectively_infinite";
  return "finite";
}

function base(a, kind) {
  return {
    token: a.token, token_symbol: a.token_symbol, spender: a.spender,
    spender_label: a.spender_label, standard: a.standard,
    allowance_kind: kind, amount: a.amount.toString(),
  };
}

export function scoreApproval(a, now, denylist = new Set()) {
  const kind = classifyAllowance(a);
  const reasons = [];
  let score = 0;
  if (kind === "zero")
    return { ...base(a, kind), severity: "info", score: 0, reasons: ["no active allowance"] };
  if (kind === "blanket") { score += 60; reasons.push(`setApprovalForAll grants the spender control of ALL ${a.standard} tokens`); }
  else if (kind === "infinite") { score += 55; reasons.push("unlimited allowance (uint256/uint96 max sentinel)"); }
  else if (kind === "effectively_infinite") { score += 45; reasons.push("allowance is astronomically large (effectively infinite)"); }
  else { score += 10; reasons.push("finite, bounded allowance"); }

  const label = a.spender_label.toLowerCase();
  const addrFlagged = denylist.has(a.spender);
  const labelFlagged = label && DRAINER_LABELS.some((b) => label.includes(b));
  if (addrFlagged) { score += 100; reasons.push(`spender address ${a.spender} is on the drainer deny-list`); }
  else if (labelFlagged) { score += 100; reasons.push(`spender labelled as known-malicious (${a.spender_label})`); }
  else if (!a.spender_verified) { score += 25; reasons.push("spender contract is unverified"); }

  if (a.last_updated != null) {
    const ageDays = Math.max(0, Math.floor((now - a.last_updated) / 86400));
    if (ageDays >= 365) { score += 15; reasons.push(`stale approval (~${ageDays} days old, never revoked)`); }
    else if (ageDays >= 180) { score += 8; reasons.push(`aging approval (~${ageDays} days old)`); }
  }
  score = Math.max(0, Math.min(100, score));
  const severity = score >= 80 ? "critical" : score >= 55 ? "high" : score >= 30 ? "medium" : score >= 1 ? "low" : "info";
  return { ...base(a, kind), severity, score, reasons };
}

export function auditApprovals(records, now, denylist = new Set()) {
  const findings = records.map((a) => scoreApproval(a, now, denylist));
  const active = findings.filter((f) => f.allowance_kind !== "zero");
  const counts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of active) counts[f.severity]++;
  const infiniteLike = active.filter((f) =>
    ["infinite", "effectively_infinite", "blanket"].includes(f.allowance_kind));
  let risk = 0;
  if (active.length) {
    const weights = active.map((f) => f.score + 1);
    const wsum = weights.reduce((x, y) => x + y, 0);
    risk = Math.round(active.reduce((s, f, i) => s + f.score * weights[i], 0) / wsum);
    risk = Math.max(risk, Math.max(...active.map((f) => f.score)));
  }
  const level = risk >= 80 ? "critical" : risk >= 55 ? "high" : risk >= 30 ? "medium" : risk >= 1 ? "low" : "clean";
  const sorted = [...active].sort((a, b) => b.score - a.score);
  return {
    tool: "approvewarden",
    total_approvals: findings.length,
    active_approvals: active.length,
    infinite_approvals: infiniteLike.length,
    risk_score: risk,
    risk_level: level,
    severity_counts: counts,
    findings: sorted,
    clean: active.length === 0,
  };
}

function parseCsv(text) {
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  const headers = lines[0].split(",").map((h) => h.trim());
  return lines.slice(1).map((ln) => {
    const cells = ln.split(",");
    const o = {};
    headers.forEach((h, i) => { o[h] = (cells[i] ?? "").trim(); });
    return o;
  });
}

export function loadApprovals(text, fmt = "auto") {
  const stripped = text.trimStart();
  if (fmt === "auto") fmt = stripped[0] === "[" || stripped[0] === "{" ? "json" : "csv";
  let recs;
  if (fmt === "json") {
    const data = JSON.parse(text);
    recs = Array.isArray(data) ? data : data.approvals ?? [data];
  } else recs = parseCsv(text);
  return recs.map(fromRecord);
}

export function scan(path, now) {
  const text = readFileSync(path, "utf8");
  const fmt = path.toLowerCase().endsWith(".csv") ? "csv" : "auto";
  return auditApprovals(loadApprovals(text, fmt), now ?? Math.floor(Date.now() / 1000));
}

const _isMain = (() => {
  try { return process.argv[1] && fileURLToPath(import.meta.url) === argv[1]; }
  catch { return false; }
})();
if (_isMain) {
  const target = argv[2];
  if (!target) { console.error("usage: node index.js <approvals.json|csv>"); process.exit(1); }
  console.log(JSON.stringify(scan(target), null, 2));
}
