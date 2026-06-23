// Rust port of the approvewarden approval-audit core.
// Mirrors the Python CLI: read a JSON/CSV approval export, classify each
// allowance, score drainer exposure 0-100, emit an aggregate report.
// Pure std library, no external crates, no network access.
use std::collections::{BTreeMap, HashSet};
use std::{env, fs, process};

const NOW_DEFAULT: i64 = 1_749_340_800; // 2026-06-08, matches the Python suite

const DRAINER_LABELS: &[&str] = &[
    "drainer", "phishing", "inferno", "pink-drainer", "angel-drainer",
    "monkey-drainer", "venom-drainer", "ms-drainer", "scam", "malicious",
    "fake-permit", "approval-farming", "wallet-drainer",
];

/// A normalized approval record. `amount` is bucketed at parse time into a
/// magnitude class so we never need 256-bit arithmetic in std-only Rust.
#[derive(Clone)]
pub struct Approval {
    pub token: String,
    pub token_symbol: String,
    pub spender: String,
    pub kind_hint: AmountClass,
    pub standard: String,
    pub approval_for_all: bool,
    pub spender_label: String,
    pub spender_verified: bool,
    pub last_updated: Option<i64>,
    pub amount_repr: String,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum AmountClass { Zero, Finite, EffInfinite, Infinite }

#[derive(Clone)]
pub struct Finding {
    pub token: String,
    pub token_symbol: String,
    pub spender: String,
    pub spender_label: String,
    pub standard: String,
    pub allowance_kind: String,
    pub severity: String,
    pub score: i32,
    pub reasons: Vec<String>,
    pub amount: String,
}

pub fn is_address(s: &str) -> bool {
    let s = s.trim();
    s.len() == 42
        && s.starts_with("0x")
        && s[2..].chars().all(|c| c.is_ascii_hexdigit())
}

pub fn normalize_address(s: &str) -> Result<String, String> {
    if is_address(s) {
        Ok(s.trim().to_lowercase())
    } else {
        Err(format!("invalid address: {s:?}"))
    }
}

/// Classify a raw amount string into a magnitude bucket without big-int math.
pub fn classify_amount(raw: &str) -> AmountClass {
    let s: String = raw
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| *c != '_' && *c != ',')
        .collect();
    if s.is_empty() || s == "none" || s == "null" || s == "0" {
        return AmountClass::Zero;
    }
    if matches!(s.as_str(), "max" | "unlimited" | "infinite" | "inf") {
        return AmountClass::Infinite;
    }
    // uint256 max / uint96 max sentinels (decimal)
    const U256_MAX: &str = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    const U96_MAX: &str = "79228162514264337593543950335";
    if s == U256_MAX || s == U96_MAX {
        return AmountClass::Infinite;
    }
    if let Some(hex) = s.strip_prefix("0x") {
        if hex.chars().all(|c| c.is_ascii_hexdigit()) {
            if hex.is_empty() || hex.chars().all(|c| c == '0') {
                return AmountClass::Zero;
            }
            // 0xff..ff (64 f's) is uint256 max
            if hex.len() == 64 && hex.chars().all(|c| c == 'f') {
                return AmountClass::Infinite;
            }
            // long hex => effectively infinite (>= ~10^33 needs >27 hex digits)
            return if hex.trim_start_matches('0').len() >= 28 {
                AmountClass::EffInfinite
            } else {
                AmountClass::Finite
            };
        }
        return AmountClass::Zero;
    }
    // decimal: compare digit count for the 10^33 threshold.
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return AmountClass::Zero;
    }
    let trimmed = digits.trim_start_matches('0');
    if trimmed.is_empty() {
        AmountClass::Zero
    } else if trimmed.len() >= 34 {
        AmountClass::EffInfinite
    } else {
        AmountClass::Finite
    }
}

pub fn classify_allowance(a: &Approval) -> String {
    if a.approval_for_all {
        return "blanket".into();
    }
    match a.kind_hint {
        AmountClass::Zero => "zero",
        AmountClass::Infinite => "infinite",
        AmountClass::EffInfinite => "effectively_infinite",
        AmountClass::Finite => "finite",
    }
    .into()
}

fn has_drainer_label(label: &str) -> bool {
    let l = label.to_lowercase();
    DRAINER_LABELS.iter().any(|b| l.contains(b))
}

fn severity_for(score: i32) -> &'static str {
    match score {
        s if s >= 80 => "critical",
        s if s >= 55 => "high",
        s if s >= 30 => "medium",
        s if s >= 1 => "low",
        _ => "info",
    }
}

fn risk_level(score: i32) -> &'static str {
    match score {
        s if s >= 80 => "critical",
        s if s >= 55 => "high",
        s if s >= 30 => "medium",
        s if s >= 1 => "low",
        _ => "clean",
    }
}

pub fn score_approval(a: &Approval, now: i64, denylist: &HashSet<String>) -> Finding {
    let kind = classify_allowance(a);
    let mut f = Finding {
        token: a.token.clone(),
        token_symbol: a.token_symbol.clone(),
        spender: a.spender.clone(),
        spender_label: a.spender_label.clone(),
        standard: a.standard.clone(),
        allowance_kind: kind.clone(),
        severity: "info".into(),
        score: 0,
        reasons: vec![],
        amount: a.amount_repr.clone(),
    };
    if kind == "zero" {
        f.reasons.push("no active allowance".into());
        return f;
    }
    let mut score = 0;
    match kind.as_str() {
        "blanket" => {
            score += 60;
            f.reasons.push(format!(
                "setApprovalForAll grants the spender control of ALL {} tokens",
                a.standard
            ));
        }
        "infinite" => {
            score += 55;
            f.reasons.push("unlimited allowance (uint256/uint96 max sentinel)".into());
        }
        "effectively_infinite" => {
            score += 45;
            f.reasons.push("allowance is astronomically large (effectively infinite)".into());
        }
        _ => {
            score += 10;
            f.reasons.push("finite, bounded allowance".into());
        }
    }
    if denylist.contains(&a.spender) {
        score += 100;
        f.reasons.push(format!("spender address {} is on the drainer deny-list", a.spender));
    } else if !a.spender_label.is_empty() && has_drainer_label(&a.spender_label) {
        score += 100;
        f.reasons.push(format!("spender labelled as known-malicious ({})", a.spender_label));
    } else if !a.spender_verified {
        score += 25;
        f.reasons.push("spender contract is unverified".into());
    }
    if let Some(last) = a.last_updated {
        let age_days = ((now - last) / 86400).max(0);
        if age_days >= 365 {
            score += 15;
            f.reasons.push(format!("stale approval (~{age_days} days old, never revoked)"));
        } else if age_days >= 180 {
            score += 8;
            f.reasons.push(format!("aging approval (~{age_days} days old)"));
        }
    }
    score = score.clamp(0, 100);
    f.score = score;
    f.severity = severity_for(score).into();
    f
}

pub struct Report {
    pub total: usize,
    pub active: usize,
    pub infinite: usize,
    pub risk_score: i32,
    pub risk_level: String,
    pub counts: BTreeMap<String, i32>,
    pub findings: Vec<Finding>,
    pub clean: bool,
}

pub fn audit(approvals: &[Approval], now: i64, denylist: &HashSet<String>) -> Report {
    let findings: Vec<Finding> = approvals.iter().map(|a| score_approval(a, now, denylist)).collect();
    let mut active: Vec<Finding> = findings.iter().filter(|f| f.allowance_kind != "zero").cloned().collect();
    let mut counts: BTreeMap<String, i32> = ["info", "low", "medium", "high", "critical"]
        .iter()
        .map(|s| (s.to_string(), 0))
        .collect();
    let mut infinite = 0;
    for f in &active {
        *counts.get_mut(&f.severity).unwrap() += 1;
        if matches!(f.allowance_kind.as_str(), "infinite" | "effectively_infinite" | "blanket") {
            infinite += 1;
        }
    }
    let mut risk = 0;
    if !active.is_empty() {
        let mut wsum = 0i64;
        let mut num = 0i64;
        let mut worst = 0;
        for f in &active {
            let w = (f.score + 1) as i64;
            wsum += w;
            num += f.score as i64 * w;
            worst = worst.max(f.score);
        }
        risk = ((num + wsum / 2) / wsum) as i32;
        risk = risk.max(worst);
    }
    active.sort_by(|a, b| b.score.cmp(&a.score));
    Report {
        total: findings.len(),
        active: active.len(),
        infinite,
        risk_score: risk,
        risk_level: risk_level(risk).into(),
        counts,
        findings: active,
        clean: false,
    }
    .finalize()
}

impl Report {
    fn finalize(mut self) -> Report {
        self.clean = self.active == 0;
        self
    }
}

// --- minimal JSON value parser (objects/arrays/strings/numbers/bool/null) ---
#[derive(Debug, Clone)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> P<'a> {
    fn ws(&mut self) {
        while self.i < self.b.len() && (self.b[self.i] as char).is_whitespace() {
            self.i += 1;
        }
    }
    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        match self.b.get(self.i).copied() {
            Some(b'{') => self.obj(),
            Some(b'[') => self.arr(),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') | Some(b'f') => self.boolean(),
            Some(b'n') => {
                self.i += 4;
                Ok(Json::Null)
            }
            Some(_) => self.number(),
            None => Err("unexpected end".into()),
        }
    }
    fn obj(&mut self) -> Result<Json, String> {
        self.i += 1;
        let mut m = BTreeMap::new();
        self.ws();
        if self.b.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Ok(Json::Obj(m));
        }
        loop {
            self.ws();
            let k = self.string()?;
            self.ws();
            self.i += 1; // ':'
            let v = self.value()?;
            m.insert(k, v);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err("bad object".into()),
            }
        }
        Ok(Json::Obj(m))
    }
    fn arr(&mut self) -> Result<Json, String> {
        self.i += 1;
        let mut v = vec![];
        self.ws();
        if self.b.get(self.i) == Some(&b']') {
            self.i += 1;
            return Ok(Json::Arr(v));
        }
        loop {
            v.push(self.value()?);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err("bad array".into()),
            }
        }
        Ok(Json::Arr(v))
    }
    fn string(&mut self) -> Result<String, String> {
        self.i += 1; // opening quote
        let mut s = String::new();
        while let Some(&c) = self.b.get(self.i) {
            self.i += 1;
            match c {
                b'"' => return Ok(s),
                b'\\' => {
                    if let Some(&e) = self.b.get(self.i) {
                        self.i += 1;
                        s.push(match e {
                            b'n' => '\n',
                            b't' => '\t',
                            b'r' => '\r',
                            other => other as char,
                        });
                    }
                }
                other => s.push(other as char),
            }
        }
        Err("unterminated string".into())
    }
    fn boolean(&mut self) -> Result<Json, String> {
        if self.b[self.i] == b't' {
            self.i += 4;
            Ok(Json::Bool(true))
        } else {
            self.i += 5;
            Ok(Json::Bool(false))
        }
    }
    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        while let Some(&c) = self.b.get(self.i) {
            if (c as char).is_ascii_digit() || matches!(c, b'-' | b'+' | b'.' | b'e' | b'E') {
                self.i += 1;
            } else {
                break;
            }
        }
        let s = std::str::from_utf8(&self.b[start..self.i]).unwrap_or("0");
        s.parse::<f64>().map(Json::Num).map_err(|_| "bad number".into())
    }
}

pub fn parse_json(text: &str) -> Result<Json, String> {
    let mut p = P { b: text.as_bytes(), i: 0 };
    p.value()
}

fn jstr(j: Option<&Json>) -> String {
    match j {
        Some(Json::Str(s)) => s.clone(),
        Some(Json::Num(n)) => {
            if n.fract() == 0.0 {
                format!("{}", *n as i64)
            } else {
                format!("{n}")
            }
        }
        Some(Json::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn jbool(j: Option<&Json>, def: bool) -> bool {
    match j {
        Some(Json::Bool(b)) => *b,
        Some(Json::Str(s)) => {
            let s = s.trim().to_lowercase();
            !(s == "0" || s == "false" || s == "no" || s == "n" || s.is_empty())
        }
        None | Some(Json::Null) => def,
        _ => def,
    }
}

pub fn from_obj(o: &BTreeMap<String, Json>) -> Result<Approval, String> {
    let get = |keys: &[&str]| -> Option<&Json> { keys.iter().find_map(|k| o.get(*k)) };
    let mut standard = jstr(get(&["standard"])).trim().to_uppercase();
    if standard.is_empty() {
        standard = "ERC20".into();
    }
    let afa = jbool(get(&["is_approval_for_all", "approval_for_all"]), false);
    let verified = jbool(get(&["spender_verified"]), true);
    let token = normalize_address(&jstr(get(&["token", "contract"])))?;
    let spender = normalize_address(&jstr(get(&["spender"])))?;
    let amount_raw = if afa { "max".to_string() } else { jstr(get(&["amount", "allowance"])) };
    let kind_hint = if afa { AmountClass::Infinite } else { classify_amount(&amount_raw) };
    let last = match get(&["last_updated"]) {
        Some(Json::Num(n)) => Some(*n as i64),
        Some(Json::Str(s)) if !s.is_empty() => s.parse::<f64>().ok().map(|f| f as i64),
        _ => None,
    };
    Ok(Approval {
        token,
        token_symbol: jstr(get(&["token_symbol", "symbol"])).trim().to_string(),
        spender,
        kind_hint,
        standard,
        approval_for_all: afa,
        spender_label: jstr(get(&["spender_label", "label"])).trim().to_string(),
        spender_verified: verified,
        last_updated: last,
        amount_repr: amount_raw,
    })
}

pub fn load_csv(text: &str) -> Result<Vec<Approval>, String> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header: Vec<String> = match lines.next() {
        Some(h) => h.split(',').map(|s| s.trim().to_string()).collect(),
        None => return Ok(vec![]),
    };
    let mut out = vec![];
    for line in lines {
        let cells: Vec<&str> = line.split(',').collect();
        let mut o = BTreeMap::new();
        for (i, h) in header.iter().enumerate() {
            o.insert(h.clone(), Json::Str(cells.get(i).unwrap_or(&"").trim().to_string()));
        }
        out.push(from_obj(&o)?);
    }
    Ok(out)
}

pub fn load_json(text: &str) -> Result<Vec<Approval>, String> {
    let v = parse_json(text)?;
    let recs: Vec<&Json> = match &v {
        Json::Arr(a) => a.iter().collect(),
        Json::Obj(o) => match o.get("approvals") {
            Some(Json::Arr(a)) => a.iter().collect(),
            _ => vec![&v],
        },
        _ => return Err("input must be array or object".into()),
    };
    let mut out = vec![];
    for r in recs {
        if let Json::Obj(o) = r {
            out.push(from_obj(o)?);
        }
    }
    Ok(out)
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

pub fn to_json(r: &Report) -> String {
    let mut out = String::from("{\n");
    out.push_str("  \"tool\": \"approvewarden\",\n");
    out.push_str(&format!("  \"total_approvals\": {},\n", r.total));
    out.push_str(&format!("  \"active_approvals\": {},\n", r.active));
    out.push_str(&format!("  \"infinite_approvals\": {},\n", r.infinite));
    out.push_str(&format!("  \"risk_score\": {},\n", r.risk_score));
    out.push_str(&format!("  \"risk_level\": \"{}\",\n", r.risk_level));
    let sc: Vec<String> = r.counts.iter().map(|(k, v)| format!("\"{k}\": {v}")).collect();
    out.push_str(&format!("  \"severity_counts\": {{{}}},\n", sc.join(", ")));
    out.push_str("  \"findings\": [\n");
    let fjson: Vec<String> = r
        .findings
        .iter()
        .map(|f| {
            let reasons: Vec<String> = f.reasons.iter().map(|x| format!("\"{}\"", esc(x))).collect();
            format!(
                "    {{\"token\": \"{}\", \"token_symbol\": \"{}\", \"spender\": \"{}\", \"standard\": \"{}\", \"allowance_kind\": \"{}\", \"severity\": \"{}\", \"score\": {}, \"reasons\": [{}]}}",
                f.token, esc(&f.token_symbol), f.spender, f.standard, f.allowance_kind, f.severity, f.score, reasons.join(", ")
            )
        })
        .collect();
    out.push_str(&fjson.join(",\n"));
    out.push_str("\n  ],\n");
    out.push_str(&format!("  \"clean\": {}\n", r.clean));
    out.push_str("}");
    out
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: approvewarden <approvals.json|csv>");
        process::exit(1);
    }
    let path = &args[1];
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };
    let approvals = if path.to_lowercase().ends_with(".csv") {
        load_csv(&text)
    } else {
        load_json(&text)
    };
    match approvals {
        Ok(a) => {
            let report = audit(&a, NOW_DEFAULT, &HashSet::new());
            println!("{}", to_json(&report));
        }
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rep(s: &str, n: usize) -> String {
        s.repeat(n)
    }
    const NOW: i64 = 1_749_340_800;

    fn mk(amount: &str, afa: bool, std: &str, label: &str, verif: bool, last: i64) -> Approval {
        let mut o = BTreeMap::new();
        o.insert("token".into(), Json::Str(format!("0x{}", rep("11", 20))));
        o.insert("symbol".into(), Json::Str("X".into()));
        o.insert("spender".into(), Json::Str(format!("0x{}", rep("22", 20))));
        o.insert("amount".into(), Json::Str(amount.into()));
        o.insert("standard".into(), Json::Str(std.into()));
        o.insert("spender_label".into(), Json::Str(label.into()));
        o.insert("spender_verified".into(), Json::Bool(verif));
        o.insert("last_updated".into(), Json::Num(last as f64));
        o.insert("is_approval_for_all".into(), Json::Bool(afa));
        from_obj(&o).unwrap()
    }

    #[test]
    fn test_normalize_address() {
        assert_eq!(normalize_address(&format!("0x{}", rep("Ab", 20))).unwrap(), format!("0x{}", rep("ab", 20)));
        assert!(normalize_address("nope").is_err());
        assert!(normalize_address("0x1234").is_err());
    }

    #[test]
    fn test_classify_amount() {
        assert_eq!(classify_amount("max"), AmountClass::Infinite);
        assert_eq!(classify_amount("0"), AmountClass::Zero);
        assert_eq!(classify_amount("1000000000000000000"), AmountClass::Finite);
        assert_eq!(classify_amount("1000000000000000000000000000000000"), AmountClass::EffInfinite);
        assert_eq!(classify_amount("0x10"), AmountClass::Finite);
    }

    #[test]
    fn test_classify_allowance() {
        assert_eq!(classify_allowance(&mk("max", false, "ERC20", "", true, NOW)), "infinite");
        assert_eq!(classify_allowance(&mk("1000000000000000000", false, "ERC20", "", true, NOW)), "finite");
        assert_eq!(classify_allowance(&mk("0", true, "ERC721", "", true, NOW)), "blanket");
        assert_eq!(classify_allowance(&mk("0", false, "ERC20", "", true, NOW)), "zero");
    }

    #[test]
    fn test_drainer_critical() {
        let f = score_approval(&mk("0", true, "ERC721", "Pink-Drainer", false, NOW), NOW, &HashSet::new());
        assert_eq!(f.severity, "critical");
        assert!(f.score >= 80);
    }

    #[test]
    fn test_finite_low() {
        let f = score_approval(&mk("1000000000000000000", false, "ERC20", "", true, NOW), NOW, &HashSet::new());
        assert_eq!(f.severity, "low");
    }

    #[test]
    fn test_zero_not_scored() {
        let f = score_approval(&mk("0", false, "ERC20", "", true, NOW), NOW, &HashSet::new());
        assert_eq!(f.score, 0);
        assert_eq!(f.allowance_kind, "zero");
    }

    #[test]
    fn test_denylist_escalates() {
        let a = mk("1000000000000000000", false, "ERC20", "", true, NOW);
        let mut dl = HashSet::new();
        dl.insert(a.spender.clone());
        let f = score_approval(&a, NOW, &dl);
        assert_eq!(f.severity, "critical");
    }

    #[test]
    fn test_audit_and_clean() {
        let data = format!(
            "{{\"approvals\":[\
            {{\"token\":\"0x{}\",\"symbol\":\"USDC\",\"spender\":\"0x{}\",\"amount\":\"max\",\"last_updated\":1672531200}},\
            {{\"token\":\"0x{}\",\"symbol\":\"BAYC\",\"spender\":\"0x{}\",\"standard\":\"ERC721\",\"is_approval_for_all\":true,\"spender_label\":\"Inferno\",\"spender_verified\":false}},\
            {{\"token\":\"0x{}\",\"symbol\":\"Z\",\"spender\":\"0x{}\",\"amount\":\"0\"}}\
            ]}}",
            rep("11", 20), rep("22", 20), rep("33", 20), rep("44", 20), rep("55", 20), rep("66", 20)
        );
        let approvals = load_json(&data).unwrap();
        assert_eq!(approvals.len(), 3);
        let r = audit(&approvals, NOW, &HashSet::new());
        assert_eq!(r.total, 3);
        assert_eq!(r.active, 2);
        assert_eq!(r.risk_level, "critical");
        assert!(!r.clean);
        assert!(r.findings[0].score >= r.findings[1].score);

        let clean = load_json(&format!("[{{\"token\":\"0x{}\",\"symbol\":\"OK\",\"spender\":\"0x{}\",\"amount\":\"0\"}}]", rep("11", 20), rep("22", 20))).unwrap();
        let rc = audit(&clean, NOW, &HashSet::new());
        assert!(rc.clean);
        assert_eq!(rc.risk_level, "clean");
        assert_eq!(rc.risk_score, 0);
    }

    #[test]
    fn test_csv() {
        let data = format!("token,symbol,spender,amount,spender_verified\n0x{},FOO,0x{},max,false\n", rep("33", 20), rep("44", 20));
        let approvals = load_csv(&data).unwrap();
        assert_eq!(approvals.len(), 1);
        assert_eq!(approvals[0].kind_hint, AmountClass::Infinite);
        assert!(!approvals[0].spender_verified);
    }

    #[test]
    fn test_to_json_roundtrips() {
        let approvals = mk("max", false, "ERC20", "", false, NOW);
        let r = audit(&[approvals], NOW, &HashSet::new());
        let out = to_json(&r);
        assert!(out.contains("\"tool\": \"approvewarden\""));
        assert!(out.contains("\"risk_level\""));
    }
}
