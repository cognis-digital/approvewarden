// Go port of the approvewarden approval-audit core.
// Mirrors the Python CLI: read a JSON/CSV approval export, classify each
// allowance, score drainer exposure 0-100, emit an aggregate report.
// Pure standard library, no network access.
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strings"
)

var (
	uint256Max     = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	uint96Max      = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 96), big.NewInt(1))
	effInfinite, _ = new(big.Int).SetString("1"+strings.Repeat("0", 33), 10) // 10^33
	addrRe         = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	drainerLabels  = []string{
		"drainer", "phishing", "inferno", "pink-drainer", "angel-drainer",
		"monkey-drainer", "venom-drainer", "ms-drainer", "scam", "malicious",
		"fake-permit", "approval-farming", "wallet-drainer",
	}
)

// Approval is one normalized approval record.
type Approval struct {
	Token          string
	TokenSymbol    string
	Spender        string
	Amount         *big.Int
	Standard       string
	ApprovalForAll bool
	SpenderLabel   string
	SpenderVerif   bool
	LastUpdated    *int64
}

// Finding is a scored result.
type Finding struct {
	Token         string   `json:"token"`
	TokenSymbol   string   `json:"token_symbol"`
	Spender       string   `json:"spender"`
	SpenderLabel  string   `json:"spender_label"`
	Standard      string   `json:"standard"`
	AllowanceKind string   `json:"allowance_kind"`
	Severity      string   `json:"severity"`
	Score         int      `json:"score"`
	Reasons       []string `json:"reasons"`
	Amount        string   `json:"amount"`
}

// Report is the aggregate audit output.
type Report struct {
	Tool           string         `json:"tool"`
	TotalApprovals int            `json:"total_approvals"`
	ActiveApproval int            `json:"active_approvals"`
	InfiniteApprov int            `json:"infinite_approvals"`
	RiskScore      int            `json:"risk_score"`
	RiskLevel      string         `json:"risk_level"`
	SeverityCounts map[string]int `json:"severity_counts"`
	Findings       []Finding      `json:"findings"`
	Clean          bool           `json:"clean"`
}

func normalizeAddress(v string) (string, error) {
	s := strings.TrimSpace(v)
	if !addrRe.MatchString(s) {
		return "", fmt.Errorf("invalid address: %q", v)
	}
	return strings.ToLower(s), nil
}

func parseAmount(v string) *big.Int {
	s := strings.ToLower(strings.TrimSpace(v))
	s = strings.NewReplacer("_", "", ",", "").Replace(s)
	if s == "" || s == "none" || s == "null" {
		return big.NewInt(0)
	}
	switch s {
	case "max", "unlimited", "infinite", "inf":
		return new(big.Int).Set(uint256Max)
	}
	if strings.HasPrefix(s, "0x") {
		n, ok := new(big.Int).SetString(s[2:], 16)
		if ok {
			return n
		}
		return big.NewInt(0)
	}
	if strings.ContainsAny(s, "e.") {
		var f float64
		fmt.Sscanf(s, "%g", &f)
		bf := new(big.Float).SetFloat64(f)
		n, _ := bf.Int(nil)
		return n
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return big.NewInt(0)
	}
	return n
}

func classifyAllowance(a Approval) string {
	if a.ApprovalForAll {
		return "blanket"
	}
	if a.Amount.Sign() <= 0 {
		return "zero"
	}
	if a.Amount.Cmp(uint256Max) == 0 || a.Amount.Cmp(uint96Max) == 0 {
		return "infinite"
	}
	if a.Amount.Cmp(effInfinite) >= 0 {
		return "effectively_infinite"
	}
	return "finite"
}

func hasDrainerLabel(label string) bool {
	l := strings.ToLower(label)
	for _, b := range drainerLabels {
		if strings.Contains(l, b) {
			return true
		}
	}
	return false
}

func scoreApproval(a Approval, now int64, denylist map[string]bool) Finding {
	kind := classifyAllowance(a)
	f := Finding{
		Token: a.Token, TokenSymbol: a.TokenSymbol, Spender: a.Spender,
		SpenderLabel: a.SpenderLabel, Standard: a.Standard,
		AllowanceKind: kind, Amount: a.Amount.String(),
	}
	if kind == "zero" {
		f.Severity = "info"
		f.Reasons = []string{"no active allowance"}
		return f
	}
	score := 0
	var reasons []string
	switch kind {
	case "blanket":
		score += 60
		reasons = append(reasons, fmt.Sprintf("setApprovalForAll grants the spender control of ALL %s tokens", a.Standard))
	case "infinite":
		score += 55
		reasons = append(reasons, "unlimited allowance (uint256/uint96 max sentinel)")
	case "effectively_infinite":
		score += 45
		reasons = append(reasons, "allowance is astronomically large (effectively infinite)")
	default:
		score += 10
		reasons = append(reasons, "finite, bounded allowance")
	}
	if denylist[a.Spender] {
		score += 100
		reasons = append(reasons, fmt.Sprintf("spender address %s is on the drainer deny-list", a.Spender))
	} else if a.SpenderLabel != "" && hasDrainerLabel(a.SpenderLabel) {
		score += 100
		reasons = append(reasons, fmt.Sprintf("spender labelled as known-malicious (%s)", a.SpenderLabel))
	} else if !a.SpenderVerif {
		score += 25
		reasons = append(reasons, "spender contract is unverified")
	}
	if a.LastUpdated != nil {
		ageDays := (now - *a.LastUpdated) / 86400
		if ageDays < 0 {
			ageDays = 0
		}
		if ageDays >= 365 {
			score += 15
			reasons = append(reasons, fmt.Sprintf("stale approval (~%d days old, never revoked)", ageDays))
		} else if ageDays >= 180 {
			score += 8
			reasons = append(reasons, fmt.Sprintf("aging approval (~%d days old)", ageDays))
		}
	}
	if score > 100 {
		score = 100
	}
	f.Score = score
	f.Reasons = reasons
	f.Severity = severityFor(score)
	return f
}

func severityFor(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 55:
		return "high"
	case score >= 30:
		return "medium"
	case score >= 1:
		return "low"
	default:
		return "info"
	}
}

func riskLevel(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 55:
		return "high"
	case score >= 30:
		return "medium"
	case score >= 1:
		return "low"
	default:
		return "clean"
	}
}

func auditApprovals(approvals []Approval, now int64, denylist map[string]bool) Report {
	findings := []Finding{}
	active := []Finding{}
	for _, a := range approvals {
		f := scoreApproval(a, now, denylist)
		findings = append(findings, f)
		if f.AllowanceKind != "zero" {
			active = append(active, f)
		}
	}
	counts := map[string]int{"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
	infinite := 0
	for _, f := range active {
		counts[f.Severity]++
		if f.AllowanceKind == "infinite" || f.AllowanceKind == "effectively_infinite" || f.AllowanceKind == "blanket" {
			infinite++
		}
	}
	risk := 0
	if len(active) > 0 {
		wsum, num, worst := 0, 0, 0
		for _, f := range active {
			w := f.Score + 1
			wsum += w
			num += f.Score * w
			if f.Score > worst {
				worst = f.Score
			}
		}
		risk = (num + wsum/2) / wsum // rounded
		if worst > risk {
			risk = worst
		}
	}
	// sort findings worst-first (insertion sort; small N)
	for i := 1; i < len(active); i++ {
		for j := i; j > 0 && active[j].Score > active[j-1].Score; j-- {
			active[j], active[j-1] = active[j-1], active[j]
		}
	}
	return Report{
		Tool: "approvewarden", TotalApprovals: len(findings),
		ActiveApproval: len(active), InfiniteApprov: infinite,
		RiskScore: risk, RiskLevel: riskLevel(risk),
		SeverityCounts: counts, Findings: active, Clean: len(active) == 0,
	}
}

func toBool(v interface{}, def bool) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		s := strings.ToLower(strings.TrimSpace(x))
		return !(s == "0" || s == "false" || s == "no" || s == "n" || s == "")
	case nil:
		return def
	}
	return def
}

func fromMap(d map[string]interface{}) (Approval, error) {
	get := func(keys ...string) interface{} {
		for _, k := range keys {
			if v, ok := d[k]; ok {
				return v
			}
		}
		return nil
	}
	asStr := func(v interface{}) string {
		if v == nil {
			return ""
		}
		return fmt.Sprintf("%v", v)
	}
	standard := strings.ToUpper(strings.TrimSpace(asStr(get("standard"))))
	if standard == "" {
		standard = "ERC20"
	}
	afa := toBool(get("is_approval_for_all", "approval_for_all"), false)
	verified := toBool(get("spender_verified"), true)
	token, err := normalizeAddress(asStr(get("token", "contract")))
	if err != nil {
		return Approval{}, err
	}
	spender, err := normalizeAddress(asStr(get("spender")))
	if err != nil {
		return Approval{}, err
	}
	var amount *big.Int
	if afa {
		amount = new(big.Int).Set(uint256Max)
	} else {
		amount = parseAmount(asStr(get("amount", "allowance")))
	}
	var last *int64
	if lv := get("last_updated"); lv != nil && asStr(lv) != "" {
		var f float64
		fmt.Sscanf(asStr(lv), "%g", &f)
		l := int64(f)
		last = &l
	}
	return Approval{
		Token: token, TokenSymbol: strings.TrimSpace(asStr(get("token_symbol", "symbol"))),
		Spender: spender, Amount: amount, Standard: standard,
		ApprovalForAll: afa, SpenderLabel: strings.TrimSpace(asStr(get("spender_label", "label"))),
		SpenderVerif: verified, LastUpdated: last,
	}, nil
}

func loadApprovals(data []byte, isCSV bool) ([]Approval, error) {
	var recs []map[string]interface{}
	if isCSV {
		r := csv.NewReader(strings.NewReader(string(data)))
		rows, err := r.ReadAll()
		if err != nil {
			return nil, err
		}
		if len(rows) < 1 {
			return nil, nil
		}
		hdr := rows[0]
		for _, row := range rows[1:] {
			m := map[string]interface{}{}
			for i, h := range hdr {
				if i < len(row) {
					m[strings.TrimSpace(h)] = row[i]
				}
			}
			recs = append(recs, m)
		}
	} else {
		var raw interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, err
		}
		switch v := raw.(type) {
		case []interface{}:
			for _, e := range v {
				if m, ok := e.(map[string]interface{}); ok {
					recs = append(recs, m)
				}
			}
		case map[string]interface{}:
			if arr, ok := v["approvals"].([]interface{}); ok {
				for _, e := range arr {
					if m, ok := e.(map[string]interface{}); ok {
						recs = append(recs, m)
					}
				}
			} else {
				recs = append(recs, v)
			}
		}
	}
	out := []Approval{}
	for _, m := range recs {
		a, err := fromMap(m)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: approvewarden <approvals.json|csv>")
		os.Exit(1)
	}
	path := os.Args[1]
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	isCSV := strings.HasSuffix(strings.ToLower(path), ".csv")
	approvals, err := loadApprovals(data, isCSV)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	report := auditApprovals(approvals, 1749340800, map[string]bool{})
	out, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(out))
}
