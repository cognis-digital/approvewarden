package main

import "testing"

const now int64 = 1749340800 // 2026-06-08

func mk(amount string, afa bool, std, label string, verif bool, last int64) Approval {
	a, err := fromMap(map[string]interface{}{
		"token":            "0x" + repeat("11", 20),
		"symbol":           "X",
		"spender":          "0x" + repeat("22", 20),
		"amount":           amount,
		"standard":         std,
		"spender_label":    label,
		"spender_verified": verif,
		"last_updated":     last,
		"is_approval_for_all": afa,
	})
	if err != nil {
		panic(err)
	}
	return a
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func TestNormalizeAddress(t *testing.T) {
	got, err := normalizeAddress("0x" + repeat("Ab", 20))
	if err != nil || got != "0x"+repeat("ab", 20) {
		t.Fatalf("normalize: %q %v", got, err)
	}
	if _, err := normalizeAddress("nope"); err == nil {
		t.Fatal("expected error on bad address")
	}
}

func TestParseAmount(t *testing.T) {
	if parseAmount("max").Cmp(uint256Max) != 0 {
		t.Fatal("max sentinel")
	}
	if parseAmount("0x10").Int64() != 16 {
		t.Fatal("hex")
	}
	if parseAmount("0").Sign() != 0 {
		t.Fatal("zero")
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		a    Approval
		want string
	}{
		{mk("max", false, "ERC20", "", true, now), "infinite"},
		{mk("1000000000000000000", false, "ERC20", "", true, now), "finite"},
		{mk("0", true, "ERC721", "", true, now), "blanket"},
		{mk("0", false, "ERC20", "", true, now), "zero"},
		{mk("1000000000000000000000000000000000", false, "ERC20", "", true, now), "effectively_infinite"},
	}
	for _, c := range cases {
		if got := classifyAllowance(c.a); got != c.want {
			t.Errorf("classify = %q, want %q", got, c.want)
		}
	}
}

func TestDrainerLabelCritical(t *testing.T) {
	f := scoreApproval(mk("0", true, "ERC721", "Pink-Drainer", false, now), now, map[string]bool{})
	if f.Severity != "critical" || f.Score < 80 {
		t.Fatalf("drainer should be critical, got %s/%d", f.Severity, f.Score)
	}
}

func TestFiniteIsLow(t *testing.T) {
	f := scoreApproval(mk("1000000000000000000", false, "ERC20", "", true, now), now, map[string]bool{})
	if f.Severity != "low" {
		t.Fatalf("finite verified should be low, got %s", f.Severity)
	}
}

func TestZeroNotScored(t *testing.T) {
	f := scoreApproval(mk("0", false, "ERC20", "", true, now), now, map[string]bool{})
	if f.Score != 0 || f.AllowanceKind != "zero" {
		t.Fatalf("zero should score 0, got %d", f.Score)
	}
}

func TestDenylistEscalates(t *testing.T) {
	a := mk("1000000000000000000", false, "ERC20", "", true, now)
	f := scoreApproval(a, now, map[string]bool{a.Spender: true})
	if f.Severity != "critical" {
		t.Fatalf("denylist hit should be critical, got %s", f.Severity)
	}
}

func TestAuditAndJSON(t *testing.T) {
	data := []byte(`{"approvals":[
		{"token":"0x` + repeat("11", 20) + `","symbol":"USDC","spender":"0x` + repeat("22", 20) + `","amount":"max","last_updated":1672531200},
		{"token":"0x` + repeat("33", 20) + `","symbol":"BAYC","spender":"0x` + repeat("44", 20) + `","standard":"ERC721","is_approval_for_all":true,"spender_label":"Inferno","spender_verified":false},
		{"token":"0x` + repeat("55", 20) + `","symbol":"Z","spender":"0x` + repeat("66", 20) + `","amount":"0"}
	]}`)
	approvals, err := loadApprovals(data, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(approvals) != 3 {
		t.Fatalf("want 3 approvals, got %d", len(approvals))
	}
	r := auditApprovals(approvals, now, map[string]bool{})
	if r.TotalApprovals != 3 || r.ActiveApproval != 2 {
		t.Fatalf("active mismatch: %d/%d", r.ActiveApproval, r.TotalApprovals)
	}
	if r.RiskLevel != "critical" {
		t.Fatalf("want critical, got %s", r.RiskLevel)
	}
	if r.Clean {
		t.Fatal("should not be clean")
	}
	if r.Findings[0].Score < r.Findings[1].Score {
		t.Fatal("findings not sorted worst-first")
	}
}

func TestCleanWallet(t *testing.T) {
	data := []byte(`[{"token":"0x` + repeat("11", 20) + `","symbol":"OK","spender":"0x` + repeat("22", 20) + `","amount":"0"}]`)
	approvals, _ := loadApprovals(data, false)
	r := auditApprovals(approvals, now, map[string]bool{})
	if !r.Clean || r.RiskLevel != "clean" || r.RiskScore != 0 {
		t.Fatalf("clean wallet failed: %+v", r)
	}
}

func TestCSV(t *testing.T) {
	data := []byte("token,symbol,spender,amount,spender_verified\n0x" + repeat("33", 20) + ",FOO,0x" + repeat("44", 20) + ",max,false\n")
	approvals, err := loadApprovals(data, true)
	if err != nil || len(approvals) != 1 {
		t.Fatalf("csv parse: %v len=%d", err, len(approvals))
	}
	if approvals[0].Amount.Cmp(uint256Max) != 0 {
		t.Fatal("csv max not parsed")
	}
	if approvals[0].SpenderVerif {
		t.Fatal("csv verified=false not parsed")
	}
}
