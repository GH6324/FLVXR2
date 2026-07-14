package socket

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolvePolicyFirewallScope(t *testing.T) {
	entry, err := resolvePolicyFirewallScope(policyBindingPayload{TargetType: "entry_node", Protocol: "any"})
	if err != nil {
		t.Fatalf("resolve entry scope: %v", err)
	}
	if got := policyScopeHooks(entry); got != "input,forward" {
		t.Fatalf("unexpected entry hooks: %s", got)
	}
	if entry.InterfaceMatch != "iifname" {
		t.Fatalf("expected ingress interface match, got %s", entry.InterfaceMatch)
	}

	exit, err := resolvePolicyFirewallScope(policyBindingPayload{TargetType: "exit_node", Protocol: "tcp"})
	if err != nil {
		t.Fatalf("resolve exit scope: %v", err)
	}
	if got := policyScopeHooks(exit); got != "output,forward" {
		t.Fatalf("unexpected exit hooks: %s", got)
	}
	if exit.InterfaceMatch != "oifname" {
		t.Fatalf("expected egress interface match, got %s", exit.InterfaceMatch)
	}

	if _, err := resolvePolicyFirewallScope(policyBindingPayload{TargetType: "tunnel_exit"}); err == nil {
		t.Fatal("tunnel scope without interface or port must be rejected")
	}
	if _, err := resolvePolicyFirewallScope(policyBindingPayload{TargetType: "tunnel", TargetRole: "", InterfaceName: "wg0"}); err == nil {
		t.Fatal("generic tunnel scope without target role must be rejected")
	}
}

func TestBuildPolicyFirewallRulesStayInsideBindingScope(t *testing.T) {
	scope, err := resolvePolicyFirewallScope(policyBindingPayload{
		TargetType:    "tunnel_exit",
		InterfaceName: "wg0",
		ListenPort:    443,
		Protocol:      "tcp",
	})
	if err != nil {
		t.Fatalf("resolve scope: %v", err)
	}
	req := PolicyPlanRequest{
		PlanID: "policy-1-binding-1",
		Rule:   policyRulePayload{Action: "reject"},
	}
	script := buildPolicyNftScript("flvx_policy_test", req, scope, nil, []string{"1.0.1.0/24"}, nil, nil)
	for _, required := range []string{
		"hook output",
		"hook forward",
		`meta oifname "wg0" tcp dport 443 ip daddr @flvx_policy_v4_dst`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("nft script missing %q:\n%s", required, script)
		}
	}
	if strings.Contains(script, "hook input") {
		t.Fatalf("exit scope must not install input hook:\n%s", script)
	}

	args := buildPolicyIPTablesArgs(scope, "policy-test", "DROP", nil, []string{"1.0.1.0/24"})
	if len(args) != 2 {
		t.Fatalf("expected output and forward rules, got %d", len(args))
	}
	for _, rule := range args {
		joined := strings.Join(rule, " ")
		if strings.Contains(joined, " INPUT ") {
			t.Fatalf("exit scope generated INPUT rule: %s", joined)
		}
		for _, required := range []string{"-o wg0", "-p tcp", "--dport 443", "-d 1.0.1.0/24"} {
			if !strings.Contains(joined, required) {
				t.Fatalf("iptables rule missing %q: %s", required, joined)
			}
		}
	}
}

func TestRefreshPolicyRuntimeStatusMarksMissingRuleAsDrifted(t *testing.T) {
	status := map[string]interface{}{
		"status":         "applied",
		"nftApplied":     true,
		"firewallMethod": "nft",
		"nftTable":       "flvx_policy_table_that_must_not_exist",
	}
	refreshPolicyRuntimeStatus("missing-policy", status)
	if status["status"] != "drifted" {
		t.Fatalf("expected drifted status, got %#v", status["status"])
	}
	if applied, _ := status["nftApplied"].(bool); applied {
		t.Fatal("missing runtime rule must clear nftApplied")
	}
}

func TestRestorePolicyPlansDoesNotHeadOfLineBlock(t *testing.T) {
	plans := []PolicyPlanRequest{
		{PlanID: "slow-policy"},
		{PlanID: "fast-policy"},
	}
	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	fastApplied := make(chan struct{})
	done := make(chan struct{})

	go func() {
		restorePolicyPlans(plans, func(plan PolicyPlanRequest) error {
			switch plan.PlanID {
			case "slow-policy":
				close(slowStarted)
				<-releaseSlow
			case "fast-policy":
				close(fastApplied)
			}
			return nil
		})
		close(done)
	}()

	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		t.Fatal("slow restore did not start")
	}
	select {
	case <-fastApplied:
	case <-time.After(time.Second):
		t.Fatal("fast restore was blocked behind a slow persisted plan")
	}
	close(releaseSlow)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("policy restore workers did not finish")
	}
}

func TestRestorePolicyPlanFileSkipsPlanRemovedWhileWaiting(t *testing.T) {
	plan := PolicyPlanRequest{PlanID: "removed-during-restore"}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("marshal plan: %v", err)
	}
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write plan: %v", err)
	}

	lock := policyPlanMutex(plan.PlanID)
	lock.Lock()
	applied := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- restorePolicyPlanFile(plan.PlanID, path, func(PolicyPlanRequest) error {
			applied <- struct{}{}
			return nil
		})
	}()
	if err := os.Remove(path); err != nil {
		lock.Unlock()
		t.Fatalf("remove plan: %v", err)
	}
	lock.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("restore removed plan: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("restore did not finish")
	}
	select {
	case <-applied:
		t.Fatal("plan removed before restore lock was acquired must not be applied")
	default:
	}
}

func policyScopeHooks(scope policyFirewallScope) string {
	hooks := make([]string, 0, len(scope.Chains))
	for _, chain := range scope.Chains {
		hooks = append(hooks, chain.Hook)
	}
	return strings.Join(hooks, ",")
}
