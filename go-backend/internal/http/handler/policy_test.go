package handler

import (
	"path/filepath"
	"strings"
	"testing"

	"go-backend/internal/store/model"
	"go-backend/internal/store/repo"
)

func TestBuildPolicyPlanRejectsDisabledObjects(t *testing.T) {
	r, err := repo.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	defer r.Close()

	provider := &model.PolicyProvider{Name: "provider", Enabled: 1, RawYAML: "payload:\n  - IP-CIDR,1.0.1.0/24"}
	if err := r.SavePolicyProvider(provider); err != nil {
		t.Fatalf("save provider: %v", err)
	}
	rule := &model.PolicyRule{Name: "rule", ProviderID: provider.ID, Action: "reject", Enabled: 1}
	if err := r.SavePolicyRule(rule); err != nil {
		t.Fatalf("save rule: %v", err)
	}
	binding := &model.PolicyBinding{PolicyID: rule.ID, TargetType: "exit_node", TargetID: 2, NodeID: 2, Protocol: "any", Enabled: 1}
	if err := r.SavePolicyBinding(binding); err != nil {
		t.Fatalf("save binding: %v", err)
	}
	binding.Enabled = 0
	if err := r.SavePolicyBinding(binding); err != nil {
		t.Fatalf("disable binding: %v", err)
	}

	h := New(r, "test-jwt-secret", "3.0.27")
	assertPolicyPlanError(t, h, binding.ID, "策略绑定已禁用")

	binding.Enabled = 1
	if err := r.SavePolicyBinding(binding); err != nil {
		t.Fatalf("enable binding: %v", err)
	}
	rule.Enabled = 0
	if err := r.SavePolicyRule(rule); err != nil {
		t.Fatalf("disable rule: %v", err)
	}
	assertPolicyPlanError(t, h, binding.ID, "策略已禁用")

	rule.Enabled = 1
	if err := r.SavePolicyRule(rule); err != nil {
		t.Fatalf("enable rule: %v", err)
	}
	provider.Enabled = 0
	if err := r.SavePolicyProvider(provider); err != nil {
		t.Fatalf("disable provider: %v", err)
	}
	assertPolicyPlanError(t, h, binding.ID, "规则源已禁用")
}

func TestPolicyBindingRuntimeChanged(t *testing.T) {
	base := &model.PolicyBinding{ID: 1, PolicyID: 2, TargetType: "exit_node", TargetID: 3, TargetRole: "exit", NodeID: 3, Protocol: "tcp", Enabled: 1}
	copy := *base
	if policyBindingRuntimeChanged(base, &copy) {
		t.Fatal("identical binding must not require runtime removal")
	}
	copy.ListenPort = 443
	if !policyBindingRuntimeChanged(base, &copy) {
		t.Fatal("listen port change must require runtime removal")
	}
}

func TestValidatePolicyBindingRequiresTunnelSelector(t *testing.T) {
	if err := validatePolicyBinding(&model.PolicyBinding{TargetType: "exit_node", Protocol: "any"}); err != nil {
		t.Fatalf("node binding should be valid: %v", err)
	}
	if err := validatePolicyBinding(&model.PolicyBinding{TargetType: "tunnel_exit", TargetID: 9, Protocol: "tcp"}); err == nil {
		t.Fatal("tunnel binding without interface or port must be rejected")
	}
	if err := validatePolicyBinding(&model.PolicyBinding{TargetType: "tunnel_exit", TargetID: 9, InterfaceName: "wg0", Protocol: "tcp"}); err != nil {
		t.Fatalf("scoped tunnel binding should be valid: %v", err)
	}
}

func assertPolicyPlanError(t *testing.T, h *Handler, bindingID int64, message string) {
	t.Helper()
	_, err := h.buildPolicyPlan(bindingID)
	if err == nil || !strings.Contains(err.Error(), message) {
		t.Fatalf("expected error containing %q, got %v", message, err)
	}
}
