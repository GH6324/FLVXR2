package socket

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	policyRestoreWorkers        = 4
	policyRuntimeCommandTimeout = 15 * time.Second
)

var policyPlanLocks sync.Map

type PolicyPlanRequest struct {
	PlanID        string                 `json:"planId"`
	Engine        string                 `json:"engine"`
	RequiresProxy bool                   `json:"requiresProxy"`
	GeneratedAt   int64                  `json:"generatedAt"`
	Binding       policyBindingPayload   `json:"binding"`
	Rule          policyRulePayload      `json:"rule"`
	Provider      *policyProviderPayload `json:"provider,omitempty"`
	ProviderRules []policyProviderRule   `json:"providerRules,omitempty"`
}

type policyBindingPayload struct {
	ID            int64  `json:"id"`
	TargetType    string `json:"targetType"`
	TargetID      int64  `json:"targetId"`
	TargetRole    string `json:"targetRole"`
	NodeID        int64  `json:"nodeId"`
	InterfaceName string `json:"interfaceName"`
	ListenPort    int    `json:"listenPort"`
	Protocol      string `json:"protocol"`
}

type policyRulePayload struct {
	ID                    int64  `json:"id"`
	Name                  string `json:"name"`
	Priority              int    `json:"priority"`
	MatchDirection        string `json:"matchDirection"`
	MatchSourceMode       string `json:"matchSourceMode"`
	MatchSourceValue      string `json:"matchSourceValue"`
	MatchDestinationMode  string `json:"matchDestinationMode"`
	MatchDestinationValue string `json:"matchDestinationValue"`
	Action                string `json:"action"`
	ActionTarget          string `json:"actionTarget"`
}

type policyProviderPayload struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	ProviderType string `json:"providerType"`
	Behavior     string `json:"behavior"`
	URL          string `json:"url"`
	Path         string `json:"path"`
	IntervalSec  int    `json:"intervalSec"`
	RawYAML      string `json:"rawYaml"`
}

type policyProviderRule struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	NoResolve bool   `json:"noResolve,omitempty"`
	Supported bool   `json:"supported"`
	Raw       string `json:"raw,omitempty"`
}

func (w *WebSocketReporter) handleApplyPolicyPlan(data interface{}) (map[string]interface{}, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("serialize policy plan: %w", err)
	}
	var req PolicyPlanRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("parse policy plan: %w", err)
	}
	if strings.TrimSpace(req.PlanID) == "" {
		return nil, fmt.Errorf("policy plan id is required")
	}
	lock := policyPlanMutex(req.PlanID)
	lock.Lock()
	defer lock.Unlock()
	return w.applyPolicyPlan(req)
}

func (w *WebSocketReporter) applyPolicyPlan(req PolicyPlanRequest) (map[string]interface{}, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("serialize policy plan: %w", err)
	}
	dir := policyPlanDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create policy dir: %w", err)
	}
	path := filepath.Join(dir, safePolicyPlanName(req.PlanID)+".json")
	statusPath := filepath.Join(dir, safePolicyPlanName(req.PlanID)+".status.json")
	if err := os.WriteFile(path, prettyJSON(raw), 0o600); err != nil {
		return nil, fmt.Errorf("write policy plan: %w", err)
	}
	nftResult := applyPolicyNftables(req)
	mihomoRequired := policyNeedsMihomoConfig(req)
	mihomoPath, mihomoErr := writePolicyMihomoConfig(req)
	if mihomoRequired && mihomoErr == nil {
		mihomoErr = fmt.Errorf("mihomo sidecar runtime is not configured; draft generated at %s", mihomoPath)
	}
	if mihomoErr != nil && nftResult.Applied {
		if removeErr := removePolicyNftables(req.PlanID); removeErr != nil {
			nftResult.Err = strings.TrimSpace(strings.Join([]string{nftResult.Err, "rollback nftables: " + removeErr.Error()}, "; "))
		}
		nftResult.Applied = false
	}
	statusValue := "applied"
	message := "policy plan applied"
	if nftResult.Skipped && mihomoPath == "" {
		statusValue = "stored"
		message = "policy plan stored; no executable nftables rule was generated"
	}
	if nftResult.Err != "" || mihomoErr != nil {
		statusValue = "failed"
		message = strings.TrimSpace(strings.Join([]string{nftResult.Err, errString(mihomoErr)}, "; "))
	}
	status := map[string]interface{}{
		"planId":           req.PlanID,
		"engine":           defaultPolicyEngine(req.Engine),
		"requiresProxy":    req.RequiresProxy,
		"planPath":         path,
		"status":           statusValue,
		"message":          message,
		"nftApplied":       nftResult.Applied,
		"nftSkipped":       nftResult.Skipped,
		"nftTable":         nftResult.Table,
		"nftRulePath":      nftResult.Path,
		"firewallMethod":   nftResult.Method,
		"mihomoConfigPath": mihomoPath,
		"mihomoApplied":    false,
		"runtime":          runtime.GOOS,
		"updatedAt":        time.Now().UnixMilli(),
	}
	statusRaw, _ := json.MarshalIndent(status, "", "  ")
	if err := os.WriteFile(statusPath, statusRaw, 0o600); err != nil {
		return nil, fmt.Errorf("write policy status: %w", err)
	}
	if statusValue == "failed" {
		return status, fmt.Errorf("%s", message)
	}
	return status, nil
}

func (w *WebSocketReporter) handleRemovePolicyPlan(data interface{}) (map[string]interface{}, error) {
	planID, err := extractPolicyPlanID(data)
	if err != nil {
		return nil, err
	}
	lock := policyPlanMutex(planID)
	lock.Lock()
	defer lock.Unlock()
	if err := removePolicyNftables(planID); err != nil {
		return nil, fmt.Errorf("remove policy runtime: %w", err)
	}
	if err := removePolicyArtifacts(planID); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"planId":    planID,
		"status":    "removed",
		"updatedAt": time.Now().UnixMilli(),
	}, nil
}

func (w *WebSocketReporter) handleGetPolicyStatus(data interface{}) (map[string]interface{}, error) {
	planID, err := extractPolicyPlanID(data)
	if err != nil {
		return nil, err
	}
	lock := policyPlanMutex(planID)
	lock.Lock()
	defer lock.Unlock()
	path := filepath.Join(policyPlanDir(), safePolicyPlanName(planID)+".status.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy status: %w", err)
	}
	var status map[string]interface{}
	if err := json.Unmarshal(raw, &status); err != nil {
		return nil, fmt.Errorf("parse policy status: %w", err)
	}
	refreshPolicyRuntimeStatus(planID, status)
	if updated, err := json.MarshalIndent(status, "", "  "); err == nil {
		_ = os.WriteFile(path, updated, 0o600)
	}
	return status, nil
}

func refreshPolicyRuntimeStatus(planID string, status map[string]interface{}) {
	status["runtimeStatusCheckedAt"] = time.Now().UnixMilli()
	applied, _ := status["nftApplied"].(bool)
	if !applied {
		return
	}
	method, _ := status["firewallMethod"].(string)
	var active bool
	switch method {
	case "nft":
		table, _ := status["nftTable"].(string)
		if table == "" {
			table = policyNftTableName(planID)
		}
		if nftPath, err := findPolicyCommand("nft", "/usr/sbin/nft", "/sbin/nft"); err == nil {
			_, err = policyRunCommandOutput(nftPath, "list", "table", "inet", table)
			active = err == nil
		}
	case "iptables":
		active = policyIPTablesRulesExist(planID)
	}
	if active {
		return
	}
	status["status"] = "drifted"
	status["nftApplied"] = false
	status["message"] = "policy runtime rule is missing; reapply is required"
}

func policyIPTablesRulesExist(planID string) bool {
	comment := safePolicyPlanName(planID)
	for _, bin := range []struct {
		name  string
		paths []string
	}{
		{name: "iptables", paths: []string{"/usr/sbin/iptables", "/sbin/iptables"}},
		{name: "ip6tables", paths: []string{"/usr/sbin/ip6tables", "/sbin/ip6tables"}},
	} {
		cmdPath, err := findPolicyCommand(bin.name, bin.paths...)
		if err != nil {
			continue
		}
		for _, chain := range []string{"INPUT", "FORWARD", "OUTPUT"} {
			out, err := policyRunCommandOutput(cmdPath, "-S", chain)
			text := string(out)
			if err == nil && (strings.Contains(text, "--comment "+comment) || strings.Contains(text, "--comment \""+comment+"\"")) {
				return true
			}
		}
	}
	return false
}

func (w *WebSocketReporter) restorePersistedPolicyPlans() {
	entries, err := os.ReadDir(policyPlanDir())
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Printf("restore policy plans: %v\n", err)
		}
		return
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".status.json") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	plans := make([]PolicyPlanRequest, 0, len(names))
	for _, name := range names {
		path := filepath.Join(policyPlanDir(), name)
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("restore policy plan %s: %v\n", name, err)
			continue
		}
		var plan PolicyPlanRequest
		if err := json.Unmarshal(raw, &plan); err != nil {
			fmt.Printf("restore policy plan %s: %v\n", name, err)
			continue
		}
		plans = append(plans, plan)
	}
	restorePolicyPlans(plans, func(plan PolicyPlanRequest) error {
		path := filepath.Join(policyPlanDir(), safePolicyPlanName(plan.PlanID)+".json")
		err := restorePolicyPlanFile(plan.PlanID, path, func(current PolicyPlanRequest) error {
			_, applyErr := w.applyPolicyPlan(current)
			return applyErr
		})
		if err != nil {
			fmt.Printf("restore policy plan %s failed: %v\n", plan.PlanID, err)
		}
		return err
	})
	w.cleanupOrphanedPolicyPlans()
}

func restorePolicyPlans(plans []PolicyPlanRequest, apply func(PolicyPlanRequest) error) {
	if len(plans) == 0 {
		return
	}
	workerCount := policyRestoreWorkers
	if len(plans) < workerCount {
		workerCount = len(plans)
	}
	jobs := make(chan PolicyPlanRequest)
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go func() {
			defer workers.Done()
			for plan := range jobs {
				_ = apply(plan)
			}
		}()
	}
	for _, plan := range plans {
		jobs <- plan
	}
	close(jobs)
	workers.Wait()
}

func policyPlanMutex(planID string) *sync.Mutex {
	key := safePolicyPlanName(planID)
	value, _ := policyPlanLocks.LoadOrStore(key, &sync.Mutex{})
	return value.(*sync.Mutex)
}

func restorePolicyPlanFile(planID, path string, apply func(PolicyPlanRequest) error) error {
	lock := policyPlanMutex(planID)
	lock.Lock()
	defer lock.Unlock()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read persisted policy plan: %w", err)
	}
	var plan PolicyPlanRequest
	if err := json.Unmarshal(raw, &plan); err != nil {
		return fmt.Errorf("parse persisted policy plan: %w", err)
	}
	if safePolicyPlanName(plan.PlanID) != safePolicyPlanName(planID) {
		return fmt.Errorf("persisted policy plan id mismatch: expected %s, got %s", planID, plan.PlanID)
	}
	return apply(plan)
}

func (w *WebSocketReporter) cleanupOrphanedPolicyPlans() {
	entries, err := os.ReadDir(policyPlanDir())
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".status.json") {
			continue
		}
		planID := strings.TrimSuffix(name, ".status.json")
		lock := policyPlanMutex(planID)
		lock.Lock()
		planPath := filepath.Join(policyPlanDir(), planID+".json")
		_, statErr := os.Stat(planPath)
		if statErr == nil {
			lock.Unlock()
			continue
		}
		if !os.IsNotExist(statErr) {
			lock.Unlock()
			fmt.Printf("inspect orphaned policy plan %s: %v\n", planID, statErr)
			continue
		}
		if err := removePolicyNftables(planID); err != nil {
			lock.Unlock()
			fmt.Printf("remove orphaned policy runtime %s: %v\n", planID, err)
			continue
		}
		if err := removePolicyArtifacts(planID); err != nil {
			fmt.Printf("remove orphaned policy artifacts %s: %v\n", planID, err)
		}
		lock.Unlock()
	}
}

func removePolicyArtifacts(planID string) error {
	base := filepath.Join(policyPlanDir(), safePolicyPlanName(planID))
	for _, path := range []string{
		base + ".json",
		base + ".status.json",
		filepath.Join(policyMihomoDir(), safePolicyPlanName(planID)+".yaml"),
	} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove policy file %s: %w", path, err)
		}
	}
	return nil
}

func extractPolicyPlanID(data interface{}) (string, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("serialize policy request: %w", err)
	}
	var req struct {
		PlanID string `json:"planId"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return "", fmt.Errorf("parse policy request: %w", err)
	}
	if strings.TrimSpace(req.PlanID) == "" {
		return "", fmt.Errorf("policy plan id is required")
	}
	return req.PlanID, nil
}

func policyPlanDir() string {
	return filepath.Join(coreConfigDir(), "policy")
}

func policyNftDir() string {
	return filepath.Join(policyPlanDir(), "nft")
}

func policyMihomoDir() string {
	return filepath.Join(policyPlanDir(), "mihomo")
}

type policyNftResult struct {
	Applied bool
	Skipped bool
	Method  string
	Table   string
	Path    string
	Err     string
}

type policyFirewallChain struct {
	Name string
	Hook string
}

type policyFirewallScope struct {
	Chains         []policyFirewallChain
	InterfaceName  string
	InterfaceMatch string
	Protocol       string
	ListenPort     int
}

func resolvePolicyFirewallScope(binding policyBindingPayload) (policyFirewallScope, error) {
	targetType := strings.ToLower(strings.TrimSpace(binding.TargetType))
	targetRole := strings.ToLower(strings.TrimSpace(binding.TargetRole))
	protocol := strings.ToLower(strings.TrimSpace(binding.Protocol))
	if protocol == "" {
		protocol = "any"
	}
	if protocol != "any" && protocol != "tcp" && protocol != "udp" {
		return policyFirewallScope{}, fmt.Errorf("unsupported policy protocol %q", binding.Protocol)
	}
	if binding.ListenPort < 0 || binding.ListenPort > 65535 {
		return policyFirewallScope{}, fmt.Errorf("invalid policy listen port %d", binding.ListenPort)
	}

	ingress := false
	requireSelector := false
	switch targetType {
	case "entry_node":
		ingress = true
	case "exit_node":
		ingress = false
	case "tunnel_entry":
		ingress = true
		requireSelector = true
	case "tunnel_exit":
		ingress = false
		requireSelector = true
	case "tunnel":
		requireSelector = true
		switch targetRole {
		case "entry", "ingress":
			ingress = true
		case "exit", "egress":
			ingress = false
		default:
			return policyFirewallScope{}, fmt.Errorf("tunnel policy requires targetRole entry or exit")
		}
	default:
		return policyFirewallScope{}, fmt.Errorf("unsupported policy target type %q", binding.TargetType)
	}

	interfaceName := strings.TrimSpace(binding.InterfaceName)
	if requireSelector && interfaceName == "" && binding.ListenPort == 0 {
		return policyFirewallScope{}, fmt.Errorf("%s policy requires interfaceName or listenPort to avoid affecting unrelated traffic", targetType)
	}

	scope := policyFirewallScope{
		InterfaceName: interfaceName,
		Protocol:      protocol,
		ListenPort:    binding.ListenPort,
	}
	if ingress {
		scope.InterfaceMatch = "iifname"
		scope.Chains = []policyFirewallChain{{Name: "flvx_policy_input", Hook: "input"}, {Name: "flvx_policy_forward", Hook: "forward"}}
	} else {
		scope.InterfaceMatch = "oifname"
		scope.Chains = []policyFirewallChain{{Name: "flvx_policy_output", Hook: "output"}, {Name: "flvx_policy_forward", Hook: "forward"}}
	}
	return scope, nil
}

func applyPolicyNftables(req PolicyPlanRequest) policyNftResult {
	result := policyNftResult{
		Table: policyNftTableName(req.PlanID),
		Path:  filepath.Join(policyNftDir(), safePolicyPlanName(req.PlanID)+".nft"),
	}
	if runtime.GOOS != "linux" {
		result.Skipped = true
		result.Err = "nftables policy is only supported on Linux"
		return result
	}
	scope, err := resolvePolicyFirewallScope(req.Binding)
	if err != nil {
		result.Skipped = true
		result.Err = err.Error()
		return result
	}
	v4Src, v4Dst, v6Src, v6Dst := collectPolicyNftCIDRs(req)
	if len(v4Src)+len(v4Dst)+len(v6Src)+len(v6Dst) == 0 {
		result.Skipped = true
		return result
	}
	nftPath, err := ensurePolicyNftCommand()
	if err != nil {
		iptablesResult := applyPolicyIPTables(req, scope, v4Src, v4Dst, v6Src, v6Dst)
		if iptablesResult.Applied || iptablesResult.Err == "" {
			return iptablesResult
		}
		result.Skipped = true
		result.Err = err.Error() + "; iptables fallback failed: " + iptablesResult.Err
		return result
	}
	if err := os.MkdirAll(policyNftDir(), 0o755); err != nil {
		result.Err = fmt.Sprintf("create nft policy dir: %v", err)
		return result
	}
	if err := removePolicyNftables(req.PlanID); err != nil {
		result.Err = fmt.Sprintf("remove previous policy runtime: %v", err)
		return result
	}
	script := buildPolicyNftScript(result.Table, req, scope, v4Src, v4Dst, v6Src, v6Dst)
	if err := os.WriteFile(result.Path, []byte(script), 0o600); err != nil {
		result.Err = fmt.Sprintf("write nft policy: %v", err)
		return result
	}
	if out, err := policyRunCommandOutput(nftPath, "-f", result.Path); err != nil {
		result.Err = fmt.Sprintf("apply nft policy: %v: %s", err, strings.TrimSpace(string(out)))
		return result
	}
	result.Applied = true
	result.Method = "nft"
	return result
}

func removePolicyNftables(planID string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	var failures []string
	if nftPath, err := findPolicyCommand("nft", "/usr/sbin/nft", "/sbin/nft"); err == nil {
		table := policyNftTableName(planID)
		if _, listErr := policyRunCommandOutput(nftPath, "list", "table", "inet", table); listErr == nil {
			if deleteErr := policyRunCommand(nftPath, "delete", "table", "inet", table); deleteErr != nil {
				failures = append(failures, deleteErr.Error())
			}
		}
	}
	if err := removePolicyIPTables(planID); err != nil {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	_ = os.Remove(filepath.Join(policyNftDir(), safePolicyPlanName(planID)+".nft"))
	return nil
}

func collectPolicyNftCIDRs(req PolicyPlanRequest) (v4Src, v4Dst, v6Src, v6Dst []string) {
	direction := strings.ToLower(strings.TrimSpace(req.Rule.MatchDirection))
	if direction == "" {
		direction = "outbound"
	}
	add := func(ruleType, value string) {
		value = strings.TrimSpace(value)
		if value == "" || strings.EqualFold(ruleType, "GEOIP") {
			return
		}
		ip, _, err := net.ParseCIDR(value)
		if err != nil || ip == nil {
			return
		}
		isV6 := ip.To4() == nil
		targetSource := strings.EqualFold(ruleType, "SRC-IP-CIDR") || direction == "inbound"
		switch {
		case isV6 && targetSource:
			v6Src = append(v6Src, value)
		case isV6:
			v6Dst = append(v6Dst, value)
		case targetSource:
			v4Src = append(v4Src, value)
		default:
			v4Dst = append(v4Dst, value)
		}
	}
	for _, item := range req.ProviderRules {
		if !item.Supported {
			continue
		}
		switch strings.ToUpper(strings.TrimSpace(item.Type)) {
		case "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR":
			add(item.Type, item.Value)
		}
	}
	addCIDRField := func(mode, value string, source bool) {
		if !strings.Contains(strings.ToLower(mode), "cidr") {
			return
		}
		for _, part := range splitPolicyValues(value) {
			ip, _, err := net.ParseCIDR(part)
			if err != nil || ip == nil {
				continue
			}
			isV6 := ip.To4() == nil
			switch {
			case isV6 && source:
				v6Src = append(v6Src, part)
			case isV6:
				v6Dst = append(v6Dst, part)
			case source:
				v4Src = append(v4Src, part)
			default:
				v4Dst = append(v4Dst, part)
			}
		}
	}
	addCIDRField(req.Rule.MatchSourceMode, req.Rule.MatchSourceValue, true)
	addCIDRField(req.Rule.MatchDestinationMode, req.Rule.MatchDestinationValue, false)
	return uniqueStrings(v4Src), uniqueStrings(v4Dst), uniqueStrings(v6Src), uniqueStrings(v6Dst)
}

func buildPolicyNftScript(table string, req PolicyPlanRequest, scope policyFirewallScope, v4Src, v4Dst, v6Src, v6Dst []string) string {
	verdict := policyNftVerdict(req.Rule.Action)
	comment := safePolicyPlanName(req.PlanID)
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", table)
	writeNftSet(&b, "flvx_policy_v4_src", "ipv4_addr", v4Src)
	writeNftSet(&b, "flvx_policy_v4_dst", "ipv4_addr", v4Dst)
	writeNftSet(&b, "flvx_policy_v6_src", "ipv6_addr", v6Src)
	writeNftSet(&b, "flvx_policy_v6_dst", "ipv6_addr", v6Dst)
	for _, chain := range scope.Chains {
		fmt.Fprintf(&b, "  chain %s {\n", chain.Name)
		fmt.Fprintf(&b, "    type filter hook %s priority filter; policy accept;\n", chain.Hook)
		for _, prefix := range policyNftScopePrefixes(scope) {
			writePolicyNftRule(&b, prefix, "ip saddr @flvx_policy_v4_src", len(v4Src) > 0, verdict, comment)
			writePolicyNftRule(&b, prefix, "ip daddr @flvx_policy_v4_dst", len(v4Dst) > 0, verdict, comment)
			writePolicyNftRule(&b, prefix, "ip6 saddr @flvx_policy_v6_src", len(v6Src) > 0, verdict, comment)
			writePolicyNftRule(&b, prefix, "ip6 daddr @flvx_policy_v6_dst", len(v6Dst) > 0, verdict, comment)
		}
		b.WriteString("  }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func policyNftScopePrefixes(scope policyFirewallScope) []string {
	base := ""
	if scope.InterfaceName != "" {
		base = fmt.Sprintf("meta %s \"%s\"", scope.InterfaceMatch, escapeNftString(scope.InterfaceName))
	}
	appendPart := func(value string) string {
		if base == "" {
			return value
		}
		return base + " " + value
	}
	if scope.ListenPort > 0 {
		if scope.Protocol == "any" {
			return []string{appendPart(fmt.Sprintf("tcp dport %d", scope.ListenPort)), appendPart(fmt.Sprintf("udp dport %d", scope.ListenPort))}
		}
		return []string{appendPart(fmt.Sprintf("%s dport %d", scope.Protocol, scope.ListenPort))}
	}
	if scope.Protocol != "any" {
		return []string{appendPart("meta l4proto " + scope.Protocol)}
	}
	return []string{base}
}

func writePolicyNftRule(b *strings.Builder, prefix, match string, enabled bool, verdict, comment string) {
	if !enabled {
		return
	}
	if prefix != "" {
		prefix += " "
	}
	fmt.Fprintf(b, "    %s%s counter %s comment \"%s\"\n", prefix, match, verdict, comment)
}

func escapeNftString(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	return strings.ReplaceAll(value, "\"", "\\\"")
}

func writeNftSet(b *strings.Builder, name, setType string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(b, "  set %s {\n", name)
	fmt.Fprintf(b, "    type %s\n", setType)
	b.WriteString("    flags interval\n")
	fmt.Fprintf(b, "    elements = { %s }\n", strings.Join(values, ", "))
	b.WriteString("  }\n")
}

func applyPolicyIPTables(req PolicyPlanRequest, scope policyFirewallScope, v4Src, v4Dst, v6Src, v6Dst []string) policyNftResult {
	result := policyNftResult{
		Method: "iptables",
		Table:  "iptables:" + safePolicyPlanName(req.PlanID),
		Path:   filepath.Join(policyNftDir(), safePolicyPlanName(req.PlanID)+".iptables.sh"),
	}
	if runtime.GOOS != "linux" {
		result.Skipped = true
		return result
	}
	iptables, err4 := findPolicyCommand("iptables", "/usr/sbin/iptables", "/sbin/iptables")
	ip6tables, err6 := findPolicyCommand("ip6tables", "/usr/sbin/ip6tables", "/sbin/ip6tables")
	if err4 != nil && err6 != nil {
		result.Skipped = true
		result.Err = "iptables/ip6tables executable not found"
		return result
	}
	if err := os.MkdirAll(policyNftDir(), 0o755); err != nil {
		result.Err = fmt.Sprintf("create iptables policy dir: %v", err)
		return result
	}
	comment := safePolicyPlanName(req.PlanID)
	verdict := strings.ToUpper(policyNftVerdict(req.Rule.Action))
	if verdict == "ACCEPT" {
		result.Skipped = true
		result.Err = "iptables fallback refuses allow rules because inserting ACCEPT at chain priority 1 can bypass the host firewall"
		return result
	}
	if err := removePolicyIPTables(req.PlanID); err != nil {
		result.Err = fmt.Sprintf("remove previous iptables policy: %v", err)
		return result
	}
	script := buildPolicyIPTablesScript(req, scope, comment, v4Src, v4Dst, v6Src, v6Dst)
	if err := os.WriteFile(result.Path, []byte(script), 0o600); err != nil {
		result.Err = fmt.Sprintf("write iptables policy: %v", err)
		return result
	}
	appliedRules := 0
	if err4 == nil {
		for _, args := range buildPolicyIPTablesArgs(scope, comment, verdict, v4Src, v4Dst) {
			if err := policyRunCommand(iptables, args...); err != nil {
				result.Err = policyIPTablesApplyError(req.PlanID, err)
				return result
			}
			appliedRules++
		}
	}
	if err6 == nil {
		for _, args := range buildPolicyIPTablesArgs(scope, comment, verdict, v6Src, v6Dst) {
			if err := policyRunCommand(ip6tables, args...); err != nil {
				result.Err = policyIPTablesApplyError(req.PlanID, err)
				return result
			}
			appliedRules++
		}
	}
	if appliedRules == 0 {
		result.Skipped = true
		result.Err = "no iptables rule was applied"
		return result
	}
	result.Applied = true
	return result
}

func removePolicyIPTables(planID string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	comment := safePolicyPlanName(planID)
	var failures []string
	for _, bin := range []struct {
		name  string
		paths []string
	}{
		{name: "iptables", paths: []string{"/usr/sbin/iptables", "/sbin/iptables"}},
		{name: "ip6tables", paths: []string{"/usr/sbin/ip6tables", "/sbin/ip6tables"}},
	} {
		cmdPath, err := findPolicyCommand(bin.name, bin.paths...)
		if err != nil {
			continue
		}
		for _, chain := range []string{"INPUT", "FORWARD", "OUTPUT"} {
			out, err := policyRunCommandOutput(cmdPath, "-S", chain)
			if err != nil {
				failures = append(failures, err.Error())
				continue
			}
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if !strings.Contains(line, "--comment \""+comment+"\"") && !strings.Contains(line, "--comment "+comment) {
					continue
				}
				args := strings.Fields(line)
				if len(args) == 0 || args[0] != "-A" {
					continue
				}
				args[0] = "-D"
				if err := policyRunCommand(cmdPath, args...); err != nil {
					failures = append(failures, err.Error())
				}
			}
		}
	}
	if policyIPTablesRulesExist(planID) {
		failures = append(failures, "iptables policy rules are still active")
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	_ = os.Remove(filepath.Join(policyNftDir(), safePolicyPlanName(planID)+".iptables.sh"))
	return nil
}

func policyIPTablesApplyError(planID string, applyErr error) string {
	message := applyErr.Error()
	if rollbackErr := removePolicyIPTables(planID); rollbackErr != nil {
		message += "; rollback iptables: " + rollbackErr.Error()
	}
	return message
}

func buildPolicyIPTablesArgs(scope policyFirewallScope, comment, verdict string, srcCIDRs, dstCIDRs []string) [][]string {
	var all [][]string
	for _, chain := range scope.Chains {
		for _, base := range policyIPTablesScopeArgs(scope, strings.ToUpper(chain.Hook)) {
			for _, cidr := range srcCIDRs {
				args := append(append([]string{}, base...), "-s", cidr, "-m", "comment", "--comment", comment, "-j", verdict)
				all = append(all, args)
			}
			for _, cidr := range dstCIDRs {
				args := append(append([]string{}, base...), "-d", cidr, "-m", "comment", "--comment", comment, "-j", verdict)
				all = append(all, args)
			}
		}
	}
	return all
}

func policyIPTablesScopeArgs(scope policyFirewallScope, chain string) [][]string {
	base := []string{"-I", chain, "1"}
	if scope.InterfaceName != "" {
		flag := "-i"
		if scope.InterfaceMatch == "oifname" {
			flag = "-o"
		}
		base = append(base, flag, scope.InterfaceName)
	}
	withProtocol := func(protocol string) []string {
		args := append([]string{}, base...)
		args = append(args, "-p", protocol)
		if scope.ListenPort > 0 {
			args = append(args, "--dport", fmt.Sprintf("%d", scope.ListenPort))
		}
		return args
	}
	if scope.ListenPort > 0 && scope.Protocol == "any" {
		return [][]string{withProtocol("tcp"), withProtocol("udp")}
	}
	if scope.Protocol != "any" {
		return [][]string{withProtocol(scope.Protocol)}
	}
	return [][]string{base}
}

func buildPolicyIPTablesScript(req PolicyPlanRequest, scope policyFirewallScope, comment string, v4Src, v4Dst, v6Src, v6Dst []string) string {
	verdict := strings.ToUpper(policyNftVerdict(req.Rule.Action))
	var b strings.Builder
	b.WriteString("# Generated by FLVX policy firewall. Applied through iptables/ip6tables fallback.\n")
	for _, args := range buildPolicyIPTablesArgs(scope, comment, verdict, v4Src, v4Dst) {
		fmt.Fprintf(&b, "iptables %s\n", strings.Join(shellQuoteArgs(args), " "))
	}
	for _, args := range buildPolicyIPTablesArgs(scope, comment, verdict, v6Src, v6Dst) {
		fmt.Fprintf(&b, "ip6tables %s\n", strings.Join(shellQuoteArgs(args), " "))
	}
	return b.String()
}

func shellQuoteArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		out = append(out, "'"+strings.ReplaceAll(arg, "'", "'\"'\"'")+"'")
	}
	return out
}

func writePolicyMihomoConfig(req PolicyPlanRequest) (string, error) {
	if !policyNeedsMihomoConfig(req) {
		return "", nil
	}
	if err := os.MkdirAll(policyMihomoDir(), 0o755); err != nil {
		return "", fmt.Errorf("create mihomo policy dir: %w", err)
	}
	path := filepath.Join(policyMihomoDir(), safePolicyPlanName(req.PlanID)+".yaml")
	content := buildPolicyMihomoConfig(req)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("write mihomo policy config: %w", err)
	}
	return path, nil
}

func policyNeedsMihomoConfig(req PolicyPlanRequest) bool {
	if req.RequiresProxy || strings.Contains(strings.ToLower(req.Engine), "mihomo") {
		return true
	}
	for _, item := range req.ProviderRules {
		if item.Supported && policyIsDomainRule(item.Type) {
			return true
		}
	}
	return false
}

func buildPolicyMihomoConfig(req PolicyPlanRequest) string {
	providerName := "flvx_policy_provider"
	if req.Provider != nil && req.Provider.Name != "" {
		providerName = sanitizeMihomoName(req.Provider.Name)
	}
	action := policyMihomoAction(req.Rule.Action, req.Rule.ActionTarget)
	var b strings.Builder
	b.WriteString("# Generated by FLVX policy firewall. This file is a sidecar policy draft.\n")
	b.WriteString("mixed-port: 0\n")
	b.WriteString("mode: rule\n")
	b.WriteString("log-level: warning\n")
	if req.Provider != nil && strings.TrimSpace(req.Provider.URL) != "" {
		b.WriteString("rule-providers:\n")
		fmt.Fprintf(&b, "  %s:\n", providerName)
		fmt.Fprintf(&b, "    type: %s\n", defaultIfEmpty(req.Provider.ProviderType, "http"))
		fmt.Fprintf(&b, "    behavior: %s\n", defaultIfEmpty(req.Provider.Behavior, "classical"))
		fmt.Fprintf(&b, "    url: \"%s\"\n", escapeYAML(req.Provider.URL))
		fmt.Fprintf(&b, "    path: \"%s\"\n", escapeYAML(defaultIfEmpty(req.Provider.Path, "./ruleset/"+providerName+".yaml")))
		interval := req.Provider.IntervalSec
		if interval <= 0 {
			interval = 86400
		}
		fmt.Fprintf(&b, "    interval: %d\n", interval)
	}
	b.WriteString("rules:\n")
	if req.Provider != nil && strings.TrimSpace(req.Provider.URL) != "" {
		fmt.Fprintf(&b, "  - RULE-SET,%s,%s\n", providerName, action)
	}
	for _, item := range req.ProviderRules {
		if !item.Supported || !policyIsDomainRule(item.Type) {
			continue
		}
		fmt.Fprintf(&b, "  - %s,%s,%s\n", strings.ToUpper(item.Type), item.Value, action)
	}
	b.WriteString("  - MATCH,DIRECT\n")
	return b.String()
}

func policyNftVerdict(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "allow", "direct", "bypass":
		return "accept"
	case "reject":
		return "reject"
	default:
		return "drop"
	}
}

func policyMihomoAction(action, target string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "allow", "direct", "bypass":
		return "DIRECT"
	case "proxy_singbox", "proxy_mihomo", "proxy_custom":
		target = strings.TrimSpace(target)
		if target == "" {
			return "PROXY"
		}
		return sanitizeMihomoName(target)
	default:
		return "REJECT"
	}
}

func policyIsDomainRule(ruleType string) bool {
	switch strings.ToUpper(strings.TrimSpace(ruleType)) {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX":
		return true
	default:
		return false
	}
}

func policyNftTableName(planID string) string {
	name := "flvx_policy_" + safePolicyPlanName(planID)
	name = strings.ReplaceAll(name, "-", "_")
	if len(name) > 60 {
		name = name[:60]
	}
	return name
}

func splitPolicyValues(value string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';' || r == ' '
	}) {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var out []string
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func sanitizeMihomoName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "flvx_policy"
	}
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func escapeYAML(value string) string {
	return strings.ReplaceAll(value, "\"", "\\\"")
}

func defaultIfEmpty(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func findPolicyCommand(name string, extraPaths ...string) (string, error) {
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	for _, path := range extraPaths {
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path, nil
		}
	}
	return "", fmt.Errorf("%s executable not found", name)
}

func ensurePolicyNftCommand() (string, error) {
	return findPolicyCommand("nft", "/usr/sbin/nft", "/sbin/nft")
}

func policyRunCommand(name string, args ...string) error {
	return policyRunCommandWithTimeout(policyRuntimeCommandTimeout, name, args...)
}

func policyRunCommandWithTimeout(timeout time.Duration, name string, args ...string) error {
	_, err := policyRunCommandOutputWithTimeout(timeout, name, args...)
	return err
}

func policyRunCommandOutput(name string, args ...string) ([]byte, error) {
	return policyRunCommandOutputWithTimeout(policyRuntimeCommandTimeout, name, args...)
}

func policyRunCommandOutputWithTimeout(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	command := strings.TrimSpace(strings.Join(append([]string{name}, args...), " "))
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("%s timed out after %s: %s", command, timeout, strings.TrimSpace(string(out)))
	}
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", command, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func safePolicyPlanName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "policy-plan"
	}
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	return b.String()
}

func defaultPolicyEngine(engine string) string {
	engine = strings.TrimSpace(engine)
	if engine == "" {
		return "nftables"
	}
	return engine
}

func prettyJSON(raw []byte) []byte {
	var v interface{}
	if json.Unmarshal(raw, &v) != nil {
		return raw
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return raw
	}
	return out
}
