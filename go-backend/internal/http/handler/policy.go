package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go-backend/internal/auth"
	"go-backend/internal/http/middleware"
	"go-backend/internal/http/response"
	"go-backend/internal/store/model"
	"go-backend/internal/ws"
)

type policyIDRequest struct {
	ID int64 `json:"id"`
}

type policyProviderRequest struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	ProviderType string `json:"providerType"`
	Behavior     string `json:"behavior"`
	URL          string `json:"url"`
	Path         string `json:"path"`
	IntervalSec  int    `json:"intervalSec"`
	Enabled      int    `json:"enabled"`
	RawYAML      string `json:"rawYaml"`
}

type policyRuleRequest struct {
	ID                    int64  `json:"id"`
	Name                  string `json:"name"`
	Priority              int    `json:"priority"`
	MatchDirection        string `json:"matchDirection"`
	MatchSourceMode       string `json:"matchSourceMode"`
	MatchSourceValue      string `json:"matchSourceValue"`
	MatchDestinationMode  string `json:"matchDestinationMode"`
	MatchDestinationValue string `json:"matchDestinationValue"`
	ProviderID            int64  `json:"providerId"`
	Action                string `json:"action"`
	ActionTarget          string `json:"actionTarget"`
	Enabled               int    `json:"enabled"`
}

type policyBindingRequest struct {
	ID            int64  `json:"id"`
	PolicyID      int64  `json:"policyId"`
	TargetType    string `json:"targetType"`
	TargetID      int64  `json:"targetId"`
	TargetRole    string `json:"targetRole"`
	NodeID        int64  `json:"nodeId"`
	InterfaceName string `json:"interfaceName"`
	ListenPort    int    `json:"listenPort"`
	Protocol      string `json:"protocol"`
	Enabled       int    `json:"enabled"`
}

type policyApplyRequest struct {
	BindingID int64 `json:"bindingId"`
}

type policyProviderParseReport struct {
	IPRuleCount      int                      `json:"ipRuleCount"`
	DomainRuleCount  int                      `json:"domainRuleCount"`
	UnsupportedCount int                      `json:"unsupportedCount"`
	Rules            []policyProviderRuleItem `json:"rules,omitempty"`
}

type policyProviderRuleItem struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	NoResolve bool   `json:"noResolve,omitempty"`
	Supported bool   `json:"supported"`
	Raw       string `json:"raw,omitempty"`
}

type policyPlan struct {
	PlanID          string                   `json:"planId"`
	Binding         model.PolicyBinding      `json:"binding"`
	Rule            model.PolicyRule         `json:"rule"`
	Provider        *model.PolicyProvider    `json:"provider,omitempty"`
	ProviderRules   []policyProviderRuleItem `json:"providerRules,omitempty"`
	Engine          string                   `json:"engine"`
	RequiresProxy   bool                     `json:"requiresProxy"`
	GeneratedAt     int64                    `json:"generatedAt"`
	ExecutionStatus string                   `json:"executionStatus"`
}

func (h *Handler) policyBundle(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	bundle, err := h.repo.GetPolicyBundle()
	if err != nil {
		response.WriteJSON(w, response.Err(-2, err.Error()))
		return
	}
	response.WriteJSON(w, response.OK(bundle))
}

func (h *Handler) policyProviderSave(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	var req policyProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, response.ErrDefault("请求参数错误"))
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		response.WriteJSON(w, response.ErrDefault("规则源名称不能为空"))
		return
	}
	if req.ID > 0 {
		boundCount, err := h.repo.CountPolicyBindingsByProvider(req.ID)
		if err != nil {
			response.WriteJSON(w, response.Err(-2, err.Error()))
			return
		}
		if boundCount > 0 {
			response.WriteJSON(w, response.ErrDefault("规则源已被已绑定策略使用，请先删除相关绑定"))
			return
		}
	}
	report := parsePolicyProviderRules(req.RawYAML)
	sum := sha256.Sum256([]byte(req.RawYAML))
	item := &model.PolicyProvider{
		ID:               req.ID,
		Name:             name,
		ProviderType:     policyDefaultString(req.ProviderType, "http"),
		Behavior:         policyDefaultString(req.Behavior, "classical"),
		URL:              strings.TrimSpace(req.URL),
		Path:             strings.TrimSpace(req.Path),
		IntervalSec:      req.IntervalSec,
		Enabled:          req.Enabled,
		RawYAML:          req.RawYAML,
		Checksum:         hex.EncodeToString(sum[:]),
		IPRuleCount:      report.IPRuleCount,
		DomainRuleCount:  report.DomainRuleCount,
		UnsupportedCount: report.UnsupportedCount,
		LastStatus:       "parsed",
	}
	if item.Enabled != 0 {
		item.Enabled = 1
	}
	if err := h.repo.SavePolicyProvider(item); err != nil {
		response.WriteJSON(w, response.Err(-2, err.Error()))
		return
	}
	response.WriteJSON(w, response.OK(item))
}

func (h *Handler) policyProviderDelete(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	var req policyIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID <= 0 {
		response.WriteJSON(w, response.ErrDefault("请求参数错误"))
		return
	}
	ruleCount, err := h.repo.CountPolicyRulesByProvider(req.ID)
	if err != nil {
		response.WriteJSON(w, response.Err(-2, err.Error()))
		return
	}
	if ruleCount > 0 {
		response.WriteJSON(w, response.ErrDefault("规则源仍被策略引用，请先删除或修改相关策略"))
		return
	}
	if err := h.repo.DeletePolicyProvider(req.ID); err != nil {
		response.WriteJSON(w, response.Err(-2, err.Error()))
		return
	}
	response.WriteJSON(w, response.OKEmpty())
}

func (h *Handler) policyRuleSave(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	var req policyRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, response.ErrDefault("请求参数错误"))
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		response.WriteJSON(w, response.ErrDefault("策略名称不能为空"))
		return
	}
	if !validPolicyAction(req.Action) {
		response.WriteJSON(w, response.ErrDefault("策略动作无效"))
		return
	}
	if req.ID > 0 {
		bindingCount, err := h.repo.CountPolicyBindingsByRule(req.ID)
		if err != nil {
			response.WriteJSON(w, response.Err(-2, err.Error()))
			return
		}
		if bindingCount > 0 {
			response.WriteJSON(w, response.ErrDefault("策略已有绑定，请先删除绑定后再编辑"))
			return
		}
	}
	item := &model.PolicyRule{
		ID:                    req.ID,
		Name:                  strings.TrimSpace(req.Name),
		Priority:              req.Priority,
		MatchDirection:        policyDefaultString(req.MatchDirection, "outbound"),
		MatchSourceMode:       policyDefaultString(req.MatchSourceMode, "any"),
		MatchSourceValue:      strings.TrimSpace(req.MatchSourceValue),
		MatchDestinationMode:  policyDefaultString(req.MatchDestinationMode, "any"),
		MatchDestinationValue: strings.TrimSpace(req.MatchDestinationValue),
		ProviderID:            req.ProviderID,
		Action:                policyDefaultString(req.Action, "reject"),
		ActionTarget:          strings.TrimSpace(req.ActionTarget),
		Enabled:               req.Enabled,
	}
	if item.Enabled != 0 {
		item.Enabled = 1
	}
	if err := h.repo.SavePolicyRule(item); err != nil {
		response.WriteJSON(w, response.Err(-2, err.Error()))
		return
	}
	response.WriteJSON(w, response.OK(item))
}

func (h *Handler) policyRuleDelete(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	var req policyIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID <= 0 {
		response.WriteJSON(w, response.ErrDefault("请求参数错误"))
		return
	}
	bindingCount, err := h.repo.CountPolicyBindingsByRule(req.ID)
	if err != nil {
		response.WriteJSON(w, response.Err(-2, err.Error()))
		return
	}
	if bindingCount > 0 {
		response.WriteJSON(w, response.ErrDefault("策略仍有关联绑定，请先删除绑定"))
		return
	}
	if err := h.repo.DeletePolicyRule(req.ID); err != nil {
		response.WriteJSON(w, response.Err(-2, err.Error()))
		return
	}
	response.WriteJSON(w, response.OKEmpty())
}

func (h *Handler) policyBindingSave(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	var req policyBindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, response.ErrDefault("请求参数错误"))
		return
	}
	if req.PolicyID <= 0 || strings.TrimSpace(req.TargetType) == "" {
		response.WriteJSON(w, response.ErrDefault("策略和绑定对象不能为空"))
		return
	}
	nodeID := req.NodeID
	if nodeID <= 0 && (req.TargetType == "entry_node" || req.TargetType == "exit_node") {
		nodeID = req.TargetID
	}
	if nodeID <= 0 {
		response.WriteJSON(w, response.ErrDefault("执行节点不能为空"))
		return
	}
	item := &model.PolicyBinding{
		ID:            req.ID,
		PolicyID:      req.PolicyID,
		TargetType:    strings.TrimSpace(req.TargetType),
		TargetID:      req.TargetID,
		TargetRole:    strings.TrimSpace(req.TargetRole),
		NodeID:        nodeID,
		InterfaceName: strings.TrimSpace(req.InterfaceName),
		ListenPort:    req.ListenPort,
		Protocol:      policyDefaultString(req.Protocol, "any"),
		Enabled:       req.Enabled,
	}
	if item.Enabled != 0 {
		item.Enabled = 1
	}
	if err := validatePolicyBinding(item); err != nil {
		response.WriteJSON(w, response.ErrDefault(err.Error()))
		return
	}
	if item.ID > 0 {
		existing, err := h.repo.GetPolicyBinding(item.ID)
		if err != nil {
			response.WriteJSON(w, response.Err(-2, err.Error()))
			return
		}
		if existing != nil && policyBindingRuntimeChanged(existing, item) {
			if err := h.removePolicyBindingRuntime(existing); err != nil {
				response.WriteJSON(w, response.ErrDefault("撤销旧策略失败，绑定未更新: "+err.Error()))
				return
			}
		}
	}
	if err := h.repo.SavePolicyBinding(item); err != nil {
		response.WriteJSON(w, response.Err(-2, err.Error()))
		return
	}
	response.WriteJSON(w, response.OK(item))
}

func (h *Handler) policyBindingDelete(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	var req policyIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID <= 0 {
		response.WriteJSON(w, response.ErrDefault("请求参数错误"))
		return
	}
	binding, err := h.repo.GetPolicyBinding(req.ID)
	if err != nil {
		response.WriteJSON(w, response.Err(-2, err.Error()))
		return
	}
	if binding == nil {
		response.WriteJSON(w, response.ErrDefault("策略绑定不存在"))
		return
	}
	if err := h.removePolicyBindingRuntime(binding); err != nil {
		response.WriteJSON(w, response.ErrDefault("撤销节点策略失败，绑定未删除: "+err.Error()))
		return
	}
	if err := h.repo.DeletePolicyBinding(req.ID); err != nil {
		response.WriteJSON(w, response.Err(-2, err.Error()))
		return
	}
	response.WriteJSON(w, response.OKEmpty())
}

func (h *Handler) removePolicyBindingRuntime(binding *model.PolicyBinding) error {
	if binding == nil || binding.ID <= 0 || binding.PolicyID <= 0 || binding.NodeID <= 0 {
		return errText("策略绑定运行信息不完整")
	}
	planID := strings.Join([]string{"policy", int64String(binding.PolicyID), "binding", int64String(binding.ID)}, "-")
	_, err := h.sendNodeCommandWithTimeout(binding.NodeID, "RemovePolicyPlan", map[string]interface{}{
		"planId": planID,
	}, time.Minute, false, false)
	return err
}

func policyBindingRuntimeChanged(before, after *model.PolicyBinding) bool {
	if before == nil || after == nil {
		return true
	}
	return before.PolicyID != after.PolicyID ||
		before.TargetType != after.TargetType ||
		before.TargetID != after.TargetID ||
		before.TargetRole != after.TargetRole ||
		before.NodeID != after.NodeID ||
		before.InterfaceName != after.InterfaceName ||
		before.ListenPort != after.ListenPort ||
		before.Protocol != after.Protocol ||
		before.Enabled != after.Enabled
}

func validatePolicyBinding(binding *model.PolicyBinding) error {
	if binding == nil {
		return errText("策略绑定不能为空")
	}
	targetType := strings.ToLower(strings.TrimSpace(binding.TargetType))
	protocol := strings.ToLower(strings.TrimSpace(binding.Protocol))
	if protocol == "" {
		protocol = "any"
	}
	if protocol != "any" && protocol != "tcp" && protocol != "udp" {
		return errText("策略协议仅支持 any、tcp 或 udp")
	}
	if binding.ListenPort < 0 || binding.ListenPort > 65535 {
		return errText("监听端口必须在 0 到 65535 之间")
	}
	switch targetType {
	case "entry_node", "exit_node":
		return nil
	case "tunnel_entry", "tunnel_exit":
		if binding.TargetID <= 0 {
			return errText("请选择隧道")
		}
	case "tunnel":
		if binding.TargetID <= 0 {
			return errText("请选择隧道")
		}
		role := strings.ToLower(strings.TrimSpace(binding.TargetRole))
		if role != "entry" && role != "ingress" && role != "exit" && role != "egress" {
			return errText("隧道策略必须选择入口侧或出口侧")
		}
	default:
		return errText("不支持的策略绑定对象")
	}
	if strings.TrimSpace(binding.InterfaceName) == "" && binding.ListenPort == 0 {
		return errText("隧道策略必须填写网络接口或监听端口，避免影响无关流量")
	}
	return nil
}

func (h *Handler) policyApply(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	var req policyApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BindingID <= 0 {
		response.WriteJSON(w, response.ErrDefault("请求参数错误"))
		return
	}
	plan, err := h.buildPolicyPlan(req.BindingID)
	if err != nil {
		response.WriteJSON(w, response.ErrDefault(err.Error()))
		return
	}
	rawPlan, _ := json.Marshal(plan)
	logItem := &model.PolicyDeploymentLog{
		BindingID: req.BindingID,
		PolicyID:  plan.Rule.ID,
		NodeID:    plan.Binding.NodeID,
		Engine:    plan.Engine,
		Action:    "apply",
		Status:    "pending",
		PlanJSON:  string(rawPlan),
	}
	if err := h.repo.CreatePolicyDeploymentLog(logItem); err != nil {
		response.WriteJSON(w, response.Err(-2, err.Error()))
		return
	}
	result, err := h.sendNodeCommandWithTimeout(plan.Binding.NodeID, "ApplyPolicyPlan", plan, 2*time.Minute, false, false)
	if err != nil {
		_ = h.repo.CreatePolicyDeploymentLog(&model.PolicyDeploymentLog{
			BindingID: req.BindingID,
			PolicyID:  plan.Rule.ID,
			NodeID:    plan.Binding.NodeID,
			Engine:    plan.Engine,
			Action:    "apply",
			Status:    "failed",
			Message:   err.Error(),
			PlanJSON:  string(rawPlan),
		})
		response.WriteJSON(w, response.Err(-2, err.Error()))
		return
	}
	_ = h.repo.CreatePolicyDeploymentLog(&model.PolicyDeploymentLog{
		BindingID: req.BindingID,
		PolicyID:  plan.Rule.ID,
		NodeID:    plan.Binding.NodeID,
		Engine:    plan.Engine,
		Action:    "apply",
		Status:    "success",
		Message:   summarizePolicyCommandResult(result),
		PlanJSON:  string(rawPlan),
	})
	response.WriteJSON(w, response.OK(map[string]interface{}{"plan": plan, "nodeResult": result}))
}

func (h *Handler) policyRemove(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	var req policyApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BindingID <= 0 {
		response.WriteJSON(w, response.ErrDefault("请求参数错误"))
		return
	}
	plan, err := h.buildPolicyPlan(req.BindingID)
	if err != nil {
		response.WriteJSON(w, response.ErrDefault(err.Error()))
		return
	}
	rawPlan, _ := json.Marshal(plan)
	result, err := h.sendNodeCommandWithTimeout(plan.Binding.NodeID, "RemovePolicyPlan", map[string]interface{}{
		"planId": plan.PlanID,
	}, time.Minute, false, false)
	if err != nil {
		_ = h.repo.CreatePolicyDeploymentLog(&model.PolicyDeploymentLog{
			BindingID: req.BindingID,
			PolicyID:  plan.Rule.ID,
			NodeID:    plan.Binding.NodeID,
			Engine:    plan.Engine,
			Action:    "remove",
			Status:    "failed",
			Message:   err.Error(),
			PlanJSON:  string(rawPlan),
		})
		response.WriteJSON(w, response.Err(-2, err.Error()))
		return
	}
	_ = h.repo.CreatePolicyDeploymentLog(&model.PolicyDeploymentLog{
		BindingID: req.BindingID,
		PolicyID:  plan.Rule.ID,
		NodeID:    plan.Binding.NodeID,
		Engine:    plan.Engine,
		Action:    "remove",
		Status:    "success",
		Message:   summarizePolicyCommandResult(result),
		PlanJSON:  string(rawPlan),
	})
	response.WriteJSON(w, response.OK(map[string]interface{}{"plan": plan, "nodeResult": result}))
}

func (h *Handler) policyStatus(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	var req policyApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BindingID <= 0 {
		response.WriteJSON(w, response.ErrDefault("请求参数错误"))
		return
	}
	binding, err := h.repo.GetPolicyBinding(req.BindingID)
	if err != nil {
		response.WriteJSON(w, response.Err(-2, err.Error()))
		return
	}
	if binding == nil {
		response.WriteJSON(w, response.ErrDefault("策略绑定不存在"))
		return
	}
	planID := strings.Join([]string{"policy", int64String(binding.PolicyID), "binding", int64String(binding.ID)}, "-")
	result, err := h.sendNodeCommandWithTimeout(binding.NodeID, "GetPolicyStatus", map[string]interface{}{
		"planId": planID,
	}, time.Minute, false, false)
	if err != nil {
		response.WriteJSON(w, response.Err(-2, err.Error()))
		return
	}
	response.WriteJSON(w, response.OK(map[string]interface{}{"nodeResult": result}))
}

func (h *Handler) buildPolicyPlan(bindingID int64) (*policyPlan, error) {
	binding, err := h.repo.GetPolicyBinding(bindingID)
	if err != nil {
		return nil, err
	}
	if binding == nil {
		return nil, errText("策略绑定不存在")
	}
	if binding.Enabled == 0 {
		return nil, errText("策略绑定已禁用")
	}
	if err := validatePolicyBinding(binding); err != nil {
		return nil, err
	}
	rule, err := h.repo.GetPolicyRule(binding.PolicyID)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return nil, errText("策略不存在")
	}
	if rule.Enabled == 0 {
		return nil, errText("策略已禁用")
	}
	var provider *model.PolicyProvider
	var providerRules []policyProviderRuleItem
	if rule.ProviderID > 0 {
		providers, err := h.repo.ListPolicyProviders()
		if err != nil {
			return nil, err
		}
		for i := range providers {
			if providers[i].ID == rule.ProviderID {
				if providers[i].Enabled == 0 {
					return nil, errText("规则源已禁用")
				}
				provider = &providers[i]
				providerRules = parsePolicyProviderRules(providers[i].RawYAML).Rules
				break
			}
		}
		if provider == nil {
			return nil, errText("规则源不存在")
		}
	}
	engine := "nftables"
	if provider != nil && provider.DomainRuleCount > 0 {
		engine = "mihomo-sidecar"
	}
	if strings.HasPrefix(strings.ToLower(rule.Action), "proxy_") {
		engine = "mihomo-sidecar"
	}
	return &policyPlan{
		PlanID:          strings.Join([]string{"policy", int64String(rule.ID), "binding", int64String(binding.ID)}, "-"),
		Binding:         *binding,
		Rule:            *rule,
		Provider:        provider,
		ProviderRules:   providerRules,
		Engine:          engine,
		RequiresProxy:   strings.HasPrefix(strings.ToLower(rule.Action), "proxy_"),
		GeneratedAt:     time.Now().UnixMilli(),
		ExecutionStatus: "planned",
	}, nil
}

func (h *Handler) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	claims, ok := r.Context().Value(middleware.ClaimsContextKey).(auth.Claims)
	if !ok {
		response.WriteJSON(w, response.Err(401, "无效的 token"))
		return false
	}
	if claims.RoleID != 0 {
		response.WriteJSON(w, response.Err(403, "仅管理员可操作策略防火墙"))
		return false
	}
	return true
}

func parsePolicyProviderRules(raw string) policyProviderParseReport {
	var report policyProviderParseReport
	for _, line := range strings.Split(raw, "\n") {
		item, ok := parsePolicyProviderRuleLine(line)
		if !ok {
			continue
		}
		switch {
		case isPolicyIPRule(item.Type) && item.Supported:
			report.IPRuleCount++
		case isPolicyDomainRule(item.Type) && item.Supported:
			report.DomainRuleCount++
		default:
			report.UnsupportedCount++
		}
		report.Rules = append(report.Rules, item)
	}
	return report
}

func parsePolicyProviderRuleLine(line string) (policyProviderRuleItem, bool) {
	text := strings.TrimSpace(line)
	if text == "" || strings.HasPrefix(text, "#") || strings.HasPrefix(text, "payload:") {
		return policyProviderRuleItem{}, false
	}
	text = strings.TrimSpace(strings.TrimPrefix(text, "-"))
	text = strings.Trim(text, "\"'")
	if text == "" || strings.HasPrefix(text, "#") {
		return policyProviderRuleItem{}, false
	}
	if idx := strings.Index(text, " #"); idx >= 0 {
		text = strings.TrimSpace(text[:idx])
	}
	parts := strings.Split(text, ",")
	if len(parts) == 0 {
		return policyProviderRuleItem{}, false
	}
	item := policyProviderRuleItem{
		Type: strings.ToUpper(strings.TrimSpace(parts[0])),
		Raw:  text,
	}
	if len(parts) > 1 {
		item.Value = strings.Trim(strings.TrimSpace(parts[1]), "\"'")
	}
	for _, part := range parts[2:] {
		if strings.EqualFold(strings.TrimSpace(part), "no-resolve") {
			item.NoResolve = true
			break
		}
	}
	item.Supported = item.Value != "" && (isPolicyIPRule(item.Type) || isPolicyDomainRule(item.Type))
	return item, true
}

func isPolicyIPRule(ruleType string) bool {
	switch strings.ToUpper(strings.TrimSpace(ruleType)) {
	case "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR":
		return true
	default:
		return false
	}
}

func isPolicyDomainRule(ruleType string) bool {
	switch strings.ToUpper(strings.TrimSpace(ruleType)) {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX":
		return true
	default:
		return false
	}
}

func validPolicyAction(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "", "allow", "drop", "reject", "direct", "bypass", "proxy_singbox", "proxy_mihomo", "proxy_custom":
		return true
	default:
		return false
	}
}

func policyDefaultString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func int64String(v int64) string {
	return strconv.FormatInt(v, 10)
}

func summarizePolicyCommandResult(result ws.CommandResult) string {
	parts := []string{}
	if status, ok := result.Data["status"].(string); ok && status != "" {
		parts = append(parts, "status="+status)
	}
	if method, ok := result.Data["firewallMethod"].(string); ok && method != "" {
		parts = append(parts, "method="+method)
	}
	if applied, ok := result.Data["nftApplied"].(bool); ok {
		parts = append(parts, "firewallApplied="+strconv.FormatBool(applied))
	}
	if msg, ok := result.Data["message"].(string); ok && msg != "" {
		parts = append(parts, msg)
	}
	if len(parts) == 0 {
		return result.Message
	}
	return strings.Join(parts, "; ")
}

type errText string

func (e errText) Error() string { return string(e) }
