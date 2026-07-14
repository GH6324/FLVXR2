package repo

import (
	"errors"
	"time"

	"go-backend/internal/store/model"
	"gorm.io/gorm"
)

type PolicyBundle struct {
	Providers []model.PolicyProvider      `json:"providers"`
	Rules     []model.PolicyRule          `json:"rules"`
	Bindings  []model.PolicyBinding       `json:"bindings"`
	Logs      []model.PolicyDeploymentLog `json:"logs"`
}

func (r *Repository) ListPolicyProviders() ([]model.PolicyProvider, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("repository not initialized")
	}
	var items []model.PolicyProvider
	err := r.db.Order("id DESC").Find(&items).Error
	return items, err
}

func (r *Repository) SavePolicyProvider(item *model.PolicyProvider) error {
	if r == nil || r.db == nil {
		return errors.New("repository not initialized")
	}
	if item == nil {
		return errors.New("provider is nil")
	}
	now := time.Now().UnixMilli()
	item.UpdatedTime = now
	if item.CreatedTime == 0 {
		item.CreatedTime = now
	}
	if item.ProviderType == "" {
		item.ProviderType = "http"
	}
	if item.Behavior == "" {
		item.Behavior = "classical"
	}
	if item.IntervalSec <= 0 {
		item.IntervalSec = 86400
	}
	if item.LastStatus == "" {
		item.LastStatus = "parsed"
	}
	if item.ID == 0 {
		return r.db.Create(item).Error
	}
	return r.db.Save(item).Error
}

func (r *Repository) DeletePolicyProvider(id int64) error {
	if r == nil || r.db == nil {
		return errors.New("repository not initialized")
	}
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.PolicyRule{}).Where("provider_id = ?", id).Update("provider_id", int64(0)).Error; err != nil {
			return err
		}
		return tx.Delete(&model.PolicyProvider{}, "id = ?", id).Error
	})
}

func (r *Repository) CountPolicyRulesByProvider(providerID int64) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("repository not initialized")
	}
	var count int64
	err := r.db.Model(&model.PolicyRule{}).Where("provider_id = ?", providerID).Count(&count).Error
	return count, err
}

func (r *Repository) CountPolicyBindingsByProvider(providerID int64) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("repository not initialized")
	}
	var count int64
	err := r.db.Model(&model.PolicyBinding{}).
		Joins("JOIN policy_rule ON policy_rule.id = policy_binding.policy_id").
		Where("policy_rule.provider_id = ?", providerID).
		Count(&count).Error
	return count, err
}

func (r *Repository) ListPolicyRules() ([]model.PolicyRule, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("repository not initialized")
	}
	var items []model.PolicyRule
	err := r.db.Order("priority ASC, id DESC").Find(&items).Error
	return items, err
}

func (r *Repository) GetPolicyRule(id int64) (*model.PolicyRule, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("repository not initialized")
	}
	var item model.PolicyRule
	err := r.db.Where("id = ?", id).First(&item).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *Repository) SavePolicyRule(item *model.PolicyRule) error {
	if r == nil || r.db == nil {
		return errors.New("repository not initialized")
	}
	if item == nil {
		return errors.New("policy rule is nil")
	}
	now := time.Now().UnixMilli()
	item.UpdatedTime = now
	if item.CreatedTime == 0 {
		item.CreatedTime = now
	}
	if item.Priority <= 0 {
		item.Priority = 100
	}
	if item.MatchDirection == "" {
		item.MatchDirection = "outbound"
	}
	if item.MatchSourceMode == "" {
		item.MatchSourceMode = "any"
	}
	if item.MatchDestinationMode == "" {
		item.MatchDestinationMode = "any"
	}
	if item.Action == "" {
		item.Action = "reject"
	}
	if item.ID == 0 {
		return r.db.Create(item).Error
	}
	return r.db.Save(item).Error
}

func (r *Repository) DeletePolicyRule(id int64) error {
	if r == nil || r.db == nil {
		return errors.New("repository not initialized")
	}
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&model.PolicyBinding{}, "policy_id = ?", id).Error; err != nil {
			return err
		}
		return tx.Delete(&model.PolicyRule{}, "id = ?", id).Error
	})
}

func (r *Repository) CountPolicyBindingsByRule(policyID int64) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("repository not initialized")
	}
	var count int64
	err := r.db.Model(&model.PolicyBinding{}).Where("policy_id = ?", policyID).Count(&count).Error
	return count, err
}

func (r *Repository) ListPolicyBindings() ([]model.PolicyBinding, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("repository not initialized")
	}
	var items []model.PolicyBinding
	err := r.db.Order("id DESC").Find(&items).Error
	return items, err
}

func (r *Repository) GetPolicyBinding(id int64) (*model.PolicyBinding, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("repository not initialized")
	}
	var item model.PolicyBinding
	err := r.db.Where("id = ?", id).First(&item).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *Repository) SavePolicyBinding(item *model.PolicyBinding) error {
	if r == nil || r.db == nil {
		return errors.New("repository not initialized")
	}
	if item == nil {
		return errors.New("policy binding is nil")
	}
	now := time.Now().UnixMilli()
	item.UpdatedTime = now
	if item.CreatedTime == 0 {
		item.CreatedTime = now
	}
	if item.Protocol == "" {
		item.Protocol = "any"
	}
	if item.ID == 0 {
		return r.db.Create(item).Error
	}
	return r.db.Save(item).Error
}

func (r *Repository) DeletePolicyBinding(id int64) error {
	if r == nil || r.db == nil {
		return errors.New("repository not initialized")
	}
	return r.db.Delete(&model.PolicyBinding{}, "id = ?", id).Error
}

func (r *Repository) CreatePolicyDeploymentLog(item *model.PolicyDeploymentLog) error {
	if r == nil || r.db == nil {
		return errors.New("repository not initialized")
	}
	if item == nil {
		return errors.New("deployment log is nil")
	}
	if item.CreatedTime == 0 {
		item.CreatedTime = time.Now().UnixMilli()
	}
	if item.Engine == "" {
		item.Engine = "nftables"
	}
	if item.Action == "" {
		item.Action = "apply"
	}
	if item.Status == "" {
		item.Status = "pending"
	}
	return r.db.Create(item).Error
}

func (r *Repository) ListPolicyDeploymentLogs(limit int) ([]model.PolicyDeploymentLog, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("repository not initialized")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var items []model.PolicyDeploymentLog
	err := r.db.Order("id DESC").Limit(limit).Find(&items).Error
	return items, err
}

func (r *Repository) GetPolicyBundle() (*PolicyBundle, error) {
	providers, err := r.ListPolicyProviders()
	if err != nil {
		return nil, err
	}
	rules, err := r.ListPolicyRules()
	if err != nil {
		return nil, err
	}
	bindings, err := r.ListPolicyBindings()
	if err != nil {
		return nil, err
	}
	logs, err := r.ListPolicyDeploymentLogs(50)
	if err != nil {
		return nil, err
	}
	return &PolicyBundle{Providers: providers, Rules: rules, Bindings: bindings, Logs: logs}, nil
}
