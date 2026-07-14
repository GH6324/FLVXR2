package model

type PolicyProvider struct {
	ID               int64  `gorm:"primaryKey;autoIncrement" json:"id"`
	Name             string `gorm:"column:name;type:varchar(160);not null" json:"name"`
	ProviderType     string `gorm:"column:provider_type;type:varchar(20);not null;default:'http'" json:"providerType"`
	Behavior         string `gorm:"column:behavior;type:varchar(20);not null;default:'classical'" json:"behavior"`
	URL              string `gorm:"column:url;type:text" json:"url"`
	Path             string `gorm:"column:path;type:text" json:"path"`
	IntervalSec      int    `gorm:"column:interval_sec;not null;default:86400" json:"intervalSec"`
	Enabled          int    `gorm:"column:enabled;not null;default:1" json:"enabled"`
	RawYAML          string `gorm:"column:raw_yaml;type:text" json:"rawYaml"`
	Checksum         string `gorm:"column:checksum;type:varchar(128);not null;default:''" json:"checksum"`
	IPRuleCount      int    `gorm:"column:ip_rule_count;not null;default:0" json:"ipRuleCount"`
	DomainRuleCount  int    `gorm:"column:domain_rule_count;not null;default:0" json:"domainRuleCount"`
	UnsupportedCount int    `gorm:"column:unsupported_count;not null;default:0" json:"unsupportedCount"`
	LastStatus       string `gorm:"column:last_status;type:varchar(40);not null;default:'pending'" json:"lastStatus"`
	LastError        string `gorm:"column:last_error;type:text" json:"lastError"`
	LastRefreshTime  int64  `gorm:"column:last_refresh_time;not null;default:0" json:"lastRefreshTime"`
	NextRefreshTime  int64  `gorm:"column:next_refresh_time;not null;default:0" json:"nextRefreshTime"`
	CreatedTime      int64  `gorm:"column:created_time;not null" json:"createdTime"`
	UpdatedTime      int64  `gorm:"column:updated_time;not null" json:"updatedTime"`
}

func (PolicyProvider) TableName() string { return "policy_provider" }

type PolicyRule struct {
	ID                    int64  `gorm:"primaryKey;autoIncrement" json:"id"`
	Name                  string `gorm:"column:name;type:varchar(160);not null" json:"name"`
	Priority              int    `gorm:"column:priority;not null;default:100" json:"priority"`
	MatchDirection        string `gorm:"column:match_direction;type:varchar(20);not null;default:'outbound'" json:"matchDirection"`
	MatchSourceMode       string `gorm:"column:match_source_mode;type:varchar(40);not null;default:'any'" json:"matchSourceMode"`
	MatchSourceValue      string `gorm:"column:match_source_value;type:text" json:"matchSourceValue"`
	MatchDestinationMode  string `gorm:"column:match_destination_mode;type:varchar(40);not null;default:'any'" json:"matchDestinationMode"`
	MatchDestinationValue string `gorm:"column:match_destination_value;type:text" json:"matchDestinationValue"`
	ProviderID            int64  `gorm:"column:provider_id;not null;default:0;index" json:"providerId"`
	Action                string `gorm:"column:action;type:varchar(40);not null;default:'reject'" json:"action"`
	ActionTarget          string `gorm:"column:action_target;type:text" json:"actionTarget"`
	Enabled               int    `gorm:"column:enabled;not null;default:1" json:"enabled"`
	CreatedTime           int64  `gorm:"column:created_time;not null" json:"createdTime"`
	UpdatedTime           int64  `gorm:"column:updated_time;not null" json:"updatedTime"`
}

func (PolicyRule) TableName() string { return "policy_rule" }

type PolicyBinding struct {
	ID            int64  `gorm:"primaryKey;autoIncrement" json:"id"`
	PolicyID      int64  `gorm:"column:policy_id;not null;index" json:"policyId"`
	TargetType    string `gorm:"column:target_type;type:varchar(40);not null" json:"targetType"`
	TargetID      int64  `gorm:"column:target_id;not null;default:0" json:"targetId"`
	TargetRole    string `gorm:"column:target_role;type:varchar(40);not null;default:''" json:"targetRole"`
	NodeID        int64  `gorm:"column:node_id;not null;default:0;index" json:"nodeId"`
	InterfaceName string `gorm:"column:interface_name;type:varchar(120)" json:"interfaceName"`
	ListenPort    int    `gorm:"column:listen_port;not null;default:0" json:"listenPort"`
	Protocol      string `gorm:"column:protocol;type:varchar(20);not null;default:'any'" json:"protocol"`
	Enabled       int    `gorm:"column:enabled;not null;default:1" json:"enabled"`
	CreatedTime   int64  `gorm:"column:created_time;not null" json:"createdTime"`
	UpdatedTime   int64  `gorm:"column:updated_time;not null" json:"updatedTime"`
}

func (PolicyBinding) TableName() string { return "policy_binding" }

type PolicyDeploymentLog struct {
	ID          int64  `gorm:"primaryKey;autoIncrement" json:"id"`
	BindingID   int64  `gorm:"column:binding_id;not null;default:0;index" json:"bindingId"`
	PolicyID    int64  `gorm:"column:policy_id;not null;default:0;index" json:"policyId"`
	NodeID      int64  `gorm:"column:node_id;not null;default:0;index" json:"nodeId"`
	Engine      string `gorm:"column:engine;type:varchar(40);not null;default:'nftables'" json:"engine"`
	Action      string `gorm:"column:action;type:varchar(40);not null;default:'apply'" json:"action"`
	Status      string `gorm:"column:status;type:varchar(40);not null;default:'pending'" json:"status"`
	Message     string `gorm:"column:message;type:text" json:"message"`
	PlanJSON    string `gorm:"column:plan_json;type:text" json:"planJson"`
	CreatedTime int64  `gorm:"column:created_time;not null" json:"createdTime"`
}

func (PolicyDeploymentLog) TableName() string { return "policy_deployment_log" }
