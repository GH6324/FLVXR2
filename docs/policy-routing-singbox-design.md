# FLVX 策略防火墙与 Mihomo Sidecar 设计

## 结论

Mihomo Sidecar 不能被设计成“代理节点管理功能”。在 FLVX 里，它应该是一个可选的本地策略执行器，服务于入口节点、出口节点或隧道流量位置。

也就是说，策略绑定对象不是代理节点，而是：

- 入口节点上的某个入站端口、服务或接口。
- 出口节点上的某个出站链路、服务或接口。
- 某条隧道的入口侧、出口侧或整条隧道。

代理节点只是策略动作之一，而且是可选动作。大多数防火墙策略可以完全不设置代理节点。

## 术语边界

| 名称 | 含义 |
| --- | --- |
| FLVX 节点 | 已接入面板的服务器，负责端口转发、隧道转发、WG、Agent 下发等能力 |
| 入口节点 | 流量进入 FLVX 网络的位置 |
| 出口节点 | 流量离开 FLVX 网络的位置 |
| 代理节点 | Sing-box、Mihomo proxy、VLESS、Trojan、Shadowsocks 等上游代理出站 |
| 策略执行器 | 在节点本机运行的本地组件，用于判断流量是否允许、拒绝、直连或交给上游 |
| Mihomo Sidecar | 可选策略执行器，不等于代理节点 |
| nftables | 内核层转发、拦截、打标和兜底防火墙 |

## 为什么不能把 Mihomo 理解成代理节点

Mihomo 确实常用于代理客户端，但它也具备这些适合 FLVX 的能力：

- 支持 Clash `rule-providers`，可以复用大量现成规则源。
- 支持 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`、`GEOIP`、端口等规则。
- 支持透明入口，例如 TUN、TPROXY、redirect、mixed listener。
- 支持 `DIRECT`、`REJECT` 这类不依赖上游代理的动作。
- 支持在需要时再把命中的流量交给某个上游代理。

所以在 FLVX 中，Mihomo 的定位应该是：

```text
流量进入某个 FLVX 绑定点
        |
        v
nftables 选择是否拦截 / 打标 / 送入本地策略端口
        |
        v
Mihomo Sidecar 做规则判定
        |
        +--> REJECT / DROP
        +--> DIRECT / 放行到原目标
        +--> 可选：交给 Sing-box 或其它代理出站
```

## 三种执行模式

### 1. 纯 nftables 模式

适合只处理 IP、CIDR、端口、协议、接口的策略。

典型场景：

- 拒绝中国 IP 入站。
- 拒绝出口访问中国 IP。
- 某个入口端口只允许指定 IP 段。
- 某条隧道只允许 TCP，不允许 UDP。

特点：

- 性能最高。
- 不需要 Mihomo。
- 不需要代理节点。
- 不支持域名级 Clash 规则。

示例：

```text
入口节点 A:
  如果来源 IP 在 CN IPv4 set 中，则 drop

出口节点 B:
  如果目标 IP 在 CN IPv4 set 中，则 reject
```

### 2. Mihomo 透明策略模式

适合需要 Clash rule-providers、域名规则、应用服务规则的策略。

典型场景：

- 使用 blackmatrix7 的 TikTok/Facebook/Instagram 规则。
- 按域名后缀拒绝某类服务。
- 按 provider 批量管理域名和 IP 规则。
- 对入口或出口流量做复杂策略判定。

特点：

- Mihomo 作为本地 sidecar 运行。
- nftables 只负责把“指定绑定点”的流量送到 Mihomo。
- 默认动作可以是 `DIRECT`，不是代理。
- 不要求入口或出口配置代理节点。

示例：

```text
隧道 T1 的出口节点 B:
  nftables 只拦截 T1 对应的出站流量
  送入本机 Mihomo tproxy listener
  Mihomo 匹配 Clash provider
  命中 CN 目的地则 REJECT
  未命中则 DIRECT
```

### 3. 可选代理出站模式

适合用户明确希望某些命中规则的流量走 Sing-box 或其它代理。

典型场景：

- 出口节点本身配置了 Sing-box 上游代理。
- 访问某些规则源命中的目标时，不直连，而是交给代理。
- 同一出口节点上，一部分流量直连，一部分流量代理。

特点：

- 代理节点是策略动作，不是策略绑定对象。
- 只有在策略动作选择“转交代理”时才使用。
- 代理出站可以由 Sing-box、Mihomo proxy-provider 或其它本机服务承接。

示例：

```text
策略动作:
  TikTok provider -> PROXY(singbox_local_1080)
  CN provider     -> REJECT
  其它流量        -> DIRECT
```

## 绑定模型

策略绑定必须表达“这条策略作用在哪段流量上”，而不是表达“这条策略使用哪个代理节点”。

### 绑定对象

| 绑定对象 | 说明 |
| --- | --- |
| `entry_node` | 入口节点全部或指定入口服务 |
| `exit_node` | 出口节点全部或指定出口服务 |
| `tunnel` | 某条隧道的整条链路 |
| `tunnel_entry` | 某条隧道的入口侧 |
| `tunnel_exit` | 某条隧道的出口侧 |
| `forward_rule` | 某条端口转发或隧道转发规则 |

### 绑定粒度

| 粒度 | 示例 |
| --- | --- |
| 节点级 | 出口节点 B 全部出站流量拒绝 CN IP |
| 服务级 | 只对节点 B 上的 `tunnel-1001` 生效 |
| 端口级 | 只对入口节点 A 的 `443/tcp` 生效 |
| 接口级 | 只对 `wg-flvx-1001` 或某个虚拟接口生效 |
| 用户级 | 只对某些用户绑定的隧道或规则生效 |

## 策略动作

策略动作分为三类。

### 防火墙动作

| 动作 | 说明 | 是否需要代理 |
| --- | --- | --- |
| `allow` | 明确允许 | 否 |
| `drop` | 静默丢弃 | 否 |
| `reject` | 拒绝并返回错误 | 否 |
| `log` | 记录命中日志 | 否 |

### 直连动作

| 动作 | 说明 | 是否需要代理 |
| --- | --- | --- |
| `direct` | 经过策略判定后放行到原始目标 | 否 |
| `bypass` | 不送入 sidecar，直接由原链路处理 | 否 |

### 可选代理动作

| 动作 | 说明 | 是否需要代理 |
| --- | --- | --- |
| `proxy_singbox` | 转交本机 Sing-box 出站 | 是 |
| `proxy_mihomo` | 转交 Mihomo proxy 或 proxy-provider | 是 |
| `proxy_custom` | 转交自定义本机 SOCKS/HTTP/TPROXY 出站 | 是 |

默认情况下，FLVX 不应该自动创建代理动作。没有配置代理动作时，策略只能做 `allow/drop/reject/direct/bypass`。

## Clash rule-providers 的处理方式

面板需要支持导入这类配置：

```yaml
rule-providers:
  TikTok:
    type: http
    behavior: classical
    path: ./ruleset/TikTok.yaml
    url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/TikTok/TikTok.yaml"
    interval: 86400
```

处理流程：

```text
管理员导入 Clash provider
        |
        v
面板下载 / 缓存 / 校验 / 解析
        |
        +--> IP-CIDR 类规则：可编译为 nftables set，也可交给 Mihomo
        +--> DOMAIN 类规则：交给 Mihomo Sidecar，不编译进 nftables
        +--> 不支持规则：保留在解析报告中提示
        |
        v
策略引用 provider
        |
        v
绑定到入口、出口或隧道
        |
        v
Agent 下发 nftables steering plan 和 Mihomo config
```

## 数据模型建议

### `policy_provider`

保存 Clash 规则源。

```sql
id BIGINT PRIMARY KEY
name VARCHAR(160) NOT NULL
provider_type VARCHAR(20) NOT NULL DEFAULT 'http'
behavior VARCHAR(20) NOT NULL DEFAULT 'classical'
url TEXT
path TEXT
interval_sec INT NOT NULL DEFAULT 86400
enabled INT NOT NULL DEFAULT 1
raw_yaml TEXT
checksum VARCHAR(128) NOT NULL DEFAULT ''
last_status VARCHAR(40) NOT NULL DEFAULT 'pending'
last_error TEXT
last_refresh_time BIGINT NOT NULL DEFAULT 0
next_refresh_time BIGINT NOT NULL DEFAULT 0
created_time BIGINT NOT NULL
updated_time BIGINT NOT NULL
```

### `policy_rule`

保存 FLVX 自己的策略规则。

```sql
id BIGINT PRIMARY KEY
name VARCHAR(160) NOT NULL
priority INT NOT NULL DEFAULT 100
match_direction VARCHAR(20) NOT NULL
match_source_mode VARCHAR(40) NOT NULL DEFAULT 'any'
match_source_value TEXT
match_destination_mode VARCHAR(40) NOT NULL DEFAULT 'any'
match_destination_value TEXT
provider_id BIGINT NOT NULL DEFAULT 0
action VARCHAR(40) NOT NULL
action_target TEXT
enabled INT NOT NULL DEFAULT 1
created_time BIGINT NOT NULL
updated_time BIGINT NOT NULL
```

`action` 取值：

- `allow`
- `drop`
- `reject`
- `direct`
- `bypass`
- `proxy_singbox`
- `proxy_mihomo`
- `proxy_custom`

### `policy_binding`

保存策略和 FLVX 流量位置的关系。

```sql
id BIGINT PRIMARY KEY
policy_id BIGINT NOT NULL
target_type VARCHAR(40) NOT NULL
target_id BIGINT NOT NULL DEFAULT 0
target_role VARCHAR(40) NOT NULL DEFAULT ''
node_id BIGINT NOT NULL DEFAULT 0
interface_name VARCHAR(120)
listen_port INT NOT NULL DEFAULT 0
protocol VARCHAR(20) NOT NULL DEFAULT 'any'
enabled INT NOT NULL DEFAULT 1
created_time BIGINT NOT NULL
updated_time BIGINT NOT NULL
```

`target_type` 取值：

- `entry_node`
- `exit_node`
- `tunnel`
- `tunnel_entry`
- `tunnel_exit`
- `forward_rule`

## Agent 下发命令

新增命令建议：

```text
InstallPolicyEngine
ApplyPolicyPlan
RemovePolicyPlan
GetPolicyStatus
RestartPolicyEngine
PreviewPolicyPlan
```

其中 `ApplyPolicyPlan` 包含：

- nftables 拦截和打标规则。
- Mihomo 配置文件。
- systemd 服务配置。
- provider 文件或 provider 缓存。
- 回滚版本号。

## 节点侧运行方式

### 纯 nftables 策略

```text
/etc/flvx/policy/
  nftables/
    policy-1001.nft
```

Agent 执行：

```text
nft -f /etc/flvx/policy/nftables/policy-1001.nft
```

### Mihomo Sidecar 策略

```text
/etc/flvx/policy/mihomo/
  config.yaml
  providers/
    TikTok.yaml
  logs/
```

systemd 服务：

```text
flvx-mihomo-policy.service
```

该服务只监听本机策略端口，不对公网暴露控制 API。

## 出入口无代理节点时的行为

这是本方案必须保证的核心场景。

### 入口无代理

入口节点只做：

- 来源 IP 判定。
- 入口端口判定。
- 协议判定。
- 可选把流量送入 Mihomo 做域名/provider 判定。
- 未命中拒绝规则时，继续进入原 FLVX 转发链路。

不会强制配置任何代理出站。

### 出口无代理

出口节点只做：

- 目标 IP 判定。
- 目标域名/provider 判定。
- 命中拒绝规则则阻断。
- 未命中时 `DIRECT` 到原始目标。

不会强制配置 Sing-box 或 Mihomo 代理节点。

### 出口存在 Sing-box

如果用户明确选择：

```text
命中 TikTok provider -> proxy_singbox
```

则流量转交给本机 Sing-box 出站。否则 Sing-box 不参与这条策略。

## UI 设计

新增一级或二级菜单：`策略防火墙`。

页面分为：

- 策略。
- 绑定。
- 规则源。
- 下发状态。
- 诊断。

### 策略编辑器

关键字段：

- 策略名称。
- 优先级。
- 匹配方向：入站、出站、双向。
- 匹配来源：任意、CIDR、IP 集合、Provider、用户、节点。
- 匹配目标：任意、CIDR、IP 集合、Provider、端口。
- 动作：允许、拒绝、丢弃、直连、旁路、转交 Sing-box、转交 Mihomo。
- 是否启用。

当用户选择 `proxy_singbox`、`proxy_mihomo`、`proxy_custom` 时，才显示代理目标配置。

### 绑定编辑器

关键字段：

- 绑定对象：入口节点、出口节点、隧道、规则。
- 绑定角色：入口侧、出口侧、整条链路。
- 生效协议：TCP、UDP、全部。
- 生效端口。
- 是否需要透明策略引擎。

UI 必须显示预览：

```text
策略：拒绝 CN 出站
绑定：隧道 T1 / 出口侧
执行节点：出口节点 B
执行方式：nftables
代理依赖：无
```

如果策略引用了域名类 provider，预览应变成：

```text
策略：拒绝 TikTok
绑定：隧道 T1 / 出口侧
执行节点：出口节点 B
执行方式：Mihomo Sidecar + nftables steering
代理依赖：无，默认 DIRECT
```

## 诊断逻辑

诊断页要回答这些问题：

- 这条策略实际下发到了哪个节点。
- 是否使用 Mihomo。
- 是否依赖代理出站。
- 命中了多少条 IP 规则。
- 命中了多少条域名规则。
- 当前 nftables 规则是否存在。
- Mihomo 服务是否运行。
- provider 是否刷新成功。
- 最后一次下发是否成功。

## 风险点

### 真实来源 IP 问题

如果入口前面有 CDN、反向代理、NAT，入口节点看到的来源 IP 可能不是最终用户 IP。此时“拒绝中国 IP 入站”只能基于节点实际看到的来源地址判断。

### 域名识别问题

域名规则需要流量中存在可识别域名，或配合 DNS/fake-ip/TUN/TPROXY 模式。纯 IP 转发场景下，内核层无法知道目标域名。

### UDP 支持

TPROXY 可以处理 TCP 和 UDP，但实际效果取决于节点内核、nftables 规则和 Mihomo 配置。第一版需要把 UDP 支持作为独立开关。

### 性能问题

纯 IP/CIDR 策略优先使用 nftables。只有域名、provider、复杂规则才进入 Mihomo，避免所有流量都经过用户态策略引擎。

## 实施阶段

### 阶段一：纯 nftables 策略

- 新增策略、绑定、规则源基础表。
- 支持手动 CIDR 和 IP provider。
- 支持入口/出口/隧道绑定。
- 支持 `allow/drop/reject`。
- Agent 下发 nftables plan。

### 阶段二：Clash provider 解析

- 支持导入 `rule-providers` YAML。
- 支持下载、缓存、刷新。
- 支持 provider 解析报告。
- IP-CIDR 规则可进入 nftables。
- DOMAIN 规则先进入 Mihomo 待下发集合。

### 阶段三：Mihomo Sidecar

- Agent 支持安装 Mihomo。
- 支持生成本机 Mihomo 配置。
- 支持 TPROXY/TUN 透明策略入口。
- 支持 `REJECT`、`DIRECT`。
- 不配置代理节点也能运行。

### 阶段四：可选代理动作

- 支持把命中流量转交 Sing-box。
- 支持 Mihomo proxy-provider。
- 支持自定义本机代理端口。
- UI 中明确标记“该策略依赖代理出站”。

## 最终建议

第一版不要把“策略路由”做成代理节点功能，而应该做成 FLVX 的流量绑定策略：

- 能用 nftables 解决的，就直接用 nftables。
- 需要 Clash provider 和域名能力时，才启用 Mihomo Sidecar。
- Mihomo 默认只做 `DIRECT/REJECT`，不要求代理节点。
- Sing-box 或其它代理只作为可选动作。
- UI 必须明确显示每条策略是否依赖代理出站。

这样既满足“入口/出口没有代理节点也能使用策略”的需求，又保留后续接入 Sing-box 代理出站的能力。
