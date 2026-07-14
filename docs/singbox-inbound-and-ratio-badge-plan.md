# Sing-box 入站下发与隧道倍数显示修复实施文档
## 背景

本次先处理两个来自移动端截图的问题：

1. 节点入站部署时，`shadowsocks` 协议下发到节点后，`sing-box check -c` 失败：
   `initialize inbound[0]: bad key`
2. 隧道/转发列表中的倍数提示直接显示为 `^1x`，在长名称和手机端换行场景下观感较差，需要换成更现代的 UI。

本文件只整理实施方案，不直接修改功能代码。

## 当前项目状态

- 当前分支：`main`
- 当前工作区：干净
- 最近提交：`26b35778 Add scoped speed limit bindings`
- 相关后端文件：
  - `go-backend/internal/http/handler/node_deploy.go`
  - `go-backend/internal/store/model/model.go`
  - `go-gost/x/socket/websocket_reporter.go`
- 相关前端文件：
  - `vite-frontend/src/pages/node/node-deploy-modal.tsx`
  - `vite-frontend/src/pages/forward.tsx`
  - `vite-frontend/src/api/types.ts`

## 问题一：Sing-box shadowsocks 入站下发失败

### 现象

移动端添加入站选择 `shadowsocks` 后，部署进度到 100% 失败，错误为：

```text
部署入站: 失败 - sing-box config check failed: exit status 1:
FATAL initialize inbound[0]: bad key
```

### 当前实现链路

1. 前端在节点部署弹窗中选择协议、网络、UDP 数据包编码、method 等参数。
2. 前端调用 `/api/v1/node/deploy/inbound/save`。
3. 后端 `saveNodeInboundDeployment` 调用 `renderInboundConfig` 生成入站配置。
4. `renderAndStoreNodeConfig` 组合完整 sing-box 配置。
5. 面板通过 `ApplyCoreConfig` 下发到节点。
6. 节点端 `go-gost/x/socket/websocket_reporter.go` 写入配置后执行：

```text
sing-box check -c /etc/flvxt2/sing-box.json
```

### 初步根因

当前 `renderInboundConfig` 中，`shadowsocks` 默认使用：

```go
inbound["method"] = optString(opt, "method", "2022-blake3-aes-128-gcm")
inbound["password"] = identity.MixedPassword
```

而 `identity.MixedPassword` 来自：

```go
MixedPassword: deployRandomToken(12)
```

这只是 12 位普通随机字符串。`2022-blake3-aes-128-gcm` / `2022-blake3-aes-256-gcm` 属于 Shadowsocks 2022 系列，对 password/key 格式和长度有要求。直接使用普通短密码会导致 sing-box 初始化时报 `bad key`。

因此，截图中的失败更像是 **Shadowsocks 2022 密钥不合规**，不是单纯的网络选项问题。

### 同时发现的潜在问题

1. 分享链接生成写死了 `2022-blake3-aes-128-gcm`：

```go
auth := base64.RawURLEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:" + identity.MixedPassword))
```

如果用户选择了其它 method，复制链接仍可能不一致。

2. 复制客户端配置也可能使用固定 cipher 文本，导致配置与真实下发不一致。

3. 前端通用网络选项会展示在 shadowsocks 表单中，但后端服务器配置已过滤 `network` 和 `packet_encoding`，客户端出站配置只对 `vless` 写入 `network`/`packet_encoding`。这部分需要明确：哪些协议展示哪些选项，避免用户误以为所有协议都支持。

### 修复目标

- `shadowsocks` 默认配置必须能通过节点端 `sing-box check`。
- 服务端入站、客户端出站、分享链接、复制客户端配置必须使用同一个 method/password 结果。
- method 不同，密码生成/校验逻辑不同。
- 部署失败时保留当前进度条错误，但错误文案要能提示“method 与 password 不匹配”这一类问题。

### 实施方案

#### 1. 新增协议凭据解析层

利用 `NodeIdentity.ProtocolCredentialsJSON` 保存协议专属凭据，不再把所有协议都塞到 `MixedPassword`。

建议结构：

```json
{
  "shadowsocks": {
    "method": "2022-blake3-aes-128-gcm",
    "password": "base64-key-here"
  }
}
```

后端新增 helper：

- `nodeProtocolCredentials(identity)`
- `getOrCreateShadowsocksCredential(identity, method)`
- `shadowsocksPasswordForMethod(method)`
- `isShadowsocks2022Method(method)`

#### 2. 按 method 生成合法密码

规则建议：

- `2022-blake3-aes-128-gcm`：生成 16 字节随机 key，再 base64 标准编码。
- `2022-blake3-aes-256-gcm`：生成 32 字节随机 key，再 base64 标准编码。
- `aes-128-gcm` / `aes-256-gcm` / `chacha20-ietf-poly1305`：可以继续使用普通随机密码，但建议生成 16-24 位以上。

注意：如果后续 sing-box 版本对编码格式有差异，以目标节点实际 `sing-box check` 为最终准绳。

#### 3. 统一渲染入口

将当前散落的 method/password 读取统一到一个函数：

```go
method, password, err := resolveShadowsocksCredential(identity, opt)
```

并用于：

- 服务端 inbound
- 客户端 outbound
- `ss://` 分享链接
- 前端复制客户端配置所依赖的 `ClientConfigJSON`

#### 4. 修复分享链接 method 写死问题

`shareURI` 里不能再写死 `2022-blake3-aes-128-gcm`，应使用当前入站实际 method：

```go
method := optString(opt, "method", defaultShadowsocksMethod)
auth := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))
```

#### 5. 前端协议选项收敛

节点部署弹窗中：

- `network` / `packet_encoding` 只在明确支持的协议上显示，优先 `vless`。
- `shadowsocks` 只展示 method，以及必要说明。
- 出站预览只展示当前协议真实会写入的字段。

#### 6. 添加后端测试

建议新增/扩展测试：

- `TestRenderShadowsocksInboundUsesValid2022AES128Key`
- `TestRenderShadowsocksInboundUsesValid2022AES256Key`
- `TestShareURIUsesSelectedShadowsocksMethod`
- `TestClientOutboundMatchesServerShadowsocksCredential`

测试至少断言：

- method 与 password 在 inbound/outbound/shareURI 中一致。
- 2022 方法生成的 password 不是 12 位普通随机字符串。
- 不同 method 切换后不会复用不兼容 key。

#### 7. 手工验收

在测试服务器上执行：

1. 添加 `shadowsocks` 入站，默认 method 部署。
2. 查看部署进度条应成功。
3. 进入节点检查：

```bash
sing-box check -c /etc/flvxt2/sing-box.json
systemctl status flvxt2-sing-box
```

4. 复制客户端配置、复制出站、复制链接，确认 method/password 一致。
5. 切换 `aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305` 分别保存并部署。

## 问题二：隧道倍数 `^1x` 显示太丑

### 现象

移动端隧道/规则列表中，隧道流量倍数被直接拼在标题后：

```text
... ^1x
```

在名称较长、多行换行、单选按钮靠右的场景下，`^1x` 像正文残留字符，视觉权重不对，也不符合当前毛玻璃/圆角 UI 风格。

### 当前实现

`vite-frontend/src/pages/forward.tsx`：

```tsx
<span className="text-primary-600 font-bold text-[10px] mr-1.5">
  ^{formatTunnelTrafficRatio(tunnel.tunnelTrafficRatio)}
</span>
```

问题点：

- 使用 `^` 作为文本前缀，语义不直观。
- 只有 10px 文本，没有背景、边框、层级。
- 在 flex 文本流中参与换行，移动端容易贴在长标题末尾。
- `1x` 其实是默认倍率，是否需要强提示也可以重新设计。

### 修复目标

- 用现代 Badge/Chip 展示倍率。
- 不破坏现有主题风格。
- 移动端长名称换行后，倍率仍然像一个独立信息标签，而不是正文的一部分。
- 同一组件可复用于表格、卡片、弹窗选择列表。

### UI 方案

新增轻量组件：

```tsx
const TrafficRatioBadge = ({ value }: { value?: number }) => ...
```

展示规则：

- `1x`：显示为低权重灰色标签，文本 `1x`
- `>1x`：显示为主色标签，文本 `倍率 2x` 或 `2x`
- 小数：最多保留两位，比如 `1.25x`
- 非法值：归一为 `1x`

推荐样式：

```tsx
className="
  inline-flex h-6 shrink-0 items-center rounded-full
  border border-primary-200/70 bg-primary-50/80
  px-2 text-[11px] font-semibold leading-none
  text-primary-700 shadow-sm backdrop-blur
  dark:border-primary-400/25 dark:bg-primary-500/15 dark:text-primary-100
"
```

移动端布局建议：

- 标题容器使用 `flex flex-wrap items-center gap-1.5`。
- 标题文本使用 `min-w-0 break-words`。
- Badge 使用 `shrink-0`，避免被压扁。
- 在选择列表/弹窗中，Badge 放在标题行右侧或下一行开头，不再混入正文。

### 是否隐藏默认 1x

建议不完全隐藏。原因：

- 用户截图里明显关注这个信息，说明它有识别价值。
- 隐藏默认值会让部分隧道“看起来缺信息”。

但默认 `1x` 应降低视觉权重：

- 灰色透明背景
- 无强烈主色
- hover/title 显示“流量倍率 1x”

### 实施步骤

1. 在 `vite-frontend/src/pages/forward.tsx` 增加 `TrafficRatioBadge`。
2. 替换 `SortableTunnelGroupContainer` 中的 `^{formatTunnelTrafficRatio(...)}`。
3. 检索所有 `trafficRatio` / `tunnelTrafficRatio` 展示点，统一复用或保持一致。
4. 检查移动端：
   - 卡片模式
   - 表格紧凑模式
   - 隧道选择/编辑弹窗如有倍率显示也一并统一
5. 通过浏览器移动端 viewport 截图验证长名称换行。

### 验收标准

- 页面中不再出现裸文本 `^1x`。
- 倍率显示为圆角 Badge。
- 长隧道名称换行时，Badge 不贴在文字中间，也不挤压单选按钮/操作按钮。
- 桌面端布局不回退。
- `npm run build` 通过。

## 风险与注意事项

1. `ProtocolCredentialsJSON` 已在模型中存在，但当前未实质使用。启用它时要保证老节点身份可以平滑迁移。
2. 已部署的 shadowsocks 入站如果原来保存了非法 password，需要在更新/重新部署时自动修正，避免继续失败。
3. 如果用户主动选择非 2022 method，不应强制使用 2022 key。
4. 前端文件目前存在部分中文乱码文本，后续改动时要避免扩大编码问题；本次只碰必要区域。
5. 倍率 UI 是展示修复，不应改变 `trafficRatio` 的业务计算逻辑。

## 建议执行顺序

1. 先修后端 shadowsocks 凭据生成和分享链接一致性。
2. 增加后端测试，覆盖默认 2022 method。
3. 再修前端协议选项展示，减少 shadowsocks 下不相关字段。
4. 最后替换倍率 Badge。
5. 构建并部署测试服务器验证。
