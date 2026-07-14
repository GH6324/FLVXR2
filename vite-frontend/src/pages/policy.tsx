import type {
  NodeApiItem,
  PolicyBindingApiItem,
  PolicyDeploymentLogApiItem,
  PolicyProviderApiItem,
  PolicyRuleApiItem,
  TunnelApiItem,
} from "@/api/types";

import { useEffect, useMemo, useState } from "react";
import toast from "react-hot-toast";
import { ShieldCheck, Network, Route, UploadCloud } from "lucide-react";

import {
  applyPolicyBinding,
  deletePolicyBinding,
  deletePolicyProvider,
  deletePolicyRule,
  getNodeList,
  getPolicyBindingStatus,
  getPolicyBundle,
  getTunnelList,
  removePolicyBinding,
  savePolicyBinding,
  savePolicyProvider,
  savePolicyRule,
} from "@/api";
import { AnimatedPage } from "@/components/animated-page";
import { PageLoadingState } from "@/components/page-state";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/shadcn-bridge/heroui/button";
import { Card, CardBody, CardHeader } from "@/shadcn-bridge/heroui/card";
import { Chip } from "@/shadcn-bridge/heroui/chip";
import { Input } from "@/shadcn-bridge/heroui/input";
import { Select, SelectItem } from "@/shadcn-bridge/heroui/select";
import { Switch } from "@/shadcn-bridge/heroui/switch";

const emptyProvider = {
  name: "",
  providerType: "http",
  behavior: "classical",
  url: "",
  path: "",
  intervalSec: 86400,
  enabled: 1,
  rawYaml: "payload:\n  - IP-CIDR,1.0.1.0/24\n  - DOMAIN-SUFFIX,example.com",
};

const emptyRule = {
  name: "",
  priority: 100,
  matchDirection: "outbound",
  matchSourceMode: "any",
  matchSourceValue: "",
  matchDestinationMode: "provider",
  matchDestinationValue: "",
  providerId: 0,
  action: "reject",
  actionTarget: "",
  enabled: 1,
};

const emptyBinding = {
  policyId: 0,
  targetType: "exit_node",
  targetId: 0,
  targetRole: "exit",
  nodeId: 0,
  interfaceName: "",
  listenPort: 0,
  protocol: "any",
  enabled: 1,
};

export default function PolicyPage() {
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [providers, setProviders] = useState<PolicyProviderApiItem[]>([]);
  const [rules, setRules] = useState<PolicyRuleApiItem[]>([]);
  const [bindings, setBindings] = useState<PolicyBindingApiItem[]>([]);
  const [logs, setLogs] = useState<PolicyDeploymentLogApiItem[]>([]);
  const [nodes, setNodes] = useState<NodeApiItem[]>([]);
  const [tunnels, setTunnels] = useState<TunnelApiItem[]>([]);
  const [providerForm, setProviderForm] = useState(emptyProvider);
  const [ruleForm, setRuleForm] = useState(emptyRule);
  const [bindingForm, setBindingForm] = useState(emptyBinding);

  const providerMap = useMemo(
    () => new Map(providers.map((item) => [item.id, item])),
    [providers],
  );
  const ruleMap = useMemo(
    () => new Map(rules.map((item) => [item.id, item])),
    [rules],
  );
  const nodeMap = useMemo(
    () => new Map(nodes.map((item) => [item.id, item])),
    [nodes],
  );
  const tunnelMap = useMemo(
    () => new Map(tunnels.map((item) => [item.id, item])),
    [tunnels],
  );
  const latestLogMap = useMemo(() => {
    const map = new Map<number, PolicyDeploymentLogApiItem>();

    for (const log of logs) {
      const current = map.get(log.bindingId);

      if (!current || (log.createdTime || 0) > (current.createdTime || 0)) {
        map.set(log.bindingId, log);
      }
    }

    return map;
  }, [logs]);

  const loadData = async () => {
    setLoading(true);
    try {
      const [bundleRes, nodeRes, tunnelRes] = await Promise.all([
        getPolicyBundle(),
        getNodeList(),
        getTunnelList(),
      ]);

      if (bundleRes.code === 0 && bundleRes.data) {
        setProviders(bundleRes.data.providers || []);
        setRules(bundleRes.data.rules || []);
        setBindings(bundleRes.data.bindings || []);
        setLogs(bundleRes.data.logs || []);
      } else {
        toast.error(bundleRes.msg || "加载策略失败");
      }
      if (nodeRes.code === 0) {
        setNodes(nodeRes.data || []);
      }
      if (tunnelRes.code === 0) {
        setTunnels(tunnelRes.data || []);
      }
    } catch {
      toast.error("加载策略数据失败");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, []);

  const handleSaveProvider = async () => {
    if (!providerForm.name.trim()) {
      toast.error("请输入规则源名称");

      return;
    }
    setSubmitting(true);
    try {
      const res = await savePolicyProvider(providerForm);

      if (res.code === 0) {
        toast.success("规则源已保存");
        setProviderForm(emptyProvider);
        await loadData();
      } else {
        toast.error(res.msg || "保存失败");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleSaveRule = async () => {
    if (!ruleForm.name.trim()) {
      toast.error("请输入策略名称");

      return;
    }
    setSubmitting(true);
    try {
      const res = await savePolicyRule(ruleForm);

      if (res.code === 0) {
        toast.success("策略已保存");
        setRuleForm(emptyRule);
        await loadData();
      } else {
        toast.error(res.msg || "保存失败");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleSaveBinding = async () => {
    if (!bindingForm.policyId || !bindingForm.nodeId) {
      toast.error("请选择策略和执行节点");

      return;
    }
    setSubmitting(true);
    try {
      const res = await savePolicyBinding(bindingForm);

      if (res.code === 0) {
        toast.success("绑定已保存");
        setBindingForm(emptyBinding);
        await loadData();
      } else {
        toast.error(res.msg || "保存失败");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleApply = async (bindingId: number) => {
    setSubmitting(true);
    try {
      const res = await applyPolicyBinding(bindingId);

      if (res.code === 0) {
        toast.success("策略计划已下发到节点");
        await loadData();
      } else {
        toast.error(res.msg || "下发失败");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleRemove = async (bindingId: number) => {
    setSubmitting(true);
    try {
      const res = await removePolicyBinding(bindingId);

      if (res.code === 0) {
        toast.success("策略已从节点撤销");
        await loadData();
      } else {
        toast.error(res.msg || "撤销失败");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleStatus = async (bindingId: number) => {
    setSubmitting(true);
    try {
      const res = await getPolicyBindingStatus(bindingId);

      if (res.code === 0) {
        const status = res.data?.nodeResult?.data?.status || "unknown";

        toast.success(`节点策略状态：${status}`);
      } else {
        toast.error(res.msg || "状态检查失败");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteBinding = async (bindingId: number) => {
    if (!window.confirm("删除绑定前会先撤销节点上的防火墙规则，确认继续？")) {
      return;
    }
    setSubmitting(true);
    try {
      const deleteRes = await deletePolicyBinding(bindingId);

      if (deleteRes.code === 0) {
        toast.success("绑定已删除，节点规则已撤销");
        await loadData();
      } else {
        toast.error(deleteRes.msg || "删除失败");
      }
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return <PageLoadingState message="正在加载策略防火墙" />;
  }

  return (
    <AnimatedPage>
      <div className="space-y-5">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div>
            <h1 className="text-2xl font-semibold text-foreground">
              策略防火墙
            </h1>
            <p className="text-sm text-default-500">
              绑定入口、出口或隧道流量位置；代理出站只是可选动作。
            </p>
          </div>
          <Button variant="bordered" onPress={() => void loadData()}>
            刷新
          </Button>
        </div>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
          <Card className="border border-white/30 bg-white/70 backdrop-blur dark:bg-black/30">
            <CardHeader className="flex items-center gap-2">
              <Network className="h-5 w-5" />
              <span className="font-semibold">规则源</span>
            </CardHeader>
            <CardBody className="space-y-3">
              <Input
                label="名称"
                value={providerForm.name}
                onChange={(e) =>
                  setProviderForm({ ...providerForm, name: e.target.value })
                }
              />
              <Input
                label="URL"
                value={providerForm.url}
                onChange={(e) =>
                  setProviderForm({ ...providerForm, url: e.target.value })
                }
              />
              <Textarea
                className="min-h-[150px]"
                value={providerForm.rawYaml}
                onChange={(e) =>
                  setProviderForm({ ...providerForm, rawYaml: e.target.value })
                }
              />
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm">
                  <Switch
                    isSelected={providerForm.enabled === 1}
                    onValueChange={(checked) =>
                      setProviderForm({
                        ...providerForm,
                        enabled: checked ? 1 : 0,
                      })
                    }
                  />
                  启用
                </div>
                <Button isLoading={submitting} onPress={handleSaveProvider}>
                  保存规则源
                </Button>
              </div>
            </CardBody>
          </Card>

          <Card className="border border-white/30 bg-white/70 backdrop-blur dark:bg-black/30">
            <CardHeader className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5" />
              <span className="font-semibold">策略</span>
            </CardHeader>
            <CardBody className="space-y-3">
              <Input
                label="策略名称"
                value={ruleForm.name}
                onChange={(e) =>
                  setRuleForm({ ...ruleForm, name: e.target.value })
                }
              />
              <Select
                label="方向"
                selectedKeys={[ruleForm.matchDirection]}
                onSelectionChange={(keys) =>
                  setRuleForm({
                    ...ruleForm,
                    matchDirection: String(Array.from(keys)[0] || "outbound"),
                  })
                }
              >
                <SelectItem key="inbound">入站</SelectItem>
                <SelectItem key="outbound">出站</SelectItem>
                <SelectItem key="both">双向</SelectItem>
              </Select>
              <Select
                label="规则源"
                selectedKeys={[String(ruleForm.providerId || 0)]}
                onSelectionChange={(keys) =>
                  setRuleForm({
                    ...ruleForm,
                    providerId: Number(Array.from(keys)[0] || 0),
                  })
                }
              >
                <SelectItem key="0">不使用规则源</SelectItem>
                {providers.map((provider) => (
                  <SelectItem key={String(provider.id)}>
                    {provider.name}
                  </SelectItem>
                ))}
              </Select>
              <Select
                label="动作"
                selectedKeys={[ruleForm.action]}
                onSelectionChange={(keys) =>
                  setRuleForm({
                    ...ruleForm,
                    action: String(Array.from(keys)[0] || "reject"),
                  })
                }
              >
                <SelectItem key="allow">允许</SelectItem>
                <SelectItem key="drop">丢弃</SelectItem>
                <SelectItem key="reject">拒绝</SelectItem>
                <SelectItem key="direct">直连</SelectItem>
                <SelectItem key="bypass">旁路</SelectItem>
                <SelectItem key="proxy_singbox">转交 Sing-box</SelectItem>
                <SelectItem key="proxy_mihomo">转交 Mihomo</SelectItem>
                <SelectItem key="proxy_custom">自定义代理</SelectItem>
              </Select>
              {ruleForm.action.startsWith("proxy_") && (
                <Input
                  label="代理目标"
                  placeholder="例如 127.0.0.1:1080"
                  value={ruleForm.actionTarget}
                  onChange={(e) =>
                    setRuleForm({ ...ruleForm, actionTarget: e.target.value })
                  }
                />
              )}
              <Button isLoading={submitting} onPress={handleSaveRule}>
                保存策略
              </Button>
            </CardBody>
          </Card>

          <Card className="border border-white/30 bg-white/70 backdrop-blur dark:bg-black/30">
            <CardHeader className="flex items-center gap-2">
              <Route className="h-5 w-5" />
              <span className="font-semibold">绑定与下发</span>
            </CardHeader>
            <CardBody className="space-y-3">
              <Select
                label="策略"
                selectedKeys={[String(bindingForm.policyId || 0)]}
                onSelectionChange={(keys) =>
                  setBindingForm({
                    ...bindingForm,
                    policyId: Number(Array.from(keys)[0] || 0),
                  })
                }
              >
                <SelectItem key="0">请选择策略</SelectItem>
                {rules.map((rule) => (
                  <SelectItem key={String(rule.id)}>{rule.name}</SelectItem>
                ))}
              </Select>
              <Select
                label="绑定对象"
                selectedKeys={[bindingForm.targetType]}
                onSelectionChange={(keys) =>
                  setBindingForm({
                    ...bindingForm,
                    targetType: String(Array.from(keys)[0] || "exit_node"),
                  })
                }
              >
                <SelectItem key="entry_node">入口节点</SelectItem>
                <SelectItem key="exit_node">出口节点</SelectItem>
                <SelectItem key="tunnel">隧道</SelectItem>
                <SelectItem key="tunnel_entry">隧道入口侧</SelectItem>
                <SelectItem key="tunnel_exit">隧道出口侧</SelectItem>
              </Select>
              {bindingForm.targetType.includes("tunnel") && (
                <>
                  <Select
                    label="隧道"
                    selectedKeys={[String(bindingForm.targetId || 0)]}
                    onSelectionChange={(keys) =>
                      setBindingForm({
                        ...bindingForm,
                        targetId: Number(Array.from(keys)[0] || 0),
                      })
                    }
                  >
                    <SelectItem key="0">请选择隧道</SelectItem>
                    {tunnels.map((tunnel) => (
                      <SelectItem key={String(tunnel.id)}>
                        {tunnel.name}
                      </SelectItem>
                    ))}
                  </Select>
                  {bindingForm.targetType === "tunnel" && (
                    <Select
                      label="作用方向"
                      selectedKeys={[bindingForm.targetRole || "exit"]}
                      onSelectionChange={(keys) =>
                        setBindingForm({
                          ...bindingForm,
                          targetRole: String(Array.from(keys)[0] || "exit"),
                        })
                      }
                    >
                      <SelectItem key="entry">入口侧</SelectItem>
                      <SelectItem key="exit">出口侧</SelectItem>
                    </Select>
                  )}
                  <Input
                    label="网络接口"
                    placeholder="例如 wg0、eth0"
                    value={bindingForm.interfaceName}
                    onChange={(event) =>
                      setBindingForm({
                        ...bindingForm,
                        interfaceName: event.target.value,
                      })
                    }
                  />
                  <Input
                    label="监听端口"
                    max={65535}
                    min={0}
                    placeholder="接口未知时可使用端口限定"
                    type="number"
                    value={String(bindingForm.listenPort || "")}
                    onChange={(event) =>
                      setBindingForm({
                        ...bindingForm,
                        listenPort: Number(event.target.value || 0),
                      })
                    }
                  />
                </>
              )}
              <Select
                label="执行节点"
                selectedKeys={[String(bindingForm.nodeId || 0)]}
                onSelectionChange={(keys) =>
                  setBindingForm({
                    ...bindingForm,
                    nodeId: Number(Array.from(keys)[0] || 0),
                    targetId: bindingForm.targetType.includes("node")
                      ? Number(Array.from(keys)[0] || 0)
                      : bindingForm.targetId,
                  })
                }
              >
                <SelectItem key="0">请选择节点</SelectItem>
                {nodes.map((node) => (
                  <SelectItem key={String(node.id)}>{node.name}</SelectItem>
                ))}
              </Select>
              <Select
                label="协议"
                selectedKeys={[bindingForm.protocol]}
                onSelectionChange={(keys) =>
                  setBindingForm({
                    ...bindingForm,
                    protocol: String(Array.from(keys)[0] || "any"),
                  })
                }
              >
                <SelectItem key="any">全部</SelectItem>
                <SelectItem key="tcp">TCP</SelectItem>
                <SelectItem key="udp">UDP</SelectItem>
              </Select>
              <Button isLoading={submitting} onPress={handleSaveBinding}>
                保存绑定
              </Button>
            </CardBody>
          </Card>
        </div>

        <Card className="border border-white/30 bg-white/70 backdrop-blur dark:bg-black/30">
          <CardHeader className="font-semibold">当前策略计划</CardHeader>
          <CardBody className="space-y-3">
            {bindings.length === 0 ? (
              <div className="py-8 text-center text-default-500">
                暂无策略绑定
              </div>
            ) : (
              bindings.map((binding) => {
                const rule = ruleMap.get(binding.policyId);
                const provider = rule?.providerId
                  ? providerMap.get(rule.providerId)
                  : undefined;
                const engine =
                  provider && (provider.domainRuleCount || 0) > 0
                    ? "Mihomo Sidecar"
                    : rule?.action?.startsWith("proxy_")
                      ? "Mihomo Sidecar"
                      : "nftables";
                const requiresProxy = !!rule?.action?.startsWith("proxy_");
                const latestLog = latestLogMap.get(binding.id);

                return (
                  <div
                    key={binding.id}
                    className="flex flex-col gap-3 rounded-lg border border-divider bg-background/70 p-4 md:flex-row md:items-center md:justify-between"
                  >
                    <div className="space-y-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-semibold">
                          {rule?.name || `策略 ${binding.policyId}`}
                        </span>
                        <Chip
                          color={engine === "nftables" ? "success" : "warning"}
                        >
                          {engine}
                        </Chip>
                        <Chip color={requiresProxy ? "danger" : "success"}>
                          {requiresProxy ? "依赖代理出站" : "无代理依赖"}
                        </Chip>
                      </div>
                      <div className="text-sm text-default-500">
                        {binding.targetType} /{" "}
                        {binding.targetType.includes("tunnel")
                          ? tunnelMap.get(binding.targetId)?.name ||
                            binding.targetId
                          : nodeMap.get(binding.nodeId)?.name || binding.nodeId}
                        {" -> "}
                        执行节点{" "}
                        {nodeMap.get(binding.nodeId)?.name || binding.nodeId}
                      </div>
                      <div className="text-xs text-default-400">
                        动作：{rule?.action || "-"}；规则源：
                        {provider?.name || "无"}；协议：
                        {binding.protocol || "any"}
                      </div>
                      {latestLog && (
                        <div className="flex flex-wrap items-center gap-2 text-xs text-default-500">
                          <Chip
                            color={
                              latestLog.status === "success"
                                ? "success"
                                : latestLog.status === "failed"
                                  ? "danger"
                                  : "default"
                            }
                            size="sm"
                            variant="flat"
                          >
                            {latestLog.action === "remove" ? "撤销" : "下发"} /{" "}
                            {latestLog.status}
                          </Chip>
                          <span className="max-w-[520px] truncate">
                            {latestLog.message || "无节点返回信息"}
                          </span>
                        </div>
                      )}
                    </div>
                    <div className="flex gap-2">
                      <Button
                        isLoading={submitting}
                        size="sm"
                        startContent={<UploadCloud className="h-4 w-4" />}
                        onPress={() => void handleApply(binding.id)}
                      >
                        下发
                      </Button>
                      <Button
                        isLoading={submitting}
                        size="sm"
                        variant="bordered"
                        onPress={() => void handleRemove(binding.id)}
                      >
                        撤销
                      </Button>
                      <Button
                        isIconOnly
                        aria-label="检查策略状态"
                        isLoading={submitting}
                        size="sm"
                        title="检查策略状态"
                        variant="bordered"
                        onPress={() => void handleStatus(binding.id)}
                      >
                        <ShieldCheck className="h-4 w-4" />
                      </Button>
                      <Button
                        color="danger"
                        size="sm"
                        variant="bordered"
                        onPress={() => void handleDeleteBinding(binding.id)}
                      >
                        删除
                      </Button>
                    </div>
                  </div>
                );
              })
            )}
          </CardBody>
        </Card>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <Card className="border border-white/30 bg-white/70 backdrop-blur dark:bg-black/30">
            <CardHeader className="font-semibold">规则源列表</CardHeader>
            <CardBody className="space-y-2">
              {providers.map((provider) => (
                <div
                  key={provider.id}
                  className="flex items-center justify-between rounded-lg border border-divider p-3"
                >
                  <div>
                    <div className="font-medium">{provider.name}</div>
                    <div className="text-xs text-default-500">
                      IP {provider.ipRuleCount || 0} / 域名{" "}
                      {provider.domainRuleCount || 0} / 不支持{" "}
                      {provider.unsupportedCount || 0}
                    </div>
                  </div>
                  <Button
                    color="danger"
                    size="sm"
                    variant="light"
                    onPress={async () => {
                      await deletePolicyProvider(provider.id);
                      await loadData();
                    }}
                  >
                    删除
                  </Button>
                </div>
              ))}
            </CardBody>
          </Card>
          <Card className="border border-white/30 bg-white/70 backdrop-blur dark:bg-black/30">
            <CardHeader className="font-semibold">策略列表</CardHeader>
            <CardBody className="space-y-2">
              {rules.map((rule) => (
                <div
                  key={rule.id}
                  className="flex items-center justify-between rounded-lg border border-divider p-3"
                >
                  <div>
                    <div className="font-medium">{rule.name}</div>
                    <div className="text-xs text-default-500">
                      {rule.matchDirection} / {rule.action} / 优先级{" "}
                      {rule.priority}
                    </div>
                  </div>
                  <Button
                    color="danger"
                    size="sm"
                    variant="light"
                    onPress={async () => {
                      await deletePolicyRule(rule.id);
                      await loadData();
                    }}
                  >
                    删除
                  </Button>
                </div>
              ))}
            </CardBody>
          </Card>
        </div>
      </div>
    </AnimatedPage>
  );
}
