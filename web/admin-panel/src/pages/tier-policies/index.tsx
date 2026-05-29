import { Alert, App as AntdApp, Button, Col, Row, Space, Form, Tooltip } from "antd";
import { PlusOutlined, ThunderboltOutlined, PlayCircleOutlined } from "@ant-design/icons";
import { useCustom, useCustomMutation, useGetIdentity } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { SectionCard } from "./components/section-card";
import { PolicyCard } from "./components/policy-card";
import { ClassifierRulesTable, ClassifierRuleDrawer } from "./components/classifier-rules-table";
import { DryRunPanel } from "./components/dry-run-panel";
import { PageHeader } from "./components/page-header";
import {
  DEFAULT_CONFIG,
  DEFAULT_POLICY,
  TIER_KEYS,
  type ClassifierRule,
  type DryRunResponse,
  type TierConfig,
  type TierKey,
  type TierPolicy,
} from "./types";
import { unwrap } from "./unwrap";

interface Identity {
  role?: string;
}

export const TierPoliciesPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = AntdApp.useApp();
  const { data: identity } = useGetIdentity<Identity>();
  const isAdmin = identity?.role === "admin";
  const rbacTooltip = isAdmin ? "" : t("common.adminRoleRequired");

  const [config, setConfig] = useState<TierConfig>(DEFAULT_CONFIG);
  const [endpointMissing, setEndpointMissing] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [testMethod, setTestMethod] = useState("GET");
  const [testHost, setTestHost] = useState("");
  const [testPath, setTestPath] = useState("/");
  const [testResult, setTestResult] = useState<DryRunResponse | null>(null);

  const isDirty = useRef(false);
  const [form] = Form.useForm<Omit<ClassifierRule, "id">>();

  const { result: loadResult, query: loadQuery } = useCustom<TierConfig>({
    url: "/api/tier-policies",
    method: "get",
    queryOptions: { retry: false },
    errorNotification: false,
  });

  useEffect(() => {
    if (!loadResult?.data) return;
    const cfg = unwrap<TierConfig>(loadResult.data);
    const policies = cfg?.policies;
    if (policies && "critical" in policies && "high" in policies) {
      setConfig({
        policies: {
          critical: policies.critical ?? DEFAULT_POLICY,
          high: policies.high ?? DEFAULT_POLICY,
          medium: policies.medium ?? DEFAULT_POLICY,
          catch_all: policies.catch_all ?? DEFAULT_POLICY,
        },
        classifier_rules: cfg?.classifier_rules ?? [],
      });
      setEndpointMissing(false);
      isDirty.current = false;
    }
  }, [loadResult]);

  useEffect(() => {
    if (loadQuery.isError) setEndpointMissing(true);
  }, [loadQuery.isError]);

  const { mutate: saveConfig, mutation: saveMutation } = useCustomMutation();
  const { mutate: runDryRun, mutation: dryRunMutation } = useCustomMutation();

  const onSave = () => {
    saveConfig(
      { url: "/api/tier-policies", method: "put", values: config },
      {
        onSuccess: () => {
          message.success(t("tierPolicies.saved"));
          isDirty.current = false;
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  const onDryRun = () => {
    runDryRun(
      {
        url: "/api/tier-policies/dry-run",
        method: "post",
        values: { method: testMethod, host: testHost, path: testPath },
      },
      {
        onSuccess: (data) => {
          const res = unwrap<DryRunResponse>(data?.data);
          setTestResult(res ?? { matched_tier: "unknown" });
        },
        onError: () => setTestResult({ matched_tier: t("tierPolicies.dryRunError") }),
      },
    );
  };

  const onPolicyChange = useCallback((key: TierKey, p: TierPolicy) => {
    isDirty.current = true;
    setConfig((prev) => ({ ...prev, policies: { ...prev.policies, [key]: p } }));
  }, []);

  const policyHandlers = useMemo<Record<TierKey, (p: TierPolicy) => void>>(
    () => ({
      critical: (p) => onPolicyChange("critical", p),
      high: (p) => onPolicyChange("high", p),
      medium: (p) => onPolicyChange("medium", p),
      catch_all: (p) => onPolicyChange("catch_all", p),
    }),
    [onPolicyChange],
  );

  const onAddRule = async () => {
    const values = await form.validateFields();
    isDirty.current = true;
    setConfig((prev) => ({
      ...prev,
      classifier_rules: [...prev.classifier_rules, { id: Date.now(), ...values }],
    }));
    form.resetFields();
    setDrawerOpen(false);
  };

  const onDeleteRule = (id: number) => {
    isDirty.current = true;
    setConfig((prev) => ({
      ...prev,
      classifier_rules: prev.classifier_rules.filter((r) => r.id !== id),
    }));
  };

  const tierLabels: Record<TierKey, string> = {
    critical: t("tierPolicies.tierCritical"),
    high: t("tierPolicies.tierHigh"),
    medium: t("tierPolicies.tierMedium"),
    catch_all: t("tierPolicies.tierCatchAll"),
  };

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <PageHeader
        loading={loadQuery.isLoading}
        saving={saveMutation.isPending}
        disabled={endpointMissing}
        isAdmin={isAdmin}
        rbacTooltip={rbacTooltip}
        onRefresh={() => loadQuery.refetch()}
        onSave={onSave}
        t={t}
      />

      {endpointMissing && (
        <Alert
          type="warning"
          showIcon
          message={t("tierPolicies.endpointMissing")}
          description={t("tierPolicies.endpointMissingDesc")}
        />
      )}

      <SectionCard
        icon={<ThunderboltOutlined style={{ color: "#1677ff" }} />}
        title={t("tierPolicies.perTierPolicies")}
      >
        <Row gutter={[12, 12]}>
          {TIER_KEYS.map((key) => (
            <Col key={key} xs={24} sm={12} xl={6}>
              <PolicyCard
                tierKey={key}
                label={tierLabels[key]}
                policy={config?.policies?.[key] ?? DEFAULT_POLICY}
                onChange={policyHandlers[key]}
                disabled={!isAdmin}
                t={t}
              />
            </Col>
          ))}
        </Row>
      </SectionCard>

      <SectionCard
        icon={<ThunderboltOutlined style={{ color: "#722ed1" }} />}
        title={t("tierPolicies.classifierRules")}
        extra={
          <Tooltip title={rbacTooltip}>
            <Button
              size="small"
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => setDrawerOpen(true)}
              disabled={!isAdmin}
            >
              {t("tierPolicies.addRule")}
            </Button>
          </Tooltip>
        }
      >
        <ClassifierRulesTable
          rules={config.classifier_rules}
          onDelete={onDeleteRule}
          disabled={!isAdmin}
          t={t}
          tierLabels={tierLabels}
        />
      </SectionCard>

      <SectionCard
        icon={<PlayCircleOutlined style={{ color: "#13c2c2" }} />}
        title={t("tierPolicies.testClassifier")}
      >
        <DryRunPanel
          method={testMethod}
          host={testHost}
          path={testPath}
          result={testResult}
          running={dryRunMutation.isPending}
          disabled={endpointMissing}
          onMethodChange={setTestMethod}
          onHostChange={setTestHost}
          onPathChange={setTestPath}
          onRun={onDryRun}
          t={t}
        />
      </SectionCard>

      <ClassifierRuleDrawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        onAdd={onAddRule}
        form={form}
        t={t}
        tierLabels={tierLabels}
      />
    </Space>
  );
};
