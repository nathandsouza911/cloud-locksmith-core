"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle, Plus, Shield } from "lucide-react";
import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  PageHeader,
  SeverityBadge,
  StatCard,
  TableSkeleton,
} from "@/components/ui";
import { useBaselineTemplates, useFleetPosture } from "@/lib/api/hooks";
import * as ep from "@/lib/api/endpoints";
import { BADGE_LABELS, BADGE_STYLES, BASELINE_CONTROLS, toSelectableControls } from "@/lib/baselineControls";

type ApplyResult = {
  status: string;
  organization_id: string;
  baseline_name: string;
  controls: string[];
  tenant_count: number;
  tenant_ids: string[];
  message: string;
};

function postureColor(score: number) {
  if (score >= 80) return "#22d3ee";
  if (score >= 60) return "#facc15";
  return "#f87171";
}

function postureValue(score: number | null) {
  return score ?? 0;
}

export default function BaselinesPage() {
  const [selectedControls, setSelectedControls] = useState<string[]>(
    BASELINE_CONTROLS.map((control) => control.id),
  );
  const [selectedTemplateId, setSelectedTemplateId] = useState<string | null>(null);
  const [applyResult, setApplyResult] = useState<ApplyResult | null>(null);
  const [applying, setApplying] = useState(false);
  const [baselineName, setBaselineName] = useState("Default Secure Baseline");
  const [createLoading, setCreateLoading] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const fleetQuery = useFleetPosture();
  const templatesQuery = useBaselineTemplates();
  const tenants = fleetQuery.data?.tenants ?? [];
  const templates = templatesQuery.data ?? [];
  const affectedTenants = tenants.filter((tenant) => tenant.failed_controls > 0);
  const criticalControls = BASELINE_CONTROLS.filter((control) => control.severity === "CRITICAL").length;

  useEffect(() => {
    if (!toast) return undefined;
    const timeout = window.setTimeout(() => setToast(null), 2500);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  useEffect(() => {
    if (templates.length === 0) return;
    const selectedTemplate = templates.find((template) => template.id === selectedTemplateId);
    if (selectedTemplate) return;
    const nextTemplate = templates[0];
    setSelectedTemplateId(nextTemplate.id);
    setBaselineName(nextTemplate.baseline_name);
    setSelectedControls(toSelectableControls(nextTemplate.controls));
  }, [selectedTemplateId, templates]);

  function selectTemplate(template: ep.BaselineTemplate) {
    setSelectedTemplateId(template.id);
    setBaselineName(template.baseline_name);
    setSelectedControls(toSelectableControls(template.controls));
    setApplyResult(null);
    setActionError(null);
  }

  function toggleControl(id: string) {
    setSelectedControls((current) =>
      current.includes(id) ? current.filter((controlId) => controlId !== id) : [...current, id],
    );
    setApplyResult(null);
  }

  async function handleApply(template?: ep.BaselineTemplate) {
    setApplying(true);
    setActionError(null);
    try {
      // organization_id is derived server-side from the authenticated tenant.
      const payload = {
        baseline_name: template?.baseline_name ?? baselineName,
        controls: template?.controls ?? selectedControls,
      };
      if (template) {
        selectTemplate(template);
      }
      const result = await ep.applyBaseline(payload);
      setApplyResult(result);
      setToast(`Applied ${payload.baseline_name}`);
      fleetQuery.refetch();
      templatesQuery.refetch();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Apply failed");
    } finally {
      setApplying(false);
    }
  }

  async function handleCreateBaseline() {
    setCreateLoading(true);
    setActionError(null);
    try {
      const savedTemplate = await ep.createBaselineTemplate(baselineName, selectedControls);
      setToast("Baseline template saved");
      selectTemplate(savedTemplate);
      templatesQuery.refetch();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Save failed");
    } finally {
      setCreateLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Baselines"
        subtitle="Create reusable identity baselines, select them later, and apply the chosen baseline across your tenant fleet."
        actions={
          <div className="flex gap-2">
            <Button variant="primary" size="sm" loading={applying} onClick={() => handleApply()}>
              <CheckCircle size={13} /> Apply Baseline
            </Button>
          </div>
        }
      />

      {toast ? (
        <Card className="px-4 py-3 border-cyan-500/30 bg-cyan-500/10 text-sm text-cyan-100">{toast}</Card>
      ) : null}

      {actionError ? <ErrorState message={actionError} /> : null}

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          label="Controls in Baseline"
          value={selectedControls.length}
          sub={`of ${BASELINE_CONTROLS.length} available`}
          accent="text-cyan-400"
          icon={<Shield size={18} />}
        />
        <StatCard
          label="Tenants Affected"
          value={fleetQuery.loading ? "-" : affectedTenants.length}
          sub="have failed controls"
          accent="text-yellow-400"
          icon={<AlertTriangle size={18} />}
        />
        <StatCard
          label="Critical Controls"
          value={criticalControls}
          sub="highest priority"
          accent="text-red-400"
        />
        <StatCard
          label="Saved Baselines"
          value={templatesQuery.loading ? "-" : templates.length}
          sub="templates available"
          accent="text-green-400"
          icon={<CheckCircle size={18} />}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="overflow-hidden lg:col-span-2">
          <div className="flex items-center justify-between border-b border-gray-800 px-5 py-4">
            <div>
              <p className="text-sm font-semibold text-gray-200">Baseline Controls</p>
              <p className="mt-0.5 text-xs text-gray-500">
                Select controls to include in the active baseline template.
              </p>
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setSelectedControls(BASELINE_CONTROLS.map((control) => control.id))}
                className="text-xs text-cyan-400 transition-colors hover:text-cyan-300"
              >
                Select All
              </button>
              <span className="text-gray-700">|</span>
              <button
                onClick={() => setSelectedControls([])}
                className="text-xs text-gray-400 transition-colors hover:text-gray-200"
              >
                Clear
              </button>
            </div>
          </div>
          <div className="divide-y divide-gray-800/50">
            {BASELINE_CONTROLS.map((control) => {
              const checked = selectedControls.includes(control.id);
              return (
                <label
                  key={control.id}
                  className="flex cursor-pointer items-start gap-4 px-5 py-3.5 transition-colors hover:bg-gray-800/30"
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => toggleControl(control.id)}
                    className="mt-0.5 h-4 w-4 cursor-pointer rounded border-gray-600 bg-gray-800 accent-cyan-500"
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-medium text-gray-200">{control.label}</span>
                      <SeverityBadge value={control.severity} />
                      {control.badges.map((badge) => (
                        <span
                          key={badge}
                          className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-semibold tracking-wide ${BADGE_STYLES[badge]}`}
                        >
                          {BADGE_LABELS[badge]}
                        </span>
                      ))}
                    </div>
                    <p className="mt-0.5 text-xs text-gray-500">{control.description}</p>
                    <p className="mt-0.5 text-[10px] font-mono text-gray-600">{control.id}</p>
                  </div>
                </label>
              );
            })}
          </div>
          <div className="border-t border-gray-800 px-5 py-3">
            <p className="text-[11px] text-gray-500">
              Break-glass account usage and Conditional Access break-glass exclusion are
              <span className="text-gray-400"> always monitored</span> — they are not part of the selectable
              baseline and require manual review when triggered.
            </p>
          </div>
        </Card>

        <div className="space-y-4">
          <Card className="space-y-4 p-5">
            <p className="text-sm font-semibold text-gray-200">Save Baseline Template</p>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-gray-400">Baseline Name</label>
              <input
                value={baselineName}
                onChange={(event) => setBaselineName(event.target.value)}
                className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-200 outline-none transition-colors focus:border-cyan-500"
                placeholder="Default Secure Baseline"
              />
            </div>
            <p className="text-xs text-gray-500">
              {selectedControls.length} control{selectedControls.length !== 1 ? "s" : ""} selected
            </p>
            <Button
              variant="primary"
              size="sm"
              className="w-full justify-center"
              loading={createLoading}
              onClick={handleCreateBaseline}
            >
              <Plus size={13} /> Save Baseline Template
            </Button>
          </Card>

          <Card className="overflow-hidden">
            <div className="border-b border-gray-800 px-5 py-3.5">
              <p className="text-sm font-semibold text-gray-200">Saved Baselines</p>
            </div>
            {templatesQuery.loading ? (
              <div className="p-4">
                <TableSkeleton rows={4} cols={2} />
              </div>
            ) : templatesQuery.error ? (
              <ErrorState message={templatesQuery.error} />
            ) : templates.length === 0 ? (
              <EmptyState message="No saved baselines yet" />
            ) : (
              <div className="divide-y divide-gray-800/50">
                {templates.map((template) => {
                  const selected = template.id === selectedTemplateId;
                  return (
                    <div
                      key={template.id}
                      className={`flex items-center gap-3 px-5 py-3 transition-colors ${selected ? "bg-cyan-500/10" : "hover:bg-gray-800/30"}`}
                    >
                      <button className="min-w-0 flex-1 text-left" onClick={() => selectTemplate(template)}>
                        <p
                          className={`truncate text-sm font-medium ${selected ? "text-cyan-100" : "text-gray-200"}`}
                        >
                          {template.baseline_name}
                        </p>
                        <p className="text-xs text-gray-500">
                          {template.controls.length} control{template.controls.length !== 1 ? "s" : ""}
                        </p>
                      </button>
                      <Button
                        variant={selected ? "primary" : "secondary"}
                        size="sm"
                        loading={applying && selected}
                        onClick={() => handleApply(template)}
                      >
                        Apply
                      </Button>
                    </div>
                  );
                })}
              </div>
            )}
          </Card>

          <Card className="overflow-hidden">
            <div className="border-b border-gray-800 px-5 py-3.5">
              <p className="text-sm font-semibold text-gray-200">Tenants with Baseline Gaps</p>
            </div>
            {fleetQuery.loading ? (
              <div className="p-4">
                <TableSkeleton rows={5} cols={2} />
              </div>
            ) : fleetQuery.error ? (
              <ErrorState message={fleetQuery.error} />
            ) : affectedTenants.length === 0 ? (
              <EmptyState message="All tenants are compliant" />
            ) : (
              <div className="divide-y divide-gray-800/50">
                {affectedTenants.map((tenant) => (
                  <div key={tenant.tenant_id} className="flex items-center gap-3 px-5 py-3">
                    <div
                      className="h-1.5 w-1.5 shrink-0 rounded-full"
                      style={{ background: postureColor(postureValue(tenant.posture_score)) }}
                    />
                    <span className="flex-1 truncate text-sm text-gray-300">{tenant.tenant_name}</span>
                    <span
                      className="text-xs font-bold tabular-nums"
                      style={{ color: postureColor(postureValue(tenant.posture_score)) }}
                    >
                      {tenant.posture_score ?? "-"}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>

      {applyResult ? (
        <Card className="overflow-hidden border border-green-500/30 bg-green-500/5">
          <div className="flex items-center gap-2 border-b border-gray-800/50 px-5 py-4">
            <CheckCircle size={14} className="text-green-400" />
            <p className="text-sm font-semibold text-gray-200">Baseline Applied Successfully</p>
          </div>
          <div className="space-y-2 px-5 py-4">
            <p className="text-sm text-gray-300">{applyResult.message}</p>
            <p className="text-xs text-gray-500">
              Applied <span className="font-medium text-gray-300">{applyResult.baseline_name}</span> with{" "}
              {applyResult.controls.length} control{applyResult.controls.length !== 1 ? "s" : ""}.
            </p>
            <p className="text-xs text-gray-500">
              This updates the desired state only. Remediations remain manual unless executed through the
              remediation workflow.
            </p>
          </div>
        </Card>
      ) : null}
    </div>
  );
}
