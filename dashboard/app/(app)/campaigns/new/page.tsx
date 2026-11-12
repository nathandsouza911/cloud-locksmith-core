"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { Button, Card, PageHeader } from "@/components/ui";
import { useAuth } from "@/lib/auth-context";
import { useCampaignPreview } from "@/lib/api/hooks";
import { createCampaign } from "@/lib/api/campaigns";

// Known SAFE controls from the backend CONTROL_REGISTRY.
// Only controls with auto_remediation_level=SAFE and is_executable=True are permitted.
// The backend enforces this at API time; this list is a frontend affordance only.
const SAFE_CONTROLS = [
  { id: "IDENTITY_UNUSED_ACCOUNT", label: "Identity — Unused Account" },
  { id: "IDENTITY_GUEST_INVITES_OPEN", label: "Identity — Guest Invitations Open" },
  { id: "IDENTITY_USER_CONSENT_POLICY", label: "Identity — User Consent Policy" },
];

export default function NewCampaignPage() {
  const { isSmb, tenants } = useAuth();
  const router = useRouter();

  const [selectedControls, setSelectedControls] = useState<string[]>([]);
  const [selectedTenants, setSelectedTenants] = useState<string[]>([]);
  const [dryRun, setDryRun] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { data: previewData } = useCampaignPreview(selectedControls, selectedTenants);
  const showPreview = selectedControls.length > 0 && selectedTenants.length > 0;

  if (isSmb) {
    router.replace("/dashboard");
    return null;
  }

  function toggleControl(id: string) {
    setSelectedControls((prev) => (prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id]));
  }

  function toggleTenant(id: string) {
    setSelectedTenants((prev) => (prev.includes(id) ? prev.filter((t) => t !== id) : [...prev, id]));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const campaign = await createCampaign({
        control_ids: selectedControls,
        target_tenant_ids: selectedTenants,
        dry_run: dryRun,
      });
      router.push(`/campaigns/${campaign.campaign_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create campaign");
    } finally {
      setLoading(false);
    }
  }

  const canSubmit = selectedControls.length > 0 && selectedTenants.length > 0;

  return (
    <div className="space-y-6">
      <PageHeader title="New Campaign" subtitle="Create a fleet-wide remediation campaign" actions={null} />

      <form onSubmit={handleSubmit} className="space-y-6 max-w-2xl">
        {/* Controls */}
        <Card className="p-5 space-y-4">
          <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider">
            Select Controls to Remediate
          </h2>
          <p className="text-xs text-gray-500">
            Only SAFE controls that can be automatically reversed are shown.
          </p>
          <div className="space-y-2">
            {SAFE_CONTROLS.map((ctrl) => (
              <label
                key={ctrl.id}
                className="flex items-center gap-3 cursor-pointer"
                htmlFor={`ctrl-${ctrl.id}`}
              >
                <input
                  id={`ctrl-${ctrl.id}`}
                  type="checkbox"
                  aria-label={ctrl.id}
                  checked={selectedControls.includes(ctrl.id)}
                  onChange={() => toggleControl(ctrl.id)}
                  className="w-4 h-4 rounded border-gray-600 bg-gray-800 text-cyan-500 focus:ring-cyan-500"
                />
                <span className="text-sm text-gray-300">
                  {ctrl.label}
                  <span className="ml-2 font-mono text-xs text-gray-500">({ctrl.id})</span>
                </span>
              </label>
            ))}
          </div>
        </Card>

        {/* Tenants */}
        <Card className="p-5 space-y-4">
          <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider">
            Select Target Tenants
          </h2>
          <p className="text-xs text-gray-500">
            Campaign will target failing findings across all selected tenants.
          </p>
          {tenants.length === 0 ? (
            <p className="text-sm text-yellow-400">
              No tenants connected. Connect tenants before creating a campaign.
            </p>
          ) : (
            <div className="space-y-2">
              {tenants.map((t) => (
                <label
                  key={t.tenant_id}
                  className="flex items-center gap-3 cursor-pointer"
                  htmlFor={`tenant-${t.tenant_id}`}
                >
                  <input
                    id={`tenant-${t.tenant_id}`}
                    type="checkbox"
                    aria-label={t.tenant_name}
                    checked={selectedTenants.includes(t.tenant_id)}
                    onChange={() => toggleTenant(t.tenant_id)}
                    className="w-4 h-4 rounded border-gray-600 bg-gray-800 text-cyan-500 focus:ring-cyan-500"
                  />
                  <span className="text-sm text-gray-300">{t.tenant_name}</span>
                </label>
              ))}
            </div>
          )}
        </Card>

        {/* Pre-creation finding preview */}
        {showPreview && previewData && previewData.items.length > 0 && (
          <Card className="p-5 space-y-3" data-testid="campaign-preview-panel">
            <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider">Finding Preview</h2>
            <p className="text-xs text-gray-500">
              Active findings that will be remediated per selected tenant.
            </p>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="py-1.5 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">
                    Tenant
                  </th>
                  <th className="py-1.5 text-right text-xs font-semibold text-gray-400 uppercase tracking-wider">
                    Findings
                  </th>
                </tr>
              </thead>
              <tbody>
                {previewData.items.map((item) => (
                  <tr key={item.tenant_id} className="border-b border-gray-800/40">
                    <td className="py-2 text-sm text-gray-300">{item.tenant_name ?? item.tenant_id}</td>
                    <td
                      className={`py-2 text-right text-sm tabular-nums font-semibold ${item.finding_count === 0 ? "text-gray-600" : "text-cyan-400"}`}
                    >
                      {item.finding_count}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        )}

        {/* Dry run */}
        <Card className="p-5">
          <label className="flex items-center gap-3 cursor-pointer" htmlFor="dry-run">
            <input
              id="dry-run"
              type="checkbox"
              checked={dryRun}
              onChange={(e) => setDryRun(e.target.checked)}
              className="w-4 h-4 rounded border-gray-600 bg-gray-800 text-cyan-500 focus:ring-cyan-500"
            />
            <div>
              <p className="text-sm font-medium text-gray-200">Dry Run</p>
              <p className="text-xs text-gray-500">
                Simulate execution without applying any changes to tenants.
              </p>
            </div>
          </label>
        </Card>

        {error && <p className="text-sm text-red-400 px-1">{error}</p>}

        <div className="flex gap-3">
          <Button type="submit" variant="primary" disabled={!canSubmit || loading} loading={loading}>
            Create Campaign
          </Button>
          <Button type="button" variant="secondary" onClick={() => router.push("/campaigns")}>
            Cancel
          </Button>
        </div>
      </form>
    </div>
  );
}
