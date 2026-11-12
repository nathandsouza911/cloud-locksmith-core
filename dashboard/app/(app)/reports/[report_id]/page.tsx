"use client";

import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import { ArrowLeft, ShieldCheck, ShieldX, TrendingUp, TrendingDown, Minus, Code, Users } from "lucide-react";
import { Card, PageHeader, Button, TableSkeleton, ErrorState } from "@/components/ui";
import { useReportAttestation, useArchivedReport, useFleetPosture } from "@/lib/api/hooks";
import { useAuth } from "@/lib/auth-context";

function HashField({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <div className="space-y-1">
      <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">{label}</p>
      <p className="break-all font-mono text-xs text-gray-300">{value ?? "—"}</p>
    </div>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return <p className="mb-4 text-sm font-semibold text-gray-200">{children}</p>;
}

export default function ReportDetailPage() {
  const params = useParams();
  const router = useRouter();
  const { tenantId } = useAuth();
  const [devMode, setDevMode] = useState(false);

  const reportId = typeof params.report_id === "string" ? parseInt(params.report_id, 10) : null;

  const attestationQuery = useReportAttestation(reportId);
  const archivedQuery = useArchivedReport();
  const fleetQuery = useFleetPosture();

  const attestation = attestationQuery.data;
  const archived = archivedQuery.data;
  const fleet = fleetQuery.data;

  const comparison = archived?.payload?.historical_comparison;

  const currentTenant = fleet?.tenants?.find((t) => t.tenant_id === tenantId);
  const showBenchmark = currentTenant !== undefined && fleet !== null && (fleet.fleet_size ?? 0) > 1;

  const loading = attestationQuery.loading || archivedQuery.loading || fleetQuery.loading;

  // Safely extract the nested attestation object — it's a required field per
  // the type but defensive access prevents crashes on unexpected API shapes.
  const attestationObj = attestation?.attestation;

  // Safe JSON for developer mode: guard against null values and non-serializable
  // data that would cause JSON.stringify to throw.
  function safeJson(value: unknown): string {
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return '"[unserializable]"';
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={`Report Integrity #${reportId ?? "…"}`}
        subtitle="Cryptographic verification of report authenticity and chain integrity"
        actions={
          <Button variant="secondary" size="sm" onClick={() => router.back()}>
            <ArrowLeft size={13} /> Back
          </Button>
        }
      />

      {loading ? (
        <TableSkeleton rows={4} cols={2} />
      ) : attestationQuery.error ? (
        <ErrorState message={attestationQuery.error} />
      ) : !attestation ? (
        <ErrorState message="No report found. Generate an evidence report first." />
      ) : (
        <>
          {/* ── Attestation validity banner ─────────────────────────────── */}
          <Card className="p-5">
            <div className="flex items-center gap-3">
              {attestation?.signature_valid ? (
                <ShieldCheck size={24} className="shrink-0 text-green-400" />
              ) : (
                <ShieldX size={24} className="shrink-0 text-red-400" />
              )}
              <div>
                <p className="text-sm font-semibold text-gray-200">
                  {attestation?.signature_valid ? "Attestation Valid" : "Attestation Invalid"}
                </p>
                <p className="text-xs text-gray-400">
                  {attestation?.signature_valid
                    ? "HMAC-SHA256 signature verified. This report has not been tampered with."
                    : "Signature verification failed. Report integrity cannot be confirmed."}
                </p>
              </div>
            </div>
          </Card>

          {/* ── Chain integrity hashes ──────────────────────────────────── */}
          <Card className="p-5">
            <SectionTitle>Chain Integrity</SectionTitle>
            <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
              <HashField label="Content Hash (SHA-256)" value={attestationObj?.content_hash} />
              <HashField label="Chain Hash" value={attestationObj?.chain_hash} />
              <HashField label="Attestation Signature (HMAC-SHA256)" value={attestation?.signature} />
              <div className="space-y-1">
                <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">Generated At</p>
                <p className="text-sm text-gray-300">
                  {attestationObj?.generated_at
                    ? new Date(attestationObj.generated_at).toLocaleString()
                    : "—"}
                </p>
                <p className="text-xs text-gray-500">
                  Attested:{" "}
                  {attestationObj?.attested_at ? new Date(attestationObj.attested_at).toLocaleString() : "—"}
                </p>
              </div>
            </div>

            {Object.keys(attestationObj?.controls_summary ?? {}).length > 0 ? (
              <div className="mt-5 border-t border-gray-800 pt-4">
                <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-gray-400">
                  Controls Summary at Attestation
                </p>
                <div className="flex flex-wrap gap-3">
                  {Object.entries(attestationObj?.controls_summary ?? {}).map(([key, count]) => (
                    <span
                      key={key}
                      className="rounded-full border border-gray-700 bg-gray-800 px-3 py-1 text-xs text-gray-300"
                    >
                      {key.replace(/_/g, " ")}: <span className="font-semibold text-white">{count}</span>
                    </span>
                  ))}
                </div>
              </div>
            ) : null}
          </Card>

          {/* ── Historical comparison ───────────────────────────────────── */}
          {comparison ? (
            <Card className="p-5">
              <SectionTitle>Historical Comparison</SectionTitle>
              <div className="grid grid-cols-3 gap-6">
                <div className="space-y-1">
                  <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">
                    Previous Score
                  </p>
                  <p className="text-3xl font-bold tabular-nums text-gray-300">
                    {comparison.previous_score ?? "—"}
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">
                    Current Score
                  </p>
                  <p className="text-3xl font-bold tabular-nums text-white">
                    {comparison.current_score ?? "—"}
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">Delta</p>
                  {comparison.delta !== null && comparison.delta !== undefined ? (
                    <div className="flex items-center gap-1.5">
                      {comparison.delta > 0 ? (
                        <TrendingUp size={20} className="text-green-400" />
                      ) : comparison.delta < 0 ? (
                        <TrendingDown size={20} className="text-red-400" />
                      ) : (
                        <Minus size={20} className="text-gray-400" />
                      )}
                      <p
                        className={`text-3xl font-bold tabular-nums ${
                          comparison.delta > 0
                            ? "text-green-400"
                            : comparison.delta < 0
                              ? "text-red-400"
                              : "text-gray-400"
                        }`}
                      >
                        {comparison.delta > 0 ? "+" : ""}
                        {comparison.delta}
                      </p>
                    </div>
                  ) : (
                    <p className="text-3xl font-bold text-gray-500">—</p>
                  )}
                </div>
              </div>
              {comparison.improvement_summary ? (
                <p className="mt-4 text-sm text-gray-400">{comparison.improvement_summary}</p>
              ) : null}
            </Card>
          ) : null}

          {/* ── MSP fleet benchmark ─────────────────────────────────────── */}
          {showBenchmark ? (
            <Card className="p-5">
              <div className="mb-4 flex items-center gap-2">
                <Users size={16} className="text-cyan-400" />
                <p className="text-sm font-semibold text-gray-200">MSP Fleet Benchmark</p>
              </div>
              <div className="grid grid-cols-2 gap-6 md:grid-cols-4">
                <div className="space-y-1">
                  <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">This Tenant</p>
                  <p className="text-2xl font-bold tabular-nums text-white">
                    {currentTenant?.posture_score ?? "—"}
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">
                    Fleet Average
                  </p>
                  <p className="text-2xl font-bold tabular-nums text-cyan-400">
                    {fleet?.fleet_avg_score ?? "—"}
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">Percentile</p>
                  <p className="text-2xl font-bold tabular-nums text-white">
                    {currentTenant?.percentile != null ? `${currentTenant.percentile}th` : "—"}
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">Position</p>
                  <p className="text-sm font-semibold text-cyan-300">
                    {currentTenant?.relative_position ?? "—"}
                  </p>
                  <p className="text-xs text-gray-500">{fleet?.fleet_size ?? "—"} tenants in fleet</p>
                </div>
              </div>
            </Card>
          ) : null}

          {/* ── Developer mode ──────────────────────────────────────────── */}
          <div>
            <Button variant={devMode ? "primary" : "ghost"} size="sm" onClick={() => setDevMode((v) => !v)}>
              <Code size={13} /> {devMode ? "Hide" : "Show"} Raw JSON
            </Button>
          </div>
          {devMode ? (
            <Card className="p-5">
              <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-gray-400">
                Raw Attestation + Archived Payload
              </p>
              <pre className="max-h-[600px] overflow-auto rounded-lg bg-gray-950 p-4 text-xs leading-relaxed text-gray-300">
                {safeJson({ attestation: attestation ?? null, archived: archived ?? null })}
              </pre>
            </Card>
          ) : null}
        </>
      )}
    </div>
  );
}
