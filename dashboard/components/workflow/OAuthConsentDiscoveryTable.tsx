"use client";

/**
 * Gate 2 validation slice — the minimal, read-only delegated OAuth consent
 * inventory. Deliberately separate from ResourceList (the shared review
 * component every other workflow resource uses): that component renders a
 * risk badge and KEEP/REVOKE/ESCALATE/IGNORE action buttons for every
 * resource, which would put a non-functional "Revoke" button next to a
 * control that is explicitly not executable
 * (IDENTITY_OAUTH_APP_CONSENT_DISCOVERY, is_executable=False on the
 * backend). This component only ever shows the four-column contract:
 * Application, Consented by, Permissions, Date — no risk, no score, no
 * action, no recommendation.
 *
 * Data comes from the same GET /workflows/oauth-review/review endpoint
 * WorkflowReviewPage uses (the backend's composite projector merges both
 * controls into one response) — this component just filters to its own
 * control_id and ignores everything else.
 */

import { Card, ErrorState, TableSkeleton } from "@/components/ui";
import { useWorkflowReview } from "@/lib/api/hooks";
import type { WorkflowReviewResource, WorkflowResourceFact } from "@/types/workflow";

const DISCOVERY_CONTROL_ID = "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY";

function factValue(facts: WorkflowResourceFact[], label: string): string {
  const fact = facts.find((f) => f.label === label);
  if (fact == null || fact.value == null || fact.value === "") return "Unknown";
  return String(fact.value);
}

export function OAuthConsentDiscoveryTable() {
  const { data, loading, error } = useWorkflowReview("oauth-review");

  if (loading) return <TableSkeleton rows={4} cols={4} />;
  if (error) return <ErrorState message={error} />;
  if (!data) return null;

  const rows: WorkflowReviewResource[] = data.resources.filter(
    (resource) => resource.control_id === DISCOVERY_CONTROL_ID,
  );

  return (
    <Card className="p-5 space-y-4">
      <div>
        <h2 className="text-sm font-semibold text-gray-200">Delegated OAuth App Consent</h2>
        <p className="text-xs text-gray-500 mt-1">
          Delegated OAuth permissions currently granted to applications in this tenant, with consent date
          shown where Microsoft&apos;s own records still retain it.
        </p>
      </div>

      {rows.length === 0 ? (
        <p data-testid="discovery-empty-state" className="text-sm text-gray-400">
          No delegated OAuth application grants were found in this tenant.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table data-testid="discovery-table" className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-gray-500">
                <th className="pb-2 pr-4">Application</th>
                <th className="pb-2 pr-4">Consented by</th>
                <th className="pb-2 pr-4">Permissions</th>
                <th className="pb-2">Date</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((resource) => (
                <tr key={resource.resource_id} className="border-t border-gray-800">
                  <td className="py-2 pr-4">{factValue(resource.facts, "Application")}</td>
                  <td className="py-2 pr-4">{factValue(resource.facts, "Consented by")}</td>
                  <td className="py-2 pr-4">{factValue(resource.facts, "Permissions")}</td>
                  <td className="py-2">{factValue(resource.facts, "Date")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
