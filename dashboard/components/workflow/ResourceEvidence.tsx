"use client";

/**
 * The evidence panel: labelled facts plus the fingerprint the decision is
 * bound to. The hash is shown because it is what makes a decision auditable —
 * it is the reason a previously-approved item can reappear.
 */

import type { WorkflowReviewResource } from "@/types/workflow";

export function ResourceEvidence({ resource }: { resource: WorkflowReviewResource }) {
  return (
    <div className="space-y-3">
      <p className="text-sm text-gray-400">{resource.risk_explanation}</p>

      {resource.facts.length > 0 && (
        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
          {resource.facts.map((fact) => (
            <div key={fact.label} className="contents">
              <dt className="text-gray-400">{fact.label}</dt>
              <dd className={fact.emphasis ? "font-medium" : undefined}>
                {fact.value === null || fact.value === undefined ? "—" : String(fact.value)}
              </dd>
            </div>
          ))}
        </dl>
      )}

      <p className="font-mono text-xs text-gray-500">Evidence {resource.evidence_hash}</p>
    </div>
  );
}
