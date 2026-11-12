"use client";

/**
 * Resources grouped by delta state.
 *
 * Unattended work comes first: a technician should never have to hunt past ten
 * already-approved items to find the four that are new.
 */

import React from "react";

import type { DeltaState } from "@/types/work";
import type { WorkflowReviewAction, WorkflowReviewResource } from "@/types/workflow";
import { ReviewActions } from "./ReviewActions";
import { ResourceEvidence } from "./ResourceEvidence";

const DELTA_LABELS: Record<string, string> = {
  NEW: "New",
  CHANGED: "Changed since last review",
  NEEDS_REVIEW: "Triaged, still open",
  PREVIOUSLY_REVIEWED: "Previously reviewed",
  IGNORED: "Ignored",
  RESOLVED: "Resolved",
};

const ACTIONABLE: DeltaState[] = ["NEW", "CHANGED", "NEEDS_REVIEW"];

interface Props {
  resources: WorkflowReviewResource[];
  actions: WorkflowReviewAction[];
  disabled?: boolean;
  renderResourceDetail?: (resource: WorkflowReviewResource) => React.ReactNode;
  onDecide: (resource: WorkflowReviewResource, decision: string) => void;
}

export function ResourceList({ resources, actions, disabled, renderResourceDetail, onDecide }: Props) {
  const ordered = [...resources].sort((a, b) => {
    const aOpen = ACTIONABLE.includes(a.delta_state as DeltaState) ? 0 : 1;
    const bOpen = ACTIONABLE.includes(b.delta_state as DeltaState) ? 0 : 1;
    return aOpen - bOpen;
  });

  return (
    <ul className="space-y-4">
      {ordered.map((resource) => (
        <li
          key={`${resource.control_id}/${resource.resource_id}`}
          className="rounded-lg border border-gray-800 p-4"
        >
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="font-medium">{resource.title}</p>
              {resource.subtitle && <p className="text-sm text-gray-400">{resource.subtitle}</p>}
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span>{resource.risk_level}</span>
              <span>{DELTA_LABELS[resource.delta_state ?? ""] ?? "—"}</span>
            </div>
          </div>

          {resource.previous_reviewed_by && (
            <p className="mt-1 text-xs text-gray-500">
              {resource.previous_decision} by {resource.previous_reviewed_by}
            </p>
          )}

          <div className="mt-3">
            {renderResourceDetail ? renderResourceDetail(resource) : <ResourceEvidence resource={resource} />}
          </div>

          {ACTIONABLE.includes(resource.delta_state as DeltaState) && (
            <div className="mt-3">
              <ReviewActions
                actions={actions}
                disabled={disabled}
                onDecide={(decision) => onDecide(resource, decision)}
              />
            </div>
          )}
        </li>
      ))}
    </ul>
  );
}
