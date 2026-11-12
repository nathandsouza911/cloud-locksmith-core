"use client";

/**
 * The workflow review screen — used by every workflow.
 *
 * Renders the panels a technician needs: Summary, Progress, Resources, Delta,
 * Evidence, Review actions and Completion. Everything is driven by the generic
 * API response, so adding a workflow adds no UI.
 *
 * `renderResourceDetail` is the single escape hatch, for a workflow whose
 * resources genuinely need a richer panel (OAuth's scope table). It replaces
 * the evidence panel only — never the surrounding structure.
 */

import React, { useCallback, useState } from "react";
import { useRouter } from "next/navigation";

import { Button, Card, ErrorState, PageHeader, TableSkeleton } from "@/components/ui";
import ConfirmModal from "@/components/ui/ConfirmModal";
import { RunProgress } from "@/components/workflow/RunProgress";
import { ResourceList } from "@/components/workflow/ResourceList";
import { useWorkflowReview } from "@/lib/api/hooks";
import {
  completeWorkflowReview,
  executeWorkflowRemediation,
  simulateWorkflowRemediation,
  submitWorkflowDecision,
} from "@/lib/api/endpoints";
import type { WorkflowRemediationSimulation, WorkflowReviewResource } from "@/types/workflow";

interface Props {
  workflowKey: string;
  renderResourceDetail?: (resource: WorkflowReviewResource) => React.ReactNode;
  /**
   * Excludes matching resources from the reviewable (action-having) list.
   * For a control with no remediation path (e.g. a pure discovery control,
   * is_executable=False on the backend), showing it here would put a
   * non-functional Revoke button next to it — the caller renders it
   * elsewhere, read-only, instead. NOTE: progress/completion counts still
   * come from the unfiltered backend response and may include the excluded
   * resources — a known, accepted limitation for this validation slice.
   */
  resourceFilter?: (resource: WorkflowReviewResource) => boolean;
}

interface PendingRemediation {
  resource: WorkflowReviewResource;
  simulation: WorkflowRemediationSimulation;
}

export function WorkflowReviewPage({ workflowKey, renderResourceDetail, resourceFilter }: Props) {
  const router = useRouter();
  const { data, loading, error, refetch } = useWorkflowReview(workflowKey);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<PendingRemediation | null>(null);

  const recordDecision = useCallback(
    async (resource: WorkflowReviewResource, decision: string) => {
      await submitWorkflowDecision(workflowKey, {
        control_id: resource.control_id,
        resource_id: resource.resource_id,
        decision,
      });
      await refetch();
    },
    [workflowKey, refetch],
  );

  const decide = useCallback(
    async (resource: WorkflowReviewResource, decision: string) => {
      setBusy(true);
      setActionError(null);
      try {
        // REVOKE means "remediate this now" — it must go through simulate and
        // an explicit confirm before anything touches the live tenant. Every
        // other decision (Keep/Ignore/Escalate) is audit-trail-only and can be
        // recorded directly.
        if (decision === "REVOKE") {
          const simulation = await simulateWorkflowRemediation(workflowKey, {
            control_id: resource.control_id,
            resource_ids: [resource.resource_id],
          });
          setPending({ resource, simulation });
          return;
        }
        await recordDecision(resource, decision);
      } catch (err) {
        setActionError(err instanceof Error ? err.message : "Could not record that decision");
      } finally {
        setBusy(false);
      }
    },
    [workflowKey, recordDecision],
  );

  const cancelRemediation = useCallback(() => {
    setPending(null);
    setBusy(false);
  }, []);

  const confirmRemediation = useCallback(async () => {
    // Guards a double-click on the modal's own confirm button while the first
    // execute call is still in flight.
    if (!pending || busy) return;
    const { resource } = pending;
    setBusy(true);
    setActionError(null);
    try {
      await executeWorkflowRemediation(workflowKey, {
        control_id: resource.control_id,
        resource_ids: [resource.resource_id],
        confirmed: true,
      });
      setPending(null);
      await refetch();
    } catch (err) {
      setPending(null);
      setActionError(err instanceof Error ? err.message : "Could not remediate that item");
    } finally {
      setBusy(false);
    }
  }, [pending, busy, workflowKey, refetch]);

  const complete = useCallback(async () => {
    setBusy(true);
    setActionError(null);
    try {
      await completeWorkflowReview(workflowKey);
      // Nothing left to do on this screen once a review is closed — back to
      // the queue of what's still outstanding, same as finishing any other
      // work-queue item.
      router.push("/work");
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Could not complete the review");
      setBusy(false);
    }
  }, [workflowKey, router]);

  if (loading) return <TableSkeleton />;
  if (error) return <ErrorState message={error} />;
  if (!data) return null;

  const { workflow, progress, run, resources: allResources, review_actions } = data;
  const resources = resourceFilter ? allResources.filter(resourceFilter) : allResources;

  return (
    <div className="space-y-6">
      {/* Summary */}
      <PageHeader title={workflow.name} subtitle={workflow.description} />
      {workflow.review_philosophy && (
        <Card className="p-5">
          <p className="text-sm text-gray-400">{workflow.review_philosophy}</p>
        </Card>
      )}

      {/* Progress — RunProgress already renders the resource/reviewed/remaining
          count and percent; a second summary line here would just repeat it. */}
      <Card className="p-5">
        <RunProgress total={progress.total_resources} reviewed={progress.reviewed_resources} />
      </Card>

      {actionError && <ErrorState message={actionError} />}

      {/* Resources + Delta + Evidence + Review actions */}
      <Card>
        <ResourceList
          resources={resources}
          actions={review_actions}
          disabled={busy}
          renderResourceDetail={renderResourceDetail}
          onDecide={decide}
        />
      </Card>

      {/* Completion */}
      <Card className="p-5">
        <Button
          variant="primary"
          onClick={complete}
          disabled={busy || !progress.is_complete || run.state === "COMPLETED"}
        >
          Complete review
        </Button>
      </Card>

      {/* Remediation confirm — REVOKE never executes on a single click. Typed
          confirmation is required because this calls Graph and changes the
          live tenant; there is no undo button in this dialog. */}
      <ConfirmModal
        open={pending !== null}
        title={`Remediate ${pending?.resource.title ?? ""}?`}
        message={pending?.simulation.summary ?? ""}
        confirmLabel="Remediate"
        variant="danger"
        requireTypedConfirm
        onConfirm={confirmRemediation}
        onCancel={cancelRemediation}
      />
    </div>
  );
}
