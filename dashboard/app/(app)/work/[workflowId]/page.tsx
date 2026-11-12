"use client";

/**
 * Workflow review screen — /work/[workflowId].
 *
 * The route segment is the workflow's URL slug. All behaviour lives in
 * WorkflowReviewPage, which serves every workflow identically.
 */

import React from "react";
import { useParams } from "next/navigation";

import { WorkflowReviewPage } from "@/components/workflow/WorkflowReviewPage";

export default function WorkflowReviewRoute() {
  const params = useParams();
  const workflowKey = String(params.workflowId ?? "");
  return <WorkflowReviewPage workflowKey={workflowKey} />;
}
