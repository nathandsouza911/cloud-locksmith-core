"use client";

/**
 * OAuth Review's resource detail: the permission scopes and their individual
 * risk, which is the whole basis of the revoke decision.
 *
 * This is the only workflow-specific UI in the platform. It replaces the
 * evidence panel and nothing else.
 */

import React from "react";

import { ResourceEvidence } from "@/components/workflow/ResourceEvidence";
import type { WorkflowReviewResource } from "@/types/workflow";

export function OAuthScopeDetail({ resource }: { resource: WorkflowReviewResource }) {
  const scopeRisks = (resource.evidence.scope_risks as Record<string, string> | undefined) ?? {};
  const scopes = (resource.evidence.scopes as string[] | undefined) ?? [];

  return (
    <div className="space-y-3">
      <ResourceEvidence resource={resource} />
      {scopes.length > 0 && (
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-gray-400">
              <th className="font-normal">Permission</th>
              <th className="font-normal">Risk</th>
            </tr>
          </thead>
          <tbody>
            {scopes.map((scope) => (
              <tr key={scope}>
                <td className="font-mono text-xs">{scope}</td>
                <td>{scopeRisks[scope] ?? "MEDIUM"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
