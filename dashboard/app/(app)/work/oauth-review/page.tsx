"use client";

/**
 * OAuth Review — /work/oauth-review.
 *
 * Two things share this screen:
 *  - IDENTITY_ILLICIT_CONSENT_GRANTS, reviewed through the normal
 *    KEEP/REVOKE/ESCALATE/IGNORE workflow (WorkflowReviewPage), identical to
 *    every other workflow screen apart from the scope table, which enters
 *    through the one supported escape hatch.
 *  - IDENTITY_OAUTH_APP_CONSENT_DISCOVERY (Gate 2 validation slice), a pure
 *    read-only inventory with no remediation path. It's excluded from the
 *    reviewable list via resourceFilter and rendered separately as a plain
 *    four-column table — see OAuthConsentDiscoveryTable for why it can't
 *    just reuse ResourceList's action buttons.
 */

import React from "react";

import { OAuthConsentDiscoveryTable } from "@/components/workflow/OAuthConsentDiscoveryTable";
import { OAuthScopeDetail } from "@/components/workflow/OAuthScopeDetail";
import { WorkflowReviewPage } from "@/components/workflow/WorkflowReviewPage";

const DISCOVERY_CONTROL_ID = "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY";

export default function OAuthReviewRoute() {
  return (
    <div className="space-y-6">
      <OAuthConsentDiscoveryTable />
      <WorkflowReviewPage
        workflowKey="oauth-review"
        renderResourceDetail={(resource) => <OAuthScopeDetail resource={resource} />}
        resourceFilter={(resource) => resource.control_id !== DISCOVERY_CONTROL_ID}
      />
    </div>
  );
}
