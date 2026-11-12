/**
 * OAuth Review's scope table — the platform's only workflow-specific UI.
 *
 * It replaces the evidence panel and nothing else, which is what keeps the
 * escape hatch from becoming a second review screen.
 */

import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import React from "react";

import { OAuthScopeDetail } from "../OAuthScopeDetail";

const RESOURCE = {
  control_id: "IDENTITY_ILLICIT_CONSENT_GRANTS",
  resource_id: "g1",
  resource_type: "SERVICE_PRINCIPAL",
  title: "Zapier",
  subtitle: "Zapier Inc.",
  risk_level: "CRITICAL" as const,
  risk_explanation: "Zapier can modify or send data using Mail.ReadWrite.",
  risk_drivers: ["scopes:Mail.ReadWrite"],
  recommended_action: "REVOKE",
  facts: [],
  evidence: {
    scopes: ["Mail.ReadWrite", "User.Read"],
    scope_risks: { "Mail.ReadWrite": "CRITICAL", "User.Read": "LOW" },
  },
  evidence_hash: "hash-1",
  compliance_result_id: 1,
  delta_state: "NEW" as const,
  previous_decision: null,
  previous_reviewed_by: null,
  previous_reviewed_at: null,
};

it("shows each permission and its individual risk", () => {
  render(<OAuthScopeDetail resource={RESOURCE} />);
  expect(screen.getByText("Mail.ReadWrite")).toBeInTheDocument();
  expect(screen.getByText("CRITICAL")).toBeInTheDocument();
  expect(screen.getByText("User.Read")).toBeInTheDocument();
});

it("still shows the shared evidence panel", () => {
  render(<OAuthScopeDetail resource={RESOURCE} />);
  expect(screen.getByText(/hash-1/)).toBeInTheDocument();
});
