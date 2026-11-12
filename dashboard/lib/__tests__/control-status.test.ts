/**
 * Tests for lib/control-status.ts -- pure decision logic extracted from
 * controls/page.tsx so it can be verified without a React render.
 *
 * RED phase: all tests fail until the module is created.
 */

import { deriveNonCaStatus, buildControlButtonState } from "../control-status";
import type { ComplianceResult } from "@/types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeResult(overrides: Partial<ComplianceResult> = {}): ComplianceResult {
  return {
    id: "r1",
    tenant_id: "t1",
    control_id: "IDENTITY_ILLICIT_CONSENT_GRANTS",
    resource_id: "t1",
    passed: false,
    severity: "CRITICAL",
    evidence: {},
    decision_status: "PENDING",
    evaluated_at: new Date().toISOString(),
    ...overrides,
  };
}

function makeCapability(mode: "auto" | "manual" | "blocked", extra: Record<string, unknown> = {}) {
  return {
    allowed: mode !== "blocked",
    mode,
    reason: mode === "blocked" ? "capability_unavailable" : "manual_remediate",
    notes: "",
    ...extra,
  } as import("@/types").ControlCapabilityDecision;
}

// ---------------------------------------------------------------------------
// PART 3 -- deriveNonCaStatus: COMPLIANT replaces ENFORCED
// ---------------------------------------------------------------------------

describe("deriveNonCaStatus", () => {
  test("returns NOT_CONFIGURED when no results exist", () => {
    const { status } = deriveNonCaStatus("IDENTITY_ILLICIT_CONSENT_GRANTS", []);
    expect(status).toBe("NOT_CONFIGURED");
  });

  test("returns NOT_CONFIGURED when latest result has passed=false", () => {
    const { status } = deriveNonCaStatus("IDENTITY_ILLICIT_CONSENT_GRANTS", [makeResult({ passed: false })]);
    expect(status).toBe("NOT_CONFIGURED");
  });

  test("returns PARTIAL when remediation_status is FAILED", () => {
    const { status } = deriveNonCaStatus("IDENTITY_ILLICIT_CONSENT_GRANTS", [
      makeResult({ passed: true, remediation_status: "FAILED" }),
    ]);
    expect(status).toBe("PARTIAL");
  });

  test("returns PARTIAL when remediation_status is BLOCKED", () => {
    const { status } = deriveNonCaStatus("IDENTITY_ILLICIT_CONSENT_GRANTS", [
      makeResult({ passed: true, remediation_status: "BLOCKED" }),
    ]);
    expect(status).toBe("PARTIAL");
  });

  test("returns COMPLIANT (not ENFORCED) when latest result passed=true", () => {
    const { status } = deriveNonCaStatus("IDENTITY_ILLICIT_CONSENT_GRANTS", [makeResult({ passed: true })]);
    expect(status).toBe("COMPLIANT");
    expect(status).not.toBe("ENFORCED");
  });

  test("picks the most-recent result when multiple exist for same control", () => {
    const older = makeResult({
      passed: false,
      evaluated_at: "2024-01-01T00:00:00Z",
    });
    const newer = makeResult({
      passed: true,
      evaluated_at: "2024-06-01T00:00:00Z",
    });
    const { status } = deriveNonCaStatus("IDENTITY_ILLICIT_CONSENT_GRANTS", [older, newer]);
    expect(status).toBe("COMPLIANT");
  });

  test("ignores results for other control IDs", () => {
    const { status } = deriveNonCaStatus("IDENTITY_USER_CONSENT_POLICY", [
      makeResult({ control_id: "IDENTITY_ILLICIT_CONSENT_GRANTS", passed: true }),
    ]);
    expect(status).toBe("NOT_CONFIGURED");
  });

  test("returns the associated finding when found", () => {
    const result = makeResult({ passed: false });
    const { finding } = deriveNonCaStatus("IDENTITY_ILLICIT_CONSENT_GRANTS", [result]);
    expect(finding).toBe(result);
  });

  test("returns undefined finding when no results exist", () => {
    const { finding } = deriveNonCaStatus("IDENTITY_ILLICIT_CONSENT_GRANTS", []);
    expect(finding).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// PART 2 -- buildControlButtonState: disabled/label for COMPLIANT findings
// ---------------------------------------------------------------------------

describe("buildControlButtonState -- compliant finding guard", () => {
  test("returns disabled button with Compliant label when status is COMPLIANT", () => {
    const cap = makeCapability("manual");
    const state = buildControlButtonState("IDENTITY_ILLICIT_CONSENT_GRANTS", cap, "COMPLIANT");
    expect(state.buttonDisabled).toBe(true);
    expect(state.buttonLabel).toMatch(/compliant/i);
  });

  test("COMPLIANT disables button even when capability is auto", () => {
    const cap = makeCapability("auto");
    const state = buildControlButtonState("IDENTITY_ILLICIT_CONSENT_GRANTS", cap, "COMPLIANT");
    expect(state.buttonDisabled).toBe(true);
  });

  test("NOT_CONFIGURED + manual capability keeps Review and Fix enabled", () => {
    const cap = makeCapability("manual");
    const state = buildControlButtonState("IDENTITY_ILLICIT_CONSENT_GRANTS", cap, "NOT_CONFIGURED");
    expect(state.buttonDisabled).toBe(false);
    expect(state.buttonLabel).toMatch(/review/i);
  });
});

// ---------------------------------------------------------------------------
// PART 1 -- buildControlButtonState: CA_BREAK_GLASS_EXCLUSION license gate
// ---------------------------------------------------------------------------

describe("buildControlButtonState -- CA_BREAK_GLASS_EXCLUSION license gate", () => {
  test("shows License Required when ca_license_available=false", () => {
    const cap = makeCapability("manual", { ca_license_available: false });
    const state = buildControlButtonState("CA_BREAK_GLASS_EXCLUSION", cap, "NOT_CONFIGURED");
    expect(state.buttonLabel).toMatch(/license required/i);
    expect(state.buttonDisabled).toBe(true);
  });

  test("shows Review and Fix when ca_license_available=true", () => {
    const cap = makeCapability("manual", { ca_license_available: true });
    const state = buildControlButtonState("CA_BREAK_GLASS_EXCLUSION", cap, "NOT_CONFIGURED");
    expect(state.buttonLabel).not.toMatch(/license required/i);
    expect(state.buttonDisabled).toBe(false);
  });

  test("other CA controls still show License Required when unlicensed", () => {
    for (const controlId of ["CA_MFA_ALL_USERS", "CA_MFA_ADMINS", "CA_LEGACY_AUTH_BLOCK"]) {
      const cap = makeCapability("manual", { ca_license_available: false });
      const state = buildControlButtonState(controlId, cap, "NOT_CONFIGURED");
      expect(state.buttonLabel).toMatch(/license required/i);
      expect(state.buttonDisabled).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// Regression: existing non-CA manual behavior unchanged
// ---------------------------------------------------------------------------

describe("buildControlButtonState -- non-CA manual (existing behavior)", () => {
  test("IDENTITY_USER_CONSENT_POLICY NOT_CONFIGURED shows Review and Fix enabled", () => {
    const cap = makeCapability("manual");
    const state = buildControlButtonState("IDENTITY_USER_CONSENT_POLICY", cap, "NOT_CONFIGURED");
    expect(state.buttonLabel).toMatch(/review/i);
    expect(state.buttonDisabled).toBe(false);
  });

  test("blocked capability disables button regardless of status", () => {
    const cap = makeCapability("blocked");
    const state = buildControlButtonState("IDENTITY_USER_CONSENT_POLICY", cap, "NOT_CONFIGURED");
    expect(state.buttonDisabled).toBe(true);
  });
});
