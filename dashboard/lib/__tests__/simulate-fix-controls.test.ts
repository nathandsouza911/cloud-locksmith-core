import { canSimulateFix, SIMULATE_FIX_CONTROLS } from "../simulate-fix-controls";

describe("SIMULATE_FIX_CONTROLS — allowed set", () => {
  test("contains CA_MFA_ALL_USERS", () => {
    expect(SIMULATE_FIX_CONTROLS.has("CA_MFA_ALL_USERS")).toBe(true);
  });

  test("contains CA_MFA_ADMINS", () => {
    expect(SIMULATE_FIX_CONTROLS.has("CA_MFA_ADMINS")).toBe(true);
  });

  test("does not contain CA_GUEST_MFA", () => {
    expect(SIMULATE_FIX_CONTROLS.has("CA_GUEST_MFA")).toBe(false);
  });

  test("does not contain CA_LEGACY_AUTH_BLOCK", () => {
    expect(SIMULATE_FIX_CONTROLS.has("CA_LEGACY_AUTH_BLOCK")).toBe(false);
  });

  test("does not contain CA_DEVICE_CODE_FLOW_BLOCK", () => {
    expect(SIMULATE_FIX_CONTROLS.has("CA_DEVICE_CODE_FLOW_BLOCK")).toBe(false);
  });

  test("does not contain CA_AUTHENTICATION_TRANSFER_BLOCK", () => {
    expect(SIMULATE_FIX_CONTROLS.has("CA_AUTHENTICATION_TRANSFER_BLOCK")).toBe(false);
  });

  test("does not contain CA_BREAK_GLASS_EXCLUSION", () => {
    expect(SIMULATE_FIX_CONTROLS.has("CA_BREAK_GLASS_EXCLUSION")).toBe(false);
  });

  test("does not contain IDENTITY_BREAK_GLASS_ACCOUNT", () => {
    expect(SIMULATE_FIX_CONTROLS.has("IDENTITY_BREAK_GLASS_ACCOUNT")).toBe(false);
  });

  test("does not contain IDENTITY_MFA_NOT_ENFORCED", () => {
    expect(SIMULATE_FIX_CONTROLS.has("IDENTITY_MFA_NOT_ENFORCED")).toBe(false);
  });

  test("does not contain IDENTITY_LEGACY_AUTH_ALLOWED", () => {
    expect(SIMULATE_FIX_CONTROLS.has("IDENTITY_LEGACY_AUTH_ALLOWED")).toBe(false);
  });

  test("does not contain IDENTITY_USER_CONSENT_ALLOWED", () => {
    expect(SIMULATE_FIX_CONTROLS.has("IDENTITY_USER_CONSENT_ALLOWED")).toBe(false);
  });

  test("does not contain IDENTITY_PASSWORD_PROTECTION_WEAK", () => {
    expect(SIMULATE_FIX_CONTROLS.has("IDENTITY_PASSWORD_PROTECTION_WEAK")).toBe(false);
  });
});

describe("canSimulateFix", () => {
  test("returns true for CA_MFA_ALL_USERS", () => {
    expect(canSimulateFix("CA_MFA_ALL_USERS")).toBe(true);
  });

  test("returns true for CA_MFA_ADMINS", () => {
    expect(canSimulateFix("CA_MFA_ADMINS")).toBe(true);
  });

  test("returns false for CA_GUEST_MFA", () => {
    expect(canSimulateFix("CA_GUEST_MFA")).toBe(false);
  });

  test("returns false for CA_LEGACY_AUTH_BLOCK", () => {
    expect(canSimulateFix("CA_LEGACY_AUTH_BLOCK")).toBe(false);
  });

  test("returns false for CA_DEVICE_CODE_FLOW_BLOCK", () => {
    expect(canSimulateFix("CA_DEVICE_CODE_FLOW_BLOCK")).toBe(false);
  });

  test("returns false for CA_AUTHENTICATION_TRANSFER_BLOCK", () => {
    expect(canSimulateFix("CA_AUTHENTICATION_TRANSFER_BLOCK")).toBe(false);
  });

  test("returns false for CA_BREAK_GLASS_EXCLUSION", () => {
    expect(canSimulateFix("CA_BREAK_GLASS_EXCLUSION")).toBe(false);
  });

  test("returns false for IDENTITY_BREAK_GLASS_ACCOUNT", () => {
    expect(canSimulateFix("IDENTITY_BREAK_GLASS_ACCOUNT")).toBe(false);
  });

  test("returns false for IDENTITY_MFA_NOT_ENFORCED", () => {
    expect(canSimulateFix("IDENTITY_MFA_NOT_ENFORCED")).toBe(false);
  });

  test("returns false for empty string", () => {
    expect(canSimulateFix("")).toBe(false);
  });

  test("returns false for unknown control", () => {
    expect(canSimulateFix("UNKNOWN_CONTROL_XYZ")).toBe(false);
  });
});
