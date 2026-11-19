import {
  executionAlreadyDone,
  executionSucceeded,
  normalizeExecuteFailureMessage,
} from "../remediation-result";

describe("executionSucceeded", () => {
  it.each([
    [{ status: "success" }, true],
    [{ status: "SUCCESS" }, true],
    [{ status: "executed" }, true],
    [{ status: "failed", remediation_status: "SUCCESS" as const }, true],
    [{ status: "failed" }, false],
    [{ status: "blocked" }, false],
    [{ status: "cooldown_active" }, false],
    [{ status: "backoff_active" }, false],
    [{ status: "already_executing" }, false],
    [{ status: "skipped_no_change" }, false],
    [{ status: "suppressed_for_review" }, false],
    [{ status: "failed", remediation_status: "FAILED" as const }, false],
    [{ status: "" }, false],
    [null, false],
    [undefined, false],
  ])("%j -> %s", (response, expected) => {
    expect(executionSucceeded(response as never)).toBe(expected);
  });
});

describe("normalizeExecuteFailureMessage", () => {
  it("prefers message, then reason, then status", () => {
    expect(normalizeExecuteFailureMessage("failed", "R", "msg")).toBe("msg");
    expect(normalizeExecuteFailureMessage("failed", "R")).toBe("Execution failed: R");
    expect(normalizeExecuteFailureMessage("failed")).toBe("Execution failed: failed");
    expect(normalizeExecuteFailureMessage()).toBe("Execution failed");
  });
});

describe("executionAlreadyDone", () => {
  it.each([
    [{ status: "already_compliant" }, true],
    [{ status: "ALREADY_RESOLVED" }, true],
    [{ status: "success" }, false],
    [{ status: "failed" }, false],
    [null, false],
    [undefined, false],
  ])("%j -> %s", (response, expected) => {
    expect(executionAlreadyDone(response as never)).toBe(expected);
  });
});
