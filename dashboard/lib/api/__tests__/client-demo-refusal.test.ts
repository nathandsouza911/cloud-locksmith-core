import { ApiError, api } from "@/lib/api/client";

jest.mock("@/lib/auth", () => ({
  getApiBaseUrl: () => "http://api.test",
  getSelectedTenantId: () => "demo-tenant",
  getToken: () => null,
}));

function respondWith(status: number, body: unknown) {
  global.fetch = jest.fn().mockResolvedValue({
    ok: status < 400,
    status,
    statusText: "Forbidden",
    text: () => Promise.resolve(JSON.stringify(body)),
    headers: new Headers({ "content-type": "application/json" }),
  }) as unknown as typeof fetch;
}

test("a write refused by demo mode explains itself in plain words", async () => {
  respondWith(403, { detail: "disabled_in_demo_mode" });

  const error = (await api
    .post("/api/v1/remediation/decisions/by-result/1/approve")
    .catch((e: unknown) => e)) as ApiError;

  expect(error).toBeInstanceOf(ApiError);
  expect(error.status).toBe(403);
  expect(error.code).toBe("disabled_in_demo_mode");
  expect(error.message).toMatch(/demo/i);
  expect(error.message).not.toBe("disabled_in_demo_mode");
});

test("other 403 details are passed through unchanged", async () => {
  respondWith(403, { detail: "Approval expired" });

  const error = (await api.post("/api/v1/x").catch((e: unknown) => e)) as ApiError;

  expect(error.message).toBe("Approval expired");
});
