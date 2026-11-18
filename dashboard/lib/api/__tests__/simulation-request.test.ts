import { runSimulation } from "@/lib/api/endpoints";
import { canSimulateFix } from "@/lib/simulate-fix-controls";

jest.mock("@/lib/auth", () => ({
  getApiBaseUrl: () => "http://api.test",
  getSelectedTenantId: () => "tenant-a",
  getToken: () => null,
}));

test("Simulate Fix sends only the control; the server reads the tenant itself", async () => {
  const fetchMock = jest.fn().mockResolvedValue({
    ok: true,
    status: 200,
    headers: new Headers({ "content-type": "application/json" }),
    json: () => Promise.resolve({}),
  });
  global.fetch = fetchMock as unknown as typeof fetch;

  await runSimulation({ control_id: "CA_MFA_ALL_USERS" });

  const [url, init] = fetchMock.mock.calls[0];
  expect(url).toBe("http://api.test/api/v1/simulations/run");
  expect(JSON.parse(init.body)).toEqual({ control_id: "CA_MFA_ALL_USERS" });
});

test("only the two MFA controls can be simulated", () => {
  expect(canSimulateFix("CA_MFA_ADMINS")).toBe(true);
  expect(canSimulateFix("CA_LEGACY_AUTH_BLOCK")).toBe(false);
});
