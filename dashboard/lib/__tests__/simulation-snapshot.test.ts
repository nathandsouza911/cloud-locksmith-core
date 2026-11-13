import { requireTenantIdentitySnapshot } from "@/lib/simulation";
import type { DirectoryUser } from "@/types";

const user = (id: string, roles: string[] = []) => ({ id, roles }) as unknown as DirectoryUser;

describe("requireTenantIdentitySnapshot", () => {
  it("surfaces the users error instead of 'still loading' when the user list failed", () => {
    const reason = "This needs a full connect to Microsoft.";
    expect(() => requireTenantIdentitySnapshot(null, reason)).toThrow(reason);
  });

  it("says data is still loading when there is no error and no users yet", () => {
    expect(() => requireTenantIdentitySnapshot(null, null)).toThrow("Tenant identity data is still loading.");
  });

  it("returns the snapshot when users are available", () => {
    const snapshot = requireTenantIdentitySnapshot([user("u1", ["Global Administrator"]), user("u2")], null);
    expect(snapshot.users).toEqual(["u1", "u2"]);
    expect(snapshot.roles).toEqual({ "Global Administrator": ["u1"] });
  });
});
