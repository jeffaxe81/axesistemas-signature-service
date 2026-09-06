import { describe, expect, it } from "vitest";
import { resolveTenantContext } from "./tenantContext.js";

describe("resolveTenantContext", () => {
  it("resolves exactly one server-authorized tenant", () => {
    expect(
      resolveTenantContext({ subject: "dispatch", authorizedTenants: ["tenant-a"] })
    ).toEqual({ tenantId: "tenant-a", subject: "dispatch" });
  });

  it("fails closed for zero tenants", () => {
    expect(() =>
      resolveTenantContext({ subject: "x", authorizedTenants: [] })
    ).toThrow("TENANT_UNRESOLVED");
  });

  it("fails closed for multiple tenants", () => {
    expect(() =>
      resolveTenantContext({ subject: "x", authorizedTenants: ["a", "b"] })
    ).toThrow("TENANT_UNRESOLVED");
  });

  it("deduplicates server-authorized tenants before resolving", () => {
    expect(
      resolveTenantContext({ subject: "dispatch", authorizedTenants: ["tenant-a", "tenant-a"] })
    ).toEqual({ tenantId: "tenant-a", subject: "dispatch" });
  });
});
