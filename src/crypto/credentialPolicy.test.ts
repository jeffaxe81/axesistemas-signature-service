import { describe, expect, it } from "vitest";
import { CredentialPolicy } from "./credentialPolicy.js";

describe("CredentialPolicy", () => {
  it("allows the exact tenant, credentialRef and trustMode tuple", () => {
    const policy = new CredentialPolicy([
      { tenantId: "tenant-a", credentialRef: "cert-a", trustMode: "production" },
    ]);

    expect(() => policy.assertAllowed("tenant-a", "cert-a", "production")).not.toThrow();
  });

  it("fails closed when credentialRef is not allowed for tenant", () => {
    const policy = new CredentialPolicy([
      { tenantId: "tenant-a", credentialRef: "cert-a", trustMode: "production" },
    ]);

    expect(() => policy.assertAllowed("tenant-b", "cert-a", "production"))
      .toThrowError("CREDENTIAL_NOT_ALLOWED");
  });

  it("fails closed when trustMode does not match", () => {
    const policy = new CredentialPolicy([
      { tenantId: "tenant-a", credentialRef: "cert-a", trustMode: "fake" },
    ]);

    expect(() => policy.assertAllowed("tenant-a", "cert-a", "production"))
      .toThrowError("CREDENTIAL_NOT_ALLOWED");
  });
});
