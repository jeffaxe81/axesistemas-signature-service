import type { TrustMode } from "../trust/capabilities.js";

export type CredentialPolicyEntry = {
  tenantId: string;
  credentialRef: string;
  trustMode: TrustMode;
};

export class CredentialPolicy {
  constructor(private readonly entries: readonly CredentialPolicyEntry[]) {}

  assertAllowed(tenantId: string, credentialRef: string, trustMode: TrustMode): void {
    const allowed = this.entries.some(
      entry =>
        entry.tenantId === tenantId &&
        entry.credentialRef === credentialRef &&
        entry.trustMode === trustMode
    );

    if (!allowed) {
      throw new Error("CREDENTIAL_NOT_ALLOWED");
    }
  }
}
