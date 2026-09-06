export type AuthIdentity = {
  subject: string;
  authorizedTenants: string[];
};

export type TenantContext = {
  tenantId: string;
  subject: string;
};

export function resolveTenantContext(identity: AuthIdentity): TenantContext {
  const tenants = [
    ...new Set(identity.authorizedTenants.map(value => value.trim()).filter(Boolean)),
  ];

  if (tenants.length !== 1) {
    throw new Error("TENANT_UNRESOLVED");
  }

  return {
    tenantId: tenants[0],
    subject: identity.subject,
  };
}
