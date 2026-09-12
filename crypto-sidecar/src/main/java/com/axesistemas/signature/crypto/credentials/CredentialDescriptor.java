package com.axesistemas.signature.crypto.credentials;

public record CredentialDescriptor(
    String tenantId,
    String credentialRef,
    String trustMode,
    String pkcs12Path,
    String passwordEnv
) {
  public CredentialDescriptor {
    requireNonBlank(tenantId, "tenantId");
    requireNonBlank(credentialRef, "credentialRef");
    requireNonBlank(trustMode, "trustMode");
    requireNonBlank(pkcs12Path, "pkcs12Path");
    requireNonBlank(passwordEnv, "passwordEnv");
  }

  private static void requireNonBlank(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("INVALID_CREDENTIAL_CONFIG:" + name);
    }
  }
}
