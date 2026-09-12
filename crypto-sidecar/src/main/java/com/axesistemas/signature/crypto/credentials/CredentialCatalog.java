package com.axesistemas.signature.crypto.credentials;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class CredentialCatalog {

  private final Map<String, CredentialDescriptor> credentials;

  public CredentialCatalog(List<CredentialDescriptor> descriptors) {
    this.credentials = new HashMap<>();
    for (var descriptor : descriptors) {
      var key = key(descriptor.tenantId(), descriptor.credentialRef());
      if (credentials.putIfAbsent(key, descriptor) != null) {
        throw new IllegalArgumentException("DUPLICATE_CREDENTIAL_CONFIG");
      }
    }
  }

  public CredentialDescriptor resolve(String tenantId, String credentialRef) {
    var descriptor = credentials.get(key(tenantId, credentialRef));
    if (descriptor == null) {
      throw new IllegalArgumentException("CREDENTIAL_NOT_FOUND");
    }
    return descriptor;
  }

  private static String key(String tenantId, String credentialRef) {
    return tenantId + "\u0000" + credentialRef;
  }
}
