package com.axesistemas.signature.crypto.credentials;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;

class CredentialCatalogTest {

  @Test
  void resolvesOnlyExactTenantAndCredentialRef() {
    var descriptor = new CredentialDescriptor(
        "tenant-a",
        "cert-a",
        "production",
        "/run/secrets/cert-a.p12",
        "CERT_A_PASSWORD"
    );
    var catalog = new CredentialCatalog(List.of(descriptor));

    assertThat(catalog.resolve("tenant-a", "cert-a")).isSameAs(descriptor);
  }

  @Test
  void failsClosedAcrossTenantsWithoutRevealingCredentialExistence() {
    var catalog = new CredentialCatalog(List.of(new CredentialDescriptor(
        "tenant-a",
        "cert-a",
        "production",
        "/run/secrets/cert-a.p12",
        "CERT_A_PASSWORD"
    )));

    assertThatThrownBy(() -> catalog.resolve("tenant-b", "cert-a"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("CREDENTIAL_NOT_FOUND");
  }
}
