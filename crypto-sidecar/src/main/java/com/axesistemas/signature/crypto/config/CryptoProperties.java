package com.axesistemas.signature.crypto.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "axesistemas.crypto")
public class CryptoProperties {

  @Min(1)
  private long maxPdfBytes = 10_485_760L;

  @NotBlank
  private String internalToken;

  @Valid
  private List<Credential> credentials = new ArrayList<>();

  public long getMaxPdfBytes() {
    return maxPdfBytes;
  }

  public void setMaxPdfBytes(long maxPdfBytes) {
    this.maxPdfBytes = maxPdfBytes;
  }

  public String getInternalToken() {
    return internalToken;
  }

  public void setInternalToken(String internalToken) {
    this.internalToken = internalToken;
  }

  public List<Credential> getCredentials() {
    return credentials;
  }

  public void setCredentials(List<Credential> credentials) {
    this.credentials = credentials == null ? new ArrayList<>() : new ArrayList<>(credentials);
  }

  public static class Credential {
    @NotBlank
    private String tenantId;

    @NotBlank
    private String credentialRef;

    @NotBlank
    private String trustMode;

    @NotBlank
    private String pkcs12Path;

    @NotBlank
    private String passwordEnv;

    public String getTenantId() {
      return tenantId;
    }

    public void setTenantId(String tenantId) {
      this.tenantId = tenantId;
    }

    public String getCredentialRef() {
      return credentialRef;
    }

    public void setCredentialRef(String credentialRef) {
      this.credentialRef = credentialRef;
    }

    public String getTrustMode() {
      return trustMode;
    }

    public void setTrustMode(String trustMode) {
      this.trustMode = trustMode;
    }

    public String getPkcs12Path() {
      return pkcs12Path;
    }

    public void setPkcs12Path(String pkcs12Path) {
      this.pkcs12Path = pkcs12Path;
    }

    public String getPasswordEnv() {
      return passwordEnv;
    }

    public void setPasswordEnv(String passwordEnv) {
      this.passwordEnv = passwordEnv;
    }
  }
}
