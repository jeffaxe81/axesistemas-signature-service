package com.axesistemas.signature.crypto.config;

import com.axesistemas.signature.crypto.credentials.CredentialCatalog;
import com.axesistemas.signature.crypto.credentials.CredentialDescriptor;
import com.axesistemas.signature.crypto.security.InternalAuthFilter;
import java.util.stream.Collectors;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SidecarConfiguration {

  @Bean
  CredentialCatalog credentialCatalog(CryptoProperties properties) {
    var descriptors = properties.getCredentials().stream()
        .map(value -> new CredentialDescriptor(
            value.getTenantId(),
            value.getCredentialRef(),
            value.getTrustMode(),
            value.getPkcs12Path(),
            value.getPasswordEnv()
        ))
        .collect(Collectors.toUnmodifiableList());
    return new CredentialCatalog(descriptors);
  }

  @Bean
  FilterRegistrationBean<InternalAuthFilter> internalAuthFilterRegistration(
      CryptoProperties properties
  ) {
    var registration = new FilterRegistrationBean<>(
        new InternalAuthFilter(properties.getInternalToken())
    );
    registration.addUrlPatterns("/internal/*");
    registration.setOrder(1);
    return registration;
  }
}
