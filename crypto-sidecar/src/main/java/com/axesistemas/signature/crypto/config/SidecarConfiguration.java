package com.axesistemas.signature.crypto.config;

import com.axesistemas.signature.crypto.credentials.CredentialCatalog;
import com.axesistemas.signature.crypto.credentials.CredentialDescriptor;
import com.axesistemas.signature.crypto.credentials.PasswordResolver;
import com.axesistemas.signature.crypto.pades.PadesSigningService;
import com.axesistemas.signature.crypto.pades.PadesValidationService;
import com.axesistemas.signature.crypto.security.InternalAuthFilter;
import java.time.Clock;
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
  PasswordResolver passwordResolver() {
    return envName -> {
      String value = System.getenv(envName);
      if (value == null || value.isBlank()) {
        throw new IllegalArgumentException("CREDENTIAL_UNAVAILABLE");
      }
      return value.toCharArray();
    };
  }

  @Bean
  Clock cryptoClock() {
    return Clock.systemUTC();
  }

  @Bean
  PadesSigningService padesSigningService(
      CredentialCatalog catalog,
      PasswordResolver passwordResolver,
      CryptoProperties properties,
      Clock cryptoClock
  ) {
    return new PadesSigningService(
        catalog,
        passwordResolver,
        properties.getMaxPdfBytes(),
        cryptoClock
    );
  }

  @Bean
  PadesValidationService padesValidationService(CryptoProperties properties) {
    return new PadesValidationService(properties.getMaxPdfBytes());
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
