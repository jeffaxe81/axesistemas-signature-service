package com.axesistemas.signature.crypto;

import com.axesistemas.signature.crypto.config.CryptoProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(CryptoProperties.class)
public class CryptoSidecarApplication {

  public static void main(String[] args) {
    SpringApplication.run(CryptoSidecarApplication.class, args);
  }
}
