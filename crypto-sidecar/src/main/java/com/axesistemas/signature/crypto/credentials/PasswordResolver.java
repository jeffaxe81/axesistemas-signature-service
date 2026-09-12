package com.axesistemas.signature.crypto.credentials;

@FunctionalInterface
public interface PasswordResolver {
  char[] resolve(String envName);
}
