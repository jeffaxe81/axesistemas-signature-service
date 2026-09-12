package com.axesistemas.signature.crypto.pades;

import org.springframework.http.HttpStatus;

public final class PadesError extends RuntimeException {
  private final String code;
  private final HttpStatus status;

  public PadesError(String code, HttpStatus status) {
    super(code);
    this.code = code;
    this.status = status;
  }

  public String code() {
    return code;
  }

  public HttpStatus status() {
    return status;
  }

  public static PadesError unprocessable(String code) {
    return new PadesError(code, HttpStatus.UNPROCESSABLE_ENTITY);
  }

  public static PadesError forbidden(String code) {
    return new PadesError(code, HttpStatus.FORBIDDEN);
  }

  public static PadesError unavailable(String code) {
    return new PadesError(code, HttpStatus.SERVICE_UNAVAILABLE);
  }
}
