package com.axesistemas.signature.crypto.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.springframework.web.filter.OncePerRequestFilter;

public final class InternalAuthFilter extends OncePerRequestFilter {

  private static final String BEARER_PREFIX = "Bearer ";
  private final byte[] expectedToken;

  public InternalAuthFilter(String token) {
    if (token == null || token.isBlank()) {
      throw new IllegalArgumentException("CRYPTO_INTERNAL_TOKEN_REQUIRED");
    }
    this.expectedToken = token.getBytes(StandardCharsets.UTF_8);
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain
  ) throws ServletException, IOException {
    var authorization = request.getHeader("Authorization");
    if (!authorized(authorization)) {
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      response.setContentType("application/json");
      response.getWriter().write("{\"code\":\"UNAUTHORIZED\"}");
      return;
    }

    filterChain.doFilter(request, response);
  }

  private boolean authorized(String authorization) {
    if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
      return false;
    }
    var supplied = authorization.substring(BEARER_PREFIX.length()).getBytes(StandardCharsets.UTF_8);
    return MessageDigest.isEqual(expectedToken, supplied);
  }
}
