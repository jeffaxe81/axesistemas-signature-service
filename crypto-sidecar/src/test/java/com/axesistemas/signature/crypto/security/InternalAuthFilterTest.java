package com.axesistemas.signature.crypto.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class InternalAuthFilterTest {

  @Test
  void rejectsMissingAuthorizationHeader() throws Exception {
    var filter = new InternalAuthFilter("internal-test-token");
    var request = new MockHttpServletRequest("POST", "/internal/v1/pades/sign");
    var response = new MockHttpServletResponse();

    filter.doFilter(request, response, new MockFilterChain());

    assertThat(response.getStatus()).isEqualTo(401);
  }

  @Test
  void rejectsWrongBearerWithoutEchoingSecret() throws Exception {
    var filter = new InternalAuthFilter("internal-test-token");
    var request = new MockHttpServletRequest("POST", "/internal/v1/pades/sign");
    request.addHeader("Authorization", "Bearer wrong-secret");
    var response = new MockHttpServletResponse();

    filter.doFilter(request, response, new MockFilterChain());

    assertThat(response.getStatus()).isEqualTo(401);
    assertThat(response.getContentAsString()).doesNotContain("wrong-secret");
    assertThat(response.getContentAsString()).doesNotContain("internal-test-token");
  }

  @Test
  void allowsExactBearerToken() throws Exception {
    var filter = new InternalAuthFilter("internal-test-token");
    var request = new MockHttpServletRequest("POST", "/internal/v1/pades/sign");
    request.addHeader("Authorization", "Bearer internal-test-token");
    var response = new MockHttpServletResponse();

    filter.doFilter(request, response, new MockFilterChain());

    assertThat(response.getStatus()).isEqualTo(200);
  }
}
