package com.axesistemas.signature.crypto.pades;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.axesistemas.signature.crypto.credentials.CredentialCatalog;
import com.axesistemas.signature.crypto.credentials.CredentialDescriptor;
import com.axesistemas.signature.crypto.credentials.PasswordResolver;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PadesValidationServiceTest {

  @TempDir
  Path tempDir;

  private byte[] pdf;
  private PadesSigningService signingService;
  private PadesValidationService validationService;

  @BeforeEach
  void setUp() throws Exception {
    Path pfx = TestPkcs12Factory.create(tempDir);
    try (InputStream input = getClass().getResourceAsStream("/minimal.pdf")) {
      if (input == null) throw new IllegalStateException("minimal.pdf fixture missing");
      pdf = input.readAllBytes();
    }
    var catalog = new CredentialCatalog(List.of(new CredentialDescriptor(
        "tenant-a",
        "cert-a",
        "production",
        pfx.toString(),
        "TEST_PFX_PASSWORD"
    )));
    PasswordResolver passwords = ignored -> TestPkcs12Factory.PASSWORD.toCharArray();
    signingService = new PadesSigningService(catalog, passwords, 10_485_760L, Clock.systemUTC());
    validationService = new PadesValidationService(10_485_760L);
  }

  @Test
  void validatesCryptographicIntegrityOfGeneratedPades() {
    var signed = signingService.sign(signRequest(), pdf);
    var validation = validationService.validate(validationRequest(signed, signed.signedPdf()), signed.signedPdf());

    assertThat(validation.valid()).isTrue();
    assertThat(validation.code()).isNull();
    assertThat(validation.trustMode()).isEqualTo("production");
    assertThat(validation.format()).isEqualTo("pades");
    assertThat(validation.baseline()).isEqualTo("B-B");
    assertThat(validation.evidence().signatureCount()).isGreaterThanOrEqualTo(1);
    assertThat(validation.evidence().cryptographicIntegrity()).isTrue();
  }

  @Test
  void detectsMutationInsidePreviouslySignedContent() {
    var signed = signingService.sign(signRequest(), pdf);
    byte[] mutated = signed.signedPdf().clone();
    byte[] needle = "Axesistemas PAdES test".getBytes(StandardCharsets.US_ASCII);
    int offset = indexOf(mutated, needle);
    assertThat(offset).isGreaterThanOrEqualTo(0);
    mutated[offset] = (byte) 'B';

    var validation = validationService.validate(
        validationRequestWithHash(signed, PadesSigningServiceTest.sha256(mutated)),
        mutated
    );

    assertThat(validation.valid()).isFalse();
    assertThat(validation.code()).isEqualTo("SIGNATURE_VALIDATION_FAILED");
    assertThat(validation.evidence().cryptographicIntegrity()).isFalse();
  }

  @Test
  void rejectsValidationWhenArtifactHashDoesNotMatchBytes() {
    var signed = signingService.sign(signRequest(), pdf);
    var request = validationRequestWithHash(signed, "0".repeat(64));

    assertThatThrownBy(() -> validationService.validate(request, signed.signedPdf()))
        .isInstanceOf(PadesError.class)
        .hasMessage("DOCUMENT_HASH_MISMATCH");
  }

  private PadesSigningService.SignRequest signRequest() {
    String hash = PadesSigningServiceTest.sha256(pdf);
    return new PadesSigningService.SignRequest(
        "tenant-a", "req-1", "participant-1", "cert-a", "production",
        hash, hash, "B-B", "none"
    );
  }

  private PadesValidationService.ValidationRequest validationRequest(
      PadesSigningService.SignResult signed,
      byte[] bytes
  ) {
    return validationRequestWithHash(signed, PadesSigningServiceTest.sha256(bytes));
  }

  private PadesValidationService.ValidationRequest validationRequestWithHash(
      PadesSigningService.SignResult signed,
      String hash
  ) {
    return new PadesValidationService.ValidationRequest(
        "tenant-a", "req-1", "participant-1", "cert-a", "production",
        PadesSigningServiceTest.sha256(pdf), hash
    );
  }

  private static int indexOf(byte[] haystack, byte[] needle) {
    outer: for (int i = 0; i <= haystack.length - needle.length; i++) {
      for (int j = 0; j < needle.length; j++) {
        if (haystack[i + j] != needle[j]) continue outer;
      }
      return i;
    }
    return -1;
  }
}
