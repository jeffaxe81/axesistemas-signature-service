package com.axesistemas.signature.crypto.pades;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.axesistemas.signature.crypto.credentials.CredentialCatalog;
import com.axesistemas.signature.crypto.credentials.CredentialDescriptor;
import com.axesistemas.signature.crypto.credentials.PasswordResolver;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.apache.pdfbox.Loader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PadesSigningServiceTest {

  @TempDir
  Path tempDir;

  private Path pfx;
  private byte[] pdf;

  @BeforeEach
  void setUp() throws Exception {
    pfx = TestPkcs12Factory.create(tempDir);
    try (InputStream input = getClass().getResourceAsStream("/minimal.pdf")) {
      if (input == null) throw new IllegalStateException("minimal.pdf fixture missing");
      pdf = input.readAllBytes();
    }
  }

  @Test
  void signsRealPadesBaselineBAndReturnsSanitizedCertificateMetadata() throws Exception {
    var service = signingService(Clock.systemUTC(), 10_485_760L);
    var result = service.sign(request("none", sha256(pdf)), pdf);

    assertThat(new String(result.signedPdf(), 0, 5, StandardCharsets.US_ASCII)).isEqualTo("%PDF-");
    assertThat(result.metadata().artifactSha256()).isEqualTo(sha256(result.signedPdf()));
    assertThat(result.metadata().engine()).isEqualTo("DSS");
    assertThat(result.metadata().engineVersion()).isEqualTo("6.4");
    assertThat(result.metadata().certificate().fingerprintSha256()).hasSize(64);
    assertThat(result.metadata().certificate().serial()).isNotBlank();
    assertThat(result.metadata().certificate().signatureAlgorithm()).isNotBlank();
    assertThat(result.metadata().certificate().toString())
        .doesNotContain(TestPkcs12Factory.PASSWORD)
        .doesNotContain("privateKey")
        .doesNotContain("keystore");
  }

  @Test
  void standardAppearanceAddsVisibleSignatureField() throws Exception {
    var service = signingService(Clock.systemUTC(), 10_485_760L);
    var result = service.sign(request("standard", sha256(pdf)), pdf);

    try (var document = Loader.loadPDF(result.signedPdf())) {
      var acroForm = document.getDocumentCatalog().getAcroForm();
      assertThat(acroForm).isNotNull();
      assertThat(acroForm.getFields()).isNotEmpty();
    }
  }

  @Test
  void rejectsWrongInputHash() throws Exception {
    var service = signingService(Clock.systemUTC(), 10_485_760L);
    assertThatThrownBy(() -> service.sign(request("none", "0".repeat(64)), pdf))
        .isInstanceOf(PadesError.class)
        .hasMessage("DOCUMENT_HASH_MISMATCH");
  }

  @Test
  void rejectsNonPdfAndOversizedPdf() throws Exception {
    var service = signingService(Clock.systemUTC(), 10_485_760L);
    byte[] notPdf = "not-a-pdf".getBytes(StandardCharsets.UTF_8);
    assertThatThrownBy(() -> service.sign(request("none", sha256(notPdf)), notPdf))
        .isInstanceOf(PadesError.class)
        .hasMessage("PDF_INVALID");

    var tinyLimit = signingService(Clock.systemUTC(), 10L);
    assertThatThrownBy(() -> tinyLimit.sign(request("none", sha256(pdf)), pdf))
        .isInstanceOf(PadesError.class)
        .hasMessage("PDF_TOO_LARGE");
  }

  @Test
  void rejectsCertificateOutsideValidityWindowWithStableCodes() throws Exception {
    var beforeValidity = signingService(
        Clock.fixed(Instant.parse("2000-01-01T00:00:00Z"), ZoneOffset.UTC),
        10_485_760L
    );
    assertThatThrownBy(() -> beforeValidity.sign(request("none", sha256(pdf)), pdf))
        .isInstanceOf(PadesError.class)
        .hasMessage("CERTIFICATE_NOT_YET_VALID");

    var afterValidity = signingService(
        Clock.fixed(Instant.parse("2100-01-01T00:00:00Z"), ZoneOffset.UTC),
        10_485_760L
    );
    assertThatThrownBy(() -> afterValidity.sign(request("none", sha256(pdf)), pdf))
        .isInstanceOf(PadesError.class)
        .hasMessage("CERTIFICATE_EXPIRED");
  }

  private PadesSigningService signingService(Clock clock, long maxPdfBytes) {
    var catalog = new CredentialCatalog(List.of(new CredentialDescriptor(
        "tenant-a",
        "cert-a",
        "production",
        pfx.toString(),
        "TEST_PFX_PASSWORD"
    )));
    PasswordResolver passwordResolver = name -> {
      if (!"TEST_PFX_PASSWORD".equals(name)) throw new IllegalArgumentException("missing env");
      return TestPkcs12Factory.PASSWORD.toCharArray();
    };
    return new PadesSigningService(catalog, passwordResolver, maxPdfBytes, clock);
  }

  private PadesSigningService.SignRequest request(String visualSignature, String inputHash) {
    return new PadesSigningService.SignRequest(
        "tenant-a",
        "req-1",
        "participant-1",
        "cert-a",
        "production",
        sha256(pdf),
        inputHash,
        "B-B",
        visualSignature
    );
  }

  static String sha256(byte[] bytes) {
    try {
      return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (Exception error) {
      throw new IllegalStateException(error);
    }
  }
}
