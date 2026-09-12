package com.axesistemas.signature.crypto.pades;

import com.axesistemas.signature.crypto.credentials.CredentialCatalog;
import com.axesistemas.signature.crypto.credentials.PasswordResolver;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.DSSJavaFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import java.awt.Font;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore.PasswordProtection;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HexFormat;
import java.util.UUID;

public final class PadesSigningService {

  private static final String ENGINE_VERSION = "6.4";

  private final CredentialCatalog catalog;
  private final PasswordResolver passwordResolver;
  private final long maxPdfBytes;
  private final Clock clock;

  public PadesSigningService(
      CredentialCatalog catalog,
      PasswordResolver passwordResolver,
      long maxPdfBytes,
      Clock clock
  ) {
    this.catalog = catalog;
    this.passwordResolver = passwordResolver;
    this.maxPdfBytes = maxPdfBytes;
    this.clock = clock;
  }

  public SignResult sign(SignRequest request, byte[] pdf) {
    validateRequest(request, pdf);
    var credential = resolveCredential(request);
    char[] password = resolvePassword(credential.passwordEnv());

    try (var token = new Pkcs12SignatureToken(
        new File(credential.pkcs12Path()),
        new PasswordProtection(password)
    )) {
      var keys = token.getKeys();
      if (keys.isEmpty()) {
        throw PadesError.unavailable("CREDENTIAL_UNAVAILABLE");
      }
      DSSPrivateKeyEntry privateKey = keys.get(0);
      validateCertificateTime(privateKey.getCertificate());

      PAdESSignatureParameters parameters = new PAdESSignatureParameters();
      parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
      parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
      parameters.setSigningCertificate(privateKey.getCertificate());
      parameters.setCertificateChain(privateKey.getCertificateChain());
      parameters.bLevel().setSigningDate(Date.from(clock.instant()));
      configureAppearance(parameters, request);

      DSSDocument toSign = new InMemoryDocument(pdf, "document.pdf");
      PAdESService service = new PAdESService(new CommonCertificateVerifier());
      service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
      ToBeSigned dataToSign = service.getDataToSign(toSign, parameters);
      SignatureValue signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
      DSSDocument signedDocument = service.signDocument(toSign, parameters, signatureValue);
      byte[] signedPdf = DSSUtils.toByteArray(signedDocument);

      var certificateMetadata = certificateMetadata(privateKey.getCertificate());
      var metadata = new SignMetadata(
          UUID.randomUUID().toString(),
          sha256(signedPdf),
          request.trustMode(),
          "DSS",
          ENGINE_VERSION,
          certificateMetadata
      );
      return new SignResult(signedPdf, metadata);
    } catch (PadesError error) {
      throw error;
    } catch (Exception error) {
      throw PadesError.unavailable("CREDENTIAL_UNAVAILABLE");
    } finally {
      Arrays.fill(password, '\0');
    }
  }

  private void validateRequest(SignRequest request, byte[] pdf) {
    if (!"B-B".equals(request.baseline())) {
      throw PadesError.unprocessable("UNSUPPORTED_BASELINE");
    }
    if (!"none".equals(request.visualSignature()) && !"standard".equals(request.visualSignature())) {
      throw PadesError.unprocessable("SIGNATURE_GENERATION_FAILED");
    }
    if (pdf.length > maxPdfBytes) {
      throw PadesError.unprocessable("PDF_TOO_LARGE");
    }
    if (!isPdf(pdf)) {
      throw PadesError.unprocessable("PDF_INVALID");
    }
    if (!sha256(pdf).equals(request.inputArtifactSha256())) {
      throw PadesError.unprocessable("DOCUMENT_HASH_MISMATCH");
    }
  }

  private com.axesistemas.signature.crypto.credentials.CredentialDescriptor resolveCredential(SignRequest request) {
    try {
      var credential = catalog.resolve(request.tenantId(), request.credentialRef());
      if (!credential.trustMode().equals(request.trustMode())) {
        throw PadesError.forbidden("CREDENTIAL_NOT_ALLOWED");
      }
      return credential;
    } catch (PadesError error) {
      throw error;
    } catch (IllegalArgumentException error) {
      throw PadesError.unprocessable("CREDENTIAL_NOT_FOUND");
    }
  }

  private char[] resolvePassword(String envName) {
    try {
      char[] password = passwordResolver.resolve(envName);
      if (password == null || password.length == 0) {
        throw PadesError.unavailable("CREDENTIAL_UNAVAILABLE");
      }
      return password;
    } catch (PadesError error) {
      throw error;
    } catch (RuntimeException error) {
      throw PadesError.unavailable("CREDENTIAL_UNAVAILABLE");
    }
  }

  private void validateCertificateTime(CertificateToken certificateToken) {
    X509Certificate certificate = certificateToken.getCertificate();
    Instant now = clock.instant();
    if (now.isBefore(certificate.getNotBefore().toInstant())) {
      throw PadesError.unprocessable("CERTIFICATE_NOT_YET_VALID");
    }
    if (now.isAfter(certificate.getNotAfter().toInstant())) {
      throw PadesError.unprocessable("CERTIFICATE_EXPIRED");
    }
  }

  private void configureAppearance(PAdESSignatureParameters parameters, SignRequest request) {
    if (!"standard".equals(request.visualSignature())) return;

    SignatureImageParameters imageParameters = new SignatureImageParameters();
    SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
    fieldParameters.setPage(1);
    fieldParameters.setOriginX(36);
    fieldParameters.setOriginY(36);
    fieldParameters.setWidth(260);
    fieldParameters.setHeight(60);
    fieldParameters.setFieldId("axesistemas-" + safeFieldId(request.participantId()));
    imageParameters.setFieldParameters(fieldParameters);

    SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
    DSSJavaFont font = new DSSJavaFont(Font.SANS_SERIF);
    font.setSize(9);
    textParameters.setFont(font);
    textParameters.setText(
        "Assinado eletronicamente\nParticipante: " + safeVisualText(request.participantId())
    );
    imageParameters.setTextParameters(textParameters);
    parameters.setImageParameters(imageParameters);
  }

  private CertificateMetadata certificateMetadata(CertificateToken token) throws Exception {
    X509Certificate certificate = token.getCertificate();
    return new CertificateMetadata(
        sha256(certificate.getEncoded()),
        certificate.getSerialNumber().toString(16),
        certificate.getSubjectX500Principal().getName(),
        certificate.getIssuerX500Principal().getName(),
        certificate.getNotBefore().toInstant().toString(),
        certificate.getNotAfter().toInstant().toString(),
        certificate.getSigAlgName()
    );
  }

  private static String safeFieldId(String value) {
    return value.replaceAll("[^A-Za-z0-9_-]", "_").substring(0, Math.min(80, value.length()));
  }

  private static String safeVisualText(String value) {
    String sanitized = value.replaceAll("[\\r\\n\\t]", " ").trim();
    return sanitized.length() <= 120 ? sanitized : sanitized.substring(0, 120);
  }

  private static boolean isPdf(byte[] bytes) {
    if (bytes.length < 5) return false;
    return new String(bytes, 0, 5, StandardCharsets.US_ASCII).equals("%PDF-");
  }

  static String sha256(byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (Exception error) {
      throw new IllegalStateException(error);
    }
  }

  public record SignRequest(
      String tenantId,
      String requestId,
      String participantId,
      String credentialRef,
      String trustMode,
      String sourceDocumentSha256,
      String inputArtifactSha256,
      String baseline,
      String visualSignature
  ) {}

  public record CertificateMetadata(
      String fingerprintSha256,
      String serial,
      String subject,
      String issuer,
      String notBefore,
      String notAfter,
      String signatureAlgorithm
  ) {}

  public record SignMetadata(
      String operationId,
      String artifactSha256,
      String trustMode,
      String engine,
      String engineVersion,
      CertificateMetadata certificate
  ) {}

  public record SignResult(byte[] signedPdf, SignMetadata metadata) {}
}
