package com.axesistemas.signature.crypto.pades;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import java.nio.charset.StandardCharsets;
import java.util.List;

public final class PadesValidationService {

  private final long maxPdfBytes;

  public PadesValidationService(long maxPdfBytes) {
    this.maxPdfBytes = maxPdfBytes;
  }

  public ValidationResult validate(ValidationRequest request, byte[] signedPdf) {
    validateInput(request, signedPdf);

    try {
      DSSDocument signedDocument = new InMemoryDocument(signedPdf, "signed.pdf");
      SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
      validator.setCertificateVerifier(new CommonCertificateVerifier());

      List<AdvancedSignature> signatures = validator.getSignatures();
      if (signatures.isEmpty()) {
        return invalid(request.trustMode(), 0, 0, "UNKNOWN", "NO_SIGNATURE");
      }

      boolean integrity = true;
      for (AdvancedSignature signature : signatures) {
        try {
          signature.checkSignatureIntegrity();
        } catch (RuntimeException error) {
          integrity = false;
          break;
        }
      }

      Reports reports = validator.validateDocument();
      SimpleReport simple = reports.getSimpleReport();
      String firstSignatureId = simple.getFirstSignatureId();
      String signatureFormat = firstSignatureId == null
          ? "UNKNOWN"
          : String.valueOf(simple.getSignatureFormat(firstSignatureId));
      String indication = firstSignatureId == null
          ? "NO_SIGNATURE"
          : String.valueOf(simple.getIndication(firstSignatureId));

      boolean baselineB = SignatureLevel.PAdES_BASELINE_B.toString().equals(signatureFormat);
      boolean valid = integrity && baselineB && simple.getSignaturesCount() > 0;
      PadesEvidence evidence = new PadesEvidence(
          simple.getSignaturesCount(),
          simple.getValidSignaturesCount(),
          integrity,
          signatureFormat,
          indication
      );

      return new ValidationResult(
          valid,
          valid ? null : "SIGNATURE_VALIDATION_FAILED",
          request.trustMode(),
          "pades",
          "B-B",
          evidence
      );
    } catch (PadesError error) {
      throw error;
    } catch (Exception error) {
      return invalid(request.trustMode(), 0, 0, "UNKNOWN", "VALIDATION_ERROR");
    }
  }

  private void validateInput(ValidationRequest request, byte[] signedPdf) {
    if (signedPdf.length > maxPdfBytes) {
      throw PadesError.unprocessable("PDF_TOO_LARGE");
    }
    if (!isPdf(signedPdf)) {
      throw PadesError.unprocessable("PDF_INVALID");
    }
    if (!PadesSigningService.sha256(signedPdf).equals(request.artifactSha256())) {
      throw PadesError.unprocessable("DOCUMENT_HASH_MISMATCH");
    }
  }

  private ValidationResult invalid(
      String trustMode,
      int signatureCount,
      int validSignatureCount,
      String format,
      String indication
  ) {
    return new ValidationResult(
        false,
        "SIGNATURE_VALIDATION_FAILED",
        trustMode,
        "pades",
        "B-B",
        new PadesEvidence(
            signatureCount,
            validSignatureCount,
            false,
            format,
            indication
        )
    );
  }

  private static boolean isPdf(byte[] bytes) {
    if (bytes.length < 5) return false;
    return new String(bytes, 0, 5, StandardCharsets.US_ASCII).equals("%PDF-");
  }

  public record ValidationRequest(
      String tenantId,
      String requestId,
      String participantId,
      String credentialRef,
      String trustMode,
      String sourceDocumentSha256,
      String artifactSha256
  ) {}

  public record ValidationResult(
      boolean valid,
      String code,
      String trustMode,
      String format,
      String baseline,
      PadesEvidence evidence
  ) {}
}
