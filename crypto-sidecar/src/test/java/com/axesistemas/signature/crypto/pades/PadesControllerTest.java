package com.axesistemas.signature.crypto.pades;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class PadesControllerTest {

  @Test
  void signEndpointReturnsMultipartWithoutSecretMaterial() throws Exception {
    var signing = mock(PadesSigningService.class);
    var validation = mock(PadesValidationService.class);
    byte[] signedPdf = "%PDF-1.7 signed".getBytes(StandardCharsets.US_ASCII);
    var metadata = new PadesSigningService.SignMetadata(
        "op-1",
        "a".repeat(64),
        "production",
        "DSS",
        "6.4",
        new PadesSigningService.CertificateMetadata(
            "f".repeat(64), "01", "CN=Signer", "CN=Issuer",
            "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", "SHA256withRSA"
        )
    );
    when(signing.sign(any(), any())).thenReturn(new PadesSigningService.SignResult(signedPdf, metadata));

    var mvc = MockMvcBuilders
        .standaloneSetup(new PadesController(signing, validation))
        .setControllerAdvice(new PadesController.PadesExceptionHandler())
        .build();

    var metadataPart = new MockMultipartFile(
        "metadata", "metadata.json", MediaType.APPLICATION_JSON_VALUE,
        ("{\"tenantId\":\"tenant-a\",\"requestId\":\"req-1\","
            + "\"participantId\":\"participant-1\",\"credentialRef\":\"cert-a\","
            + "\"trustMode\":\"production\",\"sourceDocumentSha256\":\"" + "b".repeat(64) + "\","
            + "\"inputArtifactSha256\":\"" + "b".repeat(64) + "\","
            + "\"baseline\":\"B-B\",\"visualSignature\":\"none\"}")
            .getBytes(StandardCharsets.UTF_8)
    );
    var documentPart = new MockMultipartFile(
        "document", "document.pdf", MediaType.APPLICATION_PDF_VALUE,
        "%PDF-1.4 test".getBytes(StandardCharsets.US_ASCII)
    );

    mvc.perform(multipart("/internal/v1/pades/sign").file(metadataPart).file(documentPart))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(MediaType.MULTIPART_FORM_DATA));
  }

  @Test
  void stablePadesErrorsReturnOnlyTheAllowlistedCode() throws Exception {
    var signing = mock(PadesSigningService.class);
    var validation = mock(PadesValidationService.class);
    when(signing.sign(any(), any())).thenThrow(PadesError.unprocessable("PDF_INVALID"));

    var mvc = MockMvcBuilders
        .standaloneSetup(new PadesController(signing, validation))
        .setControllerAdvice(new PadesController.PadesExceptionHandler())
        .build();

    var metadataPart = new MockMultipartFile(
        "metadata", "metadata.json", MediaType.APPLICATION_JSON_VALUE,
        ("{\"tenantId\":\"tenant-a\",\"requestId\":\"req-1\","
            + "\"participantId\":\"participant-1\",\"credentialRef\":\"cert-a\","
            + "\"trustMode\":\"production\",\"sourceDocumentSha256\":\"" + "b".repeat(64) + "\","
            + "\"inputArtifactSha256\":\"" + "b".repeat(64) + "\","
            + "\"baseline\":\"B-B\",\"visualSignature\":\"none\"}")
            .getBytes(StandardCharsets.UTF_8)
    );
    var documentPart = new MockMultipartFile(
        "document", "document.pdf", MediaType.APPLICATION_PDF_VALUE,
        "bad".getBytes(StandardCharsets.UTF_8)
    );

    mvc.perform(multipart("/internal/v1/pades/sign").file(metadataPart).file(documentPart))
        .andExpect(status().isUnprocessableEntity())
        .andExpect(content().json("{\"code\":\"PDF_INVALID\"}"));
  }
}
