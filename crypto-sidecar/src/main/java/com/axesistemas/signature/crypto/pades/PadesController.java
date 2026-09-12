package com.axesistemas.signature.crypto.pades;

import java.io.IOException;
import java.util.Map;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/internal/v1/pades")
public class PadesController {

  private final PadesSigningService signingService;
  private final PadesValidationService validationService;

  public PadesController(
      PadesSigningService signingService,
      PadesValidationService validationService
  ) {
    this.signingService = signingService;
    this.validationService = validationService;
  }

  @PostMapping(
      value = "/sign",
      consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
      produces = MediaType.MULTIPART_FORM_DATA_VALUE
  )
  public ResponseEntity<MultiValueMap<String, Object>> sign(
      @RequestPart("metadata") PadesSigningService.SignRequest metadata,
      @RequestPart("document") MultipartFile document
  ) throws IOException {
    var result = signingService.sign(metadata, document.getBytes());
    MultipartBodyBuilder body = new MultipartBodyBuilder();
    body.part("metadata", result.metadata()).contentType(MediaType.APPLICATION_JSON);
    body.part("document", namedResource(result.signedPdf(), "signed.pdf"))
        .contentType(MediaType.APPLICATION_PDF);
    return ResponseEntity.ok()
        .contentType(MediaType.MULTIPART_FORM_DATA)
        .body(body.build());
  }

  @PostMapping(
      value = "/validate",
      consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE
  )
  public PadesValidationService.ValidationResult validate(
      @RequestPart("metadata") PadesValidationService.ValidationRequest metadata,
      @RequestPart("document") MultipartFile document
  ) throws IOException {
    return validationService.validate(metadata, document.getBytes());
  }

  private static ByteArrayResource namedResource(byte[] bytes, String filename) {
    return new ByteArrayResource(bytes) {
      @Override
      public String getFilename() {
        return filename;
      }
    };
  }

  @RestControllerAdvice(assignableTypes = PadesController.class)
  public static class PadesExceptionHandler {
    @ExceptionHandler(PadesError.class)
    public ResponseEntity<Map<String, String>> handle(PadesError error) {
      return ResponseEntity.status(error.status()).body(Map.of("code", error.code()));
    }

    @ExceptionHandler(IOException.class)
    public ResponseEntity<Map<String, String>> handleIo(IOException error) {
      return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
          .body(Map.of("code", "PDF_INVALID"));
    }
  }
}
