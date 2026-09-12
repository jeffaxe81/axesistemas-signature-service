import { createHash } from "node:crypto";
import type {
  CryptoFormatEngine,
  PadesSignInput,
  PadesSignResult,
  PadesValidationInput,
  PadesValidationResult,
} from "./cryptoFormatEngine.js";

export type DssCryptoFormatEngineOptions = {
  baseUrl: string;
  serviceToken: string;
  timeoutMs: number;
  maxPdfBytes: number;
  fetchImpl?: typeof fetch;
};

const ALLOWED_SIDECAR_CODES = new Set([
  "CREDENTIAL_NOT_ALLOWED",
  "CREDENTIAL_NOT_FOUND",
  "CREDENTIAL_UNAVAILABLE",
  "CERTIFICATE_EXPIRED",
  "CERTIFICATE_NOT_YET_VALID",
  "PDF_INVALID",
  "PDF_TOO_LARGE",
  "DOCUMENT_HASH_MISMATCH",
  "UNSUPPORTED_SIGNATURE_FORMAT",
  "UNSUPPORTED_BASELINE",
  "SIGNATURE_GENERATION_FAILED",
  "SIGNATURE_VALIDATION_FAILED",
]);

export class DssCryptoFormatEngine implements CryptoFormatEngine {
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly options: DssCryptoFormatEngineOptions) {
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async signPades(input: PadesSignInput): Promise<PadesSignResult> {
    this.assertPdfSize(input.pdf);
    this.assertHash(input.pdf, input.inputArtifactSha256);

    const response = await this.call(
      "/internal/v1/pades/sign",
      this.buildForm(
        {
          tenantId: input.tenantId,
          requestId: input.requestId,
          participantId: input.participantId,
          credentialRef: input.credentialRef,
          trustMode: input.trustMode,
          sourceDocumentSha256: input.sourceDocumentSha256,
          inputArtifactSha256: input.inputArtifactSha256,
          baseline: input.baseline,
          visualSignature: input.visualSignature,
        },
        input.pdf,
        "document.pdf"
      ),
      "SIGNATURE_GENERATION_FAILED"
    );

    const contentType = response.headers.get("content-type") ?? "";
    if (!contentType.toLowerCase().startsWith("multipart/form-data")) {
      throw new Error("SIGNATURE_GENERATION_FAILED");
    }

    let form: FormData;
    try {
      form = await response.formData();
    } catch {
      throw new Error("SIGNATURE_GENERATION_FAILED");
    }

    const metadata = await readJsonPart(form.get("metadata"));
    const document = form.get("document");
    if (!isRecord(metadata) || !(document instanceof Blob)) {
      throw new Error("SIGNATURE_GENERATION_FAILED");
    }

    const result = parseSignMetadata(metadata);
    const signedPdf = Buffer.from(await document.arrayBuffer());
    const artifactSha256 = sha256(signedPdf);
    if (artifactSha256 !== result.artifactSha256) {
      throw new Error("DOCUMENT_HASH_MISMATCH");
    }

    return { ...result, signedPdf };
  }

  async validatePades(input: PadesValidationInput): Promise<PadesValidationResult> {
    this.assertPdfSize(input.signedPdf);
    this.assertHash(input.signedPdf, input.artifactSha256);

    const response = await this.call(
      "/internal/v1/pades/validate",
      this.buildForm(
        {
          tenantId: input.tenantId,
          requestId: input.requestId,
          participantId: input.participantId,
          sourceDocumentSha256: input.sourceDocumentSha256,
          artifactSha256: input.artifactSha256,
        },
        input.signedPdf,
        "signed.pdf"
      ),
      "SIGNATURE_VALIDATION_FAILED"
    );

    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      throw new Error("SIGNATURE_VALIDATION_FAILED");
    }

    return parseValidationResult(payload);
  }

  private buildForm(metadata: Record<string, unknown>, pdf: Buffer, filename: string): FormData {
    const form = new FormData();
    form.set(
      "metadata",
      new Blob([JSON.stringify(metadata)], { type: "application/json" }),
      "metadata.json"
    );
    form.set(
      "document",
      new Blob([Uint8Array.from(pdf)], { type: "application/pdf" }),
      filename
    );
    return form;
  }

  private async call(path: string, body: FormData, fallbackCode: string): Promise<Response> {
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.options.baseUrl.replace(/\/$/, "")}${path}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${this.options.serviceToken}` },
        body,
        signal: AbortSignal.timeout(this.options.timeoutMs),
      });
    } catch (error) {
      if (
        error instanceof DOMException &&
        (error.name === "TimeoutError" || error.name === "AbortError")
      ) {
        throw new Error("CRYPTO_ENGINE_TIMEOUT");
      }
      throw new Error("CRYPTO_ENGINE_UNAVAILABLE");
    }

    if (response.ok) return response;
    if (response.status === 401 || response.status === 403) {
      throw new Error("CRYPTO_ENGINE_UNAVAILABLE");
    }

    const code = await readAllowlistedErrorCode(response);
    throw new Error(code ?? fallbackCode);
  }

  private assertPdfSize(pdf: Buffer): void {
    if (pdf.byteLength > this.options.maxPdfBytes) {
      throw new Error("PDF_TOO_LARGE");
    }
  }

  private assertHash(pdf: Buffer, expected: string): void {
    if (sha256(pdf) !== expected) {
      throw new Error("DOCUMENT_HASH_MISMATCH");
    }
  }
}

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

async function readAllowlistedErrorCode(response: Response): Promise<string | undefined> {
  if (!(response.headers.get("content-type") ?? "").toLowerCase().includes("application/json")) {
    return undefined;
  }
  try {
    const payload = await response.json();
    if (
      isRecord(payload) &&
      typeof payload.code === "string" &&
      ALLOWED_SIDECAR_CODES.has(payload.code)
    ) {
      return payload.code;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

async function readJsonPart(part: FormDataEntryValue | null): Promise<unknown> {
  if (part instanceof Blob) {
    try {
      return JSON.parse(await part.text()) as unknown;
    } catch {
      return undefined;
    }
  }
  if (typeof part === "string") {
    try {
      return JSON.parse(part) as unknown;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function parseSignMetadata(payload: Record<string, unknown>): Omit<PadesSignResult, "signedPdf"> {
  const certificate = payload.certificate;
  if (
    typeof payload.operationId !== "string" ||
    typeof payload.artifactSha256 !== "string" ||
    !isTrustMode(payload.trustMode) ||
    payload.engine !== "DSS" ||
    typeof payload.engineVersion !== "string" ||
    !isRecord(certificate) ||
    typeof certificate.fingerprintSha256 !== "string" ||
    typeof certificate.serial !== "string" ||
    typeof certificate.notBefore !== "string" ||
    typeof certificate.notAfter !== "string" ||
    typeof certificate.signatureAlgorithm !== "string"
  ) {
    throw new Error("SIGNATURE_GENERATION_FAILED");
  }

  return {
    operationId: payload.operationId,
    artifactSha256: payload.artifactSha256,
    trustMode: payload.trustMode,
    engine: "DSS",
    engineVersion: payload.engineVersion,
    certificate: {
      fingerprintSha256: certificate.fingerprintSha256,
      serial: certificate.serial,
      ...(typeof certificate.subject === "string" ? { subject: certificate.subject } : {}),
      ...(typeof certificate.issuer === "string" ? { issuer: certificate.issuer } : {}),
      notBefore: certificate.notBefore,
      notAfter: certificate.notAfter,
      signatureAlgorithm: certificate.signatureAlgorithm,
    },
  };
}

function parseValidationResult(payload: unknown): PadesValidationResult {
  if (
    !isRecord(payload) ||
    typeof payload.valid !== "boolean" ||
    !isTrustMode(payload.trustMode) ||
    payload.format !== "pades" ||
    payload.baseline !== "B-B" ||
    !isRecord(payload.evidence) ||
    (payload.code !== undefined && typeof payload.code !== "string")
  ) {
    throw new Error("SIGNATURE_VALIDATION_FAILED");
  }

  return {
    valid: payload.valid,
    ...(typeof payload.code === "string" ? { code: payload.code } : {}),
    trustMode: payload.trustMode,
    format: "pades",
    baseline: "B-B",
    evidence: payload.evidence,
  };
}

function isTrustMode(value: unknown): value is "fake" | "sandbox" | "production" {
  return value === "fake" || value === "sandbox" || value === "production";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
