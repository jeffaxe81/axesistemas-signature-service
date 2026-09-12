import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { DssCryptoFormatEngine } from "./dssCryptoFormatEngine.js";
import type { PadesSignInput } from "./cryptoFormatEngine.js";

const sourcePdf = Buffer.from("%PDF-1.7\nsource");
const signedPdf = Buffer.from("%PDF-1.7\nsigned");
const signedHash = createHash("sha256").update(signedPdf).digest("hex");

const signInput: PadesSignInput = {
  tenantId: "tenant-a",
  requestId: "req-1",
  participantId: "participant-1",
  credentialRef: "cert-a",
  trustMode: "production",
  sourceDocumentSha256: createHash("sha256").update(sourcePdf).digest("hex"),
  inputArtifactSha256: createHash("sha256").update(sourcePdf).digest("hex"),
  pdf: sourcePdf,
  baseline: "B-B",
  visualSignature: "none",
};

function signResponse(hash = signedHash): Response {
  const body = new FormData();
  body.set(
    "metadata",
    new Blob([
      JSON.stringify({
        operationId: "op-1",
        artifactSha256: hash,
        trustMode: "production",
        engine: "DSS",
        engineVersion: "6.5",
        certificate: {
          fingerprintSha256: "f".repeat(64),
          serial: "01",
          notBefore: "2026-01-01T00:00:00Z",
          notAfter: "2027-01-01T00:00:00Z",
          signatureAlgorithm: "SHA256withRSA",
        },
      }),
    ], { type: "application/json" })
  );
  body.set("document", new Blob([signedPdf], { type: "application/pdf" }), "signed.pdf");
  return new Response(body, { status: 200 });
}

function engine(fetchImpl: typeof fetch) {
  return new DssCryptoFormatEngine({
    baseUrl: "http://crypto-sidecar:8080",
    serviceToken: "super-secret-token",
    timeoutMs: 2_000,
    maxPdfBytes: 10_485_760,
    fetchImpl,
  });
}

describe("DssCryptoFormatEngine", () => {
  it("sends PDF as multipart with sanitized metadata and internal bearer auth", async () => {
    const fetchImpl = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      expect(init?.method).toBe("POST");
      const headers = new Headers(init?.headers);
      expect(headers.get("authorization")).toBe("Bearer super-secret-token");
      const form = init?.body as FormData;
      const metadataPart = form.get("metadata");
      const documentPart = form.get("document");
      expect(metadataPart).toBeInstanceOf(Blob);
      expect(documentPart).toBeInstanceOf(Blob);
      const metadata = JSON.parse(await (metadataPart as Blob).text()) as Record<string, unknown>;
      expect(metadata).toMatchObject({
        tenantId: "tenant-a",
        requestId: "req-1",
        participantId: "participant-1",
        credentialRef: "cert-a",
        baseline: "B-B",
        visualSignature: "none",
      });
      expect(JSON.stringify(metadata)).not.toContain("super-secret-token");
      expect(JSON.stringify(metadata)).not.toMatch(/password|privateKey|keystore/i);
      expect(Buffer.from(await (documentPart as Blob).arrayBuffer())).toEqual(sourcePdf);
      return signResponse();
    }) as unknown as typeof fetch;

    const result = await engine(fetchImpl).signPades(signInput);
    expect(result.signedPdf).toEqual(signedPdf);
    expect(result.artifactSha256).toBe(signedHash);
  });

  it("rejects a signed PDF whose bytes do not match sidecar artifactSha256", async () => {
    const fetchImpl = vi.fn(async () => signResponse("0".repeat(64))) as unknown as typeof fetch;
    await expect(engine(fetchImpl).signPades(signInput)).rejects.toThrow("DOCUMENT_HASH_MISMATCH");
  });

  it("maps 401 and 403 without leaking the service token", async () => {
    const fetchImpl = vi.fn(async () => new Response("forbidden super-secret-token", { status: 403 })) as unknown as typeof fetch;
    await expect(engine(fetchImpl).signPades(signInput)).rejects.toThrow("CRYPTO_ENGINE_UNAVAILABLE");
    try {
      await engine(fetchImpl).signPades(signInput);
    } catch (error) {
      expect(String(error)).not.toContain("super-secret-token");
    }
  });

  it("maps allowlisted structured sidecar errors to stable domain codes", async () => {
    const fetchImpl = vi.fn(async () =>
      new Response(JSON.stringify({ code: "PDF_INVALID" }), {
        status: 422,
        headers: { "content-type": "application/json" },
      })) as unknown as typeof fetch;
    await expect(engine(fetchImpl).signPades(signInput)).rejects.toThrow("PDF_INVALID");
  });

  it("maps unknown sidecar bodies to a generic signing failure", async () => {
    const fetchImpl = vi.fn(async () => new Response("java stack trace secret=abc", { status: 500 })) as unknown as typeof fetch;
    await expect(engine(fetchImpl).signPades(signInput)).rejects.toThrow("SIGNATURE_GENERATION_FAILED");
  });

  it("maps timeout failures to CRYPTO_ENGINE_TIMEOUT", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new DOMException("timed out", "TimeoutError");
    }) as unknown as typeof fetch;
    await expect(engine(fetchImpl).signPades(signInput)).rejects.toThrow("CRYPTO_ENGINE_TIMEOUT");
  });

  it("validates PAdES through the sidecar and returns only structured result", async () => {
    const fetchImpl = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      const form = init?.body as FormData;
      expect(Buffer.from(await (form.get("document") as Blob).arrayBuffer())).toEqual(signedPdf);
      return new Response(
        JSON.stringify({
          valid: true,
          trustMode: "production",
          format: "pades",
          baseline: "B-B",
          evidence: { signatureCount: 1 },
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }) as unknown as typeof fetch;

    const result = await engine(fetchImpl).validatePades({
      tenantId: "tenant-a",
      requestId: "req-1",
      participantId: "participant-1",
      sourceDocumentSha256: signInput.sourceDocumentSha256,
      artifactSha256: signedHash,
      signedPdf,
    });
    expect(result).toMatchObject({ valid: true, format: "pades", baseline: "B-B" });
  });
});
