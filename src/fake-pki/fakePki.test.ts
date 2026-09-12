import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { FakeCertificateAuthority } from "./fakeCertificateAuthority.js";
import { FakeSigningProvider } from "./fakeSigningProvider.js";
import { FakeTimestampProvider } from "./fakeTimestampProvider.js";
import { FakeValidationProvider } from "./fakeValidationProvider.js";

const fixedNow = () => new Date("2026-09-12T12:00:00.000Z");

it("emite, assina e valida um artefato fake", async () => {
  const ca = new FakeCertificateAuthority({ now: fixedNow });
  const certificate = ca.issue({ subject: "FAKE TEST Ana", validForSeconds: 3600 });
  const signer = new FakeSigningProvider(ca, certificate.serial);
  const validator = new FakeValidationProvider(ca);
  const signed = await signer.signBytes(Buffer.from("documento"));

  await expect(validator.validateFakeArtifact(signed)).resolves.toMatchObject({
    valid: true,
    trustMode: "fake",
  });
});

it("expõe estados expirado e revogado", () => {
  const ca = new FakeCertificateAuthority({ now: fixedNow });
  const expired = ca.issue({ subject: "FAKE EXPIRED", validForSeconds: -1 });
  expect(ca.status(expired.serial)).toBe("expired");

  const active = ca.issue({ subject: "FAKE REVOKED", validForSeconds: 3600 });
  ca.revoke(active.serial);
  expect(ca.status(active.serial)).toBe("revoked");
});

it("mapeia certificado expirado, revogado e desconhecido", async () => {
  const ca = new FakeCertificateAuthority({ now: fixedNow });
  const expired = ca.issue({ subject: "FAKE EXPIRED", validForSeconds: -1 });
  const expiredSigner = new FakeSigningProvider(ca, expired.serial);
  const validator = new FakeValidationProvider(ca);
  expect((await validator.validateFakeArtifact(await expiredSigner.signBytes(Buffer.from("a")))).code).toBe(
    "CERTIFICATE_EXPIRED"
  );

  const revoked = ca.issue({ subject: "FAKE REVOKED", validForSeconds: 3600 });
  const revokedSigner = new FakeSigningProvider(ca, revoked.serial);
  const revokedArtifact = await revokedSigner.signBytes(Buffer.from("b"));
  ca.revoke(revoked.serial);
  expect((await validator.validateFakeArtifact(revokedArtifact)).code).toBe("CERTIFICATE_REVOKED");

  expect(
    (
      await validator.validateFakeArtifact({
        ...revokedArtifact,
        certificateSerial: "unknown-serial",
      })
    ).code
  ).toBe("CERTIFICATE_UNTRUSTED");
});

it("detecta hash divergente e assinatura adulterada", async () => {
  const ca = new FakeCertificateAuthority({ now: fixedNow });
  const certificate = ca.issue({ subject: "FAKE TEST", validForSeconds: 3600 });
  const signer = new FakeSigningProvider(ca, certificate.serial);
  const validator = new FakeValidationProvider(ca);
  const signed = await signer.signBytes(Buffer.from("documento"));

  expect(
    (
      await validator.validateFakeArtifact({
        ...signed,
        payload: Buffer.from("adulterado"),
      })
    ).code
  ).toBe("DOCUMENT_HASH_MISMATCH");

  expect(
    (
      await validator.validateFakeArtifact({
        ...signed,
        signatureBase64: Buffer.from("assinatura-invalida").toString("base64"),
      })
    ).code
  ).toBe("SIGNATURE_INVALID");
});

it("gera timestamp fake íntegro e rejeita token adulterado", async () => {
  const timestamp = new FakeTimestampProvider({ now: fixedNow });
  const artifactSha256 = createHash("sha256").update("artifact").digest("hex");
  const issued = await timestamp.timestamp({ artifactSha256 });
  expect(timestamp.validateToken(issued.token)).toMatchObject({ valid: true, trustMode: "fake" });

  const decoded = JSON.parse(Buffer.from(issued.token, "base64url").toString("utf8"));
  decoded.artifactSha256 = "0".repeat(64);
  const tampered = Buffer.from(JSON.stringify(decoded)).toString("base64url");
  expect(timestamp.validateToken(tampered)).toMatchObject({ valid: false, code: "TIMESTAMP_INVALID" });
});
