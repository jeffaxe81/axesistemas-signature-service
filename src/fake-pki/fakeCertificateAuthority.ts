import {
  createHash,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";

export type FakeCertificate = {
  serial: string;
  subject: string;
  issuer: "AXESISTEMAS FAKE DEV ROOT";
  notBefore: string;
  notAfter: string;
  publicKeyPem: string;
  trustMode: "fake";
};

export type FakeCertificateStatus = "valid" | "expired" | "revoked" | "unknown";

export type FakeCertificateAuthorityOptions = {
  now: () => Date;
};

export class FakeCertificateAuthority {
  private readonly certificates = new Map<string, FakeCertificate>();
  private readonly privateKeys = new Map<string, KeyObject>();
  private readonly revoked = new Set<string>();
  private sequence = 0;

  constructor(
    private readonly options: FakeCertificateAuthorityOptions = {
      now: () => new Date(),
    }
  ) {}

  issue(input: { subject: string; validForSeconds: number }): FakeCertificate {
    const issuedAt = this.options.now();
    const sequence = ++this.sequence;
    const serial = createHash("sha256")
      .update(`${input.subject}|${issuedAt.toISOString()}|${sequence}`)
      .digest("hex");
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const certificate: FakeCertificate = {
      serial,
      subject: input.subject,
      issuer: "AXESISTEMAS FAKE DEV ROOT",
      notBefore: issuedAt.toISOString(),
      notAfter: new Date(
        issuedAt.getTime() + input.validForSeconds * 1000
      ).toISOString(),
      publicKeyPem: publicKey
        .export({ type: "spki", format: "pem" })
        .toString(),
      trustMode: "fake",
    };

    this.certificates.set(serial, certificate);
    this.privateKeys.set(serial, privateKey);
    return structuredClone(certificate);
  }

  revoke(serial: string): void {
    if (this.certificates.has(serial)) {
      this.revoked.add(serial);
    }
  }

  status(serial: string): FakeCertificateStatus {
    const certificate = this.certificates.get(serial);
    if (!certificate) return "unknown";
    if (this.revoked.has(serial)) return "revoked";
    if (new Date(certificate.notAfter).getTime() <= this.options.now().getTime()) {
      return "expired";
    }
    return "valid";
  }

  getCertificate(serial: string): FakeCertificate | null {
    const certificate = this.certificates.get(serial);
    return certificate ? structuredClone(certificate) : null;
  }

  getPrivateKey(serial: string): KeyObject | null {
    return this.privateKeys.get(serial) ?? null;
  }
}
