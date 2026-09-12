import type {
  FakeCertificate,
  FakeCertificateAuthority,
  FakeCertificateStatus,
} from "./fakeCertificateAuthority.js";

export class FakeCertificateProvider {
  constructor(private readonly authority: FakeCertificateAuthority) {}

  issue(input: { subject: string; validForSeconds: number }): FakeCertificate {
    return this.authority.issue(input);
  }

  revoke(serial: string): void {
    this.authority.revoke(serial);
  }

  status(serial: string): FakeCertificateStatus {
    return this.authority.status(serial);
  }
}
