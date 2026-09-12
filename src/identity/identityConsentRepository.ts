import type { ConsentRecord } from "../consent/consentRecord.js";
import type { IdentityEvidence } from "./identityEvidence.js";
import type { IdentitySession } from "./identitySession.js";

export interface IdentityConsentRepository {
  saveSession(session: IdentitySession): Promise<void>;
  getSession(tenantId: string, sessionId: string): Promise<IdentitySession | undefined>;
  saveIdentityEvidence(evidence: IdentityEvidence): Promise<void>;
  getLatestIdentityEvidence(
    tenantId: string,
    requestId: string,
    participantId: string
  ): Promise<IdentityEvidence | undefined>;
  saveConsent(consent: ConsentRecord): Promise<void>;
  getLatestConsent(
    tenantId: string,
    requestId: string,
    participantId: string
  ): Promise<ConsentRecord | undefined>;
}

export class InMemoryIdentityConsentRepository implements IdentityConsentRepository {
  private readonly sessions = new Map<string, IdentitySession>();
  private readonly identityEvidence: IdentityEvidence[] = [];
  private readonly consents: ConsentRecord[] = [];

  async saveSession(session: IdentitySession): Promise<void> {
    this.sessions.set(this.sessionKey(session.tenantId, session.id), session);
  }

  async getSession(
    tenantId: string,
    sessionId: string
  ): Promise<IdentitySession | undefined> {
    return this.sessions.get(this.sessionKey(tenantId, sessionId));
  }

  async saveIdentityEvidence(evidence: IdentityEvidence): Promise<void> {
    const existing = this.identityEvidence.findIndex(
      item => item.tenantId === evidence.tenantId && item.id === evidence.id
    );
    if (existing >= 0) this.identityEvidence.splice(existing, 1);
    this.identityEvidence.push(evidence);
  }

  async getLatestIdentityEvidence(
    tenantId: string,
    requestId: string,
    participantId: string
  ): Promise<IdentityEvidence | undefined> {
    return [...this.identityEvidence]
      .reverse()
      .find(
        item =>
          item.tenantId === tenantId &&
          item.requestId === requestId &&
          item.participantId === participantId
      );
  }

  async saveConsent(consent: ConsentRecord): Promise<void> {
    const existing = this.consents.findIndex(
      item => item.tenantId === consent.tenantId && item.id === consent.id
    );
    if (existing >= 0) this.consents.splice(existing, 1);
    this.consents.push(consent);
  }

  async getLatestConsent(
    tenantId: string,
    requestId: string,
    participantId: string
  ): Promise<ConsentRecord | undefined> {
    return [...this.consents]
      .reverse()
      .find(
        item =>
          item.tenantId === tenantId &&
          item.requestId === requestId &&
          item.participantId === participantId
      );
  }

  private sessionKey(tenantId: string, sessionId: string): string {
    return `${tenantId}:${sessionId}`;
  }
}
