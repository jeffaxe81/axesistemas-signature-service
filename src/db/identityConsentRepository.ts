import { and, desc, eq } from "drizzle-orm";
import type { NodePgDatabase } from "drizzle-orm/node-postgres";
import type { ConsentRecord, ConsentDecision, ConsentStatus } from "../consent/consentRecord.js";
import type { IdentityEvidence } from "../identity/identityEvidence.js";
import type {
  AuthenticationMethod,
  IdentityAssurance,
} from "../identity/identityPolicy.js";
import type { IdentityConsentRepository } from "../identity/identityConsentRepository.js";
import type {
  IdentitySession,
  IdentitySessionStatus,
} from "../identity/identitySession.js";
import {
  consentRecords,
  identityEvidences,
  identitySessions,
} from "./schema.js";
import * as schema from "./schema.js";

export class DrizzleIdentityConsentRepository implements IdentityConsentRepository {
  constructor(private readonly db: NodePgDatabase<typeof schema>) {}

  async saveSession(session: IdentitySession): Promise<void> {
    await this.db
      .insert(identitySessions)
      .values({
        tenantId: session.tenantId,
        id: session.id,
        requestId: session.requestId,
        participantId: session.participantId,
        providerId: session.providerId,
        providerSessionId: session.providerSessionId,
        method: session.method,
        purpose: session.purpose,
        status: session.status,
        challengeId: session.challengeId,
        challengeDigest: session.challengeDigest,
        expiresAt: session.expiresAt,
        attemptCount: session.attemptCount,
        maxAttempts: session.maxAttempts,
        createdAt: session.createdAt,
        updatedAt: session.updatedAt,
        completedAt: session.completedAt ?? null,
      })
      .onConflictDoUpdate({
        target: [identitySessions.tenantId, identitySessions.id],
        set: {
          providerSessionId: session.providerSessionId,
          status: session.status,
          challengeDigest: session.challengeDigest,
          expiresAt: session.expiresAt,
          attemptCount: session.attemptCount,
          maxAttempts: session.maxAttempts,
          updatedAt: session.updatedAt,
          completedAt: session.completedAt ?? null,
        },
      });
  }

  async getSession(
    tenantId: string,
    sessionId: string
  ): Promise<IdentitySession | undefined> {
    const [row] = await this.db
      .select()
      .from(identitySessions)
      .where(and(eq(identitySessions.tenantId, tenantId), eq(identitySessions.id, sessionId)))
      .limit(1);

    return row ? mapSession(row) : undefined;
  }

  async saveIdentityEvidence(evidence: IdentityEvidence): Promise<void> {
    await this.db
      .insert(identityEvidences)
      .values({
        tenantId: evidence.tenantId,
        id: evidence.id,
        requestId: evidence.requestId,
        participantId: evidence.participantId,
        identitySessionId: evidence.identitySessionId,
        providerId: evidence.providerId,
        method: evidence.method,
        assurance: evidence.assurance,
        acr: evidence.acr ?? null,
        amr: evidence.amr ?? null,
        externalSubjectHash: evidence.externalSubjectHash ?? null,
        verifiedAt: evidence.verifiedAt,
        providerEvidence: structuredClone(evidence.providerEvidence),
        createdAt: evidence.createdAt,
      })
      .onConflictDoNothing({
        target: [identityEvidences.tenantId, identityEvidences.id],
      });
  }

  async getLatestIdentityEvidence(
    tenantId: string,
    requestId: string,
    participantId: string
  ): Promise<IdentityEvidence | undefined> {
    const [row] = await this.db
      .select()
      .from(identityEvidences)
      .where(
        and(
          eq(identityEvidences.tenantId, tenantId),
          eq(identityEvidences.requestId, requestId),
          eq(identityEvidences.participantId, participantId)
        )
      )
      .orderBy(desc(identityEvidences.verifiedAt), desc(identityEvidences.createdAt))
      .limit(1);

    return row ? mapEvidence(row) : undefined;
  }

  async saveConsent(consent: ConsentRecord): Promise<void> {
    await this.db
      .insert(consentRecords)
      .values({
        tenantId: consent.tenantId,
        id: consent.id,
        requestId: consent.requestId,
        participantId: consent.participantId,
        identityEvidenceId: consent.identityEvidenceId,
        documentSha256: consent.documentSha256,
        statementHash: consent.statementHash,
        decision: consent.decision,
        status: consent.status,
        providerId: consent.providerId,
        acceptedAt: consent.acceptedAt ?? null,
        declinedAt: consent.declinedAt ?? null,
        expiresAt: consent.expiresAt ?? null,
        providerEvidence: structuredClone(consent.providerEvidence),
        createdAt: consent.createdAt,
      })
      .onConflictDoNothing({
        target: [consentRecords.tenantId, consentRecords.id],
      });
  }

  async getLatestConsent(
    tenantId: string,
    requestId: string,
    participantId: string
  ): Promise<ConsentRecord | undefined> {
    const [row] = await this.db
      .select()
      .from(consentRecords)
      .where(
        and(
          eq(consentRecords.tenantId, tenantId),
          eq(consentRecords.requestId, requestId),
          eq(consentRecords.participantId, participantId)
        )
      )
      .orderBy(desc(consentRecords.createdAt))
      .limit(1);

    return row ? mapConsent(row) : undefined;
  }
}

function mapSession(row: typeof identitySessions.$inferSelect): IdentitySession {
  return {
    tenantId: row.tenantId,
    id: row.id,
    requestId: row.requestId,
    participantId: row.participantId,
    providerId: row.providerId,
    providerSessionId: row.providerSessionId,
    method: row.method as AuthenticationMethod,
    purpose: row.purpose as "document-signing",
    status: row.status as IdentitySessionStatus,
    challengeId: row.challengeId,
    challengeDigest: row.challengeDigest,
    expiresAt: row.expiresAt,
    attemptCount: row.attemptCount,
    maxAttempts: row.maxAttempts,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    ...(row.completedAt ? { completedAt: row.completedAt } : {}),
  };
}

function mapEvidence(row: typeof identityEvidences.$inferSelect): IdentityEvidence {
  return Object.freeze({
    tenantId: row.tenantId,
    id: row.id,
    requestId: row.requestId,
    participantId: row.participantId,
    identitySessionId: row.identitySessionId,
    providerId: row.providerId,
    method: row.method as AuthenticationMethod,
    assurance: row.assurance as IdentityAssurance,
    ...(row.acr ? { acr: row.acr } : {}),
    ...(row.amr ? { amr: [...row.amr] } : {}),
    ...(row.externalSubjectHash ? { externalSubjectHash: row.externalSubjectHash } : {}),
    verifiedAt: row.verifiedAt,
    providerEvidence: structuredClone(row.providerEvidence),
    createdAt: row.createdAt,
  });
}

function mapConsent(row: typeof consentRecords.$inferSelect): ConsentRecord {
  return Object.freeze({
    tenantId: row.tenantId,
    id: row.id,
    requestId: row.requestId,
    participantId: row.participantId,
    identityEvidenceId: row.identityEvidenceId,
    documentSha256: row.documentSha256,
    statementHash: row.statementHash,
    decision: row.decision as ConsentDecision,
    status: row.status as ConsentStatus,
    providerId: row.providerId,
    ...(row.acceptedAt ? { acceptedAt: row.acceptedAt } : {}),
    ...(row.declinedAt ? { declinedAt: row.declinedAt } : {}),
    ...(row.expiresAt ? { expiresAt: row.expiresAt } : {}),
    providerEvidence: structuredClone(row.providerEvidence),
    createdAt: row.createdAt,
  });
}
