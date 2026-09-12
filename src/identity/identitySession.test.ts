import { describe, expect, it } from "vitest";
import {
  assertSessionUsable,
  createIdentitySession,
  incrementIdentityAttempt,
  transitionIdentitySession,
  type IdentitySession,
} from "./identitySession.js";

const now = new Date("2026-09-12T18:00:00Z");

function makeBaseSession(): IdentitySession {
  return createIdentitySession({
    tenantId: "tenant-a",
    id: "session-1",
    requestId: "request-1",
    participantId: "participant-1",
    providerId: "fake-identity",
    method: "fake",
    challengeId: "challenge-1",
    challengeDigest: "digest",
    now,
    ttlSeconds: 60,
    maxAttempts: 3,
  });
}

describe("IdentitySession", () => {
  it("starts challenge_pending with policy TTL and zero attempts", () => {
    const session = makeBaseSession();
    expect(session.status).toBe("challenge_pending");
    expect(session.attemptCount).toBe(0);
    expect(session.maxAttempts).toBe(3);
    expect(session.expiresAt.toISOString()).toBe("2026-09-12T18:01:00.000Z");
  });

  it("expires a pending session after its TTL", () => {
    const session = makeBaseSession();
    expect(() =>
      assertSessionUsable(session, new Date("2026-09-12T18:01:01Z"))
    ).toThrowError("IDENTITY_CHALLENGE_EXPIRED");
  });

  it("rejects replay after a session is verified", () => {
    const verified = transitionIdentitySession(makeBaseSession(), "verified", now);
    expect(() => assertSessionUsable(verified, now)).toThrowError(
      "IDENTITY_REPLAY_DETECTED"
    );
  });

  it("rejects a session after max attempts", () => {
    let exhausted = makeBaseSession();
    exhausted = incrementIdentityAttempt(exhausted, now);
    exhausted = incrementIdentityAttempt(exhausted, now);
    exhausted = incrementIdentityAttempt(exhausted, now);
    expect(() => assertSessionUsable(exhausted, now)).toThrowError(
      "IDENTITY_CHALLENGE_INVALID"
    );
  });

  it("rejects transitions out of terminal states", () => {
    const denied = transitionIdentitySession(makeBaseSession(), "denied", now);
    expect(() => transitionIdentitySession(denied, "verified", now)).toThrowError(
      "INVALID_IDENTITY_SESSION_TRANSITION"
    );
  });
});
