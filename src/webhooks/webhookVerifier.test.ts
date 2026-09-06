import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { verifyWebhookSignature } from "./webhookVerifier.js";

const secret = "test-secret";
const timestamp = "1788715800";
const rawBody = Buffer.from('{"eventId":"evt-1"}');

function signatureFor(body: Buffer, ts: string) {
  return createHmac("sha256", secret).update(`${ts}.`).update(body).digest("hex");
}

describe("verifyWebhookSignature", () => {
  it("accepts a valid HMAC inside the timestamp window", () => {
    expect(() =>
      verifyWebhookSignature(
        rawBody,
        { signature: signatureFor(rawBody, timestamp), timestamp },
        secret,
        1788715800
      )
    ).not.toThrow();
  });

  it("rejects invalid signature", () => {
    expect(() =>
      verifyWebhookSignature(rawBody, { signature: "bad", timestamp }, secret, 1788715800)
    ).toThrow("WEBHOOK_SIGNATURE_INVALID");
  });

  it("rejects stale timestamp before accepting the event", () => {
    expect(() =>
      verifyWebhookSignature(
        rawBody,
        { signature: signatureFor(rawBody, timestamp), timestamp },
        secret,
        1788716401
      )
    ).toThrow("WEBHOOK_TIMESTAMP_INVALID");
  });
});
