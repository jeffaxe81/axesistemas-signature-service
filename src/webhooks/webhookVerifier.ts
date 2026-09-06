import { createHmac, timingSafeEqual } from "node:crypto";

export type WebhookHeaders = {
  signature?: string;
  timestamp?: string;
};

const MAX_TIMESTAMP_SKEW_SECONDS = 300;

export function verifyWebhookSignature(
  rawBody: Buffer,
  headers: WebhookHeaders,
  secret: string,
  nowEpochSeconds = Math.floor(Date.now() / 1000)
): void {
  const timestamp = headers.timestamp;
  const signature = headers.signature;
  const parsedTimestamp = timestamp ? Number(timestamp) : Number.NaN;

  if (
    !timestamp ||
    !Number.isSafeInteger(parsedTimestamp) ||
    Math.abs(nowEpochSeconds - parsedTimestamp) > MAX_TIMESTAMP_SKEW_SECONDS
  ) {
    throw new Error("WEBHOOK_TIMESTAMP_INVALID");
  }

  if (!signature || !/^[a-f0-9]{64}$/i.test(signature)) {
    throw new Error("WEBHOOK_SIGNATURE_INVALID");
  }

  const expectedHex = createHmac("sha256", secret)
    .update(`${timestamp}.`)
    .update(rawBody)
    .digest("hex");

  const expected = Buffer.from(expectedHex, "hex");
  const received = Buffer.from(signature, "hex");

  if (expected.length !== received.length || !timingSafeEqual(expected, received)) {
    throw new Error("WEBHOOK_SIGNATURE_INVALID");
  }
}
