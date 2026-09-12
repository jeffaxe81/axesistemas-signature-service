import { describe, expect, it } from "vitest";
import { InMemoryChallengeRateLimiter } from "./challengeRateLimiter.js";

describe("InMemoryChallengeRateLimiter", () => {
  it("allows the configured number of calls then denies with retryAfterSeconds", () => {
    const limiter = new InMemoryChallengeRateLimiter({ limit: 5, windowSeconds: 60 });
    const now = new Date("2026-09-12T18:00:00Z");

    for (let i = 0; i < 5; i += 1) {
      expect(limiter.consume("tenant-a:req-1:p1:identity-start", now)).toEqual({
        allowed: true,
      });
    }
    expect(limiter.consume("tenant-a:req-1:p1:identity-start", now)).toMatchObject({
      allowed: false,
      retryAfterSeconds: 60,
    });
  });

  it("isolates keys and resets after the fixed window", () => {
    const limiter = new InMemoryChallengeRateLimiter({ limit: 1, windowSeconds: 60 });
    const now = new Date("2026-09-12T18:00:00Z");

    expect(limiter.consume("tenant-a:req-1:p1:identity-start", now)).toEqual({ allowed: true });
    expect(limiter.consume("tenant-b:req-1:p1:identity-start", now)).toEqual({ allowed: true });
    expect(
      limiter.consume("tenant-a:req-1:p1:identity-start", new Date("2026-09-12T18:01:00Z"))
    ).toEqual({ allowed: true });
  });
});
