export interface ChallengeRateLimiter {
  consume(
    key: string,
    now: Date
  ): { allowed: true } | { allowed: false; retryAfterSeconds: number };
}

type WindowState = {
  startedAtMs: number;
  count: number;
};

export class InMemoryChallengeRateLimiter implements ChallengeRateLimiter {
  private readonly windows = new Map<string, WindowState>();
  private readonly windowMs: number;

  constructor(private readonly options: { limit: number; windowSeconds: number }) {
    if (!Number.isInteger(options.limit) || options.limit < 1) {
      throw new Error("INVALID_RATE_LIMIT");
    }
    if (!Number.isInteger(options.windowSeconds) || options.windowSeconds < 1) {
      throw new Error("INVALID_RATE_LIMIT_WINDOW");
    }
    this.windowMs = options.windowSeconds * 1000;
  }

  consume(
    key: string,
    now: Date
  ): { allowed: true } | { allowed: false; retryAfterSeconds: number } {
    const nowMs = now.getTime();
    const current = this.windows.get(key);

    if (!current || nowMs - current.startedAtMs >= this.windowMs) {
      this.windows.set(key, { startedAtMs: nowMs, count: 1 });
      return { allowed: true };
    }

    if (current.count < this.options.limit) {
      current.count += 1;
      return { allowed: true };
    }

    return {
      allowed: false,
      retryAfterSeconds: Math.max(
        1,
        Math.ceil((current.startedAtMs + this.windowMs - nowMs) / 1000)
      ),
    };
  }
}
