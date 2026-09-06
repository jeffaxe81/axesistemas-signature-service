import { describe, expect, it } from "vitest";
import { sha256 } from "./documentHash.js";

describe("document hashing", () => {
  it("hashes document bytes deterministically", () => {
    expect(sha256(Buffer.from("axe"))).toBe(
      "025412d3df803873ca98af5b3475ac798b52f6c6b100dede2851c7a1dadb7b2e"
    );
  });
});
