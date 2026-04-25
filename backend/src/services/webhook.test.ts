import { describe, it, expect } from "vitest";
import { createHmac } from "crypto";
import { getRetryDelaySeconds, computeSignature } from "./webhook";

describe("computeSignature", () => {
  it("produces sha256=<hex> matching manual HMAC-SHA256", () => {
    const secret = "test-secret";
    const body = JSON.stringify({ event: "stream.created", payload: { id: "abc" } });
    const expected = "sha256=" + createHmac("sha256", secret).update(body).digest("hex");
    expect(computeSignature(secret, body)).toBe(expected);
  });

  it("produces a known digest for a fixed input", () => {
    // echo -n 'hello' | openssl dgst -sha256 -hmac 'secret'
    // => 88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b
    expect(computeSignature("secret", "hello")).toBe(
      "sha256=88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b"
    );
  });
});

describe("Webhook Retry Logic", () => {
    it("should return correct retry delays", () => {
        const expectedDelays = [5, 15, 60, 300, 900];

        expectedDelays.forEach((expectedDelay, index) => {
            const delay = getRetryDelaySeconds(index);
            expect(delay).toBe(expectedDelay);
        });
    });

    it("should return last delay for attempts beyond max", () => {
        const delay = getRetryDelaySeconds(10);
        expect(delay).toBe(900); // Last delay
    });

    it("should handle negative attempt numbers", () => {
        const delay = getRetryDelaySeconds(-1);
        expect(delay).toBe(900); // Last delay
    });

    it("should have correct sequence: 5s, 15s, 60s, 300s, 900s", () => {
        const delays = [0, 1, 2, 3, 4].map((i) => getRetryDelaySeconds(i));
        expect(delays).toEqual([5, 15, 60, 300, 900]);
    });
});
