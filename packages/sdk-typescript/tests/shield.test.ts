import { describe, it, expect } from "vitest";
import { Shield, Decision } from "../src/index.js";

describe("Shield", () => {
  it("should require API key", () => {
    expect(() => new Shield()).toThrow("API key is required");
  });

  it("should accept API key via constructor", () => {
    const shield = new Shield({ apiKey: "test-key" });
    expect(shield).toBeDefined();
  });

  it("should create a guard function", () => {
    const shield = new Shield({ apiKey: "test-key" });
    const guarded = shield.guard("test_tool", async (params) => "result");
    expect(typeof guarded).toBe("function");
  });

  it("should create a session", () => {
    const shield = new Shield({ apiKey: "test-key" });
    const session = shield.session("Summarize emails");
    expect(session).toBeDefined();
  });
});

describe("Decision", () => {
  it("should have correct enum values", () => {
    expect(Decision.ALLOW).toBe("ALLOW");
    expect(Decision.BLOCK).toBe("BLOCK");
    expect(Decision.REQUIRE_CONFIRMATION).toBe("REQUIRE_CONFIRMATION");
  });
});
