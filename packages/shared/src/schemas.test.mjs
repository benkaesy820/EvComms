import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  appSettingsSchema,
  createMessageRequestSchema,
  processNotificationJobsRequestSchema,
  registerRequestSchema,
  requestPasswordResetSchema,
  resetPasswordSchema
} from "./schemas.ts";

describe("shared validation contracts", () => {
  test("registration keeps customer identity strict and normalized", () => {
    const input = registerRequestSchema.parse({
      name: "  Ama Customer  ",
      email: "  AMA@example.com  ",
      phone: "+233501234567",
      password: "Safe-password-123"
    });

    assert.equal(input.name, "Ama Customer");
    assert.equal(input.email, "AMA@example.com");
    assert.equal(input.phone, "+233501234567");
  });

  test("registration rejects weak passwords and invalid Ghana phone numbers", () => {
    assert.equal(
      registerRequestSchema.safeParse({
        name: "Ama",
        email: "ama@example.com",
        phone: "123",
        password: "password"
      }).success,
      false
    );
  });

  test("messages are trimmed, bounded, and never blank", () => {
    assert.deepEqual(createMessageRequestSchema.parse({ body: "  hello  " }), { body: "hello" });
    assert.equal(createMessageRequestSchema.safeParse({ body: "   " }).success, false);
    assert.equal(createMessageRequestSchema.safeParse({ body: "x".repeat(5001) }).success, false);
  });

  test("notification processing defaults stay small and bounded", () => {
    assert.deepEqual(processNotificationJobsRequestSchema.parse({}), { dryRun: false, limit: 5 });
    assert.equal(processNotificationJobsRequestSchema.safeParse({ limit: 26 }).success, false);
    assert.equal(processNotificationJobsRequestSchema.safeParse({ limit: 0 }).success, false);
  });

  test("settings protect operational bounds", () => {
    const settings = appSettingsSchema.parse({
      siteName: "Ev Bus Support",
      companyName: "Ev Network",
      tagline: "Support that feels human.",
      supportEmail: "support@example.com",
      maxActiveConversationsPerAgent: 20,
      emailNotificationDebounceMinutes: 5
    });

    assert.equal(settings.maxActiveConversationsPerAgent, 20);
    assert.equal(appSettingsSchema.safeParse({ ...settings, maxActiveConversationsPerAgent: 0 }).success, false);
    assert.equal(appSettingsSchema.safeParse({ ...settings, emailNotificationDebounceMinutes: 31 }).success, false);
  });

  test("password reset inputs are constrained", () => {
    assert.equal(requestPasswordResetSchema.safeParse({ email: "customer@example.com" }).success, true);
    assert.equal(resetPasswordSchema.safeParse({ token: "x".repeat(31), password: "Safe-password-123" }).success, false);
    assert.equal(resetPasswordSchema.safeParse({ token: "x".repeat(32), password: "weak" }).success, false);
  });
});
