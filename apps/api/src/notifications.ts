import { notificationJobs, users } from "@evbus/db";
import { and, asc, eq, inArray, lte, sql } from "drizzle-orm";
import { getConnection, getDb } from "./db";
import { sendEmail, type EmailMessage } from "./email";
import type { Env } from "./index";

export type NotificationType =
  | "auth.password_reset"
  | "customer.approved"
  | "customer.rejected"
  | "conversation.message"
  | "conversation.closed"
  | "conversation.reassigned";

export interface EnqueueNotificationInput {
  recipientId: string | null | undefined;
  type: NotificationType;
  payload: Record<string, unknown>;
  dedupeKey?: string;
  nextAttemptAt?: Date;
}

export async function enqueueNotification(env: Env, input: EnqueueNotificationInput) {
  if (!input.recipientId) return null;

  const db = getDb(env);
  const id = crypto.randomUUID();
  const existing = input.dedupeKey
    ? await db
        .select({
          id: notificationJobs.id,
          status: notificationJobs.status,
          payload: notificationJobs.payload
        })
        .from(notificationJobs)
        .where(eq(notificationJobs.dedupeKey, input.dedupeKey))
        .limit(1)
    : [];

  const existingJob = existing[0];
  if (
    existingJob &&
    input.type === "conversation.message" &&
    (existingJob.status === "queued" || existingJob.status === "failed")
  ) {
    await db
      .update(notificationJobs)
      .set({
        status: "queued",
        payload: mergeMessagePayload(existingJob.payload, input.payload),
        nextAttemptAt: input.nextAttemptAt ?? new Date(),
        updatedAt: new Date()
      })
      .where(eq(notificationJobs.id, existingJob.id));
    return existingJob.id;
  }

  try {
    await db.insert(notificationJobs).values({
      id,
      recipientId: input.recipientId,
      channel: "email",
      type: input.type,
      status: "queued",
      dedupeKey: input.dedupeKey ?? null,
      payload: input.payload,
      attempts: 0,
      nextAttemptAt: input.nextAttemptAt ?? new Date()
    });
  } catch (error) {
    if (isDuplicateKeyError(error) && input.type === "conversation.message" && input.dedupeKey) {
      return mergeExistingMessageNotification(env, input);
    }
    if (isDuplicateKeyError(error)) return null;
    throw error;
  }

  return id;
}

async function mergeExistingMessageNotification(env: Env, input: EnqueueNotificationInput) {
  if (!input.dedupeKey) return null;
  const db = getDb(env);
  const [existingJob] = await db
    .select({
      id: notificationJobs.id,
      status: notificationJobs.status,
      payload: notificationJobs.payload
    })
    .from(notificationJobs)
    .where(eq(notificationJobs.dedupeKey, input.dedupeKey))
    .limit(1);

  if (!existingJob || (existingJob.status !== "queued" && existingJob.status !== "failed")) {
    return null;
  }

  await db
    .update(notificationJobs)
    .set({
      status: "queued",
      payload: mergeMessagePayload(existingJob.payload, input.payload),
      nextAttemptAt: input.nextAttemptAt ?? new Date(),
      updatedAt: new Date()
    })
    .where(eq(notificationJobs.id, existingJob.id));

  return existingJob.id;
}

export async function processNotificationJobs(
  env: Env,
  options: { dryRun: boolean; limit: number }
) {
  const db = getDb(env);
  const now = new Date();
  const jobs = await db
    .select({
      id: notificationJobs.id,
      recipientId: notificationJobs.recipientId,
      type: notificationJobs.type,
      payload: notificationJobs.payload,
      attempts: notificationJobs.attempts
    })
    .from(notificationJobs)
    .where(
      and(
        eq(notificationJobs.channel, "email"),
        inArray(notificationJobs.status, ["queued", "failed"]),
        lte(notificationJobs.nextAttemptAt, now)
      )
    )
    .orderBy(asc(notificationJobs.createdAt))
    .limit(options.limit);

  const results: Array<{
    id: string;
    status: "sent" | "failed" | "skipped" | "dry_run";
    error: string | null;
  }> = [];
  const recipientIds = [...new Set(jobs.map((job) => job.recipientId))];
  const recipients = recipientIds.length
    ? await db
        .select({
          id: users.id,
          name: users.name,
          email: users.email,
          status: users.status,
          emailNotificationsEnabled: users.emailNotificationsEnabled
        })
        .from(users)
        .where(inArray(users.id, recipientIds))
    : [];
  const recipientsById = new Map(recipients.map((recipient) => [recipient.id, recipient]));

  for (const job of jobs) {
    if (!options.dryRun && !(await claimNotificationJob(env, job.id))) {
      continue;
    }

    const recipient = recipientsById.get(job.recipientId);

    if (!recipient || recipient.status === "rejected" || recipient.status === "suspended") {
      const error = "Recipient is unavailable for notification delivery.";
      if (options.dryRun) {
        results.push({ id: job.id, status: "dry_run", error });
        continue;
      }

      await db
        .update(notificationJobs)
        .set({
          status: "skipped",
          attempts: sql`${notificationJobs.attempts} + 1`,
          lastError: error,
          updatedAt: now
        })
        .where(eq(notificationJobs.id, job.id));
      results.push({ id: job.id, status: "skipped", error });
      continue;
    }

    if (job.type === "conversation.message" && recipient.emailNotificationsEnabled === 0) {
      const error = "Recipient disabled message email notifications.";
      if (options.dryRun) {
        results.push({ id: job.id, status: "dry_run", error });
        continue;
      }

      await db
        .update(notificationJobs)
        .set({
          status: "skipped",
          attempts: sql`${notificationJobs.attempts} + 1`,
          lastError: error,
          updatedAt: now
        })
        .where(eq(notificationJobs.id, job.id));
      results.push({ id: job.id, status: "skipped", error });
      continue;
    }

    let message: EmailMessage;
    try {
      message = renderEmail(job.type, job.payload, recipient);
    } catch (error) {
      const message = getErrorMessage(error);
      if (options.dryRun) {
        results.push({ id: job.id, status: "dry_run", error: message });
        continue;
      }

      await markJobFailed(env, job.id, job.attempts + 1, message);
      results.push({ id: job.id, status: "failed", error: message });
      continue;
    }

    if (options.dryRun) {
      results.push({ id: job.id, status: "dry_run", error: null });
      continue;
    }

    try {
      await sendEmail(env, message);

      await db
        .update(notificationJobs)
        .set({
          status: "sent",
          sentAt: new Date(),
          lastError: null,
          updatedAt: new Date()
        })
        .where(eq(notificationJobs.id, job.id));
      results.push({ id: job.id, status: "sent", error: null });
    } catch (error) {
      const message = getErrorMessage(error);
      await markJobFailed(env, job.id, job.attempts + 1, message);
      results.push({ id: job.id, status: "failed", error: message });
    }
  }

  return {
    dryRun: options.dryRun,
    processed: results.length,
    sent: results.filter((result) => result.status === "sent").length,
    failed: results.filter((result) => result.status === "failed").length,
    skipped: results.filter((result) => result.status === "skipped").length,
    jobs: results
  };
}

async function claimNotificationJob(env: Env, jobId: string) {
  const result = await getConnection(env).execute(
    `UPDATE notification_jobs
      SET status = 'sending',
        attempts = attempts + 1,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
        AND status IN ('queued', 'failed')`,
    [jobId],
    { fullResult: true }
  );

  return result.rowsAffected === 1;
}

async function markJobFailed(env: Env, jobId: string, attempts: number, error: string) {
  const db = getDb(env);
  await db
    .update(notificationJobs)
    .set({
      status: "failed",
      lastError: error.slice(0, 1000),
      nextAttemptAt: getNextAttemptAt(attempts),
      updatedAt: new Date()
    })
    .where(eq(notificationJobs.id, jobId));
}

function getNextAttemptAt(attempts: number) {
  const delayMinutes = Math.min(60, Math.max(1, attempts) * 5);
  return new Date(Date.now() + delayMinutes * 60_000);
}

function renderEmail(
  type: string,
  payload: unknown,
  recipient: { name: string; email: string }
): EmailMessage {
  const data = isRecord(payload) ? payload : {};
  const greeting = `Hi ${recipient.name},`;

  if (type === "customer.approved") {
    return buildMessage(recipient, "Your Ev Bus account is approved", [
      greeting,
      "Your Ev Bus support account has been approved. You can now sign in and message the support team."
    ]);
  }

  if (type === "auth.password_reset") {
    const token = getString(data.token);
    if (!token) throw new Error("Password reset token missing.");
    return buildMessage(recipient, "Reset your Ev Bus password", [
      greeting,
      "Use this password reset token within 30 minutes:",
      token,
      "If you did not ask for this, you can ignore this email."
    ]);
  }

  if (type === "customer.rejected") {
    const reason = getString(data.reason);
    return buildMessage(recipient, "Your Ev Bus account request was reviewed", [
      greeting,
      reason
        ? `Your account request was not approved. Reason: ${reason}`
        : "Your account request was not approved.",
      "If you think this was a mistake, please contact support."
    ]);
  }

  if (type === "conversation.message") {
    const preview = getString(data.preview) ?? "You have a new support message.";
    const count = getNumber(data.count) ?? 1;
    const subject =
      count > 1 ? `${count} new Ev Bus support messages` : "New Ev Bus support message";
    return buildMessage(recipient, subject, [
      greeting,
      count > 1
        ? `You have ${count} new messages in your Ev Bus support conversation. Latest message:`
        : "You have a new message in your Ev Bus support conversation:",
      `"${preview}"`
    ]);
  }

  if (type === "conversation.closed") {
    const note = getString(data.note);
    return buildMessage(recipient, "Your Ev Bus support conversation was closed", [
      greeting,
      "Your support conversation has been closed.",
      note ? `Closing note: ${note}` : "Thank you for contacting Ev Bus support."
    ]);
  }

  if (type === "conversation.reassigned") {
    return buildMessage(recipient, "Ev Bus conversation assigned to you", [
      greeting,
      "A customer support conversation has been assigned to you."
    ]);
  }

  throw new Error(`Unsupported notification type: ${type}`);
}

function buildMessage(recipient: { name: string; email: string }, subject: string, lines: string[]) {
  const text = [...lines, "", "Ev Bus"].join("\n");
  const html = `<p>${lines.map(escapeHtml).join("</p><p>")}</p><p>Ev Bus</p>`;

  return {
    to: {
      email: recipient.email,
      name: recipient.name
    },
    subject,
    text,
    html
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function getString(value: unknown) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function getNumber(value: unknown) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function mergeMessagePayload(existing: unknown, incoming: Record<string, unknown>) {
  const current = isRecord(existing) ? existing : {};
  const currentCount = getNumber(current.count) ?? 1;
  return {
    ...current,
    ...incoming,
    count: currentCount + 1
  };
}

function escapeHtml(value: string) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function getErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : "Notification job failed.";
}

function isDuplicateKeyError(error: unknown) {
  return error instanceof Error && /Duplicate entry|1062/.test(error.message);
}
