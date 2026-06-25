import type { Env } from "./index";

export interface EmailMessage {
  to: {
    email: string;
    name?: string;
  };
  subject: string;
  text: string;
  html: string;
}

export type EmailProvider = "brevo" | "gmail";

export interface EmailDelivery {
  provider: EmailProvider;
}

export async function sendEmail(env: Env, message: EmailMessage) {
  const errors: string[] = [];

  if (env.BREVO_API_KEY) {
    try {
      await sendBrevoEmail(env, message);
      return { provider: "brevo" } satisfies EmailDelivery;
    } catch (error) {
      errors.push(error instanceof Error ? error.message : "Brevo send failed.");
    }
  } else {
    errors.push("BREVO_API_KEY is not configured.");
  }

  if (hasGmailConfig(env)) {
    try {
      await sendGmailEmail(env, message);
      return { provider: "gmail" } satisfies EmailDelivery;
    } catch (error) {
      errors.push(error instanceof Error ? error.message : "Gmail send failed.");
    }
  } else {
    errors.push("Gmail fallback is not configured.");
  }

  throw new Error(errors.join(" | "));
}

async function sendBrevoEmail(env: Env, message: EmailMessage) {
  if (!env.BREVO_API_KEY) {
    throw new Error("BREVO_API_KEY is not configured.");
  }

  const senderEmail = env.EMAIL_FROM || env.SMTP_USER;
  if (!senderEmail) {
    throw new Error("EMAIL_FROM or SMTP_USER must be configured for the sender address.");
  }

  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      accept: "application/json",
      "api-key": env.BREVO_API_KEY,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      sender: {
        email: senderEmail,
        name: env.EMAIL_FROM_NAME ?? "Ev Bus"
      },
      to: [
        {
          email: message.to.email,
          name: message.to.name
        }
      ],
      subject: message.subject,
      textContent: message.text,
      htmlContent: message.html
    })
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Brevo send failed with ${response.status}: ${body.slice(0, 300)}`);
  }
}

async function sendGmailEmail(env: Env, message: EmailMessage) {
  const from = env.GMAIL_FROM || env.EMAIL_FROM || env.SMTP_USER;
  if (!from) {
    throw new Error("GMAIL_FROM, EMAIL_FROM, or SMTP_USER must be configured for Gmail fallback.");
  }

  const accessToken = await getGmailAccessToken(env);
  const raw = base64UrlEncode(
    [
      `From: ${formatMailbox(from, env.EMAIL_FROM_NAME ?? "Ev Bus")}`,
      `To: ${formatMailbox(message.to.email, message.to.name)}`,
      `Subject: ${encodeHeader(message.subject)}`,
      "MIME-Version: 1.0",
      'Content-Type: multipart/alternative; boundary="evbus-boundary"',
      "",
      "--evbus-boundary",
      'Content-Type: text/plain; charset="UTF-8"',
      "Content-Transfer-Encoding: 8bit",
      "",
      message.text,
      "--evbus-boundary",
      'Content-Type: text/html; charset="UTF-8"',
      "Content-Transfer-Encoding: 8bit",
      "",
      message.html,
      "--evbus-boundary--"
    ].join("\r\n")
  );

  const response = await fetch("https://gmail.googleapis.com/gmail/v1/users/me/messages/send", {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({ raw })
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Gmail send failed with ${response.status}: ${body.slice(0, 300)}`);
  }
}

async function getGmailAccessToken(env: Env) {
  if (env.GMAIL_ACCESS_TOKEN) return env.GMAIL_ACCESS_TOKEN;

  if (!env.GMAIL_CLIENT_ID || !env.GMAIL_CLIENT_SECRET || !env.GMAIL_REFRESH_TOKEN) {
    throw new Error("Gmail OAuth credentials are not configured.");
  }

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      client_id: env.GMAIL_CLIENT_ID,
      client_secret: env.GMAIL_CLIENT_SECRET,
      refresh_token: env.GMAIL_REFRESH_TOKEN,
      grant_type: "refresh_token"
    })
  });

  const body = await response.json<Record<string, unknown>>();
  if (!response.ok || typeof body.access_token !== "string") {
    throw new Error(`Gmail token refresh failed with ${response.status}.`);
  }

  return body.access_token;
}

function hasGmailConfig(env: Env) {
  return Boolean(
    env.GMAIL_ACCESS_TOKEN ||
      (env.GMAIL_CLIENT_ID && env.GMAIL_CLIENT_SECRET && env.GMAIL_REFRESH_TOKEN)
  );
}

function formatMailbox(email: string, name?: string) {
  if (!name) return email;
  return `"${name.replaceAll('"', '\\"')}" <${email}>`;
}

function encodeHeader(value: string) {
  return /[^\x20-\x7E]/.test(value) ? `=?UTF-8?B?${base64EncodeUtf8(value)}?=` : value;
}

function base64UrlEncode(value: string) {
  return base64EncodeUtf8(value).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64EncodeUtf8(value: string) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
