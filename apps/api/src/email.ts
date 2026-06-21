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

export async function sendEmail(env: Env, message: EmailMessage) {
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
