const sessionCookieName = "evbus_session";

export function getSessionToken(request: Request) {
  const cookie = request.headers.get("Cookie");
  if (!cookie) return null;

  for (const part of cookie.split(";")) {
    const [name, ...valueParts] = part.trim().split("=");
    if (name === sessionCookieName) {
      return decodeURIComponent(valueParts.join("="));
    }
  }

  return null;
}

export function createSessionCookie(token: string, expiresAt: Date, secure: boolean) {
  return withSecurity(
    [
    `${sessionCookieName}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Expires=${expiresAt.toUTCString()}`
    ],
    secure
  );
}

export function clearSessionCookie(secure: boolean) {
  return withSecurity(
    [
    `${sessionCookieName}=`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    ],
    secure
  );
}

function withSecurity(parts: string[], secure: boolean) {
  return [...parts, ...(secure ? ["Secure"] : [])].join("; ");
}
