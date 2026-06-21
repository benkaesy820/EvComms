import { z } from "zod";

export class HttpError extends Error {
  constructor(
    public readonly status: number,
    message: string
  ) {
    super(message);
  }
}

export async function readJson<T>(request: Request, schema: z.ZodSchema<T>) {
  let body: unknown;

  try {
    body = await request.json();
  } catch {
    throw new HttpError(400, "Invalid JSON body.");
  }

  const parsed = schema.safeParse(body);

  if (!parsed.success) {
    throw new HttpError(400, parsed.error.issues[0]?.message ?? "Invalid request.");
  }

  return parsed.data;
}

export function json(body: unknown, status = 200, headers: HeadersInit = {}) {
  return Response.json(body, {
    status,
    headers
  });
}

export function notFound() {
  return json({ error: "Not found" }, 404);
}
