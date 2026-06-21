import { drizzle } from "drizzle-orm/tidb-serverless";
import * as schema from "./schema";

export function createDb(databaseUrl: string) {
  return drizzle(databaseUrl, { schema });
}

export type Db = ReturnType<typeof createDb>;
