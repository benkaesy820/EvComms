import { connect } from "@tidbcloud/serverless";
import { createDb } from "@evbus/db";
import type { Env } from "./index";

export function getDatabaseUrl(env: Env) {
  if (!env.TIDB_DATABASE_URL) {
    throw new Error("TIDB_DATABASE_URL is not configured.");
  }

  return env.TIDB_DATABASE_URL;
}

export function getDb(env: Env) {
  return createDb(getDatabaseUrl(env));
}

export function getConnection(env: Env) {
  return connect({ url: getDatabaseUrl(env) });
}
