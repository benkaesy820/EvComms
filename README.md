# Ev Bus Support App

Ev Bus is a mobile-first customer support PWA with a Cloudflare Worker API, Durable Object WebSockets, TiDB Cloud storage, and shared TypeScript contracts.

## First Commands

```sh
corepack enable
pnpm install
pnpm dev:web
pnpm dev:api
```

For local Worker database access, copy `apps/api/.dev.vars.example` to `apps/api/.dev.vars` and set `TIDB_DATABASE_URL`.
Wrangler reads `.dev.vars`; Vite-style `.env` files are not automatically loaded into Workers.

Run the development migration after the API server starts:

```sh
curl -X POST http://127.0.0.1:8787/dev/migrate
```

If the runtime database user cannot create tables, run `packages/db/migrations/0001_auth.sql` in the TiDB console or with a database user that has DDL privileges.

## Workspace

- `apps/web` - Vite + React PWA frontend.
- `apps/api` - Cloudflare Worker API and realtime Durable Object.
- `packages/shared` - shared schemas, types, and constants.
- `packages/db` - Drizzle schema and TiDB client helpers.
