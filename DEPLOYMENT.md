# 🚀 Deployment Guide — EcomReady Backend on Koyeb Free Tier

## Stack Overview
- **Backend**: Fastify + TypeScript → Docker (Node 20 Alpine)  
- **Database**: Turso (libSQL)  
- **Storage**: Cloudflare R2  
- **Email**: Brevo  
- **Frontend**: Vite + React → Cloudflare Pages  

---

## 1. Git Setup

### Repo structure (recommended)
Keep backend and frontend in the same monorepo:
```
evcomms/
├── backend/     ← your Fastify app
├── frontend/    ← your Vite/React app
├── .gitignore   ← root ignore file (provided)
└── README.md
```

### Push to GitHub
```bash
git init
git add .
git commit -m "initial commit"
git remote add origin https://github.com/YOUR_USERNAME/evcomms.git
git branch -M main
git push -u origin main
```

> ⚠️ Make sure `.env` is in `.gitignore` — never commit secrets!

---

## 2. Backend → Koyeb Free Tier

### A. Pre-requisites
- Koyeb account: https://app.koyeb.com  
- Your Dockerfile is already production-ready (exposes port 7860, has healthcheck)

### B. Create a new Service on Koyeb
1. Go to **Koyeb Dashboard → Create Service**
2. Choose **GitHub** as source → select your repo
3. Set **Root directory** to `backend/`
4. Koyeb will auto-detect the `Dockerfile`
5. Set **Port** to `7860` (matches your Dockerfile `EXPOSE`)
6. Choose the **Free** instance type (nano)

### C. Environment Variables (set in Koyeb dashboard)
Copy these into the **Environment Variables** section:

```
NODE_ENV=production
PORT=7860
HOST=0.0.0.0

# Turso Database
TURSO_DATABASE_URL=libsql://your-db.turso.io
TURSO_AUTH_TOKEN=your-turso-auth-token

# Auth — generate with: openssl rand -base64 48
JWT_SECRET=your-very-long-random-secret-at-least-32-chars
JWT_ISSUER=https://innocent-wenda-benkbear-30d64231.koyeb.app
JWT_AUDIENCE=EcomReady

# Cloudflare R2 Storage
R2_ACCOUNT_ID=your-account-id
R2_ACCESS_KEY_ID=your-access-key-id
R2_SECRET_ACCESS_KEY=your-secret-access-key
R2_BUCKET_NAME=your-bucket-name
R2_PUBLIC_URL=https://your-r2-public-url.com

# Brevo Email
BREVO_API_KEY=xkeysib-your-brevo-api-key
BREVO_SENDER_EMAIL=noreply@yourdomain.com
BREVO_SENDER_NAME=EcomReady

# App
APP_NAME=EcomReady
APP_URL=https://evcomms.pages.dev
CORS_ORIGIN=https://evcomms.pages.dev
```

> 💡 `CORS_ORIGIN` must match your Cloudflare Pages URL exactly — your backend uses this for CORS and cookie `sameSite: none`.

### D. Run DB migration after first deploy
Koyeb doesn't support run-once jobs on free tier. You have two options:

**Option 1 (Recommended):** Add a startup migration to `src/index.ts`
See `backend/src/index.ts` modification below.

**Option 2:** Run migration locally pointing at your production Turso DB:
```bash
TURSO_DATABASE_URL=libsql://your-db.turso.io \
TURSO_AUTH_TOKEN=your-token \
npm run db:migrate
```

---

## 3. Startup Migration (add to backend/src/index.ts)

Replace your `main()` function with this to auto-migrate on boot:

```typescript
import { runMigrations } from './db/index.js'  // adjust import if needed

async function main(): Promise<void> {
  try {
    // Run migrations on startup (safe — skips already-applied ones)
    await runMigrations()
    await startServer()
    logger.info(`Server running in ${env.nodeEnv} mode on port ${env.port}`)
  } catch (error) {
    logger.fatal(error, 'Failed to start server')
    process.exit(1)
  }
}
```

---

## 4. Frontend → Cloudflare Pages

### A. Connect to Cloudflare Pages
1. Go to **Cloudflare Dashboard → Pages → Create a project**
2. Connect your GitHub repo
3. Set **Root directory** to `frontend/`
4. **Build command**: `npm run build`
5. **Build output directory**: `dist`
6. **Node version**: `20`

### B. Environment Variables (set in Cloudflare Pages)
```
VITE_API_URL=https://innocent-wenda-benkbear-30d64231.koyeb.app
```

> Your `src/lib/api.ts` already reads `import.meta.env.VITE_API_URL` — this is all you need.

### C. SPA Routing fix
Create `frontend/public/_redirects` (already handled if you add this file):
```
/*    /index.html    200
```

---

## 5. Koyeb Free Tier — Important Limits

| Limit | Free Tier |
|-------|-----------|
| Services | 2 |
| Instance type | Nano (0.1 vCPU, 256MB RAM) |
| Sleep after inactivity | **Yes — 5 min** |
| Outbound bandwidth | 100 GB/mo |
| Custom domains | ✅ Yes |

> ⚠️ **Cold starts**: The free tier sleeps after inactivity. First request after sleep takes ~5-15 seconds. Consider adding a free uptime pinger (e.g. UptimeRobot hitting `/health` every 4 minutes).

---

## 6. Healthcheck
Your `/health` endpoint is already registered. Koyeb will use:
```
GET /health  →  200 OK
```
Your Dockerfile healthcheck also calls this — you're good.

---

## 7. Quick Checklist Before Going Live

- [ ] `.env` is in `.gitignore` ✅  
- [ ] `dist/` is in `.gitignore` ✅  
- [ ] `JWT_SECRET` is 32+ random chars (not the example value)  
- [ ] `CORS_ORIGIN` in Koyeb = exact Cloudflare Pages URL  
- [ ] `VITE_API_URL` in Cloudflare = exact Koyeb URL  
- [ ] DB migration run against production Turso  
- [ ] Admin seeded: `npm run seed:admin` (pointed at prod DB)  
- [ ] UptimeRobot pinging `/health` every 4 min to avoid cold starts  
