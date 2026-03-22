# 🚀 Deployment Guide — EvComms

## Your URLs
| Service | URL |
|---------|-----|
| **Backend (Koyeb)** | https://your-app.koyeb.app |
| **Frontend (Cloudflare Pages)** | https://your-app.pages.dev |
| **Frontend (preview)** | https://08a628cd.your-app.pages.dev |

---

## 1. Git Setup

```bash
git init
git add .
git commit -m "initial commit"
git remote add origin https://github.com/YOUR_USERNAME/evcomms.git
git branch -M main
git push -u origin main
```

> ⚠️ `.env.production` is in `.gitignore` — it will NOT be pushed to GitHub.
> Keep it safe locally and paste values manually into Koyeb / Cloudflare dashboards.

---

## 2. Backend → Koyeb

### A. Create Service
1. Koyeb Dashboard → Create Service → GitHub
2. Select your repo, set Root directory to backend/
3. Koyeb auto-detects the Dockerfile
4. Set Port to 7860
5. Choose Free (nano) instance

### B. Paste these into Koyeb → Environment Variables

NODE_ENV=production
PORT=7860
HOST=0.0.0.0
TURSO_DATABASE_URL=https://your-db-name.turso.io
TURSO_AUTH_TOKEN=your-turso-auth-token
JWT_SECRET=your-jwt-secret-min-32-chars
JWT_EXPIRY_MINUTES=15
JWT_ISSUER=https://your-app.koyeb.app
JWT_AUDIENCE=EvComms
APP_NAME=EvComms
APP_URL=https://your-app.pages.dev
CORS_ORIGIN=https://your-app.pages.dev,https://08a628cd.your-app.pages.dev
BREVO_API_KEY=YOUR_BREVO_API_KEY_HERE
BREVO_SENDER_EMAIL=noreply@yourdomain.com
BREVO_SENDER_NAME=EvComms
R2_ACCOUNT_ID=your-r2-account-id
R2_ACCESS_KEY_ID=your-r2-access-key-id
R2_SECRET_ACCESS_KEY=your-r2-secret-access-key
R2_BUCKET_NAME=your-bucket-name
R2_PUBLIC_URL=https://pub-xxxxxxxxxxxx.r2.dev
IMAGEKIT_PUBLIC_KEY=your-imagekit-public-key
IMAGEKIT_PRIVATE_KEY=your-imagekit-private-key
IMAGEKIT_URL_ENDPOINT=https://ik.imagekit.io/your-id

### C. Run DB migration (first deploy only)
cd backend
npm install
npm run db:migrate   # pointed at production Turso via .env.production
npm run seed:admin

---

## 3. Frontend → Cloudflare Pages

### A. Create Project
1. Cloudflare Dashboard → Pages → Create a project
2. Connect GitHub repo
3. Root directory: frontend/
4. Build command: npm run build
5. Build output directory: dist
6. Node version: 20

### B. Environment Variable (Cloudflare Pages → Settings → Environment Variables)
VITE_API_URL=https://your-app.koyeb.app

### C. SPA Routing
frontend/public/_redirects is already in your project (/*  /index.html  200)
Cloudflare Pages picks this up automatically.

---

## 4. Koyeb Free Tier — Keep it awake

Set up UptimeRobot (free) to ping every 4 minutes:
URL: https://your-app.koyeb.app/health

---

## 5. Pre-launch Checklist

- [ ] Koyeb env vars pasted (all 20 variables)
- [ ] VITE_API_URL set in Cloudflare Pages
- [ ] DB migration run against production Turso
- [ ] Admin seeded (npm run seed:admin)
- [ ] /health responding on Koyeb
- [ ] UptimeRobot monitor active
- [ ] .env.production NOT in git (already in .gitignore)
