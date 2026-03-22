# EcomReady — Monorepo

## Structure
```
evcomms/
├── backend/    Fastify + TypeScript API (deploys to Koyeb)
├── frontend/   Vite + React SPA (deploys to Cloudflare Pages)
├── DEPLOYMENT.md  ← read this first
└── .gitignore
```

## Quick Start (Development)
```bash
# Backend
cd backend && npm install && npm run dev

# Frontend (new terminal)
cd frontend && npm install && npm run dev
```

## Production Deployment
See **DEPLOYMENT.md** for full Koyeb + Cloudflare Pages setup.
