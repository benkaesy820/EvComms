# ── Stage 1: Build ──────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app/backend

# Install ALL deps (including devDeps needed for TypeScript compiler)
COPY package*.json ./
RUN npm ci

# Copy source and compile TypeScript → JavaScript
COPY . .
RUN npm run build

# ── Stage 2: Production ──────────────────────────────────────────────────────
FROM node:20-alpine AS runner

WORKDIR /app/backend

# Install production deps only (no TypeScript, no dev tools)
COPY package*.json ./
RUN npm ci --omit=dev

# Copy ONLY the compiled output from the build stage
COPY --from=builder /app/backend/dist ./dist

# If your app reads config.json at runtime, copy it too
# COPY --from=builder /app/backend/config.json ./config.json

# Expose the port Koyeb (and HF Spaces) expects
EXPOSE 7860

# Runtime environment variables
# These are defaults — override them in Koyeb's dashboard for secrets
ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=7860

# ─────────────────────────────────────────────────────────────────────────────
# CMD path is based on your tsconfig.json inside backend/:
#
#   "rootDir": "src"  →  dist/index.js        ← most likely (use this one)
#   "rootDir": "."    →  dist/src/index.js
#
# If the container crashes on start, swap to the other one.
# ─────────────────────────────────────────────────────────────────────────────
CMD ["node", "dist/index.js"]
