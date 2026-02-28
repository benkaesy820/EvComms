# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app/backend

# Install deps (including devDeps needed for tsc)
COPY package*.json ./
RUN npm ci

# Copy source and compile
COPY . .
RUN npm run build

# ── Stage 2: Production ───────────────────────────────────────────────────────
FROM node:20-alpine AS runner

WORKDIR /app/backend

# Production deps only
COPY package*.json ./
RUN npm ci --omit=dev

# Copy compiled output from build stage
COPY --from=builder /app/backend/dist ./dist

EXPOSE 7860

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=7860

CMD ["node", "dist/src/index.js"]
