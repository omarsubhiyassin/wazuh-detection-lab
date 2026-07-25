# Custom detection-lab dashboard: build the SPA, then serve it + the BFF.
# Runs as a container in the stack so Docker keeps it alive/restarts it — no
# fragile background process. Config (indexer RO creds, DASH_* auth, TLS cert
# paths) is injected by compose; see infra/docker-compose.override.yml.

# --- build stage: needs dev deps (vite/tsc) to produce dist/ ---
FROM node:22-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json vite.config.ts index.html ./
COPY src ./src
RUN npm run build

# --- runtime stage: only prod deps + server + built SPA ---
FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY server ./server
COPY --from=build /app/dist ./dist
EXPOSE 8787
# The server serves dist/ (../dist from server/) and reads all config from env.
CMD ["node", "server/index.js"]
