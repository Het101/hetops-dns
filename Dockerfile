# Build stage: better-sqlite3 is a native module, so it needs a compiler when no
# prebuilt binary matches. The compiler stays here; the runtime image doesn't ship it.
FROM node:22-alpine AS deps
WORKDIR /app
RUN apk add --no-cache python3 make g++
COPY package*.json ./
# ci, not install: exactly the versions in package-lock.json, or fail.
RUN npm ci --omit=dev

FROM node:22-alpine
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Persistent data (SQLite DB: users, history, alerts). Mount a volume here so it
# survives container restarts:  docker run -v hetops_data:/app/data ...
# Still runs as root: existing volumes are root-owned, and switching user needs a
# one-off chown of the volume first.
ENV DB_PATH=/app/data/hetops.db
RUN mkdir -p /app/data
VOLUME ["/app/data"]

EXPOSE 3000

ENV PORT=3000
ENV NODE_ENV=production

CMD ["node", "server.js"]
