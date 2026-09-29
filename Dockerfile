# syntax=docker/dockerfile:1
FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /app

# Install workspace dependencies first for better layer caching.
COPY package.json package-lock.json ./
COPY packages/oidc-caep-client/package.json packages/oidc-caep-client/
COPY demo/package.json demo/
RUN npm ci --omit=dev --workspaces --include-workspace-root && npm cache clean --force

COPY packages/oidc-caep-client/src packages/oidc-caep-client/src
COPY demo/server.js demo/
COPY demo/public demo/public

USER node
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:3000/ >/dev/null || exit 1
CMD ["node", "demo/server.js"]
