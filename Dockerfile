# Works on Raspberry Pi (arm64) and x86 — no native modules (SQLite is built into Node).
FROM node:24-slim

ENV NODE_ENV=production \
    DATA_DIR=/data \
    PORT=8790
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force

COPY src ./src

USER node
EXPOSE 8790
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8790/v1/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "--disable-warning=ExperimentalWarning", "src/server.js"]
