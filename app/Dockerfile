# Build context is the repository root (see docker-compose.yml), so paths
# below are relative to the repo root, not this app/ folder.

FROM node:18-alpine

WORKDIR /usr/src/app

COPY app/package.json ./
RUN npm install --omit=dev

COPY app/server.js ./
COPY scripts/generate-logs.sh /usr/local/bin/generate-logs.sh
COPY app/entrypoint.sh ./entrypoint.sh

RUN chmod +x /usr/local/bin/generate-logs.sh ./entrypoint.sh \
    && mkdir -p /opt/admin/logs

EXPOSE 3075

ENTRYPOINT ["./entrypoint.sh"]
