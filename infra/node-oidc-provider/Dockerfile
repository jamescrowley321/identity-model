FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32

WORKDIR /app

# Copy package files and install production dependencies only (lockfile enforced)
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Copy application code
COPY provider.js .

# Run as non-root user (built-in node user in alpine image)
USER node

EXPOSE 9010

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q --spider http://localhost:9010/.well-known/openid-configuration || exit 1

CMD ["node", "provider.js"]
