FROM node:20-alpine

WORKDIR /app

# Copy package files and install production dependencies only (lockfile enforced)
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Copy application code
COPY provider.js .

# Run as non-root user (built-in node user in alpine image)
USER node

EXPOSE 9000

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q --spider http://localhost:9000/.well-known/openid-configuration || exit 1

CMD ["node", "provider.js"]
