FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
ENV DASHBOARD_PORT=9080 \
    DASHBOARD_DATA_DIR=/data
RUN mkdir -p /data && chown node:node /data
VOLUME ["/data"]
EXPOSE 9080
USER node
CMD ["node", "server.js"]
