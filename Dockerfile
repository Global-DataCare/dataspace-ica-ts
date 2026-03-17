FROM node:22-bookworm

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY bin ./bin
COPY src ./src
COPY certs ./certs
COPY README.md ./

ENV NODE_ENV=production
ENV ICA_API_HOST=0.0.0.0
ENV ICA_API_PORT=3310

EXPOSE 3310

USER node

CMD ["node", "./src/api/server.ts"]
