FROM node:22-bookworm

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    poppler-utils \
    tesseract-ocr \
    tesseract-ocr-spa \
    tesseract-ocr-por \
    tesseract-ocr-eng \
  && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY bin ./bin
COPY src ./src
COPY certs ./certs
COPY README.md ./

ENV ICA_API_HOST=0.0.0.0
ENV ICA_API_PORT=3310

EXPOSE 3310

USER node

CMD ["node", "./src/api/server.ts"]
