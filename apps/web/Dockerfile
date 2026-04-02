FROM node:20-alpine

WORKDIR /app

ARG NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
ARG NEXT_PUBLIC_LAB_BASE_URL=http://localhost:3100

ENV NEXT_PUBLIC_API_BASE_URL=${NEXT_PUBLIC_API_BASE_URL} \
    NEXT_PUBLIC_LAB_BASE_URL=${NEXT_PUBLIC_LAB_BASE_URL} \
    NEXT_TELEMETRY_DISABLED=1

COPY package*.json ./
RUN npm ci --include=dev

COPY . .
RUN npm run build
RUN npm prune --omit=dev
RUN npm install --no-save typescript

ENV NODE_ENV=production

EXPOSE 3000

CMD ["npm", "run", "start"]
