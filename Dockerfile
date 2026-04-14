FROM node:20-alpine

WORKDIR /app

# Install production dependencies only
COPY package*.json ./
RUN npm install --omit=dev --no-audit --no-fund

# Copy pre-compiled dist
COPY dist/ ./dist/

EXPOSE 3000

CMD ["node", "dist/index.js"]
