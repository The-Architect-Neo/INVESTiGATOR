FROM node:20-alpine

WORKDIR /app

# Install production dependencies only
COPY package*.json ./
RUN npm install --omit=dev --no-audit --no-fund

# Copy pre-compiled dist and static files
COPY dist/ ./dist/
COPY index.html ./

EXPOSE 3000

CMD ["node", "dist/index.js"]
