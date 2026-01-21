FROM node:18-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN apk add --no-cache openssl
RUN npm install

COPY . .

# Generate Prisma client
RUN npx prisma generate

# Build TypeScript
RUN npm run build

# Create non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Change ownership of the app directory so the user can write to the DB
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 3000

# Start command
CMD ["npm", "start"]
