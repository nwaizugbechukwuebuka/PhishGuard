# Frontend Production Dockerfile
FROM node:18-alpine as build

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Production stage
FROM nginx:alpine as production

# Copy custom nginx configuration
COPY ../../deployment/nginx.conf /etc/nginx/conf.d/default.conf

# Copy built application
COPY --from=build /app/dist /usr/share/nginx/html

# Add non-root user
RUN addgroup -g 1001 -S phishguard && \
    adduser -S phishguard -u 1001

# Change ownership of nginx directories
RUN chown -R phishguard:phishguard /var/cache/nginx && \
    chown -R phishguard:phishguard /var/log/nginx && \
    chown -R phishguard:phishguard /etc/nginx/conf.d

# Touch nginx.pid and change ownership
RUN touch /var/run/nginx.pid && \
    chown -R phishguard:phishguard /var/run/nginx.pid

# Switch to non-root user
USER phishguard

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/ || exit 1

# Expose port
EXPOSE 3000

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
