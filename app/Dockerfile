FROM node:20-slim

# Set working directory
WORKDIR /app

# Copy package files
COPY app/package*.json ./

# Install dependencies (node_modules from host are excluded via .dockerignore)
# Use --ignore-scripts to avoid permission issues with postinstall hooks (esbuild),
# then run node to trigger esbuild's own platform-specific binary resolution.
RUN npm ci --ignore-scripts && \
    chmod +x node_modules/esbuild/bin/esbuild && \
    node node_modules/esbuild/install.js

# Copy app source (excludes node_modules, dist, .astro via .dockerignore)
COPY app/ ./

# Build the Astro app
ENV DOCKER=true
ENV NODE_ENV=production
RUN npm run build

# Expose port
EXPOSE 4321

# Set port environment variable
ENV PORT=4321
ENV HOST=0.0.0.0

# Run the built Node.js server
CMD ["node", "./dist/server/entry.mjs"]
