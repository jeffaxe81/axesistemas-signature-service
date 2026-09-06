FROM node:24-alpine AS build
WORKDIR /app
RUN corepack enable
COPY package.json ./
RUN corepack pnpm install --no-frozen-lockfile
COPY tsconfig.json tsconfig.build.json vitest.config.ts ./
COPY src ./src
RUN corepack pnpm build

FROM node:24-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package.json ./
RUN corepack enable && corepack pnpm install --prod --no-frozen-lockfile
COPY --from=build /app/dist ./dist
EXPOSE 3000
CMD ["node", "dist/index.js"]
