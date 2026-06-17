FROM node:24-slim AS build

WORKDIR /app

COPY package.json package-lock.json ./

RUN npm ci --include=dev

COPY knexfile.js ./
COPY tsconfig.json ./
COPY public ./public
COPY src ./src

RUN npm run build


FROM node:24-slim

WORKDIR /app

RUN apt-get update \
	&& apt-get install -y --no-install-recommends curl \
	&& rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./

RUN npm ci --omit=dev \
	&& npm cache clean --force

COPY --from=build --chown=node:node /app/dist ./dist
COPY --chown=node:node package.json package-lock.json elastic-apm-node.cjs knexfile.js ./
COPY --chown=node:node config ./config
COPY --chown=node:node migrations ./migrations

ENV NODE_ENV=production \
	ELASTIC_APM_CONFIG_FILE=elastic-apm-node.cjs

USER node

EXPOSE 13110

CMD [ "node", "--experimental-loader", "elastic-apm-node/loader.mjs", "-r", "elastic-apm-node/start.js", "dist/src/index.js" ]
