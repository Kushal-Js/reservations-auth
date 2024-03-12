FROM node:20-alpine AS development

WORKDIR /app

COPY package*.json ./
COPY tsconfig.json tsconfig.json
COPY nest-cli.json nest-cli.json

RUN npm install -g pnpm
RUN pnpm install glob rimraf

RUN pnpm install

COPY . .
COPY libs ./dist/libs
RUN pnpm run build

FROM node:20-alpine AS production

ARG NODE_ENV=production
ENV NODE_ENV=${NODE_ENV}

WORKDIR /app

COPY package*.json ./

RUN npm install -g pnpm
RUN pnpm install
COPY libs ./dist/libs

COPY . .

COPY --from=development /app/dist ./dist
COPY --from=development /app/libs ./dist/libs

CMD ["node", "dist/main"]
