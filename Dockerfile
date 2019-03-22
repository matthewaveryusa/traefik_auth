FROM node:alpine as build
RUN apk add python g++ make

FROM build as app
RUN mkdir -p /app/data && chown -R node:node /app
WORKDIR /app
COPY --chown=node:node package*.json ./
RUN npm install
COPY --chown=node:node . .
CMD [ "npm", "run", "start"]
