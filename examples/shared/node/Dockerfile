FROM node:21.1-bullseye-slim@sha256:2c247f69ae354d692fcb76cab79cdbaa14485c0e0375a70efca9a98201b4ed29 as node-base


FROM node-base as node-http-auth
ARG NODE_APP=.
ARG NODE_APP_NAME=http-service/server
# Add an env to save ARG
ENV NODE_APP_PATH "/app/${NODE_APP_NAME}"
COPY "$NODE_APP" /app
# Dont use exec form to interpolate correctly
CMD node $NODE_APP_PATH
