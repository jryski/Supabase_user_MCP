# Anthropic OSS Scanner build environment. Public source and synthetic tests only.
# The scanner provides the repository checkout as the Docker build context.
FROM node:22.20.0-bookworm

ENV CI=1
WORKDIR /src
COPY . /src

# Match the runtime and npm versions pinned by .node-version and package.json.
# Initial image construction is online; the scanner runs offline afterwards.
RUN npm install --global npm@11.19.0 \
    && test "$(npm --version)" = "11.19.0" \
    && npm ci \
    && npm run check

# No application service is started and no production credentials are needed.
