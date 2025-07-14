# Copyright 2025 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM python:3.13-slim AS base

FROM base AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    g++ \
    swig

WORKDIR /app

COPY . /app

RUN --mount=type=cache,target=/root/.cache/uv \
  uv sync --frozen --all-extras

FROM base

COPY --from=builder /app /app

ENV PATH="/app/.venv/bin:$PATH"

ENTRYPOINT ["model_signing"]
CMD ["--help"]

ARG APP_VERSION="1.0.1"

LABEL org.opencontainers.image.title="Model Transparency Library" \
      org.opencontainers.image.description="Supply chain security for ML" \
      org.opencontainers.image.version=$APP_VERSION \
      org.opencontainers.image.authors="The Sigstore Authors <sigstore-dev@googlegroups.com>" \
      org.opencontainers.image.licenses="Apache-2.0" \
