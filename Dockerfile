# syntax=docker/dockerfile:1.6
FROM python:3.10-slim
# NOTE: Pin this image to a digest to stabilize cache (example):
# FROM python:3.10-slim@sha256:<digest>
# If the slim image updates, the dependency install layer is rebuilt.

# Install Poetry
ENV POETRY_HOME=/opt/poetry \
    POETRY_VERSION=1.8.3 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1

# Install system dependencies and Poetry
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    gnupg \
    ca-certificates \
    apt-transport-https \
    lsb-release \
    && curl -sSL https://install.python-poetry.org | python3 - --version ${POETRY_VERSION} \
    && ln -s /opt/poetry/bin/poetry /usr/local/bin/poetry \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

RUN mkdir -p /opt/trivy-cache
# Download database for air-gapped use
RUN trivy image --cache-dir /opt/trivy-cache --download-db-only

ENV TRIVY_CACHE_DIR=/data/trivy-cache

WORKDIR /app

# Dependency layer: copy manifest + lock first so dependency install is cached.
# Rebuild only when pyproject.toml / poetry.lock change (faster app-only edits).
COPY pyproject.toml poetry.lock* ./
# Use BuildKit cache mounts so large wheels are reused across builds.
RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=cache,target=/root/.cache/pypoetry \
    poetry install --no-root --no-interaction

# Copy application code
COPY app/ ./app

# Expose port
EXPOSE 8000

# Copy the entrypoint script
COPY init.sh /init.sh
RUN chmod +x /init.sh

# Initialize environment
ENTRYPOINT ["/init.sh"]
# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]