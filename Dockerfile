FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    gnupg \
    ca-certificates \
    apt-transport-https \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Create Trivy cache directory and download database for air-gapped use
RUN mkdir -p /opt/trivy-cache
RUN trivy image --cache-dir /opt/trivy-cache --download-db-only

# Set Trivy cache directory environment variable
ENV TRIVY_CACHE_DIR=/data/trivy-cache

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY /app .

# Expose port
EXPOSE 8000

# Copy the entrypoint script
COPY init.sh /init.sh
RUN chmod +x /init.sh

# Initialize environment
ENTRYPOINT ["/init.sh"]
# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]