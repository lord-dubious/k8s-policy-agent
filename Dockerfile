FROM python:3.11-slim

WORKDIR /app

# Install git for GitOps operations
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ src/

# Install dependencies
RUN pip install --no-cache-dir -e .

# Create non-root user
RUN useradd -m -u 1000 agent
USER agent

# Set environment variables
ENV K8S_POLICY_MOCK_MODE=false
ENV K8S_POLICY_DRY_RUN=true

ENTRYPOINT ["k8s-policy"]
CMD ["--help"]
