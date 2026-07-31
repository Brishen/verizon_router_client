FROM docker.io/library/python:3.11-slim

WORKDIR /app

# Install system dependencies if any are needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install the package with operator dependencies
RUN pip install --no-cache-dir -e ".[operator]"

# Run the kopf operator
CMD ["kopf", "run", "-m", "verizon_router_client.operator"]

LABEL org.opencontainers.image.source=https://github.com/Brishen/verizon_router_client
LABEL org.opencontainers.image.description="Verizon Router Operator"
LABEL org.opencontainers.image.licenses=MIT
