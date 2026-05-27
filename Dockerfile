FROM python:3.11-slim

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
CMD ["kopf", "run", "src/verizon_router_client/operator.py"]
