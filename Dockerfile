FROM python:3.12-slim

# Install dependencies
RUN pip install --no-cache-dir pytest>=8

# Copy experiment code
COPY experiments/ /app/experiments/

WORKDIR /app/experiments

# Install package in editable mode
RUN pip install --no-cache-dir -e ".[dev]"

# Default: run smoke test
CMD ["make", "smoke"]
