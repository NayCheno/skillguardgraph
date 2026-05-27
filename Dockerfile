FROM python:3.12-slim

# Install smoke-test dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends make \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir "pytest>=8"

# Copy experiment code
COPY experiments/ /app/experiments/

WORKDIR /app/experiments

# Install package in editable mode
RUN pip install --no-cache-dir -e ".[dev]"

# Default: run smoke test
CMD ["make", "smoke"]
