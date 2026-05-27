FROM python:3.12-slim

RUN pip install --no-cache-dir pytest

COPY experiments/ /app/experiments/

WORKDIR /app/experiments

ENV PYTHONPATH="/app/experiments/src"

CMD ["make", "smoke"]
