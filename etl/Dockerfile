# Data refresher (B8): runs `python -m etl.refresh --loop` next to the databases.
# Built by docker compose (context = repo root); see the `refresher` service.
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY etl/requirements.txt etl/requirements.txt
RUN pip install --no-cache-dir -r etl/requirements.txt
COPY etl etl
COPY db/neo4j db/neo4j
CMD ["python", "-m", "etl.refresh", "--loop"]
