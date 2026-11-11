FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
RUN mkdir -p /data && chown nobody:nogroup /data
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

EXPOSE 8000
USER nobody
ENV FORENSICGRAPH_DB_PATH=/data/forensicgraph.db
CMD ["uvicorn", "forensicgraph.api:app", "--host", "0.0.0.0", "--port", "8000"]
