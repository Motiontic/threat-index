# E2B sandbox template for Threat Index heavy jobs (see docs/IMPLEMENTATION_PLAN.md §6).
# Build:  e2b template build -n threat-index-jobs -d e2b.Dockerfile
# E2B templates must be Debian-based.
FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl unzip ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# DuckDB CLI: reads receipts, diffs big files, writes Parquet. Pin and verify the version at M0.
ARG DUCKDB_VERSION=1.3.2
RUN curl -fsSL -o /tmp/duckdb.zip \
      "https://github.com/duckdb/duckdb/releases/download/v${DUCKDB_VERSION}/duckdb_cli-linux-amd64.zip" \
 && unzip /tmp/duckdb.zip -d /usr/local/bin \
 && rm /tmp/duckdb.zip

WORKDIR /app
# The jobs bundle (built from e2b/jobs with the shared @ti/parsers code).
COPY jobs/dist/ /app/
