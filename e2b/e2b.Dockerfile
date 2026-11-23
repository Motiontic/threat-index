# E2B sandbox template for Threat Index heavy jobs (see docs/IMPLEMENTATION_PLAN.md §6).
# Build (a person, with E2B_API_KEY set; never a loop):  node e2b/build-template.mjs <template-name>
# That script bundles e2b/jobs, then builds this file with the e2b SDK (`e2b template build` was removed in 2026).
# E2B templates must be Debian-based.
FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# DuckDB CLI: reads receipts, diffs big files, writes Parquet. Pinned, and checked against the digest GitHub
# publishes for the release asset (linux amd64) before it is unpacked. To upgrade, change both values.
ARG DUCKDB_VERSION=2.0.1
ARG DUCKDB_SHA256=b676268be4d39e4e41a904442c9796c9914e645cc085c7505f048f2c992b5eca
RUN curl -fsSL -o /tmp/duckdb.tar.gz \
      "https://github.com/duckdb/duckdb/releases/download/v${DUCKDB_VERSION}/duckdb-cli-linux-amd64.tar.gz" \
 && echo "${DUCKDB_SHA256}  /tmp/duckdb.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/duckdb.tar.gz -C /usr/local/bin duckdb \
 && rm /tmp/duckdb.tar.gz
RUN duckdb --version

# Heavy jobs hold a day of EPSS scores or a first load in memory; the template has 4 GB.
ENV NODE_OPTIONS=--max-old-space-size=3072

WORKDIR /app
# The jobs bundle (dist/run.mjs, built by `pnpm --filter @ti/e2b-jobs bundle`).
COPY jobs/dist/ /app/
