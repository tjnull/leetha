# Enterprise Storage

Leetha's embedded SQLite database is intended for a standalone collector or a
small group of sensors. An enterprise deployment with tens of thousands of
devices needs a client/server database because the limiting workload is the
continuous sighting stream, not the inventory table itself.

## Selected enterprise database: PostgreSQL

PostgreSQL is the target primary store for enterprise mode. It fits Leetha's
mixed workload: device inventory and analyst changes are transactional, while
sightings and findings are append-heavy time-series records. It also provides
connection pooling, concurrent writers, native `inet`, `macaddr`, `jsonb`,
declarative time partitioning, and several index types without requiring a
second database product.

SQLite remains useful in two places:

- standalone installations where capture and the dashboard run on one host;
- a bounded sensor-side spool that survives loss of connectivity to the
  central Leetha server.

TimescaleDB is an optional later optimization for sites that retain very large
amounts of raw telemetry. Its hypertables, retention policies, compression,
and continuous aggregates fit the sighting stream, but enterprise Leetha must
work on standard PostgreSQL first. ClickHouse is a possible analytical archive
once a deployment reaches billions of retained events; it is not the primary
inventory database because Leetha also needs frequent row updates, constraints,
and transactional joins.

## Capacity model

Device count alone is not a useful sizing number. A site with 100,000 quiet
devices can be easier to operate than 10,000 devices producing hundreds of
stored observations per minute. Capacity planning must record:

- unique devices and active devices;
- accepted sightings per second after packet deduplication;
- raw-event retention in days;
- number of simultaneous sensors and dashboard users;
- required history resolution after the hot retention window.

As an example, 100,000 devices averaging one persisted sighting per minute
produce 144 million rows per day. Storing every such row for seven days is a
billion-row problem. Leetha therefore needs aggregation and sampling in
addition to a stronger database.

## Target data layout

The enterprise schema should use one canonical table for each concept. The
current `hosts`/`devices` and `sightings`/`observations` compatibility pairs
must be consolidated during the backend migration.

| Data | PostgreSQL layout | Retention |
|------|-------------------|-----------|
| Devices and identities | Normal relational tables keyed by tenant/site and MAC or stable identity | Indefinite |
| Current verdicts | One updatable row per device | Indefinite |
| Findings and authorization history | Relational tables with site, status, severity, and time indexes | Policy controlled |
| Raw sightings | Daily range partitions on `observed_at`; typed source/destination columns plus `jsonb` detail | Short hot window |
| Hourly summaries | Pre-aggregated device, protocol, source/destination, and finding counts | Long term |
| Fingerprint feeds | Local immutable cache, outside the operational database | Latest synchronized copy |

Raw sighting partitions should have a BRIN index on time and B-tree indexes on
`(site_id, device_id, observed_at DESC)` and other proven access paths. Source
and destination addresses must be typed columns; dashboard queries should not
extract them from JSON for every row. Old partitions can be detached or dropped
without issuing a massive row-by-row delete.

## Ingestion and dashboard rules

1. Sensors send normalized observations in bounded batches with an idempotency
   key. The server acknowledges a batch only after it is durable.
2. Writers use a connection pool and multi-row inserts or PostgreSQL `COPY`.
3. Backpressure is explicit. A disconnected sensor writes to its bounded local
   SQLite spool and resumes from the last acknowledged batch.
4. Dashboard charts read hourly or minute rollups. Raw partitions are queried
   only for device drill-down and investigations.
5. Inventory pagination uses a stable cursor such as
   `(last_active, device_id)` rather than large `OFFSET` values.
6. Search uses normalized columns and PostgreSQL trigram indexes where
   substring search is required.

## Migration sequence

PostgreSQL support is a backend project rather than a connection-string change:
Leetha currently contains SQLite placeholders, pragmas, date functions, JSON
functions, and two persistence facades.

1. Consolidate the duplicate persistence models behind one repository API.
2. Add backend-neutral integration tests and PostgreSQL CI using a service
   container.
3. Add PostgreSQL schema migrations, pooled connections, typed timestamps and
   addresses, and batched ingestion.
4. Add time partitions, summary tables, and retention jobs.
5. Add an online migration command that copies SQLite data, verifies table
   counts and checksums, then switches the configured backend.
6. Load-test at 100,000 devices and at event rates derived from real enterprise
   captures. Publish p50/p95 API latency, sustained ingest rate, storage growth,
   and dropped-event counts.

Until those gates pass, SQLite remains the supported backend. Adding a database
URL without porting and testing every query would create the appearance of
enterprise support while retaining SQLite-specific failure modes.

The current query paths can be measured with a disposable fixture:

```bash
PYTHONPATH=src python scripts/benchmark_storage.py \
  --devices 100000 --sightings 1000000
```

The benchmark reports the inventory page, dashboard aggregation, device
drill-down, and JSON connection-query timings. Results depend on storage and
CPU, so release decisions should compare them on the same host and publish the
hardware alongside the numbers.
