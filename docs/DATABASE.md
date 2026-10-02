# Phase 9/10 SQLite Audit Trail

## Purpose

The pipeline writes enriched events to SQLite as an audit trail. The
dashboard is a separate process and opens the database in read-only mode.

## Schema

- `events` stores event metadata, flattened AI and risk fields, and the full
  Phase 8 behavioral context.
- `detections` stores detector results and redacted evidence.
- `obfuscation` stores normalization results, including rescanned detections
  as JSON.

Raw metadata and explanatory risk/behavior fields remain JSON text columns.
AI results, risk assessments, and behavioral context are stored as columns on
`events`; they are not separate tables.

## Append-only protection

SQLite triggers reject `UPDATE` and `DELETE` operations on `events`,
`detections`, and `obfuscation`. The child-table foreign keys do not cascade
deletes. These controls protect against ordinary application mistakes; they
do not protect against an administrator who can alter the database file or
drop its triggers.

## Read-only dashboard

`SQLiteAuditStore(read_only=True)` opens the existing database using SQLite's
`mode=ro` URI and does not initialize or migrate the schema. It fails if the
database does not already exist. The dashboard exposes the audit status at
`/api/integrity` and summary counts at `/api/summary`.

## Integrity check

`verify_integrity()` checks that the expected immutability triggers exist,
that the audit tables do not use cascading deletes, and that live `UPDATE`
and `DELETE` attempts are rejected. Its probe transaction is rolled back.

## Existing databases

The writer adds missing behavioral-context columns to older databases when
opening them. The dashboard never performs this migration because it is
read-only. The foreign-key definition change requires a database rebuild;
the migration does not rewrite existing child tables.

## Privacy

Detection evidence is redacted by the detector layer before storage. The
dashboard presents stored values and does not reconstruct masked secrets or
payment-card numbers.
