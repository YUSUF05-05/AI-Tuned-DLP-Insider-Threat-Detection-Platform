# database/ (Phase 9 — not yet implemented)

Will contain the SQLite schema and ingestion code that reads the Phase 3-5
JSONL event logs (logs/*.jsonl) into a queryable audit-trail database.
SQLite was pre-selected as the lightweight default per the project's
"resource-efficient environment" requirement; the standard library's
`sqlite3` module needs no separate install.

Not built in this guide (Phases 0-5).
