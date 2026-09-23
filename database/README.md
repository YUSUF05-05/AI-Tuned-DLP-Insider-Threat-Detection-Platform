# database/ (Phase 9 — implemented)

SQLite audit trail. `sqlite_audit.py` implements `SQLiteAuditStore`, a
thread-safe (single shared connection + `threading.RLock`, WAL mode)
persistence layer for fully-enriched `DLPEvent`s. `schema.sql` is the
canonical DDL (hybrid normalization — see its own header comment for the
per-table reasoning). Wired into `run_pipeline_demo.py`'s `analyze_event()`;
every flagged event is written here in addition to `logs/flagged_events.jsonl`.

See `tests/test_sqlite_audit.py` (schema, round-trip, concurrency) and
`tests/test_pipeline_integration.py` (real pipeline -> real .db file).
