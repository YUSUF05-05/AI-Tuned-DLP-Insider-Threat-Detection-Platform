-- database/schema.sql  (Phase 9)
--
-- Canonical DDL for the SQLite audit trail. Kept as a standalone .sql file
-- (read by database/sqlite_audit.py at init time, not duplicated as a Python
-- string) for the same reason detection_policy.yaml is externalized rather
-- than hardcoded: a reviewer should be able to read and diff the schema
-- without reading Python, and it can be applied manually with
-- `sqlite3 audit_trail.db < database/schema.sql` for inspection/debugging.
--
-- DESIGN: hybrid normalization, not a single JSON blob table and not full
-- 3NF either -- picked deliberately for what Phase 10's dashboard will
-- actually need to do:
--   - `events`      : one row per DLPEvent. AI analysis and risk assessment
--                     are FLATTENED into columns here (not child tables)
--                     because they are strictly 1:1 with the event and are
--                     exactly what a dashboard filters/sorts by (severity,
--                     score, category) -- burying them in JSON would mean
--                     re-parsing JSON on every query just to sort by risk.
--   - `detections`  : one row per DetectionResult, many:1 to events, since
--                     a single event can have multiple detector matches and
--                     "show me every event card_detector matched" is a real
--                     query shape.
--   - `obfuscation` : one row per ObfuscationResult, many:1 to events.
--                     Its nested rescanned_detections are kept as JSON
--                     rather than a third child table -- going one more
--                     level relational here has real diminishing returns
--                     for a field that exists for audit completeness, not
--                     as a primary query/filter dimension.
--   - raw_metadata (source-specific, heterogeneous keys per collector) and
--     the risk breakdown (components/explanation, informational rather than
--     filterable) stay as JSON text columns rather than tables, for the
--     same reason.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS events (
    event_id                    TEXT PRIMARY KEY,
    schema_version               TEXT NOT NULL,
    timestamp                    TEXT NOT NULL,   -- event's own ISO-8601 timestamp (from common.event_schema)
    host                         TEXT NOT NULL,
    user                         TEXT NOT NULL,
    source                       TEXT NOT NULL,   -- 'file' | 'clipboard' | 'http'
    event_type                   TEXT NOT NULL,
    object_ref                   TEXT NOT NULL,
    size_bytes                   INTEGER NOT NULL DEFAULT 0,
    content_excerpt              TEXT,
    raw_metadata_json            TEXT NOT NULL DEFAULT '{}',
    any_match                    INTEGER NOT NULL DEFAULT 0,   -- 0/1, denormalized for fast filtering
    needs_ai_review               INTEGER NOT NULL DEFAULT 0,  -- 0/1

    -- Phase 6 AI analysis, flattened (1:1 -- NULL columns mean "not attempted")
    ai_status                    TEXT,             -- 'ok' | 'error' | NULL
    ai_is_sensitive               INTEGER,          -- 0/1/NULL
    ai_category                  TEXT,
    ai_confidence                 REAL,
    ai_reasoning                 TEXT,
    ai_model                     TEXT,
    ai_duration_ms                INTEGER,
    ai_error                     TEXT,

    -- Phase 7 risk assessment, flattened (1:1 -- NULL means not scored, i.e. event was never flagged)
    risk_score                   INTEGER,
    risk_base_score               INTEGER,
    risk_severity                 TEXT,             -- 'low' | 'medium' | 'high' | 'critical'
    risk_behavioral_adjustment    INTEGER,
    risk_components_json          TEXT,             -- {"deterministic": 0.9, "ai": 0.0, ...}
    risk_explanation_json         TEXT,             -- ["deterministic: ...", "ai: ...", ...]

    inserted_at                   TEXT NOT NULL     -- when THIS ROW was written -- audit-of-the-audit-trail:
                                                      -- distinct from `timestamp` (when the activity happened)
);

CREATE TABLE IF NOT EXISTS detections (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id      TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    detector      TEXT NOT NULL,
    matched       INTEGER NOT NULL,   -- 0/1
    category      TEXT,
    confidence    REAL NOT NULL DEFAULT 0.0,
    matches_json  TEXT NOT NULL DEFAULT '[]',   -- redacted/masked evidence only (see Phase 4 -- never raw secrets/PANs)
    details_json  TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS obfuscation (
    id                         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id                  TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    technique                 TEXT NOT NULL,
    found                     INTEGER NOT NULL,   -- 0/1
    layers                    INTEGER NOT NULL DEFAULT 0,
    decoded_excerpt           TEXT,
    rescanned_detections_json  TEXT NOT NULL DEFAULT '[]'
);

-- Indexes on the columns Phase 10's dashboard will actually filter/sort by.
CREATE INDEX IF NOT EXISTS idx_events_user       ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_severity   ON events(risk_severity);
CREATE INDEX IF NOT EXISTS idx_events_source     ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_score      ON events(risk_score);

CREATE INDEX IF NOT EXISTS idx_detections_event_id  ON detections(event_id);
CREATE INDEX IF NOT EXISTS idx_detections_category  ON detections(category);

CREATE INDEX IF NOT EXISTS idx_obfuscation_event_id ON obfuscation(event_id);
