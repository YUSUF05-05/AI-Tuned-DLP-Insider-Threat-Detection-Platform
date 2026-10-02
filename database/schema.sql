-- database/schema.sql  (Phase 9; append-only enforcement + full behavioral
-- context added in Phase 10 Step 0 -- see docs/DATABASE.md)
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
--   - `events`      : one row per DLPEvent. AI analysis, risk assessment,
--                     and (as of Phase 10 Step 0) Phase 8's full behavioral
--                     correlation context are all FLATTENED into columns
--                     here (not child tables) because they are strictly
--                     1:1 with the event and are exactly what a dashboard
--                     filters/sorts by (severity, score, category) --
--                     burying them in JSON would mean re-parsing JSON on
--                     every query just to sort by risk.
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
--     the risk/behavioral breakdowns (components/explanation, informational
--     rather than filterable) stay as JSON text columns rather than tables,
--     for the same reason.

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

    -- Phase 8 behavioral correlation context, persisted in FULL as of this
    -- Phase 10 Step 0 fix. Previously only risk_behavioral_adjustment (the
    -- single integer risk_engine actually consumes) was kept -- the
    -- REASONING behind that integer, computed by
    -- correlation/behavior_tracker.py's correlate(), was discarded the
    -- moment compute_risk() returned it. That meant an analyst staring at a
    -- CRITICAL event that got there partly via a +12 behavioral bonus had
    -- no way to see WHY: how many prior events, whether the trend was
    -- escalating, which category recurred. Flattened as columns here for
    -- the same 1:1-with-the-event reasoning as the ai_*/risk_* columns
    -- above. See docs/DATABASE.md "Full behavioral context, not just the
    -- adjustment integer".
    behavioral_event_count_in_window INTEGER,
    behavioral_escalating             INTEGER,      -- 0/1/NULL
    behavioral_repeated_categories_json TEXT,        -- e.g. ["customer_data", "financial"]
    behavioral_explanation_json       TEXT,          -- ["repeated activity: ...", "escalation: ...", "repeated category: ..."]

    inserted_at                   TEXT NOT NULL     -- when THIS ROW was written -- audit-of-the-audit-trail:
                                                      -- distinct from `timestamp` (when the activity happened)
);

-- No ON DELETE CASCADE on either child-table foreign key below (Phase 10
-- Step 0 fix -- see "Append-only enforcement" section near the bottom of
-- this file for the full rationale). Both now default to SQLite's NO
-- ACTION: deleting a row from `events` that still has child `detections`/
-- `obfuscation` rows fails the foreign-key check, rather than silently
-- taking the evidence down with it.

CREATE TABLE IF NOT EXISTS detections (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id      TEXT NOT NULL REFERENCES events(event_id),
    detector      TEXT NOT NULL,
    matched       INTEGER NOT NULL,   -- 0/1
    category      TEXT,
    confidence    REAL NOT NULL DEFAULT 0.0,
    matches_json  TEXT NOT NULL DEFAULT '[]',   -- redacted/masked evidence only (see Phase 4 -- never raw secrets/PANs)
    details_json  TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS obfuscation (
    id                         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id                  TEXT NOT NULL REFERENCES events(event_id),
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

-- ---------------------------------------------------------------------------
-- Append-only enforcement (Phase 10 Step 0).
--
-- WHY TRIGGERS *AND* A REMOVED CASCADE, NOT JUST ONE:
-- The BEFORE UPDATE/DELETE triggers below are the actual, direct control --
-- any UPDATE or DELETE against these three tables aborts the statement,
-- full stop (see database.sqlite_audit.SQLiteAuditStore.verify_integrity(),
-- which live-fires exactly this to confirm it's really true in a given
-- database file, not just that this comment says so). Removing
-- `ON DELETE CASCADE` from the child-table foreign keys above is redundant
-- *given the triggers are in place*, but was worth fixing anyway:
-- ON DELETE CASCADE actively encoded "deleting an event should delete its
-- evidence too", which is precisely backwards for an audit trail, and is
-- the kind of latent behavior a future schema change could reintroduce a
-- real deletion path around (e.g. a future migration that temporarily
-- drops one trigger and forgets the FK default had quietly been
-- undermining append-only-ness the whole time). Defense in depth, not
-- belt-and-suspenders theater.
--
-- WHAT THIS DOES NOT DEFEND AGAINST (see docs/THREAT_MODEL.md Security
-- Assumption A1): a connection with sufficient privilege can always
-- `DROP TRIGGER ...` before deleting rows, or edit the file directly with
-- a hex editor. These triggers stop ORDINARY application code -- including
-- a future well-meaning dashboard feature, or someone poking around in DB
-- Browser for SQLite -- from casually mutating or deleting audit history.
-- That is exactly the class of accidental/casual tamper this lab's
-- single-operator threat model (A1) is scoped to, not a guarantee against
-- a fully compromised host.
-- ---------------------------------------------------------------------------

CREATE TRIGGER IF NOT EXISTS trg_events_no_update
BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events is append-only: UPDATE is not permitted (audit trail immutability)');
END;

CREATE TRIGGER IF NOT EXISTS trg_events_no_delete
BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events is append-only: DELETE is not permitted (audit trail immutability)');
END;

CREATE TRIGGER IF NOT EXISTS trg_detections_no_update
BEFORE UPDATE ON detections
BEGIN
    SELECT RAISE(ABORT, 'detections is append-only: UPDATE is not permitted (audit trail immutability)');
END;

CREATE TRIGGER IF NOT EXISTS trg_detections_no_delete
BEFORE DELETE ON detections
BEGIN
    SELECT RAISE(ABORT, 'detections is append-only: DELETE is not permitted (audit trail immutability)');
END;

CREATE TRIGGER IF NOT EXISTS trg_obfuscation_no_update
BEFORE UPDATE ON obfuscation
BEGIN
    SELECT RAISE(ABORT, 'obfuscation is append-only: UPDATE is not permitted (audit trail immutability)');
END;

CREATE TRIGGER IF NOT EXISTS trg_obfuscation_no_delete
BEFORE DELETE ON obfuscation
BEGIN
    SELECT RAISE(ABORT, 'obfuscation is append-only: DELETE is not permitted (audit trail immutability)');
END;
