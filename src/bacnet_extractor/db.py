import os, sqlite3

DDL = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS devices (
    device_id      INTEGER PRIMARY KEY,
    address        TEXT NOT NULL,
    max_apdu       INTEGER,
    segmentation   TEXT,
    vendor_id      INTEGER,
    vendor_name    TEXT,
    model_name     TEXT,
    firmware_rev   TEXT,
    app_software   TEXT,
    last_seen_utc  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS objects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL,
    obj_type    TEXT NOT NULL,
    obj_inst    INTEGER NOT NULL,
    obj_name    TEXT,
    UNIQUE(device_id, obj_type, obj_inst)
);
CREATE TABLE IF NOT EXISTS samples (
    ts_utc      TEXT NOT NULL,
    device_id   INTEGER NOT NULL,
    obj_type    TEXT NOT NULL,
    obj_inst    INTEGER NOT NULL,
    property    TEXT NOT NULL,
    value_raw   TEXT,
    quality     TEXT,
    msg         TEXT
);
-- Helpful indices for UI queries
CREATE INDEX IF NOT EXISTS idx_objects_device_id ON objects(device_id);
CREATE INDEX IF NOT EXISTS idx_samples_device_ts ON samples(device_id, ts_utc);
"""

def get_db_path():
    return os.getenv("DB_PATH", "data/bacnet_topology.db")

def ensure_db():
    os.makedirs("data", exist_ok=True)
    con = sqlite3.connect(get_db_path())
    cur = con.cursor()
    for stmt in filter(None, DDL.split(";")):
        s = stmt.strip()
        if s:
            cur.execute(s)
    con.commit()
    return con
