import os
import threading
import time
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, jsonify, Response

from .discover import async_main as discover_async
from .db import get_db_path
from .poller import run_loop as poller_run_loop
import sqlite3
import asyncio
import csv
import io
import json

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


app = Flask(
    __name__,
    template_folder=str(Path(__file__).resolve().parents[2] / "templates"),
    static_folder=str(Path(__file__).resolve().parents[2] / "static"),
)


RUN_STATE = {
    "status": "idle",  # idle | running | done | error
    "started_at": None,
    "finished_at": None,
    "total_devices": 0,
    "completed": 0,
    "last_event": None,
    "device_stats": {},  # device_id -> {address, objects, snapshot}
    "error": None,
    "cancel": False,
    "events": [],  # recent activity log
    "last_options": {"local": None, "port": 47808, "sleep": 0.1, "snapshot": False},
}

_RUN_THREAD = None
_RUN_LOCK = threading.Lock()

# Extraction poller state
POLL_STATE = {
    "status": "idle",  # idle | running | stopping | stopped | error | done
    "started_at": None,
    "finished_at": None,
    "last_error": None,
    "last_event": None,
    "events": [],
    "cancel": False,
    "interval_sec": None,
    "project": None,
    "map_path": None,
    "last_cycle": {"points": 0, "read": 0, "errors": 0, "ts": None},
}

_POLL_THREAD = None
_POLL_LOCK = threading.Lock()


def _process_memory():
    if not psutil:
        return {"rss_mb": None, "vms_mb": None, "percent": None}
    proc = psutil.Process()
    mem = proc.memory_info()
    return {
        "rss_mb": round(mem.rss / (1024 * 1024), 1),
        "vms_mb": round(mem.vms / (1024 * 1024), 1),
        "percent": round(proc.memory_percent(), 1),
    }


def _progress(event: dict):
    # Serialize updates to RUN_STATE to avoid race conditions
    with _RUN_LOCK:
        RUN_STATE["last_event"] = event
        ev = dict(event)
        ev.setdefault("ts", datetime.utcnow().isoformat())
        RUN_STATE["events"].append(ev)
        if len(RUN_STATE["events"]) > 500:
            RUN_STATE["events"] = RUN_STATE["events"][-500:]
        t = event.get("event")
        if t == "start":
            RUN_STATE.update({
                "status": "running",
                "started_at": event.get("ts"),
                "finished_at": None,
                "total_devices": 0,
                "completed": 0,
                "device_stats": {},
                "error": None,
            })
        elif t == "whois_complete":
            RUN_STATE["total_devices"] = int(event.get("total_devices") or 0)
        elif t == "device_start":
            did = int(event.get("device_id"))
            RUN_STATE["device_stats"].setdefault(did, {"address": event.get("address"), "objects": 0, "snapshot": 0})
        elif t == "device_objects":
            did = int(event.get("device_id"))
            RUN_STATE["device_stats"].setdefault(did, {})["objects"] = int(event.get("count") or 0)
        elif t == "device_snapshot":
            did = int(event.get("device_id"))
            RUN_STATE["device_stats"].setdefault(did, {})["snapshot"] = int(event.get("count") or 0)
        elif t == "device_done":
            RUN_STATE["completed"] = min(RUN_STATE.get("completed", 0) + 1, RUN_STATE.get("total_devices", 0))
        elif t == "device_error":
            # Count as completed
            RUN_STATE["completed"] = min(RUN_STATE.get("completed", 0) + 1, RUN_STATE.get("total_devices", 0))
        elif t == "cancelled":
            RUN_STATE["status"] = "stopping"
        elif t == "complete":
            RUN_STATE["status"] = "done"
            RUN_STATE["finished_at"] = datetime.utcnow().isoformat()


def _run_discovery(local_if: str | None, port: int | None, sleep_sec: float, snapshot: bool):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(discover_async(local_if, sleep_sec, port, snapshot, progress=_progress, is_cancelled=lambda: RUN_STATE.get("cancel", False)))
    except Exception as e:
        RUN_STATE["status"] = "error"
        RUN_STATE["error"] = str(e)
    finally:
        try:
            loop.close()
        except Exception:
            pass
    if RUN_STATE.get("cancel") and RUN_STATE.get("status") not in ("error", "done"):
        RUN_STATE["status"] = "stopped"
        RUN_STATE["finished_at"] = datetime.utcnow().isoformat()


def _poll_progress(event: dict):
    with _POLL_LOCK:
        POLL_STATE["last_event"] = event
        ev = dict(event)
        ev.setdefault("ts", datetime.utcnow().isoformat())
        POLL_STATE["events"].append(ev)
        if len(POLL_STATE["events"]) > 500:
            POLL_STATE["events"] = POLL_STATE["events"][-500:]
        t = event.get("event")
        if t == "poll_cycle_start":
            POLL_STATE["last_cycle"] = {"points": int(event.get("points") or 0), "read": 0, "errors": 0, "ts": ev["ts"]}
        elif t == "poll_cycle_done":
            POLL_STATE["last_cycle"] = {"points": int(event.get("points") or 0), "read": int(event.get("read") or 0), "errors": int(event.get("errors") or 0), "ts": ev["ts"]}
        elif t == "poll_cycle_error":
            POLL_STATE["last_error"] = str(event.get("error") or "error")


def _start_discovery(local_if: str | None, port: int | None, sleep_sec: float, snapshot: bool):
    global _RUN_THREAD
    RUN_STATE.update({
        "status": "running",
        "started_at": datetime.utcnow().isoformat(),
        "finished_at": None,
        "total_devices": 0,
        "completed": 0,
        "device_stats": {},
        "error": None,
        "cancel": False,
        "events": [],
        "last_options": {"local": local_if, "port": port, "sleep": sleep_sec, "snapshot": snapshot},
    })
    _RUN_THREAD = threading.Thread(target=_run_discovery, args=(local_if, port, sleep_sec, snapshot), daemon=True)
    _RUN_THREAD.start()


def _list_map_files():
    try:
        data_dir = Path(get_db_path()).resolve().parents[0]
    except Exception:
        data_dir = Path("data")
    maps = []
    if data_dir.exists():
        for p in sorted(data_dir.glob("extraction_map_*.csv")):
            maps.append(p)
    return maps


def _start_poller(map_path: str, interval_sec: int, local_if: str | None, local_port: int | None):
    def _runner():
        loop_fn = poller_run_loop
        try:
            POLL_STATE.update({
                "status": "running",
                "started_at": datetime.utcnow().isoformat(),
                "finished_at": None,
                "last_error": None,
                "events": [],
            })
            loop_fn(map_path, int(interval_sec), local_if, local_port, is_cancelled=lambda: POLL_STATE.get("cancel", False), progress=_poll_progress)
            # If we exit naturally due to cancel, mark stopped
            if POLL_STATE.get("cancel") and POLL_STATE.get("status") not in ("error",):
                POLL_STATE["status"] = "stopped"
        except Exception as e:
            POLL_STATE["status"] = "error"
            POLL_STATE["last_error"] = str(e)
        finally:
            POLL_STATE["finished_at"] = datetime.utcnow().isoformat()
            POLL_STATE["cancel"] = False

    global _POLL_THREAD
    with _POLL_LOCK:
        if POLL_STATE.get("status") == "running":
            return False
        POLL_STATE.update({
            "status": "running",
            "started_at": datetime.utcnow().isoformat(),
            "finished_at": None,
            "cancel": False,
        })
        _POLL_THREAD = threading.Thread(target=_runner, daemon=True)
        _POLL_THREAD.start()
    return True


def db_connect():
    con = sqlite3.connect(get_db_path())
    try:
        con.row_factory = sqlite3.Row
    except Exception:
        pass
    return con


@app.route("/")
def index():
    # Discover available extraction maps
    maps = [str(p.name) for p in _list_map_files()]
    return render_template("index.html", state=RUN_STATE, poll=POLL_STATE, maps=maps, proc_mem=_process_memory())


@app.post("/start")
def start():
    global _RUN_THREAD
    with _RUN_LOCK:
        if RUN_STATE.get("status") == "running":
            return redirect(url_for("index"))
        local_if = request.form.get("local") or os.getenv("LOCAL_INTERFACE")
        port = request.form.get("port")
        port = int(port) if port else None
        sleep_sec = float(request.form.get("sleep") or 0.1)
        snapshot = request.form.get("snapshot") == "on"
        _start_discovery(local_if, port, sleep_sec, snapshot)
    return redirect(url_for("index"))


@app.get("/status.json")
def status_json():
    # Return a shallow-copied snapshot to avoid mid-read mutation
    with _RUN_LOCK:
        state = {}
        for k, v in RUN_STATE.items():
            if isinstance(v, dict):
                state[k] = dict(v)
            elif isinstance(v, list):
                state[k] = list(v)
            else:
                state[k] = v
    state["process_memory"] = _process_memory()
    return jsonify(state)


@app.get("/poll/status.json")
def poll_status_json():
    with _POLL_LOCK:
        st = {}
        for k, v in POLL_STATE.items():
            if isinstance(v, dict):
                st[k] = dict(v)
            elif isinstance(v, list):
                st[k] = list(v)
            else:
                st[k] = v
    return jsonify(st)


@app.post("/stop")
def stop():
    global _RUN_THREAD
    with _RUN_LOCK:
        if RUN_STATE.get("status") in ("running", "stopping"):
            RUN_STATE["cancel"] = True
        th = _RUN_THREAD
    # Best-effort wait for shutdown to release sockets
    if th and th.is_alive():
        for _ in range(20):
            th.join(timeout=0.15)
            if not th.is_alive():
                break
    return redirect(url_for("index"))


@app.post("/restart")
def restart():
    global _RUN_THREAD
    with _RUN_LOCK:
        # Request cancel if running
        if RUN_STATE.get("status") in ("running", "stopping"):
            RUN_STATE["cancel"] = True
        # Best-effort short wait for thread to end
        th = _RUN_THREAD
        if th and th.is_alive():
            # Wait up to ~5 seconds without blocking server too long
            for _ in range(25):
                th.join(timeout=0.2)
                if not th.is_alive():
                    break
        opts = RUN_STATE.get("last_options", {})
        _start_discovery(opts.get("local"), opts.get("port"), float(opts.get("sleep") or 0.1), bool(opts.get("snapshot")))
    return redirect(url_for("index"))


@app.post("/poll/upload")
def poll_upload():
    f = request.files.get("file")
    project = (request.form.get("project") or "").strip()
    if not f or not f.filename:
        with _POLL_LOCK:
            POLL_STATE["last_error"] = "No file uploaded"
        return redirect(url_for("index"))
    # Derive project name if missing from filename stem
    if not project:
        try:
            project = Path(f.filename).stem
        except Exception:
            project = "default"
    # Sanitize project
    project = "".join(ch for ch in project if ch.isalnum() or ch in ("-","_")) or "default"
    # Save under data/extraction_map_<project>.csv
    data_dir = Path("data")
    data_dir.mkdir(parents=True, exist_ok=True)
    out_path = data_dir / f"extraction_map_{project}.csv"
    f.save(str(out_path))
    with _POLL_LOCK:
        POLL_STATE["project"] = project
        POLL_STATE["map_path"] = str(out_path)
        POLL_STATE["last_error"] = None
    return redirect(url_for("index"))


@app.post("/poll/start")
def poll_start():
    with _POLL_LOCK:
        if POLL_STATE.get("status") == "running":
            return redirect(url_for("index"))
    # Inputs
    project = (request.form.get("project") or POLL_STATE.get("project") or "").strip()
    interval = int(request.form.get("interval") or os.getenv("DEFAULT_INTERVAL_SEC") or 900)
    local_if = request.form.get("local") or os.getenv("LOCAL_INTERFACE")
    port = request.form.get("port")
    port = int(port) if port else None
    # Resolve map path
    if POLL_STATE.get("map_path") and project and POLL_STATE.get("project") == project:
        map_path = POLL_STATE.get("map_path")
    else:
        # look for file
        cand = Path("data") / f"extraction_map_{project}.csv"
        if cand.exists():
            map_path = str(cand)
        else:
            # fallback: pick first available
            lst = _list_map_files()
            map_path = str(lst[0]) if lst else None
            project = Path(map_path).stem.replace("extraction_map_", "") if map_path else None
    if not map_path or not Path(map_path).exists():
        with _POLL_LOCK:
            POLL_STATE["last_error"] = "No extraction map found. Upload one first."
            POLL_STATE["status"] = "idle"
        return redirect(url_for("index"))

    with _POLL_LOCK:
        POLL_STATE.update({
            "interval_sec": interval,
            "project": project,
            "map_path": map_path,
        })
    _start_poller(map_path, interval, local_if, port)
    return redirect(url_for("index"))


@app.post("/poll/stop")
def poll_stop():
    global _POLL_THREAD
    with _POLL_LOCK:
        if POLL_STATE.get("status") in ("running", "stopping"):
            POLL_STATE["cancel"] = True
            POLL_STATE["status"] = "stopping"
        th = _POLL_THREAD
    if th and th.is_alive():
        for _ in range(20):
            th.join(timeout=0.15)
            if not th.is_alive():
                break
    return redirect(url_for("index"))


@app.post("/reset")
def reset():
    with _RUN_LOCK:
        if RUN_STATE.get("status") == "running":
            return redirect(url_for("index"))
        # Clear error and set idle but keep last options
        RUN_STATE.update({
            "status": "idle",
            "error": None,
            "events": [],
            "completed": 0,
            "total_devices": 0,
            "device_stats": {},
            "started_at": None,
            "finished_at": None,
            "cancel": False,
        })
    return redirect(url_for("index"))


@app.post("/hard-refresh")
def hard_refresh():
    """Cancel any running discovery, wait briefly for shutdown, and reset state to idle."""
    global _RUN_THREAD
    with _RUN_LOCK:
        # Request cancel if running
        if RUN_STATE.get("status") in ("running", "stopping"):
            RUN_STATE["cancel"] = True
        th = _RUN_THREAD
    # Wait outside lock to avoid blocking other routes
    if th and th.is_alive():
        # Wait up to 5 seconds total
        for _ in range(25):
            th.join(timeout=0.2)
            if not th.is_alive():
                break
    # Reset state to idle (preserve last_options)
    with _RUN_LOCK:
        RUN_STATE.update({
            "status": "idle",
            "error": None,
            "events": [],
            "completed": 0,
            "total_devices": 0,
            "device_stats": {},
            "started_at": None,
            "finished_at": None,
            "cancel": False,
            # Also clear any remembered form inputs so the form is blank
            "last_options": {"local": None, "port": None, "sleep": None, "snapshot": False},
        })
    return redirect(url_for("index"))


@app.get("/devices")
def devices():
    con = db_connect()
    cur = con.cursor()
    cur.execute("SELECT device_id, address, vendor_name, model_name, last_seen_utc FROM devices ORDER BY device_id")
    rows = cur.fetchall()
    con.close()
    devices = [
        {"device_id": r[0], "address": r[1], "vendor_name": r[2], "model_name": r[3], "last_seen_utc": r[4]}
        for r in rows
    ]
    return render_template("devices.html", devices=devices)


@app.get("/logs")
def logs():
    return render_template("logs.html", events=list(reversed(RUN_STATE.get("events", [])))[:500])


@app.get("/devices/<int:device_id>")
def device_detail(device_id: int):
    con = db_connect()
    cur = con.cursor()
    cur.execute("SELECT device_id, address, vendor_name, model_name, last_seen_utc FROM devices WHERE device_id=?", (device_id,))
    dev = cur.fetchone()
    cur.execute("SELECT obj_type, obj_inst, obj_name FROM objects WHERE device_id=? ORDER BY obj_type, obj_inst", (device_id,))
    objs = cur.fetchall()
    cur.execute(
        """
        SELECT obj_type, obj_inst, property, value_raw, ts_utc
        FROM samples WHERE device_id=? ORDER BY ts_utc DESC LIMIT 100
        """,
        (device_id,)
    )
    samples = cur.fetchall()
    con.close()
    return render_template("device_detail.html", device=dev, objects=objs, samples=samples)


@app.get("/data/object-counts.json")
def object_counts():
    con = db_connect()
    cur = con.cursor()
    cur.execute(
        """
        SELECT d.device_id, COALESCE(d.vendor_name,''), COALESCE(d.model_name,''), COUNT(o.id)
        FROM devices d LEFT JOIN objects o ON d.device_id = o.device_id
        GROUP BY d.device_id, d.vendor_name, d.model_name
        ORDER BY d.device_id
        """
    )
    rows = cur.fetchall()
    con.close()
    data = [{"device_id": r[0], "label": f"{r[0]} {r[1]} {r[2]}".strip(), "count": r[3] or 0} for r in rows]
    return jsonify(data)


@app.get("/data/points.csv")
def points_csv():
    con = db_connect()
    cur = con.cursor()
    cur.execute(
        """
        SELECT o.device_id,
               COALESCE(d.address, ''),
               COALESCE(d.vendor_name, ''),
               COALESCE(d.model_name, ''),
               o.obj_type,
               o.obj_inst,
               COALESCE(o.obj_name, '')
        FROM objects o
        LEFT JOIN devices d ON d.device_id = o.device_id
        ORDER BY o.device_id, o.obj_type, o.obj_inst
        """
    )
    def generate():
        try:
            buff = io.StringIO()
            w = csv.writer(buff)
            w.writerow(["device_id", "address", "vendor", "model", "obj_type", "obj_inst", "obj_name"])
            yield buff.getvalue(); buff.seek(0); buff.truncate(0)
            for r in cur.fetchall():
                w.writerow([r[0], r[1], r[2], r[3], r[4], r[5], r[6]])
                yield buff.getvalue(); buff.seek(0); buff.truncate(0)
        finally:
            try:
                con.close()
            except Exception:
                pass
    headers = {"Content-Disposition": "attachment; filename=points.csv"}
    return Response(generate(), mimetype="text/csv", headers=headers)


@app.get("/data/points.json")
def points_json():
    con = db_connect()
    try:
        cur = con.cursor()
        cur.execute(
            """
            SELECT o.device_id,
                   COALESCE(d.address, ''),
                   COALESCE(d.vendor_name, ''),
                   COALESCE(d.model_name, ''),
                   o.obj_type,
                   o.obj_inst,
                   COALESCE(o.obj_name, '')
            FROM objects o
            LEFT JOIN devices d ON d.device_id = o.device_id
            ORDER BY o.device_id, o.obj_type, o.obj_inst
            """
        )
        rows = cur.fetchall()
        items = [
            {
                "device_id": r[0],
                "address": r[1],
                "vendor": r[2],
                "model": r[3],
                "obj_type": r[4],
                "obj_inst": r[5],
                "obj_name": r[6],
            }
            for r in rows
        ]
        return jsonify(items)
    finally:
        try:
            con.close()
        except Exception:
            pass


@app.get("/data/devices.csv")
def devices_csv():
    con = db_connect()
    cur = con.cursor()
    cur.execute(
        """
        SELECT device_id,
               address,
               COALESCE(vendor_name,''),
               COALESCE(model_name,''),
               COALESCE(vendor_id,''),
               COALESCE(max_apdu,''),
               COALESCE(segmentation,''),
               COALESCE(firmware_rev,''),
               COALESCE(app_software,''),
               last_seen_utc
        FROM devices
        ORDER BY device_id
        """
    )
    def generate():
        try:
            buff = io.StringIO()
            w = csv.writer(buff)
            w.writerow([
                "device_id","address","vendor_name","model_name","vendor_id",
                "max_apdu","segmentation","firmware_rev","app_software","last_seen_utc"
            ])
            yield buff.getvalue(); buff.seek(0); buff.truncate(0)
            for r in cur.fetchall():
                w.writerow([r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9]])
                yield buff.getvalue(); buff.seek(0); buff.truncate(0)
        finally:
            try:
                con.close()
            except Exception:
                pass
    headers = {"Content-Disposition": "attachment; filename=devices.csv"}
    return Response(generate(), mimetype="text/csv", headers=headers)


@app.get("/data/devices.json")
def devices_json():
    con = db_connect()
    try:
        cur = con.cursor()
        cur.execute(
            """
            SELECT device_id,
                   address,
                   vendor_name,
                   model_name,
                   vendor_id,
                   max_apdu,
                   segmentation,
                   firmware_rev,
                   app_software,
                   last_seen_utc
            FROM devices
            ORDER BY device_id
            """
        )
        rows = cur.fetchall()
        items = [
            {
                "device_id": r[0],
                "address": r[1],
                "vendor_name": r[2],
                "model_name": r[3],
                "vendor_id": r[4],
                "max_apdu": r[5],
                "segmentation": r[6],
                "firmware_rev": r[7],
                "app_software": r[8],
                "last_seen_utc": r[9],
            }
            for r in rows
        ]
        return jsonify(items)
    finally:
        try:
            con.close()
        except Exception:
            pass


@app.get("/data/devices/<int:device_id>/objects.csv")
def device_objects_csv(device_id: int):
    con = db_connect()
    cur = con.cursor()
    cur.execute(
        """
        SELECT o.device_id,
               COALESCE(d.address, ''),
               COALESCE(d.vendor_name, ''),
               COALESCE(d.model_name, ''),
               o.obj_type,
               o.obj_inst,
               COALESCE(o.obj_name, '')
        FROM objects o
        LEFT JOIN devices d ON d.device_id = o.device_id
        WHERE o.device_id = ?
        ORDER BY o.obj_type, o.obj_inst
        """,
        (device_id,)
    )
    def generate():
        try:
            buff = io.StringIO()
            w = csv.writer(buff)
            w.writerow(["device_id", "address", "vendor", "model", "obj_type", "obj_inst", "obj_name"])
            yield buff.getvalue(); buff.seek(0); buff.truncate(0)
            for r in cur.fetchall():
                w.writerow([r[0], r[1], r[2], r[3], r[4], r[5], r[6]])
                yield buff.getvalue(); buff.seek(0); buff.truncate(0)
        finally:
            try:
                con.close()
            except Exception:
                pass
    headers = {"Content-Disposition": f"attachment; filename=device_{device_id}_objects.csv"}
    return Response(generate(), mimetype="text/csv", headers=headers)


@app.get("/data/devices/<int:device_id>/objects.json")
def device_objects_json(device_id: int):
    con = db_connect()
    try:
        cur = con.cursor()
        cur.execute(
            """
            SELECT o.device_id,
                   COALESCE(d.address, ''),
                   COALESCE(d.vendor_name, ''),
                   COALESCE(d.model_name, ''),
                   o.obj_type,
                   o.obj_inst,
                   COALESCE(o.obj_name, '')
            FROM objects o
            LEFT JOIN devices d ON d.device_id = o.device_id
            WHERE o.device_id = ?
            ORDER BY o.obj_type, o.obj_inst
            """,
            (device_id,)
        )
        rows = cur.fetchall()
        items = [
            {"device_id": r[0], "address": r[1], "vendor": r[2], "model": r[3], "obj_type": r[4], "obj_inst": r[5], "obj_name": r[6]}
            for r in rows
        ]
        return jsonify(items)
    finally:
        try:
            con.close()
        except Exception:
            pass


@app.get("/data/devices/<int:device_id>/samples.csv")
def device_samples_csv(device_id: int):
    con = db_connect()
    cur = con.cursor()
    cur.execute(
        """
        SELECT ts_utc, device_id, obj_type, obj_inst, property, value_raw, quality, msg
        FROM samples
        WHERE device_id = ?
        ORDER BY ts_utc DESC
        LIMIT 100
        """,
        (device_id,)
    )
    def generate():
        try:
            buff = io.StringIO()
            w = csv.writer(buff)
            w.writerow(["ts_utc", "device_id", "obj_type", "obj_inst", "property", "value_raw", "quality", "msg"])
            yield buff.getvalue(); buff.seek(0); buff.truncate(0)
            for r in cur.fetchall():
                w.writerow([r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]])
                yield buff.getvalue(); buff.seek(0); buff.truncate(0)
        finally:
            try:
                con.close()
            except Exception:
                pass
    headers = {"Content-Disposition": f"attachment; filename=device_{device_id}_samples.csv"}
    return Response(generate(), mimetype="text/csv", headers=headers)


@app.get("/data/devices/<int:device_id>/samples.json")
def device_samples_json(device_id: int):
    con = db_connect()
    try:
        cur = con.cursor()
        cur.execute(
            """
            SELECT ts_utc, device_id, obj_type, obj_inst, property, value_raw, quality, msg
            FROM samples
            WHERE device_id = ?
            ORDER BY ts_utc DESC
            LIMIT 100
            """,
            (device_id,)
        )
        rows = cur.fetchall()
        items = [
            {
                "ts_utc": r[0],
                "device_id": r[1],
                "obj_type": r[2],
                "obj_inst": r[3],
                "property": r[4],
                "value_raw": r[5],
                "quality": r[6],
                "msg": r[7],
            }
            for r in rows
        ]
        return jsonify(items)
    finally:
        try:
            con.close()
        except Exception:
            pass


@app.get("/data/devices/<int:device_id>/samples-all.csv")
def device_samples_all_csv(device_id: int):
    con = db_connect()
    cur = con.cursor()
    cur.execute(
        """
        SELECT ts_utc, device_id, obj_type, obj_inst, property, value_raw, quality, msg
        FROM samples
        WHERE device_id = ?
        ORDER BY ts_utc DESC
        """,
        (device_id,)
    )
    def generate():
        try:
            buff = io.StringIO()
            w = csv.writer(buff)
            w.writerow(["ts_utc", "device_id", "obj_type", "obj_inst", "property", "value_raw", "quality", "msg"])
            yield buff.getvalue(); buff.seek(0); buff.truncate(0)
            for r in cur:
                w.writerow([r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]])
                yield buff.getvalue(); buff.seek(0); buff.truncate(0)
        finally:
            try:
                con.close()
            except Exception:
                pass
    headers = {"Content-Disposition": f"attachment; filename=device_{device_id}_samples_all.csv"}
    return Response(generate(), mimetype="text/csv", headers=headers)


@app.get("/data/devices/<int:device_id>/samples-all.json")
def device_samples_all_json(device_id: int):
    con = db_connect()
    cur = con.cursor()
    cur.execute(
        """
        SELECT ts_utc, device_id, obj_type, obj_inst, property, value_raw, quality, msg
        FROM samples
        WHERE device_id = ?
        ORDER BY ts_utc DESC
        """,
        (device_id,)
    )
    def generate():
        try:
            first = True
            yield "["
            for r in cur:
                item = {
                    "ts_utc": r[0],
                    "device_id": r[1],
                    "obj_type": r[2],
                    "obj_inst": r[3],
                    "property": r[4],
                    "value_raw": r[5],
                    "quality": r[6],
                    "msg": r[7],
                }
                if not first:
                    yield ","
                first = False
                yield json.dumps(item)
            yield "]"
        finally:
            try:
                con.close()
            except Exception:
                pass
    headers = {"Content-Disposition": f"attachment; filename=device_{device_id}_samples_all.json"}
    return Response(generate(), mimetype="application/json", headers=headers)


@app.get("/data/samples-all.csv")
def samples_all_csv():
    con = db_connect()
    cur = con.cursor()
    cur.execute(
        """
        SELECT ts_utc, device_id, obj_type, obj_inst, property, value_raw, quality, msg
        FROM samples
        ORDER BY ts_utc DESC
        """
    )
    def generate():
        try:
            buff = io.StringIO()
            w = csv.writer(buff)
            w.writerow(["ts_utc", "device_id", "obj_type", "obj_inst", "property", "value_raw", "quality", "msg"])
            yield buff.getvalue(); buff.seek(0); buff.truncate(0)
            for r in cur:
                w.writerow([r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]])
                yield buff.getvalue(); buff.seek(0); buff.truncate(0)
        finally:
            try:
                con.close()
            except Exception:
                pass
    headers = {"Content-Disposition": "attachment; filename=samples_all.csv"}
    return Response(generate(), mimetype="text/csv", headers=headers)


@app.get("/data/samples-all.json")
def samples_all_json():
    con = db_connect()
    cur = con.cursor()
    cur.execute(
        """
        SELECT ts_utc, device_id, obj_type, obj_inst, property, value_raw, quality, msg
        FROM samples
        ORDER BY ts_utc DESC
        """
    )
    def generate():
        try:
            first = True
            yield "["
            for r in cur:
                item = {
                    "ts_utc": r[0],
                    "device_id": r[1],
                    "obj_type": r[2],
                    "obj_inst": r[3],
                    "property": r[4],
                    "value_raw": r[5],
                    "quality": r[6],
                    "msg": r[7],
                }
                if not first:
                    yield ","
                first = False
                yield json.dumps(item)
            yield "]"
        finally:
            try:
                con.close()
            except Exception:
                pass
    headers = {"Content-Disposition": "attachment; filename=samples_all.json"}
    return Response(generate(), mimetype="application/json", headers=headers)


def run(host="127.0.0.1", port=8000):
    dbg = str(os.getenv("FLASK_DEBUG", "")).strip().lower() in ("1", "true", "yes", "on")
    app.run(host=host, port=port, debug=dbg)


if __name__ == "__main__":
    run()
