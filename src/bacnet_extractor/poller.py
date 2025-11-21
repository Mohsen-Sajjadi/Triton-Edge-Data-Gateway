import os
import csv
import time
import threading
from datetime import datetime, timezone
from pathlib import Path

import BAC0

from .db import ensure_db
from .discover import try_read_present_value


def _create_bacnet_with_fallback(local_if: str | None, local_port: int | None, progress=None):
    tried = []
    candidates = []
    if local_port:
        candidates.append(int(local_port))
    for p in range(47808, 47821):
        if p not in candidates:
            candidates.append(p)
    last_exc = None
    for p in candidates:
        try:
            tried.append(p)
            if local_if is not None and str(local_if).strip():
                bn = BAC0.lite(local_if, port=p)
            else:
                bn = BAC0.lite(port=p)
            if progress:
                try:
                    progress({"event": "poll_port_selected", "port": p, "tried": tried[:]})
                except Exception:
                    pass
            return bn
        except Exception as e:
            msg = str(e)
            last_exc = e
            if any(s in msg.lower() for s in ["already used by bac0", "address already in use", "in use", "eaddrinuse", "bind"]):
                continue
            break
    if last_exc:
        raise last_exc
    raise RuntimeError("Unable to create BACnet stack for poller: no ports available")


def _safe_release_bacnet(bacnet):
    # Graceful BACnet shutdown (best effort across BAC0 variants)
    for meth in ("disconnect", "close", "stop", "shutdown"):
        try:
            m = getattr(bacnet, meth, None)
            if callable(m):
                m()
                break
        except Exception:
            pass
    try:
        if hasattr(bacnet, "__del__"):
            try:
                bacnet.__del__()
            except Exception:
                pass
    except Exception:
        pass


def _read_map_csv(path: str):
    entries = []
    with open(path, newline='', encoding='utf-8') as f:
        r = csv.DictReader(f)
        for row in r:
            if not row:
                continue
            # Normalize keys
            device_id = row.get('device_id') or row.get('DeviceId') or row.get('device')
            address = row.get('address') or row.get('Address')
            obj_type = row.get('obj_type') or row.get('object_type') or row.get('type')
            obj_inst = row.get('obj_inst') or row.get('object_instance') or row.get('instance')
            prop = row.get('property') or row.get('prop') or 'presentValue'
            tag = row.get('tag') or row.get('name') or None
            if not obj_type or not obj_inst:
                continue
            try:
                obj_inst = int(str(obj_inst).strip())
            except Exception:
                continue
            devid_int = None
            if device_id:
                try:
                    devid_int = int(str(device_id).strip())
                except Exception:
                    pass
            entries.append({
                'device_id': devid_int,
                'address': (str(address).strip() if address else None),
                'obj_type': str(obj_type).strip(),
                'obj_inst': obj_inst,
                'property': str(prop).strip() if prop else 'presentValue',
                'tag': (str(tag).strip() if tag else None),
            })
    return entries


def _resolve_address(cur, device_id: int):
    cur.execute("SELECT address FROM devices WHERE device_id=?", (device_id,))
    r = cur.fetchone()
    return r[0] if r else None


def _insert_sample(cur, ts_iso, device_id, obj_type, obj_inst, prop, value_raw, quality=None, msg=None):
    cur.execute(
        """
        INSERT INTO samples(ts_utc, device_id, obj_type, obj_inst, property, value_raw, quality, msg)
        VALUES(?,?,?,?,?,?,?,?)
        """,
        (ts_iso, device_id, obj_type, obj_inst, prop, None if value_raw is None else str(value_raw), quality, msg),
    )


def run_once(map_path: str, local_if: str | None = None, local_port: int | None = None, progress=None):
    entries = _read_map_csv(map_path)
    if progress:
        try:
            progress({"event": "poll_cycle_start", "points": len(entries)})
        except Exception:
            pass
    if not entries:
        return {"points": 0, "read": 0, "errors": 0}

    con = ensure_db()
    cur = con.cursor()
    bn = None
    ok = 0
    err = 0
    try:
        bn = _create_bacnet_with_fallback(local_if, local_port, progress=progress)
        ts_iso = datetime.now(timezone.utc).isoformat()
        for e in entries:
            devid = e['device_id']
            addr = e['address']
            if devid is None and not addr:
                err += 1
                continue
            if not addr and devid is not None:
                try:
                    addr = _resolve_address(cur, devid)
                except Exception:
                    addr = None
            if not addr:
                err += 1
                continue
            try:
                dev = BAC0.device(address=addr, device_id=devid if devid is not None else None, network=bn)
            except Exception as ex:
                err += 1
                try:
                    _insert_sample(cur, ts_iso, devid if devid is not None else -1, e['obj_type'], e['obj_inst'], e['property'], None, quality="poll", msg=f"device_error: {ex}")
                except Exception:
                    pass
                continue

            try:
                value = None
                msg = None
                if (e['property'] or 'presentValue') == 'presentValue':
                    value, msg = try_read_present_value(bn, dev, e['obj_type'], e['obj_inst'])
                else:
                    # generic property read attempts
                    got = False
                    for meth in ("read", "read_property", "readProperty"):
                        try:
                            m = getattr(dev, meth, None)
                            if callable(m):
                                value = m((e['obj_type'], e['obj_inst']), e['property'])
                                msg = meth
                                got = True
                                break
                        except Exception:
                            pass
                    if not got:
                        for meth in ("read", "read_multiple", "readMultiple"):
                            try:
                                m = getattr(bn, meth, None)
                                if callable(m):
                                    value = m(address=addr, device_id=devid, obj_id=(e['obj_type'], e['obj_inst']), prop=e['property'])
                                    msg = f"network.{meth}"
                                    got = True
                                    break
                            except Exception:
                                pass
                        if not got:
                            msg = "unreadable"

                _insert_sample(cur, ts_iso, devid if devid is not None else -1, e['obj_type'], e['obj_inst'], e['property'], value, quality="poll", msg=msg)
                ok += 1
            except Exception as ex:
                err += 1
                try:
                    _insert_sample(cur, ts_iso, devid if devid is not None else -1, e['obj_type'], e['obj_inst'], e['property'], None, quality="poll", msg=f"error: {ex}")
                except Exception:
                    pass
        con.commit()
    finally:
        try:
            if con:
                con.close()
        except Exception:
            pass
        if bn is not None:
            _safe_release_bacnet(bn)

    if progress:
        try:
            progress({"event": "poll_cycle_done", "points": len(entries), "read": ok, "errors": err})
        except Exception:
            pass
    return {"points": len(entries), "read": ok, "errors": err}


def run_loop(map_path: str, interval_sec: int, local_if: str | None, local_port: int | None, is_cancelled, progress=None):
    while True:
        if is_cancelled and callable(is_cancelled) and is_cancelled():
            break
        try:
            run_once(map_path, local_if=local_if, local_port=local_port, progress=progress)
        except Exception as e:
            if progress:
                try:
                    progress({"event": "poll_cycle_error", "error": str(e)})
                except Exception:
                    pass
        # Safety: release BAC0 each cycle is handled inside run_once
        # Sleep between cycles, but wake up early if cancelled
        slept = 0
        step = 0.5
        while slept < max(1, int(interval_sec)):
            if is_cancelled and callable(is_cancelled) and is_cancelled():
                break
            time.sleep(step)
            slept += step
        if is_cancelled and callable(is_cancelled) and is_cancelled():
            break

