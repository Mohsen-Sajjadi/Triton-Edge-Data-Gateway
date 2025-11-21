#!/usr/bin/env python3
"""
Discover BACnet/IP devices & object lists; store into SQLite.

Usage:
  python -m bacnet_extractor.discover
  python -m bacnet_extractor.discover --local 192.168.10.25/24 [--port 47808] [--snapshot-values] [--sleep 0.1]
"""

import argparse
import os
import asyncio
import inspect
import time
from datetime import datetime, timezone

from dotenv import load_dotenv
import BAC0

from .db import ensure_db, get_db_path


def upsert_device(cur, info):
    cur.execute(
        """
        INSERT INTO devices(device_id, address, max_apdu, segmentation, vendor_id, vendor_name,
                            model_name, firmware_rev, app_software, last_seen_utc)
        VALUES(?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(device_id) DO UPDATE SET
          address=excluded.address,
          max_apdu=excluded.max_apdu,
          segmentation=excluded.segmentation,
          vendor_id=excluded.vendor_id,
          vendor_name=excluded.vendor_name,
          model_name=excluded.model_name,
          firmware_rev=excluded.firmware_rev,
          app_software=excluded.app_software,
          last_seen_utc=excluded.last_seen_utc
        """,
        (
            info.get("device_id"),
            info.get("address"),
            info.get("max_apdu"),
            info.get("segmentation"),
            info.get("vendor_id"),
            info.get("vendor_name"),
            info.get("model_name"),
            info.get("firmware_rev"),
            info.get("app_software"),
            datetime.now(timezone.utc).isoformat(),
        ),
    )


def insert_object(cur, device_id, obj_type, obj_inst, obj_name):
    cur.execute(
        """
        INSERT OR IGNORE INTO objects(device_id, obj_type, obj_inst, obj_name)
        VALUES(?,?,?,?)
        """,
        (device_id, obj_type, obj_inst, obj_name),
    )


def insert_sample(cur, ts_iso, device_id, obj_type, obj_inst, prop, value_raw, quality=None, msg=None):
    cur.execute(
        """
        INSERT INTO samples(ts_utc, device_id, obj_type, obj_inst, property, value_raw, quality, msg)
        VALUES(?,?,?,?,?,?,?,?)
        """,
        (ts_iso, device_id, obj_type, obj_inst, prop, None if value_raw is None else str(value_raw), quality, msg),
    )


def normalize_devices(devices):
    out = []
    for d in devices:
        if isinstance(d, (list, tuple)) and len(d) >= 2:
            out.append({"address": str(d[0]), "device_id": int(d[1])})
        elif isinstance(d, dict):
            addr = d.get("address"); devid = d.get("device_id")
            if addr is not None and devid is not None:
                out.append({"address": str(addr), "device_id": int(devid)})
        else:
            try:
                s = str(d)
                addr = s.split()[-1]
                digits = "".join(ch for ch in s if ch.isdigit())
                devid = int(digits) if digits else None
                if devid is not None:
                    out.append({"address": addr, "device_id": devid})
            except Exception:
                pass
    uniq = {}
    for e in out:
        uniq[(e["address"], e["device_id"])] = e
    return list(uniq.values())


def read_object_list(dev):
    for attr in ("points", "object_list", "objects", "objectList"):
        try:
            if hasattr(dev, attr):
                val = getattr(dev, attr)
                val = val() if callable(val) else val
                if val:
                    return val
        except Exception:
            pass
    try:
        if hasattr(dev, "properties"):
            raw = dev.properties("objectList")
            if raw:
                return raw
    except Exception:
        pass
    return []


def object_iter(candidates):
    for c in candidates:
        if isinstance(c, (list, tuple)) and len(c) >= 2:
            otype = str(c[0]); inst = int(c[1]); name = None
        elif isinstance(c, dict):
            otype = str(c.get("type") or c.get("obj_type") or c.get("object_type") or "unknown")
            inst = int(c.get("instance") or c.get("obj_inst") or c.get("object_instance") or 0)
            name = c.get("name") or c.get("objectName")
        else:
            s = str(c)
            if "," in s:
                p = s.split(","); otype = p[0].strip(); inst = int(p[1].strip()); name = None
            else:
                otype, inst, name = "unknown", 0, None
        yield (otype, inst, name)


def try_read_present_value(bacnet, dev, obj_type, obj_inst):
    """
    Try different patterns to read presentValue, tolerant to BAC0 variants.
    Returns (value, msg) where msg is an info/error string (optional).
    """
    # Common BACnet property name
    prop = "presentValue"

    # 1) Device-level helper (newer BAC0):
    for meth_name in ("read", "read_property", "readProperty"):
        try:
            m = getattr(dev, meth_name, None)
            if callable(m):
                v = m((obj_type, obj_inst), prop)
                return v, f"{meth_name}"
        except Exception as e:
            last = str(e)

    # 2) Points mapping (some BAC0 builds expose points dict/attr)
    try:
        pts = getattr(dev, "points", None)
        pts = pts() if callable(pts) else pts
        if isinstance(pts, dict):
            key = f"{obj_type},{obj_inst}"
            if key in pts:
                p = pts[key]
                for attr in ("presentValue", "value", "pv"):
                    if hasattr(p, attr):
                        v = getattr(p, attr)
                        v = v() if callable(v) else v
                        return v, "points"
    except Exception as e:
        last = str(e)

    # 3) Direct indexer
    try:
        item = dev[(obj_type, obj_inst)]
        for attr in ("presentValue", "value", "pv"):
            if hasattr(item, attr):
                v = getattr(item, attr)
                v = v() if callable(v) else v
                return v, "indexer"
    except Exception as e:
        last = str(e)

    # 4) Network-level read if exposed
    for meth_name in ("read", "read_multiple", "readMultiple"):
        try:
            m = getattr(bacnet, meth_name, None)
            if callable(m):
                v = m(address=dev.address, device_id=dev.device_id, obj_id=(obj_type, obj_inst), prop=prop)
                return v, f"network.{meth_name}"
        except Exception as e:
            last = str(e)

    return None, f"unreadable: {last if 'last' in locals() else 'no method'}"


async def discover_devices(bacnet):
    """
    Try multiple BAC0 discovery entry points to be compatible across versions.
    Returns (devices, method_name)
    """
    # 1) Methods on the network object
    for meth in ("whois", "who_is", "whoIs", "discover", "scan"):
        try:
            m = getattr(bacnet, meth, None)
            if callable(m):
                res = m()
                if inspect.isawaitable(res):
                    res = await res
                if res is not None:
                    return res, f"network.{meth}"
        except Exception:
            pass

    # 2) Module-level helper
    try:
        if hasattr(BAC0, "discover") and callable(BAC0.discover):
            res = BAC0.discover(bacnet)
            if inspect.isawaitable(res):
                res = await res
            if res is not None:
                return res, "BAC0.discover"
    except Exception:
        pass

    # 3) Fallback: some versions expose .devices after initialization
    try:
        res = getattr(bacnet, "devices", None)
        if res is not None:
            return res, "network.devices"
    except Exception:
        pass

    return [], "none"


async def async_main(local_if: str | None, sleep_between: float, local_port: int | None, snapshot: bool, progress=None, is_cancelled=None):
    try:
        BAC0.log_level("error")
    except Exception:
        pass

    # Start BACnet stack with optional custom port and fallback if busy
    async def _create_bacnet_with_fallback():
        tried = []
        # Build candidate port list
        candidates = []
        if local_port:
            candidates.append(int(local_port))
        # Add typical BACnet ports range as fallback
        for p in range(47808, 47821):
            if p not in candidates:
                candidates.append(p)

        last_exc = None
        for p in candidates:
            try:
                tried.append(p)
                if local_if is not None:
                    bn = BAC0.lite(local_if, port=p)
                else:
                    bn = BAC0.lite(port=p)
                if progress:
                    try:
                        progress({"event": "port_selected", "port": p, "tried": tried[:]})
                    except Exception:
                        pass
                return bn
            except Exception as e:
                msg = str(e)
                last_exc = e
                # If the error suggests port in use or BAC0 already bound, try next port
                if any(s in msg.lower() for s in ["already used by bac0", "address already in use", "in use", "eaddrinuse", "bind"]):
                    continue
                # Other errors: break and raise
                break
        # If we reach here, we failed to create BACnet stack
        if last_exc:
            raise last_exc
        raise RuntimeError("Unable to create BACnet stack: no ports available")

    bacnet = await _create_bacnet_with_fallback()

    con = None
    try:
        if progress:
            try:
                progress({"event": "start", "ts": datetime.now(timezone.utc).isoformat()})
            except Exception:
                pass
        print("[i] Broadcasting Who-Is / Discover")
        raw, method = await discover_devices(bacnet)
        devices = normalize_devices(raw)
        print(f"[i] Found {len(devices)} device(s).")
        if progress:
            try:
                progress({"event": "whois_complete", "total_devices": len(devices), "method": method})
            except Exception:
                pass

        con = ensure_db()
        cur = con.cursor()

        for entry in devices:
            if is_cancelled and callable(is_cancelled) and is_cancelled():
                if progress:
                    try:
                        progress({"event": "cancelled"})
                    except Exception:
                        pass
                break
            addr = entry["address"]; devid = entry["device_id"]
            print(f"    + Device {devid} @ {addr}")
            if progress:
                try:
                    progress({"event": "device_start", "device_id": devid, "address": addr})
                except Exception:
                    pass
            try:
                dev = BAC0.device(address=addr, device_id=devid, network=bacnet)
            except Exception as e:
                print(f"      ! Cannot create device helper: {e}")
                if progress:
                    try:
                        progress({"event": "device_error", "device_id": devid, "address": addr, "error": str(e)})
                    except Exception:
                        pass
                continue

            info = {
                "device_id": devid,
                "address": addr,
                "max_apdu": getattr(dev, "max_apdu", None),
                "segmentation": getattr(dev, "segmentation", None),
                "vendor_id": getattr(dev, "vendor_id", None),
                "vendor_name": getattr(dev, "vendor_name", None),
                "model_name": getattr(dev, "model_name", None),
                "firmware_rev": getattr(dev, "firmware_revision", None),
                "app_software": getattr(dev, "application_software_version", None),
            }
            upsert_device(cur, info)

            # Object list
            try:
                cand = read_object_list(dev)
            except Exception as e:
                print(f"      ! objectList read failed: {e}")
                cand = []

            # Save objects
            obj_count = 0
            for (otype, inst, name) in object_iter(cand):
                insert_object(cur, devid, otype, inst, name)
                obj_count += 1
            con.commit()
            print(f"      Saved {obj_count} object(s).")
            if progress:
                try:
                    progress({"event": "device_objects", "device_id": devid, "count": obj_count})
                except Exception:
                    pass

            # Optional: snapshot presentValue
            if snapshot and obj_count:
                ts_iso = datetime.now(timezone.utc).isoformat()
                snap_count = 0
                for (otype, inst, name) in object_iter(cand):
                    # Only common value-carrying types to keep the snapshot fast
                    if otype not in ("analogInput", "analogOutput", "analogValue",
                                     "binaryInput", "binaryOutput", "binaryValue",
                                     "multiStateInput", "multiStateOutput", "multiStateValue"):
                        continue
                    try:
                        v, msg = try_read_present_value(bacnet, dev, otype, inst)
                        insert_sample(cur, ts_iso, devid, otype, inst, "presentValue", v, quality="snapshot", msg=msg)
                        snap_count += 1
                    except Exception as e:
                        # Best effort: record an error sample or at least continue
                        try:
                            insert_sample(cur, ts_iso, devid, otype, inst, "presentValue", None, quality="snapshot", msg=f"error: {e}")
                            snap_count += 1
                        except Exception as e2:
                            print(f"      ! snapshot insert failed: {e2}")
                con.commit()
                print(f"      Snapshot saved for {snap_count} object(s).")
                if progress:
                    try:
                        progress({"event": "device_snapshot", "device_id": devid, "count": snap_count})
                    except Exception:
                        pass

            # Delay, but bail quickly if cancelled
            for _ in range(int(max(1, sleep_between / 0.05))):
                if is_cancelled and callable(is_cancelled) and is_cancelled():
                    break
                await asyncio.sleep(min(0.05, max(0.0, sleep_between)))
            if progress:
                try:
                    progress({"event": "device_done", "device_id": devid})
                except Exception:
                    pass

        print(f"[i] Discovery complete. DB at: {get_db_path()}")
        if progress:
            try:
                progress({"event": "complete", "db_path": get_db_path()})
            except Exception:
                pass
    finally:
        try:
            if con is not None:
                con.close()
        except Exception:
            pass
        # Graceful BACnet shutdown (best effort across BAC0 variants)
        for meth in ("disconnect", "close", "stop", "shutdown"):
            try:
                m = getattr(bacnet, meth, None)
                if callable(m):
                    m()
                    break
            except Exception:
                pass
        # Extra best-effort cleanup for some BAC0 builds
        try:
            if hasattr(bacnet, "__del__"):
                try:
                    bacnet.__del__()
                except Exception:
                    pass
        except Exception:
            pass
        # Small delay to let OS release socket
        try:
            await asyncio.sleep(0.2)
        except Exception:
            try:
                time.sleep(0.2)
            except Exception:
                pass


def main():
    load_dotenv()
    p = argparse.ArgumentParser(description="BACnet discovery to SQLite")
    p.add_argument("--local", help="Local IP/CIDR (e.g., 192.168.10.25/24). If omitted, BAC0 auto-selects NIC.")
    p.add_argument("--port", type=int, default=None, help="Local UDP port (default 47808). Use if 47808 is busy.")
    p.add_argument("--sleep", type=float, default=0.1, help="Sleep between device queries (seconds).")
    p.add_argument("--snapshot-values", action="store_true", help="Also read presentValue once for common object types.")
    args = p.parse_args()

    asyncio.run(async_main(args.local or os.getenv("LOCAL_INTERFACE"), args.sleep, args.port, args.snapshot_values))


if __name__ == "__main__":
    main()
