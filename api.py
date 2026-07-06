"""
FastAPI wrapper around netscan.db.

Deliberately standalone: does NOT import netscan.py, so this API process
never needs scapy or root privileges just to serve JSON. It only needs
read/write access to the same netscan.db file the scanner produces.

Run with:
    uvicorn api:app --host 0.0.0.0 --port 8000
"""

import os
import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Assumes api.py lives in the same directory as netscan.py / netscan.db.
# If you move this file, update DB_PATH to point at the scanner's DB.
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netscan.db")

ONLINE_THRESHOLD_MINUTES = 15

app = FastAPI(title="NetScan API", version="1.0.0")

# A home-network dashboard will typically be served from a different
# origin/port (e.g. a static file server on 5500, or opened via file://).
# Allowing all origins is reasonable for a LAN-only tool with no auth,
# but tighten this (allow_origins=["http://localhost:XXXX"]) if you ever
# expose this port beyond your own machine.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------------------------------------------------------------------
# DB dependency — one connection per request, closed when the request
# finishes. Routes are defined as regular `def` (not `async def`) so
# FastAPI runs them in its threadpool, keeping blocking sqlite3 calls
# off the event loop.
# ----------------------------------------------------------------------

def get_db():
    if not os.path.exists(DB_PATH):
        raise HTTPException(
            status_code=503,
            detail=f"Database not found at {DB_PATH}. Run netscan.py at least once first.",
        )
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
    finally:
        conn.close()


# ----------------------------------------------------------------------
# Response models
# ----------------------------------------------------------------------

class Device(BaseModel):
    mac: str
    ip: str
    hostname: str
    vendor: str
    device_type: str
    confidence_score: int
    confidence_tier: str
    open_ports: List[int]
    banner: Optional[str] = None
    mdns_services: List[str]
    ssdp_friendly_name: Optional[str] = None
    ssdp_model_name: Optional[str] = None
    raw_ttl: Optional[int] = None
    raw_window: Optional[int] = None
    is_approved: bool
    first_seen: str
    last_seen: str
    status: str  # "online" / "offline", computed from last_seen — never stored


class ScanLogEntry(BaseModel):
    ip: str
    scan_timestamp: str


class Stats(BaseModel):
    total_devices: int
    online_now: int
    pending_approval: int
    unknown_vendor: int
    low_confidence: int


class ApprovalUpdate(BaseModel):
    is_approved: bool


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def row_to_device(row: sqlite3.Row) -> Device:
    last_seen_dt = datetime.fromisoformat(row["last_seen"])
    age_minutes = (datetime.now(timezone.utc) - last_seen_dt).total_seconds() / 60
    status = "online" if age_minutes <= ONLINE_THRESHOLD_MINUTES else "offline"

    return Device(
        mac=row["mac"],
        ip=row["ip"],
        hostname=row["hostname"],
        vendor=row["vendor"],
        device_type=row["device_type"],
        confidence_score=row["confidence_score"],
        confidence_tier=row["confidence_tier"],
        open_ports=json.loads(row["open_ports"]) if row["open_ports"] else [],
        banner=row["banner"],
        mdns_services=json.loads(row["mdns_services"]) if row["mdns_services"] else [],
        ssdp_friendly_name=row["ssdp_friendly_name"],
        ssdp_model_name=row["ssdp_model_name"],
        raw_ttl=row["raw_ttl"],
        raw_window=row["raw_window"],
        is_approved=bool(row["is_approved"]),
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        status=status,
    )


# ----------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------

@app.get("/devices", response_model=List[Device])
def list_devices(
    pending_only: bool = False,
    unknown_only: bool = False,
    db: sqlite3.Connection = Depends(get_db),
):
    """
    Returns every known device. Filters:
      ?pending_only=true  -> only devices awaiting approval
      ?unknown_only=true  -> only devices with an unrecognized OUI vendor
    """
    query = "SELECT * FROM devices"
    conditions = []
    if pending_only:
        conditions.append("is_approved = 0")
    if unknown_only:
        conditions.append("vendor = 'Unknown'")
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY last_seen DESC"

    rows = db.execute(query).fetchall()
    return [row_to_device(r) for r in rows]


@app.get("/devices/{mac}", response_model=Device)
def get_device(mac: str, db: sqlite3.Connection = Depends(get_db)):
    row = db.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"No device found with MAC {mac}")
    return row_to_device(row)


@app.get("/devices/{mac}/history", response_model=List[ScanLogEntry])
def get_device_history(mac: str, db: sqlite3.Connection = Depends(get_db)):
    """Sighting timeline for a single device — every scan it showed up in."""
    exists = db.execute("SELECT 1 FROM devices WHERE mac = ?", (mac,)).fetchone()
    if exists is None:
        raise HTTPException(status_code=404, detail=f"No device found with MAC {mac}")

    rows = db.execute(
        "SELECT ip, scan_timestamp FROM scan_log WHERE mac = ? ORDER BY scan_timestamp DESC",
        (mac,),
    ).fetchall()
    return [ScanLogEntry(ip=r["ip"], scan_timestamp=r["scan_timestamp"]) for r in rows]


@app.patch("/devices/{mac}/approve", response_model=Device)
def set_approval(mac: str, update: ApprovalUpdate, db: sqlite3.Connection = Depends(get_db)):
    """Approve or un-approve a device. This is the action your dashboard's button should call."""
    row = db.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"No device found with MAC {mac}")

    db.execute(
        "UPDATE devices SET is_approved = ? WHERE mac = ?",
        (1 if update.is_approved else 0, mac),
    )
    db.commit()

    updated_row = db.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
    return row_to_device(updated_row)


@app.get("/stats", response_model=Stats)
def get_stats(db: sqlite3.Connection = Depends(get_db)):
    rows = db.execute("SELECT * FROM devices").fetchall()
    devices = [row_to_device(r) for r in rows]

    return Stats(
        total_devices=len(devices),
        online_now=sum(1 for d in devices if d.status == "online"),
        pending_approval=sum(1 for d in devices if not d.is_approved),
        unknown_vendor=sum(1 for d in devices if d.vendor == "Unknown"),
        low_confidence=sum(1 for d in devices if d.confidence_tier == "Low"),
    )


@app.get("/health")
def health_check():
    db_exists = os.path.exists(DB_PATH)
    return {"status": "ok" if db_exists else "db_missing", "db_path": DB_PATH}
