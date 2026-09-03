"""
API SentinelOps.

Menyajikan lima endpoint:
    POST /ingest        terima batch event dari Log Shipper
    GET  /assets        daftar host dengan skor risiko
    GET  /assets/{ip}   detail satu host + riwayat skor
    GET  /timeline      event, ditandai signature atau statistical
    GET  /chat          placeholder, diisi setelah RAG jadi
    GET  /health        liveness, tanpa auth

main.py sengaja tipis: hanya routing dan validasi. Logika ada di modul
lain (db, schemas, nanti scoring dan rag).

Jalankan lokal:
    uvicorn api.main:app --reload --port 8000
Lalu buka http://localhost:8000/docs untuk dokumentasi otomatis.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from . import db
from . import schemas

app = FastAPI(
    title="SentinelOps API",
    description="Lapisan interpretasi keamanan jaringan untuk institusi tanpa tim SOC",
    version="0.1.0",
)

# Pastikan skema ada sejak modul dimuat, sebelum request pertama masuk.
db.init_db()

# Muat engine RAG sekali. Kalau index belum dibangun, aplikasi tetap
# hidup dan /chat memberi pesan jelas, bukan crash saat startup.
_rag_engine = None
_rag_error = None
try:
    from .rag_loader import load_engine
    _rag_engine = load_engine()
except Exception as exc:
    _rag_error = str(exc)


@app.get("/health")
def health():
    """Liveness. Tanpa auth. Dipakai uptime monitor dan orkestrasi Docker."""
    hosts = db.get_hosts()
    return {
        "status": "ok",
        "hosts_tracked": len(hosts),
    }


@app.post("/ingest")
def ingest(batch: schemas.IngestBatch):
    """
    Terima batch event mentah Suricata dari shipper, ratakan, simpan.
    Pydantic sudah memvalidasi bentuknya sebelum sampai di sini.
    """
    if not batch.events:
        return {"received": 0, "stored": 0}

    rows = [schemas.flatten(ev) for ev in batch.events]
    stored = db.insert_events(rows)
    return {"received": len(batch.events), "stored": stored}


@app.get("/assets")
def list_assets():
    """Daftar host, diurutkan dari skor risiko tertinggi."""
    return {"hosts": db.get_hosts()}


@app.get("/assets/{ip}")
def get_asset(ip: str):
    """Detail satu host beserta riwayat skornya."""
    host = db.get_host(ip)
    if host is None:
        raise HTTPException(status_code=404, detail=f"Host {ip} tidak ditemukan")
    return host


@app.get("/timeline")
def timeline(limit: int = 100):
    """
    Event terurut waktu, tiap event ditandai:
        signature   = berasal dari alert (Suricata sudah mendeteksi)
        statistical = event flow tanpa alert (kandidat anomali statistik)

    Pemisahan ini adalah jawaban visual atas pertanyaan
    'bukankah ini redundan dengan Suricata?'.
    """
    limit = max(1, min(limit, 500))
    with db.db_cursor() as cur:
        cur.execute(
            "SELECT ts, event_type, src_ip, dest_ip, dest_port, "
            "sid, signature, severity FROM events "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = [dict(r) for r in cur.fetchall()]

    for r in rows:
        r["source"] = "signature" if r.get("sid") else "statistical"
    return {"events": rows}


class ChatRequest(BaseModel):
    query: str


@app.post("/chat")
def chat(req: ChatRequest):
    """
    Tanya jawab RAG. Menerima {"query": "..."}, mengembalikan jawaban
    Bahasa Indonesia beserta sitasi.
    """
    if _rag_engine is None:
        raise HTTPException(
            status_code=503,
            detail=f"Mesin RAG belum siap. Jalankan indexer dulu. ({_rag_error})",
        )
    if not req.query.strip():
        raise HTTPException(status_code=422, detail="Pertanyaan kosong")
    return _rag_engine.answer(req.query)
