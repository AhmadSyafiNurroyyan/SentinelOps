import hashlib
import hmac
import os
import time

from fastapi import Header, HTTPException, Request

REPLAY_WINDOW_SECONDS = 300

_DEFAULT_SECRET_DEV_ONLY = "dev-secret-ganti-di-production"
SECRET = os.environ.get("SENTINELOPS_HMAC_SECRET", _DEFAULT_SECRET_DEV_ONLY)
if SECRET == _DEFAULT_SECRET_DEV_ONLY:
    print("[security] PERINGATAN: SENTINELOPS_HMAC_SECRET tidak di-set)")
_signature_seen = {}

def _bersihkan_cache_kadaluarsa(sekarang):
    kadaluarsa = [sig for sig, exp in _signature_seen.items() if exp < sekarang]
    for sig in kadaluarsa:
        del _signature_seen[sig]


def hitung_signature(timestamp_str, body_bytes, secret=None):
    secret = secret or SECRET
    pesan = timestamp_str.encode() + body_bytes
    return hmac.new(secret.encode(), pesan, hashlib.sha256).hexdigest()

async def verify_hmac_signature(
    request: Request,
    x_signature: str = Header(..., description="HMAC-SHA256 hex digest"),
    x_timestamp: str = Header(..., description="Unix timestamp (detik) saat request dibuat"),
):

    try:
        ts_int = int(x_timestamp)
    except ValueError:
        raise HTTPException(status_code=401, detail="X-Timestamp tidak valid (harus angka)")

    sekarang = int(time.time())
    selisih = abs(sekarang - ts_int)

    if selisih > REPLAY_WINDOW_SECONDS:
        raise HTTPException(
            status_code=401,
            detail=f"Request kadaluarsa (selisih waktu {selisih}s, batas {REPLAY_WINDOW_SECONDS}s)",
        )

    body = await request.body()
    signature_seharusnya = hitung_signature(x_timestamp, body)

    if not hmac.compare_digest(x_signature, signature_seharusnya):
        raise HTTPException(status_code=401, detail="Signature tidak valid")

    _bersihkan_cache_kadaluarsa(sekarang)
    if x_signature in _signature_seen:
        raise HTTPException(status_code=401, detail="Replay terdeteksi: signature ini sudah pernah dipakai")

    _signature_seen[x_signature] = sekarang + REPLAY_WINDOW_SECONDS
