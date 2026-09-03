"""
Model Pydantic untuk endpoint /ingest dan transformasi dari format
Suricata (bersarang) ke format datar yang dipakai db.

KONTRAK yang disepakati tim:
    Log Shipper (Ryan) mengirim event Suricata APA ADANYA, bersarang.
    Endpoint /ingest yang MERATAKAN sebelum masuk database.

    Alasannya: shipper tetap sederhana, dan validasi terjadi di batas
    sistem (endpoint), bukan tersebar. Data log adalah input tidak
    tepercaya, jadi diperlakukan sebagai hostile dan divalidasi ketat.
"""

from typing import Optional

from pydantic import BaseModel, Field


class SuricataAlert(BaseModel):
    """Bagian 'alert' pada event Suricata. Hanya ada di event_type=alert."""
    signature_id: Optional[int] = None
    signature: Optional[str] = None
    severity: Optional[int] = None
    category: Optional[str] = None


class SuricataFlow(BaseModel):
    """Bagian 'flow' pada event Suricata. Membawa volume byte."""
    bytes_toserver: int = 0
    bytes_toclient: int = 0
    pkts_toserver: int = 0
    pkts_toclient: int = 0


class SuricataEvent(BaseModel):
    """
    Satu event mentah dari eve.json. Bentuk bersarang, sesuai keluaran
    Suricata. Field yang tidak dikenal diabaikan supaya perubahan kecil
    di Suricata tidak membuat ingest gagal total.
    """
    model_config = {"extra": "ignore"}

    timestamp: str
    event_type: str
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    proto: Optional[str] = None
    alert: Optional[SuricataAlert] = None
    flow: Optional[SuricataFlow] = None


class IngestBatch(BaseModel):
    """Batch event yang dikirim shipper dalam satu POST."""
    events: list[SuricataEvent] = Field(default_factory=list)


def flatten(event: SuricataEvent) -> dict:
    """
    Ratakan satu event Suricata bersarang menjadi baris datar untuk db.
    Ini satu-satunya tempat bentuk data berubah, sesuai kontrak.
    """
    alert = event.alert or SuricataAlert()
    flow = event.flow or SuricataFlow()
    return {
        "ts": event.timestamp,
        "event_type": event.event_type,
        "src_ip": event.src_ip,
        "dest_ip": event.dest_ip,
        "dest_port": event.dest_port,
        "proto": event.proto,
        "bytes_toserver": flow.bytes_toserver,
        "bytes_toclient": flow.bytes_toclient,
        "sid": alert.signature_id,
        "signature": alert.signature,
        "severity": alert.severity,
    }
