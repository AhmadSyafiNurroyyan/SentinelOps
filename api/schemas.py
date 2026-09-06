from typing import Optional

from pydantic import BaseModel, Field

class SuricataAlert(BaseModel):
    signature_id: Optional[int] = None
    signature: Optional[str] = None
    severity: Optional[int] = None
    category: Optional[str] = None


class SuricataFlow(BaseModel):
    bytes_toserver: int = 0
    bytes_toclient: int = 0
    pkts_toserver: int = 0
    pkts_toclient: int = 0


class SuricataEvent(BaseModel):
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
    events: list[SuricataEvent] = Field(default_factory=list)

def flatten(event: SuricataEvent) -> dict:
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
