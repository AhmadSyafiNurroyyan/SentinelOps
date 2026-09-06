import json
import os
import sys

import requests

ATTACK_VERSION = "19.1"
ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    f"v{ATTACK_VERSION}/enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)

HERE = os.path.dirname(os.path.abspath(__file__))
RAW_DIR = os.path.join(HERE, "raw")
RAW_PATH = os.path.join(RAW_DIR, f"enterprise-attack-{ATTACK_VERSION}.json")
OUT_PATH = os.path.join(HERE, "attack_techniques.json")
TECHNIQUES = [
    "T1046",  # Network Service Discovery (Nmap SYN / NULL scan)
    "T1595",  # Active Scanning
    "T1110",  # Brute Force (SSH)
    "T1048",  # Exfiltration Over Alternative Protocol (transfer besar)
    "T1021",  # Remote Services
    "T1071",  # Application Layer Protocol
]


def download():
    os.makedirs(RAW_DIR, exist_ok=True)
    if os.path.exists(RAW_PATH):
        size_mb = os.path.getsize(RAW_PATH) / 1048576
        print(f"[skip]  Sudah ada: {RAW_PATH} ({size_mb:.1f} MB)")
        return

    print(f"[unduh] {ATTACK_URL}")
    print("        Ukuran sekitar 51 MB, mohon tunggu.")
    resp = requests.get(ATTACK_URL, stream=True, timeout=300)
    resp.raise_for_status()

    downloaded = 0
    with open(RAW_PATH, "wb") as f:
        for chunk in resp.iter_content(chunk_size=1 << 20):
            f.write(chunk)
            downloaded += len(chunk)
            print(f"\r        {downloaded / 1048576:.1f} MB", end="", flush=True)
    print(f"\n[ok]    Tersimpan di {RAW_PATH}")


def external_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None

def extract(objects, wanted):
    by_id = {o["id"]: o for o in objects}

    techniques = {}
    for obj in objects:
        if obj["type"] != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        tid = external_id(obj)
        if tid in wanted:
            techniques[obj["id"]] = tid

    missing = wanted - set(techniques.values())
    if missing:
        print(f"[warn]  Tidak ditemukan: {sorted(missing)}")
    mitigations = {sid: [] for sid in techniques}
    strategies = {sid: [] for sid in techniques}

    for rel in objects:
        if rel["type"] != "relationship":
            continue
        target = rel.get("target_ref")
        if target not in techniques:
            continue
        source = by_id.get(rel.get("source_ref"))
        if not source:
            continue

        rtype = rel["relationship_type"]
        if rtype == "mitigates" and source["type"] == "course-of-action":
            mitigations[target].append(source)
        elif rtype == "detects" and source["type"] == "x-mitre-detection-strategy":
            strategies[target].append(source)

    result = []
    for sid, tid in techniques.items():
        obj = by_id[sid]

        detections = []
        for strat in strategies[sid]:
            for ref in strat.get("x_mitre_analytic_refs", []):
                analytic = by_id.get(ref)
                if analytic and analytic.get("description"):
                    detections.append(analytic["description"])

        result.append({
            "technique_id": tid,
            "name": obj["name"],
            "description": obj["description"],
            "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
            "platforms": obj.get("x_mitre_platforms", []),
            "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            "mitigations": [
                {"name": m["name"], "text": m["description"]}
                for m in mitigations[sid]
            ],
            "detections": detections,
            "source_doc": f"MITRE ATT&CK Enterprise v{ATTACK_VERSION}",
            "source_url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        })

    result.sort(key=lambda r: r["technique_id"])
    return result


def main():
    download()

    print("[baca]  Memuat bundle ke memori, perlu beberapa detik.")
    with open(RAW_PATH, encoding="utf-8") as f:
        objects = json.load(f)["objects"]
    print(f"[ok]    {len(objects):,} objek STIX termuat.")

    data = extract(objects, set(TECHNIQUES))

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"[ok]    {len(data)} technique tersimpan di {OUT_PATH}")
    print()
    print("Ringkasan:")
    for t in data:
        print(
            f"  {t['technique_id']:<10} {t['name'][:38]:<40} "
            f"mitigasi={len(t['mitigations'])}  deteksi={len(t['detections'])}"
        )

    kosong = [t["technique_id"] for t in data if not t["detections"]]
    if kosong:
        print()
        print(f"[catat] Tanpa teks deteksi: {kosong}")
        print("        Wajar untuk sebagian technique. Lengkapi dari rule ET.")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as exc:
        print(f"[gagal] Unduhan bermasalah: {exc}", file=sys.stderr)
        sys.exit(1)
