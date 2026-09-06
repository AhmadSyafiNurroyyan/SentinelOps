import json
import os
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_IN = os.path.join(HERE, "raw", "eve.json")
OUT_PATH = os.path.join(HERE, "observed_sids.json")


def load_events(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        head = f.read(2048).lstrip()
        f.seek(0)

        if head.startswith("["):
            data = json.load(f)
            for item in data:
                yield item
            return

        bad = 0
        for line in f:
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                bad += 1
        if bad:
            print(f"[catat] {bad} baris tidak bisa di-parse, dilewati")


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_IN
    if not os.path.exists(path):
        print(f"[gagal] Tidak ada {path}", file=sys.stderr)
        sys.exit(1)

    size_mb = os.path.getsize(path) / 1048576
    print(f"[baca]  {path} ({size_mb:.1f} MB)")

    types = Counter()
    sids = {}
    sid_count = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    ports = Counter()
    timestamps = []
    total = 0

    for ev in load_events(path):
        total += 1
        et = ev.get("event_type", "?")
        types[et] += 1

        ts = ev.get("timestamp")
        if ts and len(timestamps) < 200000:
            timestamps.append(ts)

        if ev.get("src_ip"):
            src_ips[ev["src_ip"]] += 1
        if ev.get("dest_ip"):
            dst_ips[ev["dest_ip"]] += 1
        if ev.get("dest_port"):
            ports[ev["dest_port"]] += 1

        if et == "alert":
            alert = ev.get("alert") or {}
            sid = alert.get("signature_id")
            if sid is not None:
                sid_count[sid] += 1
                if sid not in sids:
                    sids[sid] = {
                        "sid": sid,
                        "signature": alert.get("signature"),
                        "category": alert.get("category"),
                        "severity": alert.get("severity"),
                        "technique_id_manual": None,
                        "confirmed": True,
                    }

    print(f"[ok]    {total:,} event terbaca")
    print()
    print("Jenis event:")
    for et, n in types.most_common():
        print(f"  {et:<16} {n:>8,}")

    if timestamps:
        print()
        print(f"Rentang waktu: {min(timestamps)}  sampai  {max(timestamps)}")

    print()
    print(f"SID unik yang terpicu: {len(sids)}")
    for sid in sorted(sids):
        info = sids[sid]
        print(f"  {sid:<9} x{sid_count[sid]:<5} {(info['signature'] or '')[:58]}")

    print()
    print("Host pengirim terbanyak:")
    for ip, n in src_ips.most_common(8):
        print(f"  {ip:<18} {n:>7,}")

    print()
    print("Host tujuan terbanyak:")
    for ip, n in dst_ips.most_common(8):
        print(f"  {ip:<18} {n:>7,}")

    print()
    print("Port tujuan terbanyak:")
    for p, n in ports.most_common(8):
        print(f"  {str(p):<8} {n:>7,}")

    out = [dict(sids[s], count=sid_count[s]) for s in sorted(sids)]
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print()
    print(f"[ok]    Daftar SID tersimpan di {OUT_PATH}")

    if types.get("flow", 0) == 0:
        print()
        print("[PENTING] Tidak ada event bertipe 'flow'.")
        print("          Scoring statistik membutuhkan event flow, bukan alert.")
        print("          Cek konfigurasi eve-log Suricata milik Ryan.")

    print()
    print("Berikutnya: isi technique_id_manual untuk tiap SID di")
    print("corpus/observed_sids.json, lalu simpan sebagai corpus/sid_mapping.json")


if __name__ == "__main__":
    main()
