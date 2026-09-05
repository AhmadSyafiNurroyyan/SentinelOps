import argparse
import hashlib
import hmac
import json
import os
import sys
import time

import requests

def baca_baris_baru(filepath, offset_terakhir):
    with open(filepath, "r") as f:
        f.seek(offset_terakhir)
        daftar_baris_baru = f.readlines()
        offset_baru = f.tell()
    return daftar_baris_baru, offset_baru

def simpan_offset(state_file, offset):
    with open(state_file, "w") as f:
        f.write(str(offset))


def baca_offset_tersimpan(state_file):
    try:
        with open(state_file, "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return 0

def parse_baris(baris_list):
    hasil = []
    for baris in baris_list:
        baris = baris.strip()
        if not baris:
            continue
        try:
            hasil.append(json.loads(baris))
        except json.JSONDecodeError:
            print(f"[shipper] WARNING: baris rusak, dilewati: {baris[:80]}...")
    return hasil


def buat_signature(timestamp, body_bytes, secret):
    pesan = timestamp.encode() + body_bytes
    return hmac.new(secret.encode(), pesan, hashlib.sha256).hexdigest()


def kirim_batch(api_url, secret, events, timeout=10):
    body_bytes = json.dumps({"events": events}).encode()
    timestamp = str(int(time.time()))
    signature = buat_signature(timestamp, body_bytes, secret)

    headers = {
        "Content-Type": "application/json",
        "X-Timestamp": timestamp,
        "X-Signature": signature,
    }

    try:
        resp = requests.post(api_url, data=body_bytes, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            print(f"[shipper] Berhasil kirim {len(events)} event -> HTTP {resp.status_code}")
            return True
        print(f"[shipper] API menolak batch -> HTTP {resp.status_code}: {resp.text[:200]}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"[shipper] Gagal kirim (network/API mati?): {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Log shipper: eve.json -> API SentinelOps")
    parser.add_argument("--eve-path", default="/var/log/suricata/eve.json",
                         help="Path ke file eve.json yang mau di-tail")
    parser.add_argument("--state-file", default="shipper_state.txt",
                         help="File kecil buat nyimpen offset terakhir yang sah")
    parser.add_argument("--api-url", required=True,
                         help="URL endpoint API, misal http://127.0.0.1:8000/api/ingest")
    parser.add_argument("--secret", required=True,
                         help="Shared secret buat HMAC signing (harus sama dengan api/security.py)")
    parser.add_argument("--batch-size", type=int, default=50,
                         help="Kirim batch begitu jumlah event terkumpul segini banyak")
    parser.add_argument("--batch-timeout", type=float, default=5.0,
                         help="Atau kirim batch setelah sekian detik sejak event pertama masuk buffer, "
                              "mana yang lebih dulu tercapai")
    parser.add_argument("--poll-interval", type=float, default=1.0,
                         help="Jeda antar cek file eve.json (detik)")
    parser.add_argument("--exit-when-caught-up", action="store_true",
                         help="Berhenti otomatis begitu tidak ada baris baru lagi untuk dibaca "
                             "DAN buffer sudah kosong (terkirim semua). Pakai ini untuk import "
                             "sekali jalan dari file historis yang sudah tidak bertambah lagi "
                             "(misal eve_full_validated.json), bukan untuk file live Suricata.")
    args = parser.parse_args()
    offset = baca_offset_tersimpan(args.state_file)
    offset_baca = offset
    print(f"[shipper] Mulai dari offset {offset} (file: {args.eve_path})")

    buffer = []
    waktu_buffer_mulai = None

    try:
        while True:
            try:
                ukuran_file_sekarang = os.path.getsize(args.eve_path)
            except FileNotFoundError:
                print(f"[shipper] File {args.eve_path} belum ada, menunggu...")
                time.sleep(args.poll_interval)
                continue

            if ukuran_file_sekarang < offset_baca:
                print("[shipper] File eve.json lebih kecil dari offset tersimpan "
                      "(kemungkinan di-rotate/direset) -> baca ulang dari awal.")
                offset = 0
                offset_baca = 0
                buffer = []
                waktu_buffer_mulai = None

            baris_baru, offset_baru = baca_baris_baru(args.eve_path, offset_baca)
            offset_baca = offset_baru

            if baris_baru:
                events = parse_baris(baris_baru)
                if events and not buffer:
                    waktu_buffer_mulai = time.time()
                buffer.extend(events)

            waktu_habis = (
                waktu_buffer_mulai is not None
                and (time.time() - waktu_buffer_mulai) >= args.batch_timeout
            )

            if buffer and (len(buffer) >= args.batch_size or waktu_habis):
                sukses = kirim_batch(args.api_url, args.secret, buffer)
                if sukses:
                    offset = offset_baca
                    simpan_offset(args.state_file, offset)
                    buffer = []
                    waktu_buffer_mulai = None
                else:
                    print("[shipper] Batch gagal terkirim, akan dicoba lagi "
                          f"({len(buffer)} event masih tertahan di buffer).")

            if args.exit_when_caught_up and not baris_baru and not buffer:
                print("[shipper] Sudah tidak ada baris baru dan buffer kosong -> "
                      "selesai (mode --exit-when-caught-up).")
                break

            time.sleep(args.poll_interval)

    except KeyboardInterrupt:
        print("\n[shipper] Dihentikan manual. Data di buffer yang belum sukses "
              "terkirim akan diproses ulang otomatis saat shipper dijalankan lagi.")
        sys.exit(0)


if __name__ == "__main__":
    main()