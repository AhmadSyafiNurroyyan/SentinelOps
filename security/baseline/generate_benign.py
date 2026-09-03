#!/usr/bin/env python3
"""
generate_benign.py - Generator traffic "normal" (benign) untuk baseline SentinelOps.

Jalankan script ini terus-menerus SEBELUM menjalankan skenario serangan (Nmap scan,
brute force, dsb), supaya Suricata/eve.json punya cukup data traffic normal sebagai
pembanding untuk scoring statistik (percentile/Z-score) per host.

PENTING: Hanya jalankan terhadap IP di lab isolated milik sendiri.

Contoh pemakaian (banyak host, HTTP cuma ke host yang punya web server):
    pip install paramiko requests
    nohup python3 generate_benign.py \\
        --targets 10.163.202.50,10.163.202.51,10.163.202.52,192.168.242.130 \\
        --http-targets 192.168.242.130 \\
        --ssh-user benign --ssh-pass Benign123x \\
        --min-interval 5 --max-interval 20 \\
        --duration-hours 4 \\
        > benign_runtime.log 2>&1 &
"""

import argparse
import csv
import os
import random
import subprocess
import sys
import time
from datetime import datetime, timezone

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    import requests
except ImportError:
    requests = None


LOG_HEADER = ["timestamp_utc", "activity", "target", "result", "detail"]


def log_event(log_path, activity, target, result, detail=""):
    """Catat setiap aktivitas benign ke CSV lokal sebagai ground truth,
    terpisah dari eve.json Suricata. Berguna untuk memvalidasi bahwa
    waktu-waktu ini memang seharusnya dianggap 'normal' oleh scoring engine."""
    is_new = not os.path.exists(log_path)
    with open(log_path, "a", newline="") as f:
        writer = csv.writer(f)
        if is_new:
            writer.writerow(LOG_HEADER)
        writer.writerow([datetime.now(timezone.utc).isoformat(), activity, target, result, detail])
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {activity:14s} -> {target:16s} {result} {detail}")


def do_ping(target, log_path):
    try:
        result = subprocess.run(
            ["ping", "-c", "2", "-W", "2", target],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        ok = result.returncode == 0
        log_event(log_path, "ping", target, "ok" if ok else "fail")
    except Exception as e:
        log_event(log_path, "ping", target, "error", str(e))


def do_http_request(target, port, log_path):
    if requests is None:
        log_event(log_path, "http", target, "skipped", "modul 'requests' belum terpasang")
        return
    url = f"http://{target}:{port}/"
    try:
        resp = requests.get(url, timeout=4)
        log_event(log_path, "http", target, "ok", f"status={resp.status_code}")
    except requests.exceptions.Timeout:
        log_event(log_path, "http", target, "fail", "timeout (4s)")
    except requests.exceptions.ConnectionError:
        log_event(log_path, "http", target, "fail", "connection refused / port closed")
    except Exception as e:
        log_event(log_path, "http", target, "error", f"unexpected: {str(e)}")


def do_ssh_login(target, port, username, password, log_path):
    if paramiko is None:
        log_event(log_path, "ssh_login", target, "skipped", "modul 'paramiko' belum terpasang")
        return
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(target, port=port, username=username, password=password, timeout=5)
        _, stdout, _ = client.exec_command("uptime")
        stdout.read()
        log_event(log_path, "ssh_login", target, "ok")
    except Exception as e:
        log_event(log_path, "ssh_login", target, "error", str(e))
    finally:
        client.close()


def do_small_transfer(target, port, username, password, log_path):
    """Simulasi transfer file kecil lewat SFTP. Pakai context manager supaya
    transport & sftp client selalu ditutup otomatis walau terjadi error di tengah."""
    if paramiko is None:
        log_event(log_path, "sftp_transfer", target, "skipped", "modul 'paramiko' belum terpasang")
        return
    try:
        with paramiko.Transport((target, port)) as transport:
            transport.connect(username=username, password=password)
            with paramiko.SFTPClient.from_transport(transport) as sftp:
                tmp_local = "/tmp/benign_payload.txt"
                with open(tmp_local, "w") as f:
                    f.write("baseline traffic " * random.randint(50, 200))
                remote_path = f"/tmp/benign_{int(time.time())}.txt"
                sftp.put(tmp_local, remote_path)
                sftp.remove(remote_path)
            log_event(log_path, "sftp_transfer", target, "ok")
    except Exception as e:
        log_event(log_path, "sftp_transfer", target, "error", str(e))


def main():
    parser = argparse.ArgumentParser(description="Generator traffic benign untuk baseline SentinelOps")
    parser.add_argument("--targets", required=True,
                         help="IP VM target di lab isolated. Bisa lebih dari satu, dipisah koma, "
                              "supaya tiap host punya baseline sendiri-sendiri untuk scoring.py.")
    parser.add_argument("--http-targets", default=None,
                         help="Subset IP (dipisah koma) yang khusus dipakai untuk aktivitas HTTP saja, "
                              "misal cuma VM utama yang punya web server. Kalau tidak diisi, "
                              "default-nya sama dengan --targets.")
    parser.add_argument("--skip-http", action="store_true",
                         help="Matikan aktivitas HTTP sepenuhnya (dipakai kalau tidak ada web server "
                              "yang jalan di target manapun).")
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--http-port", type=int, default=80)
    parser.add_argument("--ssh-user", default="msfadmin", help="Username SSH valid di target")
    parser.add_argument("--ssh-pass", default="msfadmin", help="Password SSH valid di target")
    parser.add_argument("--min-interval", type=int, default=30, help="Jeda minimum antar aktivitas (detik)")
    parser.add_argument("--max-interval", type=int, default=180, help="Jeda maksimum antar aktivitas (detik)")
    parser.add_argument("--log", default="benign_ground_truth.csv", help="File log lokal (ground truth, terpisah dari eve.json)")
    parser.add_argument("--duration-hours", type=float, default=None,
                         help="Kalau diisi, script berhenti otomatis setelah durasi ini (jam). "
                              "Kosongkan untuk jalan terus lewat nohup/systemd.")
    args = parser.parse_args()

    target_list = [t.strip() for t in args.targets.split(",") if t.strip()]
    if not target_list:
        print("[generate_benign] --targets kosong/tidak valid.")
        sys.exit(1)

    http_target_list = target_list
    if args.http_targets:
        http_target_list = [t.strip() for t in args.http_targets.split(",") if t.strip()]

    # Bobot dipilih supaya pola mirip aktivitas manusia sehari-hari:
    # lebih sering cek koneksi/http ringan, lebih jarang login & transfer file.
    activities = [
        ("ping", 0.35),
        ("http", 0.30),
        ("ssh_login", 0.25),
        ("sftp_transfer", 0.10),
    ]
    if args.skip_http:
        activities = [a for a in activities if a[0] != "http"]
        activities[0] = ("ping", activities[0][1] + 0.30)
    names, weights = zip(*activities)

    print(f"[generate_benign] targets={target_list} http_targets={http_target_list}. "
          f"Tekan Ctrl+C untuk berhenti manual.")
    start = time.time()

    try:
        while True:
            if args.duration_hours and (time.time() - start) > args.duration_hours * 3600:
                print("[generate_benign] durasi tercapai, berhenti.")
                break

            choice = random.choices(names, weights=weights, k=1)[0]

            if choice == "http":
                target = random.choice(http_target_list)
                do_http_request(target, args.http_port, args.log)
            else:
                # Pilih host secara acak tiap iterasi supaya SEMUA host di subnet
                # kebagian traffic baseline, bukan cuma satu host saja.
                target = random.choice(target_list)
                if choice == "ping":
                    do_ping(target, args.log)
                elif choice == "ssh_login":
                    do_ssh_login(target, args.ssh_port, args.ssh_user, args.ssh_pass, args.log)
                elif choice == "sftp_transfer":
                    do_small_transfer(target, args.ssh_port, args.ssh_user, args.ssh_pass, args.log)

            time.sleep(random.uniform(args.min_interval, args.max_interval))
    except KeyboardInterrupt:
        print("\n[generate_benign] dihentikan manual.")
        sys.exit(0)


if __name__ == "__main__":
    main()
