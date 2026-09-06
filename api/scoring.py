import argparse
import datetime
import ipaddress
import math
import statistics
import sys

import db 

FITUR_LIST = [
    "jumlah_koneksi",
    "jumlah_port_unik",
    "jumlah_src_ip_unik",
    "total_bytes_toserver",
    "jumlah_alert",
    "rate_koneksi_per_menit",
]

MIN_BASELINE_WINDOWS = 5 

def format_batas_waktu(dt, akhir=False):
    mikro = "999999" if akhir else "000000"
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{mikro}+0000"

def parse_argumen_waktu(teks):
    teks = teks.strip().replace("Z", "+00:00")
    dt = datetime.datetime.fromisoformat(teks)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def ip_layak_discore(ip_str):
    if not ip_str:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if (ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_loopback
            or ip_obj.is_link_local or ip_obj.is_unspecified):
        return False
    if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj.packed[-1] == 255:
        return False
    return True


def ambil_events(dest_ip, start_dt, end_dt):
    start_str = format_batas_waktu(start_dt, akhir=False)
    end_str = format_batas_waktu(end_dt, akhir=True)
    with db.db_cursor() as cur:
        cur.execute(
            "SELECT ts, event_type, src_ip, dest_port, bytes_toserver, sid "
            "FROM events WHERE dest_ip = ? AND ts >= ? AND ts <= ? ORDER BY ts ASC",
            (dest_ip, start_str, end_str),
        )
        return [dict(r) for r in cur.fetchall()]

def get_all_hosts_seen(rentang_baseline, rentang_window, exclude_ips=None):
    exclude_ips = set(exclude_ips or [])
    semua_ip = set()
    with db.db_cursor() as cur:
        for start_dt, end_dt in (rentang_baseline, rentang_window):
            start_str = format_batas_waktu(start_dt, akhir=False)
            end_str = format_batas_waktu(end_dt, akhir=True)
            cur.execute(
                "SELECT DISTINCT dest_ip FROM events WHERE dest_ip IS NOT NULL "
                "AND ts >= ? AND ts <= ?",
                (start_str, end_str),
            )
            semua_ip.update(r["dest_ip"] for r in cur.fetchall())
    return sorted(ip for ip in semua_ip if ip not in exclude_ips and ip_layak_discore(ip))

def hitung_fitur(events, durasi_menit):
    if durasi_menit <= 0:
        durasi_menit = 1e-9

    jumlah_koneksi = len(events)
    jumlah_port_unik = len({e["dest_port"] for e in events if e["dest_port"] is not None})
    jumlah_src_ip_unik = len({e["src_ip"] for e in events if e["src_ip"]})
    total_bytes_toserver = sum(e["bytes_toserver"] or 0 for e in events)
    jumlah_alert = sum(1 for e in events if e["event_type"] == "alert")
    rate_koneksi_per_menit = jumlah_koneksi / durasi_menit

    return {
        "jumlah_koneksi": jumlah_koneksi,
        "jumlah_port_unik": jumlah_port_unik,
        "jumlah_src_ip_unik": jumlah_src_ip_unik,
        "total_bytes_toserver": total_bytes_toserver,
        "jumlah_alert": jumlah_alert,
        "rate_koneksi_per_menit": rate_koneksi_per_menit,
    }

def potong_jadi_window(events, mulai, selesai, window_menit):
    hasil = []
    cur = mulai
    delta = datetime.timedelta(minutes=window_menit)
    while cur < selesai:
        nxt = min(cur + delta, selesai)
        is_window_terakhir = nxt >= selesai
        cur_str = format_batas_waktu(cur, akhir=False)
        if is_window_terakhir:
            nxt_str = format_batas_waktu(nxt, akhir=True)
            ev_window = [e for e in events if cur_str <= e["ts"] <= nxt_str]
        else:
            nxt_str = format_batas_waktu(nxt, akhir=False)
            ev_window = [e for e in events if cur_str <= e["ts"] < nxt_str]
        hasil.append((cur, nxt, ev_window))
        cur = nxt
    return hasil

def bangun_distribusi_baseline(dest_ip, baseline_mulai, baseline_selesai, window_menit=5):
    semua_event = ambil_events(dest_ip, baseline_mulai, baseline_selesai)
    windows = potong_jadi_window(semua_event, baseline_mulai, baseline_selesai, window_menit)

    distribusi = {f: [] for f in FITUR_LIST}
    for w_start, w_end, ev in windows:
        durasi_window_ini = (w_end - w_start).total_seconds() / 60
        fitur = hitung_fitur(ev, durasi_window_ini)
        for f in FITUR_LIST:
            distribusi[f].append(fitur[f])

    return distribusi, len(windows)

def percentile_rank(nilai, daftar_baseline):
    if not daftar_baseline:
        return 0.0
    n = len(daftar_baseline)
    count_less = sum(1 for x in daftar_baseline if x < nilai)
    count_equal = sum(1 for x in daftar_baseline if x == nilai)
    return ((count_less + 0.5 * count_equal) / n) * 100


def mad_zscore(nilai, baseline_list):
    if len(baseline_list) < 2:
        return 0.0
    median = statistics.median(baseline_list)
    mad = statistics.median(abs(x - median) for x in baseline_list)
    if mad > 0:
        return (nilai - median) / (1.4826 * mad)
    try:
        stdev = statistics.stdev(baseline_list)
    except statistics.StatisticsError:
        stdev = 0
    if stdev > 0:
        return (nilai - median) / stdev
    return 0.0 if nilai == median else float("inf")


def skor_dengan_magnitudo(nilai, baseline_list):
    persentil = percentile_rank(nilai, baseline_list)
    if not baseline_list:
        return persentil
    maksimum_baseline = max(baseline_list)
    if nilai <= maksimum_baseline or maksimum_baseline <= 0:
        return persentil
    rasio = nilai / maksimum_baseline
    bonus = min(60.0, math.log2(rasio) * 10)
    return persentil + bonus

def buat_alasan(fitur_dominan, nilai, baseline_list):
    median_baseline = statistics.median(baseline_list) if baseline_list else 0
    maksimum_baseline = max(baseline_list) if baseline_list else 0
    label = {
        "jumlah_koneksi": f"{int(nilai)} koneksi dalam satu window (baseline biasanya ~{int(median_baseline)})",
        "jumlah_port_unik": f"{int(nilai)} port berbeda disentuh dalam satu window",
        "jumlah_src_ip_unik": f"{int(nilai)} sumber IP berbeda menghubungi host ini",
        "total_bytes_toserver": f"Transfer data {nilai/1_000_000:.1f} MB (baseline median ~{median_baseline/1_000_000:.2f} MB)",
        "jumlah_alert": f"{int(nilai)} alert Suricata terpicu",
        "rate_koneksi_per_menit": f"Rata-rata {nilai:.1f} koneksi/menit, pola tidak biasa",
    }
    pesan = label.get(fitur_dominan, f"{fitur_dominan}={nilai}")
    if maksimum_baseline > 0 and nilai > maksimum_baseline:
        rasio = nilai / maksimum_baseline
        pesan += f" -- {rasio:.1f}x lipat dari maksimum yang pernah tercatat di baseline"
    return pesan

def hitung_skor_host(dest_ip, baseline_mulai, baseline_selesai,
                      window_sekarang_mulai, window_sekarang_selesai, window_menit=5):
    distribusi, jumlah_window_baseline = bangun_distribusi_baseline(
        dest_ip, baseline_mulai, baseline_selesai, window_menit
    )

    if jumlah_window_baseline < MIN_BASELINE_WINDOWS:
        return {
            "ip": dest_ip,
            "risk_score": 0,
            "band": "Aman",
            "reason": f"Baseline belum cukup ({jumlah_window_baseline} window, minimal {MIN_BASELINE_WINDOWS})",
            "baseline_status": "insufficient",
            "total_events": 0,
        }

    durasi_menit_sekarang = (window_sekarang_selesai - window_sekarang_mulai).total_seconds() / 60
    toleransi_menit = 0.01
    if abs(durasi_menit_sekarang - window_menit) > toleransi_menit:
        raise ValueError(
            f"Durasi window 'sekarang' ({durasi_menit_sekarang:.2f} menit) harus sama "
            f"dengan window_menit yang dipakai baseline ({window_menit} menit) -- kalau "
            f"beda, 5 dari 6 fitur (raw count) gak apple-to-apple dibanding baseline. "
            f"Pakai --window-start/--window-end yang selisihnya persis {window_menit} menit, "
            f"atau sesuaikan --window-minutes."
        )

    event_sekarang = ambil_events(dest_ip, window_sekarang_mulai, window_sekarang_selesai)
    fitur_sekarang = hitung_fitur(event_sekarang, durasi_menit_sekarang)

    skor_per_fitur = {f: skor_dengan_magnitudo(fitur_sekarang[f], distribusi[f]) for f in FITUR_LIST}
    fitur_dominan = max(skor_per_fitur, key=skor_per_fitur.get)
    skor = min(100.0, skor_per_fitur[fitur_dominan])

    if skor >= 90:
        band = "Berisiko"
    elif skor >= 60:
        band = "Perhatian"
    else:
        band = "Aman"

    alasan = buat_alasan(fitur_dominan, fitur_sekarang[fitur_dominan], distribusi[fitur_dominan])

    return {
        "ip": dest_ip,
        "risk_score": round(skor),
        "band": band,
        "reason": alasan,
        "baseline_status": "sufficient",
        "total_events": fitur_sekarang["jumlah_koneksi"],
    }

def main():
    parser = argparse.ArgumentParser(description="Hitung skor risiko per host (SentinelOps)")
    parser.add_argument("--baseline-start", required=True, help="mis. 2026-08-28T21:46:00+00:00")
    parser.add_argument("--baseline-end", required=True)
    parser.add_argument("--window-start", required=True, help="Window 'sekarang' yang mau dihitung skornya")
    parser.add_argument("--window-end", required=True)
    parser.add_argument("--window-minutes", type=int, default=5, help="Ukuran window baseline (menit)")
    parser.add_argument("--exclude-ip", action="append", default=None,
                         help="IP yang mau dikecualikan dari scoring (mis. gateway/router internal). "
                              "Bisa dipakai berkali-kali buat lebih dari satu IP. Alamat non-unicast "
                              "(multicast/broadcast/link-local) sudah otomatis dikecualikan.")
    args = parser.parse_args()

    baseline_mulai = parse_argumen_waktu(args.baseline_start)
    baseline_selesai = parse_argumen_waktu(args.baseline_end)
    window_mulai = parse_argumen_waktu(args.window_start)
    window_selesai = parse_argumen_waktu(args.window_end)

    hosts = get_all_hosts_seen(
        (baseline_mulai, baseline_selesai), (window_mulai, window_selesai),
        exclude_ips=args.exclude_ip,
    )
    print(f"[scoring] Menghitung skor untuk {len(hosts)} host: {hosts}")

    for host in hosts:
        hasil = hitung_skor_host(
            host, baseline_mulai, baseline_selesai, window_mulai, window_selesai, args.window_minutes
        )
        db.upsert_host(
            hasil["ip"], hasil["risk_score"], hasil["band"],
            hasil["baseline_status"], hasil["total_events"], reason=hasil["reason"],
        )
        db.record_score(hasil["ip"], hasil["risk_score"], hasil["band"])
        print(f"[scoring] {host}: skor={hasil['risk_score']:.0f} band={hasil['band']} "
              f"status_baseline={hasil['baseline_status']} alasan=\"{hasil['reason']}\"")

if __name__ == "__main__":
    main()