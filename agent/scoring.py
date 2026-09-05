#!/usr/bin/env python3
"""
api/scoring.py - Asset Risk Scoring untuk SentinelOps.

Menghitung skor risiko per host berdasarkan 6 fitur, dibandingkan (percentile)
terhadap distribusi baseline (traffic normal). Hasil disimpan lewat db.py
(punya ANCA) -- upsert_host() dan record_score() dipakai apa adanya, tidak
diubah.

6 Fitur yang dihitung per window waktu, per host:
    1. jumlah_koneksi          - total event (flow) yang tujuannya host ini
    2. jumlah_port_unik        - berapa port BERBEDA yang disentuh
    3. jumlah_src_ip_unik      - berapa sumber IP berbeda yang connect
    4. total_bytes_toserver    - total volume data yang dikirim KE host ini
    5. jumlah_alert            - berapa kali signature Suricata terpicu
    6. rate_koneksi_per_menit  - kecepatan koneksi (deteksi burst/brute force)

Cara kerja (persis pola "percentile scoring" yang dipakai sejak awal):
    1. Ambil event dari periode BASELINE, potong jadi window kecil (misal 5
       menit), hitung 6 fitur di TIAP window -> jadi distribusi "normal".
    2. Ambil event dari window TERKINI, hitung 6 fitur yang sama.
    3. Bandingkan: nilai sekarang ada di percentile berapa dibanding
       distribusi baseline? Percentile tinggi (95+) = tidak biasa.
    4. Skor akhir = percentile TERTINGGI di antara 6 fitur -- supaya satu
       anomali kuat (misal transfer 200MB) tidak "tenggelam" kalau dirata-
       rata dengan 5 fitur lain yang normal.

CATATAN INTEGRASI: db.py (ANCA) belum punya fungsi baca event per host, jadi
di sini query baca dilakukan langsung lewat db.db_cursor() -- itu context
manager yang MEMANG sudah publik/dipakai bareng di db.py, jadi ini bukan
"nerobos", cuma pakai apa yang sudah disediakan. Semua tulis (insert/upsert)
tetap lewat fungsi resmi db.py.
"""

import argparse
import datetime
import statistics
import sys

import db  # api/db.py punya ANCA


FITUR_LIST = [
    "jumlah_koneksi",
    "jumlah_port_unik",
    "jumlah_src_ip_unik",
    "total_bytes_toserver",
    "jumlah_alert",
    "rate_koneksi_per_menit",
]

MIN_BASELINE_WINDOWS = 5  # kalau baseline kurang dari ini, jangan asal kasih skor


# ---------------------------------------------------------------------------
# Bagian waktu: format HARUS sama persis dengan yang dipakai Suricata (+0000,
# bukan +00:00), karena perbandingan waktu di SQL dilakukan sebagai teks.
# ---------------------------------------------------------------------------

def format_batas_waktu(dt, akhir=False):
    """Ubah objek datetime jadi string batas waktu yang formatnya cocok
    sama data di kolom `ts` (mis. '2026-08-29T14:49:27.000000+0000').
    `akhir=True` dipakai untuk batas akhir supaya inklusif sampai akhir detik."""
    mikro = "999999" if akhir else "000000"
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{mikro}+0000"


def parse_argumen_waktu(teks):
    """Terima input waktu dari CLI dalam format fleksibel (dengan/tanpa
    offset, dengan/tanpa 'Z'), kembalikan objek datetime timezone-aware UTC."""
    teks = teks.strip().replace("Z", "+00:00")
    dt = datetime.datetime.fromisoformat(teks)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


# ---------------------------------------------------------------------------
# Bagian baca data
# ---------------------------------------------------------------------------

def ambil_events(dest_ip, start_dt, end_dt):
    """Ambil semua event yang tujuannya (dest_ip) = host tertentu, dalam
    rentang waktu tertentu. READ-ONLY, aman dipakai bareng modul lain."""
    start_str = format_batas_waktu(start_dt, akhir=False)
    end_str = format_batas_waktu(end_dt, akhir=True)
    with db.db_cursor() as cur:
        cur.execute(
            "SELECT ts, event_type, src_ip, dest_port, bytes_toserver, sid "
            "FROM events WHERE dest_ip = ? AND ts >= ? AND ts <= ? ORDER BY ts ASC",
            (dest_ip, start_str, end_str),
        )
        return [dict(r) for r in cur.fetchall()]


def get_all_hosts_seen(start_dt, end_dt):
    """Daftar semua dest_ip yang pernah muncul di tabel events dalam rentang
    waktu tertentu -- dipakai untuk tahu host mana saja yang perlu dihitung."""
    start_str = format_batas_waktu(start_dt, akhir=False)
    end_str = format_batas_waktu(end_dt, akhir=True)
    with db.db_cursor() as cur:
        cur.execute(
            "SELECT DISTINCT dest_ip FROM events WHERE dest_ip IS NOT NULL "
            "AND ts >= ? AND ts <= ?",
            (start_str, end_str),
        )
        return [r["dest_ip"] for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Bagian hitung fitur & window
# ---------------------------------------------------------------------------

def hitung_fitur(events, durasi_menit):
    """Ubah sekumpulan event (dalam satu window) jadi 6 angka fitur."""
    if durasi_menit <= 0:
        durasi_menit = 1e-9  # hindari pembagian nol

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
    """Bagi rentang waktu [mulai, selesai] jadi window-window kecil (misal per
    5 menit), kelompokkan event ke window yang sesuai berdasarkan `ts`.

    Batas atas tiap window EKSKLUSIF, kecuali window paling akhir yang tetap
    inklusif sampai `selesai` (biar konsisten sama rentang yang dipakai waktu
    ambil_events()). Ini penting -- kalau dua-duanya inklusif, event yang
    jatuh persis di detik batas (mis. 14:50:00.5xxxxx saat window pecah tiap
    14:50:00) bakal ke-hitung DUA KALI, di window sebelum dan sesudahnya."""
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
    """Hitung nilai 6 fitur di TIAP window sepanjang periode baseline --
    hasilnya distribusi (list nilai) per fitur, jadi 'patokan normal'."""
    semua_event = ambil_events(dest_ip, baseline_mulai, baseline_selesai)
    windows = potong_jadi_window(semua_event, baseline_mulai, baseline_selesai, window_menit)

    distribusi = {f: [] for f in FITUR_LIST}
    for w_start, w_end, ev in windows:
        # Pakai durasi ASLI window ini (bukan window_menit yang fixed) --
        # window paling akhir bisa lebih pendek kalau rentang baseline bukan
        # kelipatan pas dari window_menit, dan kalau dipaksa pakai
        # window_menit, rate_koneksi_per_menit di window itu jadi understated.
        durasi_window_ini = (w_end - w_start).total_seconds() / 60
        fitur = hitung_fitur(ev, durasi_window_ini)
        for f in FITUR_LIST:
            distribusi[f].append(fitur[f])

    return distribusi, len(windows)


def percentile_rank(nilai, daftar_baseline):
    """Percentile nilai sekarang dibanding distribusi baseline, pakai
    MID-RANK buat nilai yang seri (tie): nilai baseline yang sama persis
    dengan nilai sekarang dihitung SETENGAH, bukan penuh.

    Ini penting buat fitur yang baseline-nya sering banget bernilai sama
    (mis. jumlah_alert = 0 di hampir semua window normal) -- tanpa mid-rank,
    nilai yang identik sama "normal" bakal salah kebaca sebagai percentile
    100 (paling mencurigakan), padahal harusnya di sekitar 50 (biasa aja).

    100 = lebih tinggi dari SELURUH histori baseline (paling mencurigakan)."""
    if not daftar_baseline:
        return 0.0
    n = len(daftar_baseline)
    count_less = sum(1 for x in daftar_baseline if x < nilai)
    count_equal = sum(1 for x in daftar_baseline if x == nilai)
    return ((count_less + 0.5 * count_equal) / n) * 100


def buat_alasan(fitur_dominan, nilai, baseline_list):
    """Bikin teks alasan yang gampang dibaca manusia -> kolom `reason` di db.py."""
    median_baseline = statistics.median(baseline_list) if baseline_list else 0
    label = {
        "jumlah_koneksi": f"{int(nilai)} koneksi dalam satu window (baseline biasanya ~{int(median_baseline)})",
        "jumlah_port_unik": f"{int(nilai)} port berbeda disentuh dalam satu window",
        "jumlah_src_ip_unik": f"{int(nilai)} sumber IP berbeda menghubungi host ini",
        "total_bytes_toserver": f"Transfer data {nilai/1_000_000:.1f} MB, jauh di atas kebiasaan",
        "jumlah_alert": f"{int(nilai)} alert Suricata terpicu",
        "rate_koneksi_per_menit": f"Rata-rata {nilai:.1f} koneksi/menit, pola tidak biasa",
    }
    return label.get(fitur_dominan, f"{fitur_dominan}={nilai}")


# ---------------------------------------------------------------------------
# Bagian utama: hitung skor 1 host
# ---------------------------------------------------------------------------

def hitung_skor_host(dest_ip, baseline_mulai, baseline_selesai,
                      window_sekarang_mulai, window_sekarang_selesai, window_menit=5):
    """Hitung skor risiko 1 host. Return dict siap dilempar ke db.upsert_host()."""
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

    # 5 dari 6 fitur (semua KECUALI rate_koneksi_per_menit, yang sudah
    # dinormalisasi per-menit) adalah RAW COUNT dalam satu window. Itu cuma
    # bisa dibandingkan apple-to-apple ke distribusi baseline kalau window
    # "sekarang" durasinya sama kayak window_menit yang dipakai buat bikin
    # baseline. Kalau beda (mis. baseline per 5 menit tapi window sekarang
    # 1 jam), raw count-nya otomatis jauh lebih besar dari baseline manapun
    # -> percentile selalu ~100 walau gak ada anomali beneran.
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

    percentiles = {f: percentile_rank(fitur_sekarang[f], distribusi[f]) for f in FITUR_LIST}
    fitur_dominan = max(percentiles, key=percentiles.get)
    skor = percentiles[fitur_dominan]

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
    args = parser.parse_args()

    baseline_mulai = parse_argumen_waktu(args.baseline_start)
    baseline_selesai = parse_argumen_waktu(args.baseline_end)
    window_mulai = parse_argumen_waktu(args.window_start)
    window_selesai = parse_argumen_waktu(args.window_end)

    hosts = get_all_hosts_seen(baseline_mulai, window_selesai)
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
