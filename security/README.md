# Validasi Keamanan dan Skenario Pengujian

Dokumen ini menyajikan metodologi validasi SentinelOps pada lingkungan
laboratorium terisolasi. Pengujian dirancang untuk menunjukkan dua kemampuan
utama sistem:

1. mengidentifikasi aktivitas yang terdeteksi oleh signature Suricata; dan
2. menemukan anomali perilaku yang tidak menghasilkan alert signature, tetapi
   menyimpang dari baseline traffic normal.

Seluruh data pengujian berasal dari infrastruktur milik tim dan digunakan
khusus untuk validasi prototipe. Tidak ada sistem produksi atau jaringan pihak
ketiga yang menjadi target.

## 1. Topologi laboratorium

![Diagram topologi](diagram-topologi.png)

| Peran      | Alamat IP         | Keterangan                                    |
| :--------- | :---------------- | :-------------------------------------------- |
| Attacker   | `192.168.242.131` | Sumber traffic baseline dan skenario serangan |
| VM utama   | `192.168.242.130` | Menjalankan Suricata dan HTTP server          |
| Host LXD 1 | `10.163.202.50`   | Host yang dipantau di belakang `lxdbr0`       |
| Host LXD 2 | `10.163.202.51`   | Host yang dipantau di belakang `lxdbr0`       |
| Host LXD 3 | `10.163.202.52`   | Host yang dipantau di belakang `lxdbr0`       |

Suricata memantau interface `ens33` dan `lxdbr0`. Dengan konfigurasi tersebut,
traffic menuju VM utama maupun ketiga host LXD direkam dalam satu aliran
`eve.json` untuk diproses oleh SentinelOps.

## 2. Rancangan dan kronologi pengujian

Baseline traffic normal dikumpulkan selama kurang lebih empat jam menggunakan
`generate_benign.py`. Baseline ini menjadi pembanding bagi scoring statistik.
Empat skenario kemudian dijalankan pada urutan dan waktu berikut (UTC):

| Tahap      | Waktu                        | Aktivitas                                       |
| :--------- | :--------------------------- | :---------------------------------------------- |
| Baseline   | ±4 jam kontinu               | Traffic normal terkontrol                       |
| Skenario 1 | 2026-08-29 14:49:27–14:51:05 | SYN scan dengan `nmap -sS -p- -T4`              |
| Skenario 2 | 2026-08-29 14:51:11–14:51:44 | NULL scan dengan `nmap -sN -p- -T4`             |
| Skenario 3 | 2026-08-29 14:51:49–14:52:04 | Percobaan autentikasi SSH berulang dengan Hydra |
| Skenario 4 | 2026-08-29 14:52:12–14:52:39 | Transfer file sekitar 210 MB melalui SCP        |

Wrapper `run_scenario.sh` mencatat nama skenario, waktu mulai dan selesai,
perintah yang dijalankan, serta exit code ke `scenario_log.csv`. Pencatatan ini
menyediakan jejak audit yang dapat diperiksa ulang oleh dewan juri.

## 3. Sumber dan skema data

### `eve.json`

Log native Suricata dengan satu objek JSON per baris. Event yang digunakan
SentinelOps meliputi:

- `flow`: ringkasan koneksi, alamat IP, port, dan jumlah bytes;
- `alert`: signature Suricata yang terpicu;
- `anomaly`: anomali pada protokol atau application layer; dan
- `ssh`, `dns`, serta `stats`: konteks pendukung analisis.

### Ground truth dan audit trail

- `benign_ground_truth.csv` mencatat aktivitas baseline dari sisi attacker
  dengan kolom `timestamp_utc`, `activity`, `target`, `result`, dan `detail`.
- `scenario_log.csv` mencatat eksekusi keempat skenario dengan kolom
  `scenario`, `start_utc`, `end_utc`, `command`, dan `exit_code`.

Kombinasi log Suricata, ground truth, dan audit trail memungkinkan hasil
deteksi dibandingkan dengan aktivitas yang memang sengaja dilakukan.

## 4. Hasil verifikasi

| Skenario              | Bukti pada log                                                                                                                   | Interpretasi                                                                                                                            |
| :-------------------- | :------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------- |
| SYN scan              | Hingga 65.535 port unik disentuh pada masing-masing host LXD dan sekitar 56.156 port pada VM utama. Alert `SID 1000001` terpicu. | Aktivitas terdeteksi oleh signature dan terlihat sebagai pola pemindaian port.                                                          |
| NULL scan             | Terdapat 73.212 flow dengan `tcp_flags: "00"` menuju VM utama.                                                                   | Pola flag kosong konsisten dengan karakteristik NULL scan.                                                                              |
| Brute force SSH       | Alert `SID 2260002`, anomaly `invalid_banner`, dan `APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION`.                                | Rangkaian koneksi SSH cepat berulang teridentifikasi sebagai aktivitas autentikasi mencurigakan.                                        |
| Transfer volume besar | Satu flow memiliki `bytes_toserver: 219.730.171` (sekitar 210 MB) dengan `alerted: false`.                                       | Suricata tidak memicu signature, sedangkan SentinelOps dapat menilai penyimpangan volume terhadap baseline melalui statistical scoring. |

Skenario keempat merupakan validasi utama pendekatan **beyond-signature**:
SentinelOps tidak menggantikan Suricata, tetapi melengkapi titik buta yang tidak
dapat ditangani oleh signature IDS saja.

## 5. Signature yang digunakan dalam corpus RAG

| SID       | Signature                                               | Skenario            | Pemetaan ATT&CK           |
| :-------- | :------------------------------------------------------ | :------------------ | :------------------------ |
| `1000001` | Potential TCP Port Scan Detected                        | SYN scan, NULL scan | `T1595 – Active Scanning` |
| `2210063` | SURICATA STREAM 3way handshake excessive different SYNs | SYN scan, NULL scan | `T1595 – Active Scanning` |
| `2260002` | SURICATA Applayer Detect protocol only one direction    | Brute force SSH     | `T1110 – Brute Force`     |

Ketiga SID tersebut dipetakan secara eksplisit ke corpus agar Virtual SOC
Analyst dapat memberikan interpretasi dan sitasi yang relevan ketika temuan
ditanyakan melalui chatbot.

## 6. Keterbatasan dan transparansi

- Jumlah port yang tercatat pada VM utama tidak mencapai 65.535 seperti pada
  host LXD lain. Perbedaan ini kemungkinan disebabkan sebagian flow closure
  belum tertulis saat log diekspor; alert port scan tetap terkonfirmasi.
- Password SSH pada skenario brute force diketahui untuk kebutuhan lab.
  Wordlist tetap memuat sekitar 19 percobaan gagal sebelum kredensial yang
  benar, sehingga pola koneksi berulang dapat divalidasi tanpa menyerang
  sistem eksternal.
- Dataset dibuat dari lab VMware dan LXD milik tim, bukan dataset publik.
  Pilihan ini menjaga kesesuaian antara skema `eve.json`, topologi, dan ground
  truth yang digunakan SentinelOps.

Keterbatasan tersebut dicatat sebagai bagian dari validasi, bukan dihilangkan
dari pelaporan hasil.

## 7. Inventaris artefak

| Artefak                              | Fungsi                                           |
| :----------------------------------- | :----------------------------------------------- |
| `eve_attack_scenario.json.gz`        | Arsip log Suricata baseline dan seluruh skenario |
| `benign_ground_truth.csv`            | Ground truth aktivitas traffic normal            |
| `scenario_log.csv`                   | Jejak audit waktu dan perintah setiap skenario   |
| `benign_runtime.log`                 | Log eksekusi generator baseline                  |
| `scenario1_synscan.txt`              | Output mentah SYN scan                           |
| `scenario2_nullscan.txt`             | Output mentah NULL scan                          |
| `generate_benign.py`                 | Generator traffic baseline                       |
| `run_scenario.sh`                    | Pencatat eksekusi skenario                       |
| `scenarios/assets/demo_wordlist.txt` | Wordlist terkontrol untuk skenario SSH           |

Artefak log berukuran besar dan data runtime tidak dilacak Git secara default.
Arsip hasil pengujian dapat disediakan sebagai bahan demonstrasi atau
verifikasi lanjutan.
