## **1\. Topologi Lab**

| Peran | IP | Keterangan |
| :---- | :---- | :---- |
| Attacker | 192.168.242.131 | Sumber semua traffic serangan & baseline |
| VM Utama (server) | 192.168.242.130 | Suricata, memantau 2 interface (ens33 & lxdbr0), http\_server |
| Host LXD 1 | 10.163.202.50 | Container di belakang lxdbr0 |
| Host LXD 2 | 10.163.202.51 | Container di belakang lxdbr0 |
| Host LXD 3 | 10.163.202.52 | Container di belakang lxdbr0 |

Suricata dikonfigurasi memantau **dua interface sekaligus** (`ens33` dan `lxdbr0`) supaya traffic ke VM utama maupun ke ketiga host LXD sama-sama tertangkap dalam satu **`eve.json`**.

## **2\. Timeline Pengumpulan Data**

| Tahap | Waktu (UTC) | Tools/Script |
| ----- | ----- | ----- |
| Baseline (traffic normal) | **±4 jam kontinu (**bisa dilihat di *benign\_runtime.log*) | `generate_benign.py` |
| Skenario 1 — SYN scan | 2026-08-29 14:49:27 – 14:51:05 | `nmap -sS -p- -T4` |
| Skenario 2 — NULL scan | 2026-08-29 14:51:11 – 14:51:44 | `nmap -sN -p- -T4` |
| Skenario 3 — Brute force SSH | 2026-08-29 14:51:49 – 14:52:04 | `hydra -l benign -P wordlist.txt` |
| Skenario 4 — Transfer volume besar | 2026-08-29 14:52:12 – 14:52:39 | `scp bigfile.bin` (\~210MB) |

* Perintah menjalankan *generate\_benign.py* untuk log baseline:

python3 generate\_benign\_final.py \\

  \--targets 10.163.202.50,10.163.202.51,10.163.202.52,192.168.242.130 \\

  \--http-targets 192.168.242.130 \\

  \--ssh-user benign \--ssh-pass Benign123x \\

  \--min-interval 5 \--max-interval 20 \\

  \--duration-hours 4

* Semua waktu eksekusi persis (termasuk command lengkap & exit code) tercatat otomatis di **`scenario_log.csv`** lewat wrapper **`run_scenario.sh`**.

## **3\. Skema Data**

**`eve.json`** (native Suricata, satu JSON per baris). Tipe event yang relevan:

* `flow` — ringkasan koneksi (src/dest IP, port, bytes, tcp\_flags, waktu mulai/selesai)  
* `alert` — signature yang terpicu (lihat tabel SID di bawah)  
* `anomaly` — anomali protokol level app-layer  
* `ssh`, `dns`, `stats` — event pendukung/kontekstual

**`benign_ground_truth.csv`** — kolom: `timestamp_utc, activity, target, result, detail`. Log independen dari sisi attacker, dipakai untuk validasi periode baseline (ketika trafik normal gk ada serangan).

**`scenario_log.csv`** — kolom: `scenario, start_utc, end_utc, command, exit_code`. Satu file gabungan untuk keempat skenario.

## **4\. Bukti Verifikasi per Skenario**

| Skenario | Bukti di `eve.json` |
| ----- | ----- |
| 1 — SYN scan | 65.535 port unik disentuh ke masing-masing 3 host LXD; \~56.156 port ke VM utama (lihat catatan keterbatasan). Alert **SID 1000001**. |
| 2 — NULL scan | 73.212 flow dengan `tcp_flags: "00"` (flag kosong \= ciri khas NULL scan) ke VM utama |
| 3 — Brute force SSH | Alert **SID 2260002** & anomaly `invalid_banner` / `APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION`, konsisten dengan pola koneksi SSH otomatis cepat berturut-turut. Hydra melaporkan 1 password valid ditemukan (`Benign123x`, baris terakhir wordlist — password ini sengaja diketahui untuk keperluan lab). |
| 4 — Transfer volume besar | 1 flow dengan `bytes_toserver: 219.730.171` (\~210MB), **`alerted: false`** — bukti bahwa Suricata (signature-based) TIDAK menandai transfer ini sebagai mencurigakan, walau volumenya jauh di atas baseline. Ini bukti inti "anti-redundansi vs Suricata". |

### **Daftar Signature ID yang terpicu (referensi wajib untuk corpus RAG)**

| SID | Signature | Kategori | Skenario terkait | Saran mapping ATT\&CK |
| ----- | ----- | ----- | ----- | ----- |
| 1000001 | Potential TCP Port Scan Detected | — | 1, 2 | T1595 – Active Scanning |
| 2210063 | SURICATA STREAM 3way handshake excessive different SYNs | Generic Protocol Command Decode | 1, 2 | T1595 – Active Scanning |
| 2260002 | SURICATA Applayer Detect protocol only one direction | Generic Protocol Command Decode | 3 | T1110 – Brute Force |

***Penting untuk ANCA:** corpus RAG harus punya penjelasan untuk ketiga SID ini secara eksplisit, karena inilah yang akan muncul kalau chatbot ditanya soal insiden di demo.*

## **5\. Keterbatasan Jujur (untuk transparansi, bukan disembunyikan)**

* Port unik yang tercatat ke VM utama (\~56.156) tidak genap 65.535 seperti 3 host LXD lainnya. Kemungkinan penyebab: sebagian kecil flow closure belum sempat di-log Suricata pada saat file di-export (lihat catatan delay di atas). Tidak mempengaruhi validitas alert port-scan yang sudah terkonfirmasi terpicu.  
* Password SSH (`Benign123x`) sengaja diketahui sebelumnya (bukan brute force buta murni) karena akun `benign` ini juga dipakai untuk baseline traffic. Wordlist tetap berisi \~19 tebakan salah sebelum password asli, untuk mensimulasikan pola percobaan berulang.  
* Dataset ini dihasilkan murni dari lab isolated milik tim sendiri (VMware \+ LXD), bukan dataset publik — keputusan ini diambil sejak awal untuk menghindari masalah kompatibilitas skema antara `eve.json` dan dataset flow-based publik (mis. CICIDS2017). Dan sudah cukup juga sih ngambil sendiri

## **6\. Inventaris File**

| File | Isi |
| ----- | ----- |
| `eve_attack_scenario.json.gz` | Log Suricata lengkap tervalidasi, mencakup baseline \+ 4 skenario |
| `benign_ground_truth.csv` | Log aktivitas baseline dari sisi attacker |
| `scenario_log.csv benign_runtime.log` | Waktu eksekusi \+ command persis tiap skenario serangan |
| `scenario1_synscan.txt` & scenario2\_nullscan | Output mentah tiap tool serangan |
| `generate_benign.py` | Script generator traffic baseline |
| `run_scenario.sh` | Wrapper pencatat waktu eksekusi skenario |
| `wordlist.txt` | Wordlist untuk skenario brute force |

