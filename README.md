# SentinelOps

**Lapisan interpretasi keamanan jaringan untuk institusi tanpa tim SOC.**

SentinelOps membaca lalu lintas jaringan dari Suricata, memberi skor risiko
per host secara statistik, dan menjelaskan setiap peringatan dalam Bahasa
Indonesia melalui asisten berbasis RAG dengan rujukan sumber. Ditujukan untuk
sekolah, kampus, puskesmas, dan instansi daerah yang memiliki jaringan sendiri
tetapi tidak memiliki tim keamanan khusus.

Dikembangkan untuk HoloDev, HOLOGY 9.0, Universitas Brawijaya.
Subtema: Infrastruktur Sosial.

---

## Prinsip Desain

- **Read-only advisory.** Sistem hanya mengamati dan memberi saran. Tidak
  pernah memblokir, memutus, atau mengambil tindakan otomatis. Keputusan akhir
  tetap di tangan manusia. Ini keputusan desain yang disengaja, bukan
  keterbatasan.
- **Dua pipeline terpisah.** Peringatan (`alert`) dari Suricata diterjemahkan
  oleh mesin RAG. Data aliran (`flow`/`stats`) dinilai secara statistik untuk
  menangkap anomali yang tidak memicu signature apa pun. Pemisahan ini adalah
  inti kontribusi sistem.
- **Data tidak meninggalkan jaringan.** Perhitungan skor berjalan lokal. Yang
  dikirim ke API bahasa hanya teks pertanyaan dan potongan dokumen publik,
  bukan log jaringan institusi.

---

## Arsitektur Singkat

```
  Suricata (eve.json)
        │
        ▼
  Log Shipper  ──HMAC──▶  FastAPI (/ingest)
                              │
                 ┌────────────┴────────────┐
                 ▼                          ▼
        Pipeline Statistik          Pipeline RAG
        (flow/stats → skor)         (alert → penjelasan)
                 │                          │
                 ▼                          ▼
              Database  ◀──────────  Scoring Engine
                 │
                 ▼
          FastAPI (/assets, /timeline, /chat)
                 │
                 ▼
          Dashboard (React)
```

---

## Teknologi

**Backend:** Python 3.10, FastAPI, Uvicorn, SQLite
**RAG:** FAISS (pencarian vektor), BM25 (pencarian kata kunci), Reciprocal
Rank Fusion, embedding dan generasi via Gemini API
**Basis pengetahuan:** MITRE ATT&CK Enterprise v19.1, Emerging Threats Open
ruleset
**Frontend:** React
**Agent:** Log Shipper (Python) dengan penandatanganan HMAC-SHA256

---

## Kebutuhan Lingkungan

- Python 3.10 atau lebih baru
- Sebuah Gemini API key (untuk embedding dan chatbot)
- Sistem operasi: diuji pada Windows 10/11 dan Linux
- RAM minimal 1 GB untuk layanan backend

---

## Cara Menjalankan

### 1. Siapkan lingkungan

```bash
git clone https://github.com/RusdiansyahAlief19/SentinelOps.git
cd SentinelOps
python -m venv .venv
# Windows:
.venv\Scripts\Activate.ps1
# Linux/Mac:
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Konfigurasi

Buat file `.env` di direktori utama (tidak disertakan dalam repositori demi
keamanan):

```
GEMINI_API_KEY=kunci_api_anda
SENTINELOPS_HMAC_SECRET=rahasia_bersama_untuk_shipper
```

### 3. Bangun basis pengetahuan RAG

Dijalankan sekali di awal (mengunduh MITRE ATT&CK, membangun indeks):

```bash
python corpus/build_attack.py
python corpus/build_corpus.py
python corpus/indexer.py
```

### 4. Jalankan backend

```bash
uvicorn api.main:app --port 8000
```

Dokumentasi API otomatis tersedia di `http://localhost:8000/docs`.

### 5. Jalankan frontend

Dari terminal terpisah:

```bash
cd web
python -m http.server 5500
```

Buka `http://localhost:5500` di peramban.

> Catatan: alamat backend diatur pada konstanta `API` di bagian atas
> `web/index.html`. Ubah ke URL produksi saat aplikasi di-deploy.

---

## Memasukkan Data Jaringan

Sistem menerima data dari Suricata melalui Log Shipper. Untuk memasukkan
berkas `eve.json` (baik dari Suricata langsung maupun berkas historis):

```bash
python agent/shipper.py \
  --eve-path "path/ke/eve.json" \
  --api-url "http://127.0.0.1:8000/ingest" \
  --secret "rahasia_yang_sama_dengan_env" \
  --exit-when-caught-up
```

Setelah data masuk, hitung skor risiko dengan membandingkan periode serangan
terhadap baseline normal:

```bash
python api/scoring.py \
  --baseline-start "<waktu_mulai_baseline>" \
  --baseline-end   "<waktu_selesai_baseline>" \
  --window-start   "<waktu_mulai_window>" \
  --window-end     "<waktu_selesai_window>" \
  --window-minutes 1
```

Catatan: panjang window serangan harus sama dengan ukuran window baseline,
agar perbandingan setara.

---

## Akun Demo

Sistem tidak menggunakan login pada versi ini (single-tenant, satu
administrator). Seluruh fungsi dapat diakses langsung setelah aplikasi
berjalan. Data contoh akan tampil otomatis apabila backend belum terhubung.

---

## Struktur Direktori

```
sentinelops/
├── api/            Layanan FastAPI
│   ├── main.py     Endpoint: /ingest /assets /timeline /chat /health
│   ├── db.py       Skema SQLite dan kueri (parameterized)
│   ├── schemas.py  Validasi Pydantic dan transformasi event
│   ├── scoring.py  Perhitungan skor risiko per host
│   └── security.py Verifikasi HMAC untuk ingest
├── agent/          Log Shipper
├── corpus/         Pipeline basis pengetahuan RAG
├── docs/           Dokumentasi teknis, lisensi, evaluasi
├── web/            Dashboard frontend
└── requirements.txt
```

---

## Dokumen Pendukung

- `docs/LICENSES.md` — lisensi dan atribusi seluruh sumber data
- `docs/retrieval-eval.md` — hasil evaluasi retrieval RAG
- `docs/threat_model.md` — analisis STRIDE terhadap sistem sendiri
- `http://localhost:8000/docs` — dokumentasi API (OpenAPI) otomatis

---

## Keterbatasan yang Disadari

Sistem ini menggunakan deteksi berbasis anomali statistik, sehingga dapat
menghasilkan positif palsu pada host dengan pola lalu lintas tidak biasa.
Karena itu sistem bersifat advisory, keputusan akhir tetap pada analis
manusia. Baseline pada demonstrasi direkam dalam periode terbatas di
laboratorium terkendali; pada penerapan nyata, baseline dikumpulkan secara
rolling dalam periode yang lebih panjang.
