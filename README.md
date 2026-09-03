# SentinelOps

Lapisan interpretasi keamanan jaringan untuk institusi kecil (sekolah,
kampus, instansi daerah) yang punya jaringan sendiri tapi tidak punya tim
keamanan khusus. Sistem membaca alert dari Suricata, memberi skor risiko
per host secara statistik, dan menjelaskan tiap alert dalam Bahasa
Indonesia lewat chatbot RAG dengan sitasi.

Dibangun untuk HoloDev, HOLOGY 9.0 (Universitas Brawijaya).
Subtema: Infrastruktur Sosial.

> Catatan: dokumen ini adalah panduan kerja untuk tim. Panduan instalasi
> lengkap untuk penilaian lomba ada di dokumen submission terpisah.

## Prinsip desain

- **Read-only advisory.** Sistem hanya mengamati dan menyarankan, tidak
  pernah memblokir atau bertindak otomatis. Keputusan tetap di tangan manusia.
- **Dua pipeline.** Event `alert` dari Suricata diterjemahkan oleh RAG.
  Event `flow`/`stats` dinilai secara statistik untuk menangkap anomali
  yang tidak terpicu signature apa pun.
- **Data tidak keluar jaringan.** Skor dihitung lokal. Yang dikirim ke API
  Gemini hanya teks pertanyaan dan potongan dokumen publik, bukan log.

## Susunan folder

```
sentinelops/
├── api/            layanan FastAPI
│   ├── main.py     endpoint: /ingest /assets /timeline /chat /health
│   ├── db.py       skema SQLite + query (parameterized)
│   └── schemas.py  validasi Pydantic + transformasi event Suricata
├── agent/          Log Shipper (baca eve.json, kirim ke /ingest)
├── corpus/         pipeline pengetahuan RAG
│   ├── build_attack.py   ekstrak technique dari MITRE ATT&CK
│   ├── parse_et_rules.py parser rule Emerging Threats
│   ├── inspect_eve.py    inspeksi eve.json, tarik SID
│   ├── build_corpus.py   rakit chunks.json dwibahasa
│   ├── indexer.py        bangun index FAISS + BM25
│   ├── engine.py         retrieval hybrid (RRF) + Gemini
│   └── prompts.py        system prompt SOC analyst
├── docs/           dokumentasi teknis dan lisensi
└── web/            dashboard Laravel
```

## Menjalankan pertama kali

Prasyarat: Python 3.10+, dan sebuah Gemini API key.

```powershell
git clone https://github.com/RusdiansyahAlief19/SentinelOps.git
cd SentinelOps
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Buat file `.env` di root (JANGAN di-commit, sudah diabaikan git):

```
GEMINI_API_KEY=isi_key_anda
```

Bangun basis pengetahuan RAG (sekali, atau tiap corpus berubah):

```powershell
python corpus\build_attack.py
python corpus\build_corpus.py
python corpus\indexer.py
```

Jalankan API:

```powershell
uvicorn api.main:app --reload --port 8000
```

Buka `http://localhost:8000/docs` untuk dokumentasi API otomatis.

## Alur kerja git untuk tim

Selalu tarik perubahan terbaru SEBELUM mulai kerja dan sebelum push:

```powershell
git pull
# ... kerja ...
git add <file>
git commit -m "pesan singkat"
git pull
git push
```

Satu branch `main`, harus selalu bisa dijalankan. Jangan commit file
`.env`, file `.db`, atau data mentah di `corpus/raw/`, semuanya sudah
diabaikan lewat `.gitignore`.

## Yang JANGAN dilakukan

- Jangan menambah auto-block, WebSocket, atau multi-tenant. Itu di luar
  cakupan yang disepakati.
- Jangan menaruh API key langsung di kode. Selalu lewat `.env`.
- Jangan commit file besar (eve.json, bundle ATT&CK). Biarkan skrip yang
  mengunduhnya.
