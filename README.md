# SentinelOps

**Virtual SOC Analyst** untuk kampus, UMKM, dan instansi daerah yang telah
memiliki sensor jaringan tetapi belum memiliki tim SOC khusus. SentinelOps
menjadi lapisan analitik di atas Suricata: log `eve.json` dikumpulkan,
diringkas menjadi prioritas risiko per host, lalu dijelaskan dalam Bahasa
Indonesia melalui chatbot RAG dengan sitasi.

Dibangun untuk HoloDev, HOLOGY 9.0 (Universitas Brawijaya), subtema
**Infrastruktur Sosial**.

## Konsep dan fitur utama

SentinelOps menggunakan arsitektur **dual-engine**:

1. **Statistical Risk Scoring** membandingkan window traffic terbaru dengan
   baseline historis menggunakan percentile scoring pada enam fitur:
   jumlah koneksi, port unik, sumber IP unik, bytes ke server, jumlah alert,
   dan rate koneksi per menit. Pendekatan ini membantu menemukan anomali
   non-signature, termasuk transfer data besar yang tidak memicu rule IDS.
2. **Virtual SOC Analyst (RAG)** menerjemahkan SID dan konteks ancaman melalui
   hybrid search FAISS + BM25 yang digabung dengan Reciprocal Rank Fusion
   (RRF). Jawaban dibatasi pada corpus MITRE ATT&CK dan ET Open serta
   menyertakan sumber yang dapat diverifikasi.

Hasilnya disiapkan untuk empat kebutuhan dashboard:

- **Matriks risiko aset:** host diurutkan berdasarkan skor risiko dan dilengkapi
  alasan yang mudah dipahami.
- **Timeline dual-attribution:** event diberi label `signature` (alert Suricata)
  atau `statistical` (anomali perilaku).
- **Chatbot RAG:** tanya jawab tentang SID, teknik serangan, dan rekomendasi
  mitigasi.
- **API yang aman:** endpoint ingest dilindungi HMAC-SHA256, replay protection
  300 detik, validasi terpusat, dan seluruh query SQLite menggunakan parameter.

### Prinsip desain

- **Advisory-only/read-only:** tidak ada auto-block, perubahan firewall, atau
  mitigasi otomatis. Keputusan akhir tetap di tangan administrator.
- **Single-boundary validation:** agent hanya meneruskan log mentah; flattening
  dan validasi dilakukan di endpoint `/ingest`.
- **Privasi:** scoring dan penyimpanan event berjalan lokal. API Gemini hanya
  menerima pertanyaan dan potongan corpus publik, bukan log jaringan mentah.

## Struktur Project

```text
sentinelops/
├── api/                         Backend FastAPI dan logika analitik
│   ├── main.py                 Endpoint /ingest, /assets, /timeline, /chat, /health
│   ├── db.py                   Skema dan query SQLite terparameterisasi
│   ├── schemas.py              Validasi dan flattening event Suricata
│   ├── scoring.py              Baseline, percentile scoring, dan alasan risiko
│   ├── security.py             HMAC-SHA256 dan replay protection
│   └── rag_loader.py           Memuat engine RAG ke API
├── agent/
│   └── shipper.py              Tail eve.json, batching, offset, dan HMAC signing
├── corpus/                      Pipeline corpus dan retrieval RAG
│   ├── build_attack.py         Ekstraksi teknik MITRE ATT&CK
│   ├── parse_et_rules.py       Parsing rules Emerging Threats
│   ├── inspect_eve.py          Inspeksi eve.json dan pemetaan SID
│   ├── build_corpus.py         Membuat chunks bilingual
│   ├── indexer.py              Membangun index FAISS dan BM25
│   ├── engine.py               Hybrid retrieval + Gemini + sitasi
│   ├── prompts.py              System prompt SOC analyst
│   ├── eval_retrieval.py       Evaluasi kualitas retrieval
│   ├── attack_techniques.json  Hasil ekstraksi ATT&CK yang dilacak
│   ├── sid_mapping.json        Mapping SID hasil validasi skenario
│   └── chunks.json             Corpus bilingual yang dilacak
├── scripts/
│   └── setup_data.py            Orkestrasi setup corpus dan index
├── security/                    Baseline dan skenario pengujian keamanan
│   ├── baseline/                Data traffic benign
│   └── scenarios/               Skenario serangan dan hasil observasi
├── docs/                        Threat model, evaluasi retrieval, dan lisensi
├── web/                         Lokasi dashboard frontend (disiapkan untuk UI)
├── requirements.txt             Dependensi Python
└── .gitignore                   Aturan untuk secret dan artefak runtime
```

`corpus/raw/`, `faiss_index/`, `bm25_index.pkl`, database SQLite, `.env`, dan
log runtime adalah artefak lokal yang sengaja tidak dilacak Git.

## Menjalankan secara lokal

Prasyarat: Python 3.10+ dan Gemini API key.

```powershell
git clone https://github.com/RusdiansyahAlief19/SentinelOps.git
cd SentinelOps
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Buat `.env` di root (jangan di-commit):

```dotenv
GEMINI_API_KEY=isi_key_anda
SENTINELOPS_HMAC_SECRET=ganti_dengan_secret_acak
```

Siapkan corpus dan index (jalankan ulang jika sumber corpus berubah):

```powershell
python scripts\setup_data.py
```

Untuk setup tanpa memanggil Gemini saat membangun ringkasan:

```powershell
python scripts\setup_data.py --dry-run
```

Jalankan API:

```powershell
uvicorn api.main:app --reload --port 8000
```

Dokumentasi API tersedia di `http://localhost:8000/docs`. Setelah API aktif,
jalankan shipper terhadap file Suricata:

```powershell
python agent\shipper.py `
  --eve-path C:\path\ke\eve.json `
  --api-url http://127.0.0.1:8000/ingest `
  --secret $env:SENTINELOPS_HMAC_SECRET
```

## Pengujian dan keamanan

Folder `security/` berisi baseline benign dan skenario untuk memvalidasi
deteksi signature maupun anomali statistik. Detail threat model, lisensi sumber,
dan evaluasi retrieval tersedia di `docs/`.
