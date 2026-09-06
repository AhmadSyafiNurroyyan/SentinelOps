# Model Ancaman SentinelOps

## 1. Tujuan dan ruang lingkup

Dokumen ini mendeskripsikan model ancaman dan kontrol keamanan SentinelOps
berdasarkan arsitektur serta kode yang tersedia di repository. Analisis
menggunakan kerangka **STRIDE**:

- **Spoofing** — penyamaran identitas;
- **Tampering** — perubahan data atau proses tanpa otorisasi;
- **Repudiation** — penyangkalan terhadap suatu aktivitas;
- **Information Disclosure** — pengungkapan informasi;
- **Denial of Service** — gangguan terhadap ketersediaan; dan
- **Elevation of Privilege** — peningkatan hak akses secara tidak sah.

Ruang lingkup mencakup alur `eve.json` → shipper → API → SQLite, endpoint API,
engine RAG, dan integrasi ke Gemini API. Dashboard frontend belum memiliki
implementasi pada repository ini, sehingga dibahas sebagai boundary integrasi,
bukan sebagai komponen yang telah tervalidasi.

Model ini ditujukan untuk prototipe dan demonstrasi pada jaringan terisolasi.
Model ini **bukan** sertifikasi keamanan produksi dan tidak mengklaim bahwa
SentinelOps mendeteksi seluruh teknik serangan.

## 2. Aset yang dilindungi

| Aset | Nilai keamanan |
| :--- | :--- |
| Event Suricata dan database SQLite | Integritas serta kerahasiaan telemetry jaringan |
| Skor risiko, alasan, dan riwayat host | Integritas keputusan prioritas dan kerahasiaan topologi |
| Secret HMAC | Keaslian dan integritas pengiriman event |
| Corpus RAG dan mapping SID | Keandalan interpretasi serta sitasi chatbot |
| API Gemini dan API key | Kerahasiaan query, ketersediaan layanan, dan kontrol biaya |
| Jejak waktu dan hasil pengujian | Reproduksibilitas serta akuntabilitas validasi |

## 3. Arsitektur dan trust boundary

1. **Jaringan sumber → sensor Suricata**
   Traffic jaringan dianggap tidak tepercaya. Suricata menghasilkan `eve.json`
   sebagai sumber telemetry.
2. **`agent/shipper.py` → `api/main.py`**
   Komunikasi HTTP diperlakukan sebagai boundary proses-ke-proses. Endpoint
   `/ingest` memerlukan HMAC-SHA256 dan timestamp.
3. **API → SQLite**
   API memvalidasi dan meratakan event sebelum penyimpanan. Database adalah
   aset lokal yang harus dilindungi oleh permission sistem operasi.
4. **Pengguna/dashboard → API**
   Endpoint baca mengembalikan IP, event, dan skor risiko. Pada implementasi
   saat ini endpoint tersebut belum memiliki autentikasi aplikasi.
5. **API/RAG → Gemini API**
   Query chat dan konteks corpus dikirim ke penyedia eksternal untuk embedding
   dan generasi jawaban. Boundary ini memiliki implikasi privasi dan biaya.

![Diagram alur data dan batas kepercayaan SentinelOps](threats-model.png)

## 4. Asumsi keamanan

- Host yang menjalankan API, SQLite, dan secret HMAC berada dalam perimeter
  yang dikelola tim.
- File `eve.json` dan database tidak dapat dianggap sebagai sumber bukti
  immutable tanpa kontrol filesystem atau log forwarding tambahan.
- Pengguna yang dapat mengakses endpoint baca berpotensi melihat informasi
  sensitif tentang host dan aktivitas jaringan.
- Gemini API diperlakukan sebagai layanan pihak ketiga; data yang dikirim
  tidak boleh diasumsikan tetap berada di jaringan internal.
- Sistem beroperasi dalam mode **advisory-only** dan tidak memiliki hak untuk
  memblokir IP atau mengubah firewall.

## 5. Analisis STRIDE dan kontrol

### 5.1 Log Suricata dan shipper

| Kategori | Skenario ancaman | Kontrol saat ini | Risiko residual |
| :--- | :--- | :--- | :--- |
| Tampering | `eve.json` dihapus, dipotong, atau diubah sebelum dikirim | Shipper membaca file secara berurutan dan menyimpan offset | **Sedang:** belum ada append-only storage, hash chaining, atau forwarding immutable |
| Spoofing | Proses lain mengirim event palsu ke `/ingest` | HMAC-SHA256 atas timestamp dan body | **Tinggi jika secret bocor**; secret harus disimpan di environment yang terlindungi dan dirotasi |
| Tampering | Payload diubah selama transit | Signature mencakup seluruh body request | **Sedang:** HMAC menjamin integritas, bukan kerahasiaan; deployment produksi memerlukan HTTPS/TLS |
| Repudiation | Pengirim menyangkal waktu atau isi pengiriman | Timestamp dan audit trail `scenario_log.csv` untuk validasi lab | **Sedang:** belum ada audit log terpusat atau tanda tangan log yang tahan perubahan |
| Denial of Service | Batch berukuran besar atau request berulang memenuhi API | Belum ada pembatasan payload dan rate limit | **Tinggi:** perlu batas ukuran batch, timeout, dan rate limiting |

### 5.2 Verifikasi HMAC pada `/ingest`

| Kategori | Skenario ancaman | Kontrol saat ini | Risiko residual |
| :--- | :--- | :--- | :--- |
| Tampering | Signature ditebak melalui perbandingan byte demi byte | `hmac.compare_digest()` | Rendah untuk kontrol ini |
| Replay | Request valid dikirim ulang | Jendela waktu 300 detik dan cache signature yang sudah dipakai | **Sedang:** cache hanya berlaku dalam satu proses API |
| Elevation of Privilege | Secret development digunakan pada deployment | Peringatan ketika `SENTINELOPS_HMAC_SECRET` belum diatur | **Tinggi:** mode produksi sebaiknya menolak startup dengan secret default |
| Spoofing | Timestamp tidak valid atau kedaluwarsa | Parsing integer dan validasi toleransi waktu | Rendah, selama sinkronisasi waktu host terjaga |

### 5.3 Validasi API dan database

| Kategori | Skenario ancaman | Kontrol saat ini | Risiko residual |
| :--- | :--- | :--- | :--- |
| Tampering | Input event menyebabkan SQL injection | Semua query di `api/db.py` menggunakan parameter | Rendah pada kode saat ini; kontrol harus dipertahankan untuk perubahan berikutnya |
| Tampering | Payload event tidak sesuai skema | Pydantic memvalidasi `IngestBatch`, `SuricataEvent`, dan tipe field | **Sedang:** field ekstra diabaikan dan batas jumlah/ukuran batch belum ditentukan |
| Information Disclosure | File database dibaca oleh akun lokal lain | Bergantung pada permission filesystem | **Sedang:** database belum dienkripsi saat tersimpan |
| Denial of Service | Tabel `events` tumbuh tanpa batas | Belum ada retention atau pruning | **Sedang:** perlu kebijakan retensi dan monitoring kapasitas |
| Information Disclosure | Endpoint mengungkap IP dan event internal | Endpoint tersedia untuk pembacaan API | **Tinggi:** `/assets`, `/assets/{ip}`, `/timeline`, dan `/chat` belum memiliki autentikasi |

### 5.4 RAG engine dan Gemini API

| Kategori | Skenario ancaman | Kontrol saat ini | Risiko residual |
| :--- | :--- | :--- | :--- |
| Information Disclosure | Query berisi detail internal dikirim ke pihak ketiga | Corpus yang digunakan bersumber dari dokumen publik; scoring tetap lokal | **Sedang:** query pengguna tetap dikirim ke Gemini dan belum melalui redaksi IP/hostname |
| Tampering | Prompt injection mengubah peran atau keluaran model | System prompt membatasi corpus dan format jawaban | **Sedang:** belum ada validasi panjang, klasifikasi input, atau evaluasi prompt injection khusus |
| Information Disclosure | Jawaban menampilkan konteks yang tidak semestinya | Retrieval dibatasi pada chunk teratas dan jawaban disertai sumber | **Sedang:** tetap memerlukan review output dan kebijakan data yang jelas |
| Denial of Service | Pemanggilan `/chat` menghabiskan kuota atau biaya Gemini | Belum ada rate limit dan quota guard di endpoint | **Tinggi:** perlu pembatasan per pengguna/asal dan monitoring biaya |

### 5.5 Dashboard dan pengguna

Dashboard frontend belum tersedia pada repository ini. Boundary ini tetap perlu
diperhitungkan karena API mengembalikan informasi sensitif.

| Kategori | Skenario ancaman | Persyaratan mitigasi |
| :--- | :--- | :--- |
| Spoofing | Pengguna tanpa identitas mengakses dashboard | Terapkan autentikasi dan manajemen sesi sebelum deployment jaringan |
| Information Disclosure | IP, event, dan skor terlihat oleh pihak yang tidak berwenang | Terapkan otorisasi berbasis peran serta HTTPS |
| Tampering/XSS | `signature` atau `reason` dirender sebagai HTML | Gunakan escaping default dan jangan merender data event dengan raw HTML |
| Repudiation | Perubahan atau pembacaan data tidak terlacak | Tambahkan audit log untuk login, query, dan perubahan konfigurasi |

## 6. Kontrol yang telah diterapkan

- HMAC-SHA256 pada endpoint `/ingest`, dengan constant-time comparison.
- Replay protection berbasis timestamp dan signature cache.
- Validasi terpusat serta flattening event pada boundary `/ingest`.
- Parameterized query untuk operasi SQLite.
- Batas `limit` pada endpoint `/timeline` hingga 500 event.
- Arsitektur advisory-only yang tidak memiliki jalur eksekusi auto-block.
- Corpus RAG yang dibatasi pada sumber keamanan yang terdokumentasi dan
  jawaban yang mengembalikan sitasi.

## 7. Prioritas mitigasi lanjutan

| Prioritas | Mitigasi | Alasan |
| :--- | :--- | :--- |
| P0 | Autentikasi dan otorisasi seluruh endpoint baca serta `/chat` | Mencegah pengungkapan topologi dan penyalahgunaan API |
| P0 | Wajibkan secret non-default pada mode produksi | Menghilangkan kredensial bawaan yang dapat ditebak |
| P0 | HTTPS/TLS antara shipper, API, dan dashboard | Menjamin kerahasiaan selain integritas HMAC |
| P1 | Rate limiting, batas payload, dan quota guard `/chat` | Mengurangi risiko DoS dan biaya tidak terkendali |
| P1 | Retensi event, monitoring kapasitas, dan backup database | Menjaga ketersediaan serta operasional jangka panjang |
| P1 | Redaksi IP/hostname sensitif sebelum pengiriman ke Gemini | Mengurangi paparan data internal ke pihak ketiga |
| P2 | Replay store terdistribusi dan audit log terpusat | Diperlukan bila API berjalan multi-worker atau multi-instance |
| P2 | Penyimpanan log append-only atau hash chaining | Memperkuat non-repudiation dan integritas bukti |

## 8. Kesimpulan risiko

Untuk demonstrasi pada lab terisolasi, kontrol HMAC, validasi input, query
terparameterisasi, dan desain advisory-only memberikan baseline keamanan yang
memadai. Namun, implementasi saat ini belum dapat dianggap siap produksi karena
endpoint baca belum diautentikasi, transport belum diwajibkan TLS, rate limiting
belum tersedia, dan database belum dienkripsi.

Batasan tersebut dinyatakan secara eksplisit agar klaim keamanan SentinelOps
proporsional dengan kontrol yang benar-benar tersedia. Penambahan mitigasi
prioritas P0 merupakan prasyarat sebelum sistem ditempatkan pada jaringan
operasional atau memproses telemetry yang bersifat sensitif.
