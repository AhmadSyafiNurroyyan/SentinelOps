# Evaluasi Retrieval RAG SentinelOps

Total: **20/20 lolos** (100%).

Retrieval dinilai lolos bila technique yang diharapkan muncul di antara chunk yang terambil untuk pertanyaan tersebut. Pengujian ini memeriksa apakah dokumen yang tepat berhasil ditemukan, terpisah dari kualitas jawaban akhir.

| # | Kelompok | Pertanyaan | Diharapkan | Peringkat | Hasil |
|---|----------|------------|------------|-----------|-------|
| 1 | kode-eksak | Apa itu SID 1000001? | T1046 | 1 | Lolos |
| 2 | kode-eksak | Jelaskan technique T1110 | T1110 | 1 | Lolos |
| 3 | kode-eksak | Apa arti T1046? | T1046 | 1 | Lolos |
| 4 | kode-eksak | SID 2210063 itu deteksi apa? | T1046 | 1 | Lolos |
| 5 | kode-eksak | technique T1048 tentang apa? | T1048 | 1 | Lolos |
| 6 | konseptual | kenapa ada yang memindai port di jaringan saya? | T1046 | 1 | Lolos |
| 7 | konseptual | seseorang mencoba menebak password berulang kali | T1110 | 1 | Lolos |
| 8 | konseptual | ada data keluar dalam jumlah besar ke luar | T1048 | 1 | Lolos |
| 9 | konseptual | bagaimana penyerang mencari kelemahan layanan? | T1046 | 1 | Lolos |
| 10 | konseptual | apa bahaya login jarak jauh yang tidak wajar? | T1021 | 1 | Lolos |
| 11 | campuran | host saya kena port scan, itu T1046 ya? | T1046 | 1 | Lolos |
| 12 | campuran | brute force SSH bahaya nggak? | T1110 | 1 | Lolos |
| 13 | campuran | apa itu Network Service Discovery? | T1046 | 1 | Lolos |
| 14 | campuran | ada percobaan brute force, apa yang harus dilakukan? | T1110 | 1 | Lolos |
| 15 | campuran | exfiltration lewat protokol lain gimana? | T1048 | 1 | Lolos |
| 16 | campuran | pemindaian aktif dari luar jaringan | T1595 | 1 | Lolos |
| 17 | campuran | penyerang pakai remote services untuk masuk | T1021 | 1 | Lolos |
| 18 | campuran | kenapa banyak koneksi ke banyak IP tiba-tiba? | T1046 | 1 | Lolos |
| 19 | campuran | apa itu active scanning? | T1595 | 1 | Lolos |
| 20 | campuran | data dicuri lewat channel tersembunyi | T1048 | 1 | Lolos |

## Ringkasan per kelompok

| Kelompok | Menguji | Hasil |
|----------|---------|-------|
| kode-eksak | BM25 (kata/kode persis) | 5/5 |
| konseptual | FAISS (kedekatan makna) | 5/5 |
| campuran | RRF (gabungan) | 10/10 |
