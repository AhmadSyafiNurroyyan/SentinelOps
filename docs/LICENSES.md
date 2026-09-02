# Lisensi dan Atribusi Sumber Data

Dokumen ini mencatat seluruh sumber data pihak ketiga yang dipakai dalam
basis pengetahuan (corpus) SentinelOps, beserta lisensi dan kewajiban
atribusinya. Disusun untuk memenuhi Ketentuan Karya HOLOGY 9.0 butir 8:
seluruh source code, aset, dan dokumentasi yang digunakan harus bebas dari
pelanggaran hak cipta pihak lain.

Terakhir diperbarui: 2 September 2026

---

## 1. MITRE ATT&CK® Enterprise v19.1

**Sumber**
`https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.1/enterprise-attack/enterprise-attack-19.1.json`

**Tanggal unduh:** 2 September 2026
**Format:** STIX 2.1 bundle
**Pengelola:** The MITRE Corporation

**Ketentuan lisensi**

MITRE memberikan lisensi non-eksklusif dan bebas royalti untuk memakai
ATT&CK bagi keperluan riset, pengembangan, maupun komersial. Penyalinan
diizinkan dengan syarat penyalin mereproduksi penetapan hak cipta MITRE
beserta lisensinya pada setiap salinan.

**Atribusi yang direproduksi**

> © 2026 The MITRE Corporation. This work is reproduced and distributed
> with the permission of The MITRE Corporation.

**Yang kami ambil**

Hanya enam objek `attack-pattern` beserta objek `course-of-action`
(mitigasi) dan `x-mitre-analytic` (panduan deteksi) yang terkait, dipilih
karena relevan dengan empat skenario pengujian di laboratorium kami:

| Technique | Nama | Skenario terkait |
|---|---|---|
| T1046 | Network Service Discovery | Nmap SYN scan, NULL scan |
| T1595 | Active Scanning | Pemindaian dari luar jaringan |
| T1110 | Brute Force | Brute force SSH |
| T1048 | Exfiltration Over Alternative Protocol | Transfer volume besar |
| T1021 | Remote Services | Akses layanan jarak jauh |
| T1071 | Application Layer Protocol | Trafik aplikasi mencurigakan |

Bundle mentah 51 MB tidak ikut didistribusikan dalam source code kami dan
tidak dimasukkan ke dalam repositori git. Skrip `corpus/build_attack.py`
mengunduhnya langsung dari sumber resmi saat dijalankan.

**Catatan penggunaan merek**

MITRE ATT&CK® dan ATT&CK® adalah merek terdaftar milik The MITRE
Corporation. Rujukan pertama dalam setiap dokumen kami menuliskan
"MITRE ATT&CK®" secara utuh, rujukan berikutnya cukup "ATT&CK".
Penyebutan ATT&CK dalam proyek ini **tidak menyiratkan afiliasi,
sponsor, ataupun dukungan dari MITRE** terhadap SentinelOps. Nama ATT&CK
tidak dipakai sebagai bagian dari nama produk, layanan, atau logo kami.

**Batasan yang perlu disadari**

MITRE menyatakan ATT&CK tidak mengenumerasi seluruh kemungkinan perilaku
penyerang. Cakupan terhadap seluruh teknik dalam ATT&CK tidak menjamin
perlindungan menyeluruh, karena bisa ada teknik yang belum
terdokumentasi. SentinelOps menyampaikan hal ini secara terbuka dan tidak
mengklaim cakupan deteksi yang menyeluruh.

---

## 2. Emerging Threats Open Ruleset

**Sumber**
`https://rules.emergingthreats.net/open/suricata-7.0/emerging.rules.tar.gz`

**Tanggal unduh:** 2 September 2026
**Target:** Suricata 7.0
**Hak cipta:** Copyright (c) 2003-2026, Emerging Threats

**Ruleset ini memuat dua lisensi berbeda**

| Rentang SID | Lisensi |
|---|---|
| 1 sampai 3464, dan 100000000 sampai 100000908 | GPLv2 |
| 2000000 sampai 2799999 | BSD |

Teks lisensi aslinya disalin apa adanya ke `docs/et_license_raw.txt`.

### Keputusan tim

**Corpus SentinelOps hanya mengambil rule dengan SID pada rentang 2000000
sampai 2799999, yaitu rentang berlisensi BSD.** Rule di luar rentang
tersebut dilewati oleh `corpus/find_candidates.py` melalui konstanta
`MIN_SID` dan `MAX_SID`.

Ada tiga alasan.

Pertama, **menghindari pencampuran lisensi.** GPLv2 bersifat copyleft dan
membawa kewajiban yang berbeda dari BSD bagi karya turunan. Mencampur
keduanya dalam satu berkas corpus akan membuat status lisensi berkas
tersebut ambigu, dan ambiguitas seperti itu sulit dipertanggungjawabkan
dalam kompetisi yang mensyaratkan aset bebas pelanggaran hak cipta.

Kedua, **tidak ada yang hilang secara fungsional.** Seluruh rule yang
relevan dengan empat skenario laboratorium kami (pemindaian, brute force,
eksfiltrasi) berada pada rentang 2xxxxxx. Pembatasan ini tidak
mengorbankan cakupan deteksi yang kami butuhkan.

Ketiga, **BSD cukup dengan atribusi.** Kewajibannya jelas dan ringan,
yaitu mencantumkan pemberitahuan hak cipta, sehingga mudah dipenuhi
sekaligus mudah diperiksa.

**Yang kami ambil**

Hanya SID yang benar-benar terpicu di laboratorium kami dan telah
dikonfirmasi melalui `corpus/sid_mapping.json`. Berkas hasil parsing penuh
(`corpus/et_rules.json`, berisi 52.159 rule) berfungsi sebagai kamus
pencarian lokal, tidak ikut didistribusikan, dan tidak dimasukkan ke
repositori git.

---

## 3. Google Gemini API

**Dipakai untuk**

1. **Generation.** Menyusun jawaban berbahasa Indonesia dari konteks yang
   sudah diambil oleh mesin pencarian hibrida.
2. **Embedding.** Mengubah teks chunk dan pertanyaan pengguna menjadi
   vektor untuk pencarian FAISS.

**Ketentuan layanan**

Penggunaan tunduk pada Google APIs Terms of Service dan ketentuan tambahan
Gemini API yang berlaku pada tanggal penggunaan. Perlu dicatat bahwa
ketentuan pemakaian data pada tingkat layanan gratis dapat berbeda dari
tingkat berbayar, khususnya menyangkut apakah masukan pengguna dipakai
untuk peningkatan layanan. Tim memverifikasi ketentuan yang berlaku
sebelum pengumpulan karya.

**Data yang dikirim ke API**

| Dikirim | Tidak dikirim |
|---|---|
| Teks pertanyaan pengguna | Berkas log jaringan mentah |
| Potongan dokumen publik ATT&CK dan rule ET | Alamat IP internal institusi |
| | Data hasil pemindaian aset |

Pemisahan ini disengaja. Perhitungan skor risiko berjalan sepenuhnya
secara lokal di dalam jaringan institusi. Yang meninggalkan jaringan hanya
teks pertanyaan dan potongan dokumen publik yang memang sudah terbuka
untuk umum.

---

## 4. Pustaka perangkat lunak

Seluruh pustaka yang dipakai berlisensi terbuka dan permisif. Daftar
lengkap beserta versinya ada di `requirements.txt`.

| Pustaka | Fungsi | Lisensi |
|---|---|---|
| FastAPI | Kerangka kerja API | MIT |
| Uvicorn | Server ASGI | BSD 3-Clause |
| Pydantic | Validasi data | MIT |
| FAISS | Pencarian vektor | MIT |
| rank_bm25 | Pencarian kata kunci | Apache 2.0 |
| NumPy | Komputasi numerik | BSD 3-Clause |
| Requests | Klien HTTP | Apache 2.0 |
| Laravel | Kerangka kerja web | MIT |
| Tailwind CSS | Styling | MIT |

---

## 5. Pernyataan orisinalitas

Seluruh kode sumber SentinelOps ditulis oleh tim untuk kompetisi HOLOGY
9.0 dan belum pernah dipublikasikan, dilombakan, maupun memenangkan
kompetisi sejenis sebelumnya.

Data pengujian berupa berkas `eve.json` dihasilkan sendiri oleh tim dari
laboratorium jaringan terkendali milik kami, bukan diambil dari kumpulan
data pihak ketiga.

Skema pemetaan SID ke technique ATT&CK dalam `corpus/sid_mapping.json`
disusun manual oleh tim. Hal ini diperlukan karena metadata MITRE pada ET
Open terkonsentrasi pada rule malware dan command-and-control, sedangkan
rule bertema reconnaissance sebagian besar tidak memuat metadata tersebut.
Dari 409 rule bertema pemindaian yang kami temukan, tidak satu pun memuat
`mitre_technique_id`.