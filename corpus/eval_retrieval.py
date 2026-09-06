import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DOCS = os.path.join(HERE, "..", "docs")
OUT = os.path.join(DOCS, "retrieval-eval.md")

QUESTIONS = [
    # --- Kode eksak (BM25) ---
    ("Apa itu SID 1000001?", "T1046", "kode-eksak"),
    ("Jelaskan technique T1110", "T1110", "kode-eksak"),
    ("Apa arti T1046?", "T1046", "kode-eksak"),
    ("SID 2210063 itu deteksi apa?", "T1046", "kode-eksak"),
    ("technique T1048 tentang apa?", "T1048", "kode-eksak"),

    # --- Konseptual (FAISS) ---
    ("kenapa ada yang memindai port di jaringan saya?", "T1046", "konseptual"),
    ("seseorang mencoba menebak password berulang kali", "T1110", "konseptual"),
    ("ada data keluar dalam jumlah besar ke luar", "T1048", "konseptual"),
    ("bagaimana penyerang mencari kelemahan layanan?", "T1046", "konseptual"),
    ("apa bahaya login jarak jauh yang tidak wajar?", "T1021", "konseptual"),

    # --- Campuran (RRF) ---
    ("host saya kena port scan, itu T1046 ya?", "T1046", "campuran"),
    ("brute force SSH bahaya nggak?", "T1110", "campuran"),
    ("apa itu Network Service Discovery?", "T1046", "campuran"),
    ("ada percobaan brute force, apa yang harus dilakukan?", "T1110", "campuran"),
    ("exfiltration lewat protokol lain gimana?", "T1048", "campuran"),
    ("pemindaian aktif dari luar jaringan", "T1595", "campuran"),
    ("penyerang pakai remote services untuk masuk", "T1021", "campuran"),
    ("kenapa banyak koneksi ke banyak IP tiba-tiba?", "T1046", "campuran"),
    ("apa itu active scanning?", "T1595", "campuran"),
    ("data dicuri lewat channel tersembunyi", "T1048", "campuran"),
]


def main():
    sys.path.insert(0, HERE)
    import engine
    eng = engine.get_engine()

    results = []
    for q, expected, group in QUESTIONS:
        contexts = eng.retrieve(q)
        got = [c["technique_id"] for c in contexts]
        hit = expected in got
        rank = got.index(expected) + 1 if hit else None
        results.append({
            "q": q, "expected": expected, "group": group,
            "got": got, "hit": hit, "rank": rank,
        })
        mark = "PASS" if hit else "MISS"
        pos = f"peringkat {rank}" if rank else "tidak ada"
        print(f"  [{mark}] {group:11} {expected:6} {pos:14} | {q[:42]}")

    passed = sum(1 for r in results if r["hit"])
    total = len(results)
    print()
    print(f"HASIL: {passed}/{total} lolos ({passed/total*100:.0f}%)")
    print()
    for g in ("kode-eksak", "konseptual", "campuran"):
        sub = [r for r in results if r["group"] == g]
        p = sum(1 for r in sub if r["hit"])
        print(f"  {g:11}: {p}/{len(sub)}")

    write_report(results, passed, total)
    print(f"\n[ok] Laporan ditulis ke {OUT}")

    if passed < 16:
        print("\n[catat] Di bawah ambang Gate (16/20). Persempit atau")
        print("        perjelas corpus untuk chunk yang membingungkan.")

def write_report(results, passed, total):
    os.makedirs(DOCS, exist_ok=True)
    lines = [
        "# Evaluasi Retrieval RAG SentinelOps",
        "",
        f"Total: **{passed}/{total} lolos** ({passed/total*100:.0f}%).",
        "",
        "Retrieval dinilai lolos bila technique yang diharapkan muncul di "
        "antara chunk yang terambil untuk pertanyaan tersebut. Pengujian ini "
        "memeriksa apakah dokumen yang tepat berhasil ditemukan, terpisah dari "
        "kualitas jawaban akhir.",
        "",
        "| # | Kelompok | Pertanyaan | Diharapkan | Peringkat | Hasil |",
        "|---|----------|------------|------------|-----------|-------|",
    ]
    for i, r in enumerate(results, 1):
        rank = str(r["rank"]) if r["rank"] else "-"
        mark = "Lolos" if r["hit"] else "Meleset"
        q = r["q"].replace("|", "\\|")
        lines.append(
            f"| {i} | {r['group']} | {q} | {r['expected']} | {rank} | {mark} |"
        )

    lines += [
        "",
        "## Ringkasan per kelompok",
        "",
        "| Kelompok | Menguji | Hasil |",
        "|----------|---------|-------|",
    ]
    for g, desc in (("kode-eksak", "BM25 (kata/kode persis)"),
                    ("konseptual", "FAISS (kedekatan makna)"),
                    ("campuran", "RRF (gabungan)")):
        sub = [r for r in results if r["group"] == g]
        p = sum(1 for r in sub if r["hit"])
        lines.append(f"| {g} | {desc} | {p}/{len(sub)} |")

    open(OUT, "w", encoding="utf-8").write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
