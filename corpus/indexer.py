"""
Bangun index pencarian dari corpus/chunks.json.

Menghasilkan dua index yang saling melengkapi:
    faiss_index/          pencarian vektor (kedekatan makna)
    bm25_index.pkl        pencarian kata kunci (kecocokan token persis)

Setiap chunk menghasilkan DUA entri: satu untuk teks Inggris (`text`)
dan satu untuk ringkasan Indonesia (`text_id`). Keduanya menunjuk balik
ke chunk yang sama lewat chunk_id. Dengan begitu pertanyaan berbahasa
Indonesia cocok ke entri Indonesia, pertanyaan Inggris cocok ke entri
Inggris, dan hasilnya sama-sama mengarah ke chunk yang tepat.

Embedding memakai API Gemini, bukan model lokal. Ini menjaga kebutuhan
RAM tetap kecil (tanpa PyTorch) dan tidak menambah dependensi berat.

Pemakaian:
    python corpus\\indexer.py
"""

import json
import os
import pickle
import sys
import time

import faiss
import numpy as np
from rank_bm25 import BM25Okapi

HERE = os.path.dirname(os.path.abspath(__file__))
CHUNKS_PATH = os.path.join(HERE, "chunks.json")
FAISS_DIR = os.path.join(HERE, "..", "faiss_index")
FAISS_PATH = os.path.join(FAISS_DIR, "index.faiss")
META_PATH = os.path.join(FAISS_DIR, "meta.json")
BM25_PATH = os.path.join(HERE, "..", "bm25_index.pkl")

EMBED_MODEL = "gemini-embedding-001"


def tokenize(text):
    """Tokenisasi sederhana untuk BM25: huruf kecil, pisah non-alfanumerik."""
    out, cur = [], []
    for ch in text.lower():
        if ch.isalnum():
            cur.append(ch)
        elif cur:
            out.append("".join(cur))
            cur = []
    if cur:
        out.append("".join(cur))
    return out


def embed_texts(client, texts):
    """Embed daftar teks lewat Gemini, satu per satu dengan jeda aman."""
    vectors = []
    for i, t in enumerate(texts, 1):
        resp = client.models.embed_content(model=EMBED_MODEL, contents=t)
        vectors.append(resp.embeddings[0].values)
        print(f"\r  embedding {i}/{len(texts)}", end="", flush=True)
        time.sleep(0.5)
    print()
    return np.array(vectors, dtype="float32")


def main():
    if not os.path.exists(CHUNKS_PATH):
        print(f"[gagal] Tidak ada {CHUNKS_PATH}. Jalankan build_corpus.py dulu.",
              file=sys.stderr)
        sys.exit(1)

    chunks = json.load(open(CHUNKS_PATH, encoding="utf-8"))
    print(f"[baca]  {len(chunks)} chunk dari corpus")

    # Bangun dua entri per chunk: Inggris dan Indonesia.
    entries = []   # metadata tiap vektor
    texts = []     # teks yang diembed
    corpus_tokens = []  # untuk BM25

    for c in chunks:
        for lang, field in (("en", "text"), ("id", "text_id")):
            body = c.get(field)
            if not body:
                continue
            entries.append({
                "chunk_id": c["chunk_id"],
                "technique_id": c["technique_id"],
                "name": c["name"],
                "lang": lang,
                "sids": c.get("sids", []),
                "source_doc": c.get("source_doc"),
                "source_url": c.get("source_url"),
                "text": c["text"],       # selalu simpan versi Inggris utuh
                "text_id": c.get("text_id"),
            })
            texts.append(body)
            corpus_tokens.append(tokenize(body))

    print(f"[info]  {len(entries)} entri ({len(chunks)} chunk x 2 bahasa)")

    from google import genai
    from dotenv import load_dotenv
    load_dotenv()
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        print("[gagal] GEMINI_API_KEY tidak ada di .env", file=sys.stderr)
        sys.exit(1)
    client = genai.Client(api_key=key)

    print("[embed] Memanggil Gemini untuk embedding...")
    vectors = embed_texts(client, texts)
    dim = vectors.shape[1]
    print(f"[ok]    Dimensi vektor: {dim}")

    # FAISS: normalkan lalu inner product = cosine similarity.
    faiss.normalize_L2(vectors)
    index = faiss.IndexFlatIP(dim)
    index.add(vectors)

    os.makedirs(FAISS_DIR, exist_ok=True)
    faiss.write_index(index, FAISS_PATH)
    json.dump(entries, open(META_PATH, "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)

    # BM25: simpan model dan token, plus entries agar hasil bisa dipetakan.
    bm25 = BM25Okapi(corpus_tokens)
    with open(BM25_PATH, "wb") as f:
        pickle.dump({"bm25": bm25, "entries": entries,
                     "corpus_tokens": corpus_tokens}, f)

    print()
    print(f"[ok]    FAISS  -> {FAISS_PATH} ({index.ntotal} vektor)")
    print(f"[ok]    Meta   -> {META_PATH}")
    print(f"[ok]    BM25   -> {BM25_PATH}")
    print()
    print("Uji cepat retrieval:  python corpus\\indexer.py --test \"port scan\"")


def quick_test(query):
    """Uji retrieval sederhana tanpa RRF, sekadar memastikan index jalan."""
    import pickle as pk
    data = pk.load(open(BM25_PATH, "rb"))
    bm25, entries = data["bm25"], data["entries"]
    scores = bm25.get_scores(tokenize(query))
    ranked = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
    print(f"BM25 teratas untuk '{query}':")
    for i in ranked[:4]:
        e = entries[i]
        print(f"  {scores[i]:.2f}  [{e['lang']}] {e['technique_id']} {e['name']}")


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--test":
        quick_test(sys.argv[2])
    else:
        main()
