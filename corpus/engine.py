"""
Mesin RAG SentinelOps: hybrid search (FAISS + BM25) digabung dengan
Reciprocal Rank Fusion, lalu dijawab oleh Gemini dengan sitasi.

Alur satu query:
    1. Embed pertanyaan (Gemini) -> cari di FAISS (kedekatan makna)
    2. Tokenisasi pertanyaan -> cari di BM25 (kecocokan kata)
    3. Gabungkan dua peringkat dengan RRF
    4. Ambil chunk unik teratas sebagai konteks
    5. Kirim ke Gemini dengan system prompt -> jawaban + sumber

Kenapa hybrid: FAISS unggul untuk pertanyaan bahasa alami, BM25 unggul
untuk kode teknis eksak (SID, T-number) yang tidak punya makna semantik.
RRF menggabungkan keduanya tanpa perlu menyetel bobot manual.
"""

import json
import os
import pickle

import faiss
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
FAISS_PATH = os.path.join(HERE, "..", "faiss_index", "index.faiss")
META_PATH = os.path.join(HERE, "..", "faiss_index", "meta.json")
BM25_PATH = os.path.join(HERE, "..", "bm25_index.pkl")

EMBED_MODEL = "gemini-embedding-001"
CHAT_MODEL = "gemini-2.5-flash"

RRF_K = 60          # konstanta peredam RRF, nilai standar
TOP_FAISS = 6       # kandidat dari tiap mesin sebelum digabung
TOP_BM25 = 6
TOP_CONTEXT = 4     # chunk unik yang masuk ke prompt


def tokenize(text):
    """Sama persis dengan tokenizer di indexer, harus konsisten."""
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


def reciprocal_rank_fusion(faiss_ranks, bm25_ranks, k=RRF_K):
    """
    Gabung dua daftar peringkat jadi satu skor per entri.
    Rumus: skor(d) = jumlah 1/(k + rank_d) untuk tiap daftar yang memuat d.
    Peringkat mulai dari 0. Entri yang muncul di kedua daftar terangkat.
    """
    scores = {}
    for rank, idx in enumerate(faiss_ranks):
        scores[idx] = scores.get(idx, 0.0) + 1.0 / (k + rank)
    for rank, idx in enumerate(bm25_ranks):
        scores[idx] = scores.get(idx, 0.0) + 1.0 / (k + rank)
    return sorted(scores, key=lambda i: scores[i], reverse=True)


class RAGEngine:
    def __init__(self, client):
        self.client = client
        self.index = faiss.read_index(FAISS_PATH)
        self.entries = json.load(open(META_PATH, encoding="utf-8"))
        data = pickle.load(open(BM25_PATH, "rb"))
        self.bm25 = data["bm25"]

    def _embed_query(self, query):
        resp = self.client.models.embed_content(
            model=EMBED_MODEL, contents=query
        )
        vec = np.array([resp.embeddings[0].values], dtype="float32")
        faiss.normalize_L2(vec)
        return vec

    def retrieve(self, query):
        """Kembalikan chunk unik teratas hasil fusi FAISS + BM25."""
        # FAISS
        qvec = self._embed_query(query)
        _, faiss_idx = self.index.search(qvec, TOP_FAISS)
        faiss_ranks = [int(i) for i in faiss_idx[0] if i >= 0]

        # BM25
        bm25_scores = self.bm25.get_scores(tokenize(query))
        bm25_ranks = sorted(
            range(len(bm25_scores)),
            key=lambda i: bm25_scores[i], reverse=True
        )[:TOP_BM25]

        # Fusi
        fused = reciprocal_rank_fusion(faiss_ranks, bm25_ranks)

        # Ambil chunk unik: dua entri (EN/ID) bisa menunjuk chunk sama,
        # kita hanya mau satu wakil per chunk.
        seen, contexts = set(), []
        for idx in fused:
            e = self.entries[idx]
            cid = e["chunk_id"]
            if cid in seen:
                continue
            seen.add(cid)
            contexts.append(e)
            if len(contexts) >= TOP_CONTEXT:
                break
        return contexts

    def answer(self, query):
        """Retrieve lalu generate jawaban dengan sitasi."""
        import prompts

        contexts = self.retrieve(query)
        prompt = prompts.build_prompt(query, contexts)

        resp = self.client.models.generate_content(
            model=CHAT_MODEL,
            contents=prompt,
        )

        sources = [
            {
                "technique_id": c["technique_id"],
                "name": c["name"],
                "source_doc": c.get("source_doc"),
                "source_url": c.get("source_url"),
                "sids": c.get("sids", []),
            }
            for c in contexts
        ]
        return {"answer": resp.text.strip(), "sources": sources}


def get_engine():
    """Buat engine dengan client Gemini dari .env. Dipakai oleh main.py."""
    from google import genai
    from dotenv import load_dotenv
    load_dotenv()
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        raise RuntimeError("GEMINI_API_KEY tidak ditemukan di .env")
    return RAGEngine(genai.Client(api_key=key))


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Pemakaian: python corpus\\engine.py \"pertanyaan Anda\"")
        sys.exit(1)
    eng = get_engine()
    result = eng.answer(" ".join(sys.argv[1:]))
    print(result["answer"])
    print("\nSumber:")
    for s in result["sources"]:
        print(f"  - {s['technique_id']} {s['name']} ({s['source_doc']})")
