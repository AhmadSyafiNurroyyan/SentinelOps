"""
Jembatan pemuatan engine RAG untuk API.

engine.py hidup di folder corpus/ dan memakai path relatif ke root repo
untuk menemukan faiss_index/ dan bm25_index.pkl. Modul ini menambahkan
corpus/ ke sys.path lalu memuat engine, supaya main.py cukup memanggil
load_engine() tanpa tahu detail lokasi.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "corpus")


def load_engine():
    if CORPUS not in sys.path:
        sys.path.insert(0, CORPUS)
    import engine  # noqa: berada di corpus/
    return engine.get_engine()
