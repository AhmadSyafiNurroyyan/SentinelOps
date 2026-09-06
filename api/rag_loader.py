import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "corpus")


def load_engine():
    if CORPUS not in sys.path:
        sys.path.insert(0, CORPUS)
    import engine  
    return engine.get_engine()
