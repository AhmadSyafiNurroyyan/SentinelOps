from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_DIR = REPO_ROOT / "corpus"
RAW_DIR = CORPUS_DIR / "raw"
ET_RULES_PATH = RAW_DIR / "suricata.rules"
ATTACK_OUTPUT = CORPUS_DIR / "attack_techniques.json"
SID_MAPPING = CORPUS_DIR / "sid_mapping.json"
CHUNKS_OUTPUT = CORPUS_DIR / "chunks.json"
FAISS_DIR = REPO_ROOT / "faiss_index"
BM25_OUTPUT = REPO_ROOT / "bm25_index.pkl"


def run_step(label: str, script: Path, extra_args: list[str] | None = None) -> None:
    command = [sys.executable, str(script)]
    if extra_args:
        command.extend(extra_args)

    print(f"[step] {label}")
    print("       " + " ".join(command))

    subprocess.run(command, cwd=REPO_ROOT, check=True)


def require_file(path: Path, description: str) -> None:
    if not path.exists():
        raise FileNotFoundError(
            f"{description} tidak ditemukan: {path}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Siapkan dependency/data hasil generate untuk pipeline RAG SentinelOps."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Bangun corpus tanpa memanggil Gemini untuk ringkasan Bahasa Indonesia. "
            "Cocok untuk pengecekan pipeline; jangan dipakai sebagai corpus final."
        ),
    )
    parser.add_argument(
        "--skip-et",
        action="store_true",
        help="Lewati parsing Emerging Threats rules (corpus/raw/suricata.rules).",
    )
    parser.add_argument(
        "--skip-index",
        action="store_true",
        help="Jangan membangun FAISS/BM25 index.",
    )
    parser.add_argument(
        "--require-et",
        action="store_true",
        help=(
            "Gagal bila corpus/raw/suricata.rules belum tersedia. "
            "Tanpa flag ini, parsing ET akan dilewati bila file belum ada."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not (REPO_ROOT / ".git").exists():
        raise RuntimeError(
            "Repository root tidak terdeteksi. Jalankan script dari clone repo "
            "SentinelOps yang memiliki folder .git."
        )

    attack_script = CORPUS_DIR / "build_attack.py"
    et_script = CORPUS_DIR / "parse_et_rules.py"
    corpus_script = CORPUS_DIR / "build_corpus.py"
    indexer_script = CORPUS_DIR / "indexer.py"

    for script in (attack_script, et_script, corpus_script, indexer_script):
        if not script.exists():
            raise FileNotFoundError(f"Script pipeline tidak ditemukan: {script}")

    print("SentinelOps data setup")
    print(f"Repository : {REPO_ROOT}")
    print(f"Python     : {sys.executable}")
    print()
    print("Catatan:")
    print("- Bundle ATT&CK mentah disimpan di corpus/raw/ dan tidak di-commit.")
    print("- eve.json adalah output runtime Suricata dan tidak dibuat oleh script ini.")
    print("- FAISS/BM25 adalah generated artifacts dan tidak di-commit.")

    # 1) MITRE ATT&CK: build_attack.py menangani download + extraction sendiri.
    run_step("MITRE ATT&CK: download + extraction", attack_script)
    require_file(ATTACK_OUTPUT, "Hasil ekstraksi ATT&CK")

    # 2) Emerging Threats: parse jika rule mentah tersedia.
    if args.skip_et:
        print("\n[skip] Parsing Emerging Threats dinonaktifkan dengan --skip-et")
    elif not ET_RULES_PATH.exists():
        message = (
            "[warn] corpus/raw/suricata.rules belum ada. Parsing Emerging Threats "
            "dilewati. Letakkan ruleset pada path tersebut lalu jalankan ulang."
        )
        if args.require_et:
            raise FileNotFoundError(message)
        print("\n" + message)
    else:
        run_step("Emerging Threats: parse Suricata rules", et_script)

    require_file(
        SID_MAPPING,
        "sid_mapping.json (mapping SID hasil lab). "
        "Pastikan file ini sudah tersedia sebelum build corpus.",
    )

    # 3) Build bilingual RAG chunks.
    corpus_args = ["--dry-run"] if args.dry_run else []
    run_step("RAG corpus: build chunks.json", corpus_script, corpus_args)
    require_file(CHUNKS_OUTPUT, "Hasil RAG corpus")

    # 4) Build vector + keyword retrieval indexes.
    if args.skip_index:
        print("\n[skip] Pembangunan FAISS/BM25 dinonaktifkan dengan --skip-index")
    else:
        if args.dry_run:
            print(
                "\n[warn] --dry-run hanya berlaku untuk build_corpus.py. "
                "Indexing tetap memerlukan GEMINI_API_KEY karena embeddings memakai Gemini."
            )
        run_step("Retrieval index: FAISS + BM25", indexer_script)
        require_file(FAISS_DIR / "index.faiss", "FAISS index")
        require_file(FAISS_DIR / "meta.json", "FAISS metadata")
        require_file(BM25_OUTPUT, "BM25 index")

    print()
    print("[ok] SentinelOps data setup selesai.")
    print()
    print("Tracked / repository data:")
    print(f"  - {ATTACK_OUTPUT.relative_to(REPO_ROOT)}")
    print(f"  - {SID_MAPPING.relative_to(REPO_ROOT)}")
    print(f"  - {CHUNKS_OUTPUT.relative_to(REPO_ROOT)}")
    print()
    print("Generated / local-only data:")
    print(f"  - {RAW_DIR.relative_to(REPO_ROOT)}/")
    if not args.skip_index:
        print(f"  - {FAISS_DIR.relative_to(REPO_ROOT)}/")
        print(f"  - {BM25_OUTPUT.relative_to(REPO_ROOT)}")
    print()
    print("Berikutnya: jalankan FastAPI dan agent sesuai dokumentasi project.")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        print(
            f"\n[gagal] Pipeline berhenti karena command gagal (exit code {exc.returncode}).",
            file=sys.stderr,
        )
        raise SystemExit(exc.returncode) from exc
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"\n[gagal] {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
