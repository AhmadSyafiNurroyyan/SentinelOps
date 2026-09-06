import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TECH_PATH = os.path.join(HERE, "attack_techniques.json")
SID_PATH = os.path.join(HERE, "sid_mapping.json")
OUT_PATH = os.path.join(HERE, "chunks.json")
CACHE_PATH = os.path.join(HERE, ".summary_cache.json")

SUMMARY_MODEL = "gemini-2.5-flash"

def load_json(path):
    if not os.path.exists(path):
        print(f"[gagal] Tidak ada {path}", file=sys.stderr)
        sys.exit(1)
    return json.load(open(path, encoding="utf-8"))

def load_cache():
    if os.path.exists(CACHE_PATH):
        return json.load(open(CACHE_PATH, encoding="utf-8"))
    return {}

def save_cache(cache):
    json.dump(cache, open(CACHE_PATH, "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)

def build_english_text(tech, sids):
    parts = [f"{tech['name']} ({tech['technique_id']}).", tech["description"]]

    if tech.get("mitigations"):
        mit = "; ".join(m["name"] for m in tech["mitigations"])
        parts.append(f"Mitigations: {mit}.")

    if tech.get("detections"):
        parts.append("Detection: " + tech["detections"][0])

    if sids:
        sid_list = ", ".join(
            f"SID {s['sid']} ({s['signature']})" for s in sids
        )
        parts.append(f"Related detection signatures: {sid_list}.")

    return " ".join(parts)

def summarize_id(client, text, technique_name):
    prompt = (
        "Ringkas teks keamanan siber berikut ke dalam Bahasa Indonesia yang "
        "jelas, 2 sampai 3 kalimat, untuk staf IT sekolah yang bukan ahli "
        "keamanan. Jelaskan apa itu, kenapa berbahaya, dan tanda-tandanya. "
        "Jangan menambah informasi di luar teks. Pertahankan istilah teknis "
        "penting (seperti port scan, brute force) namun beri konteks singkat.\n\n"
        f"Judul: {technique_name}\n\nTeks:\n{text}"
    )
    resp = client.models.generate_content(
        model=SUMMARY_MODEL,
        contents=prompt,
    )
    return resp.text.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true",
                        help="Jangan panggil API, pakai placeholder ringkasan")
    args = parser.parse_args()

    techniques = load_json(TECH_PATH)
    sid_mapping = load_json(SID_PATH)
    cache = load_cache()

    sids_by_tech = {}
    for s in sid_mapping:
        tid = s.get("technique_id")
        if tid:
            sids_by_tech.setdefault(tid, []).append(s)

    client = None
    if not args.dry_run:
        from google import genai
        from dotenv import load_dotenv
        load_dotenv()
        key = os.getenv("GEMINI_API_KEY")
        if not key:
            print("[gagal] GEMINI_API_KEY tidak ditemukan di .env", file=sys.stderr)
            sys.exit(1)
        client = genai.Client(api_key=key)

    chunks = []
    api_calls = 0

    for tech in techniques:
        tid = tech["technique_id"]
        sids = sids_by_tech.get(tid, [])
        text_en = build_english_text(tech, sids)

        if text_en in cache:
            text_id = cache[text_en]
            source = "cache"
        elif args.dry_run:
            text_id = f"[DRY-RUN] Ringkasan Indonesia untuk {tech['name']} belum dibuat."
            source = "dry-run"
        else:
            text_id = summarize_id(client, text_en, tech["name"])
            cache[text_en] = text_id
            save_cache(cache)
            api_calls += 1
            source = "api"
            time.sleep(1.5)  

        chunk = {
            "chunk_id": f"tech_{tid.lower()}",
            "technique_id": tid,
            "name": tech["name"],
            "tactics": tech.get("tactics", []),
            "sids": [s["sid"] for s in sids],
            "text": text_en,
            "text_id": text_id,
            "source_doc": tech.get("source_doc"),
            "source_url": tech.get("source_url"),
        }
        chunks.append(chunk)
        print(f"  [{source:8}] {tid:<8} {tech['name'][:40]}")

    json.dump(chunks, open(OUT_PATH, "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)

    print()
    print(f"[ok]    {len(chunks)} chunk tersimpan di {OUT_PATH}")
    print(f"[ok]    {api_calls} panggilan API baru, sisanya dari cache")
    if args.dry_run:
        print("[catat] Mode dry-run: text_id masih placeholder.")
        print("        Jalankan tanpa --dry-run untuk ringkasan sungguhan.")


if __name__ == "__main__":
    main()
