"""
Parser Emerging Threats Open ruleset untuk SentinelOps.

Jalankan dari root repo:
    python corpus/parse_et_rules.py

Input:
    corpus/raw/suricata.rules
Output:
    corpus/et_rules.json

Yang diekstrak per rule: sid, rev, msg, classtype, protocol, arah,
reference, dan technique_id MITRE bila rule-nya mencantumkan metadata.

Catatan: tidak semua rule ET Open punya metadata MITRE. Cakupannya
parsial, dan itu wajar. SID yang tidak terpetakan otomatis dipetakan
manual belakangan (jumlahnya sedikit untuk skenario lab kita).
"""

import json
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
IN_PATH = os.path.join(HERE, "raw", "suricata.rules")
OUT_PATH = os.path.join(HERE, "et_rules.json")

# Header rule: action proto src sport arah dst dport
RE_HEADER = re.compile(
    r"^(?P<action>alert|drop|pass|reject)\s+"
    r"(?P<proto>\S+)\s+"
    r"(?P<src>\S+)\s+(?P<sport>\S+)\s+"
    r"(?P<dir><>|->)\s+"
    r"(?P<dst>\S+)\s+(?P<dport>\S+)\s*\("
)

# msg boleh mengandung karakter yang di-escape, jadi jangan pakai [^"]*
RE_MSG = re.compile(r'\bmsg\s*:\s*"((?:[^"\\]|\\.)*)"')
RE_SID = re.compile(r"\bsid\s*:\s*(\d+)")
RE_REV = re.compile(r"\brev\s*:\s*(\d+)")
RE_CLASSTYPE = re.compile(r"\bclasstype\s*:\s*([\w\-]+)")
RE_REFERENCE = re.compile(r"\breference\s*:\s*([^;]+);")
RE_METADATA = re.compile(r"\bmetadata\s*:\s*([^;]+);")


def join_continuations(lines):
    """
    Rule ET boleh dipecah beberapa baris dengan backslash di ujung.
    Gabungkan dulu sebelum di-parse, kalau tidak rule panjang akan
    terbaca terpotong dan sid-nya hilang.
    """
    buffer = ""
    for raw in lines:
        line = raw.rstrip("\n")
        if line.rstrip().endswith("\\"):
            buffer += line.rstrip()[:-1].rstrip() + " "
            continue
        yield buffer + line
        buffer = ""
    if buffer:
        yield buffer


def parse_metadata(text):
    """
    Format: 'created_at 2010_07_30, mitre_technique_id T1046, ...'
    Dipisah koma, lalu kata pertama jadi kunci, sisanya jadi nilai.
    """
    out = {}
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        parts = item.split(None, 1)
        if len(parts) == 2:
            out[parts[0]] = parts[1].strip()
    return out


def parse_rule(line):
    header = RE_HEADER.match(line)
    if not header:
        return None

    sid = RE_SID.search(line)
    if not sid:
        return None  # rule tanpa sid tidak berguna untuk kita

    msg = RE_MSG.search(line)
    rev = RE_REV.search(line)
    classtype = RE_CLASSTYPE.search(line)

    references = []
    for ref in RE_REFERENCE.findall(line):
        ref = ref.strip()
        if "," in ref:
            kind, value = ref.split(",", 1)
            references.append({"type": kind.strip(), "value": value.strip()})
        else:
            references.append({"type": "unknown", "value": ref})

    meta = {}
    for chunk in RE_METADATA.findall(line):
        meta.update(parse_metadata(chunk))

    technique = meta.get("mitre_technique_id")
    if technique:
        technique = technique.strip().upper()

    return {
        "sid": int(sid.group(1)),
        "rev": int(rev.group(1)) if rev else None,
        "msg": msg.group(1) if msg else None,
        "classtype": classtype.group(1) if classtype else None,
        "protocol": header.group("proto"),
        "direction": header.group("dir"),
        "src": header.group("src"),
        "dst": header.group("dst"),
        "dst_port": header.group("dport"),
        "references": references,
        "technique_id": technique,
        "tactic_id": meta.get("mitre_tactic_id"),
        "tactic_name": (meta.get("mitre_tactic_name") or "").replace("_", " ") or None,
        "source_doc": "Emerging Threats Open ruleset",
    }


def main():
    if not os.path.exists(IN_PATH):
        print(f"[gagal] Tidak ada {IN_PATH}", file=sys.stderr)
        print("        Minta file /var/lib/suricata/rules/suricata.rules dari VM Ryan,", file=sys.stderr)
        print("        atau unduh ET Open sementara sebagai pengganti.", file=sys.stderr)
        sys.exit(1)

    with open(IN_PATH, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    total_lines = len(lines)
    rules = []
    skipped_comment = 0
    unparsed = 0

    for line in join_continuations(lines):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            skipped_comment += 1
            continue
        parsed = parse_rule(stripped)
        if parsed:
            rules.append(parsed)
        else:
            unparsed += 1

    # SID unik, ambil rev tertinggi bila ada duplikat
    by_sid = {}
    for r in rules:
        prev = by_sid.get(r["sid"])
        if prev is None or (r["rev"] or 0) > (prev["rev"] or 0):
            by_sid[r["sid"]] = r
    rules = sorted(by_sid.values(), key=lambda r: r["sid"])

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(rules, f, ensure_ascii=False, indent=2)

    with_technique = [r for r in rules if r["technique_id"]]

    print(f"[baca]  {total_lines:,} baris, {skipped_comment:,} komentar/nonaktif dilewati")
    if unparsed:
        print(f"[catat] {unparsed:,} baris tidak dikenali sebagai rule")
    print(f"[ok]    {len(rules):,} rule unik tersimpan di {OUT_PATH}")
    print(f"[ok]    {len(with_technique):,} rule punya metadata MITRE "
          f"({len(with_technique) / max(len(rules), 1) * 100:.1f}%)")

    if with_technique:
        print()
        print("Technique terbanyak:")
        for tid, n in Counter(r["technique_id"] for r in with_technique).most_common(10):
            print(f"  {tid:<12} {n:,} rule")

    print()
    print("Classtype terbanyak:")
    for ct, n in Counter(r["classtype"] for r in rules if r["classtype"]).most_common(5):
        print(f"  {ct:<28} {n:,}")


if __name__ == "__main__":
    main()
