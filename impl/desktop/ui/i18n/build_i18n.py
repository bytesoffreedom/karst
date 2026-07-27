#!/usr/bin/env python3
"""Inject the desktop UI translation table into index.html.

The KARST desktop (Tauri) frontend is a single static index.html. Its interface strings
live here as a plain, reviewable JSON table (strings.json) rather than trapped inside the
minified `const I18N=…` line in the page. This is deliberately NOT a build-time codegen
step — it's a maintenance helper: edit strings.json, run this once, commit the result.

  strings.json  — canonical table: English key -> {en,ru,es,pt,de,fr,zh,ja,id}.
                  Human-reviewed translations are reused verbatim from the egui client's
                  i18n (impl/gui/src/i18n.rs); the desktop-specific gaps are machine-assisted
                  and flagged for native-speaker review. This table MIRRORS gui/src/i18n.rs
                  and is the hand-sync point between the two frontends.

Language order matches the page's <select> options: en, ru, es, pt, de, fr, zh, ja, id.

Usage:
    python3 desktop/ui/i18n/build_i18n.py          # rewrites the const I18N=… line in index.html
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
STRINGS = os.path.join(HERE, "strings.json")
HTML = os.path.normpath(os.path.join(HERE, "..", "index.html"))

def main():
    table = json.load(open(STRINGS, encoding="utf-8"))
    # t() falls back to the English key, so the 'en' column is redundant in the page payload.
    payload = {k: {c: v for c, v in row.items() if c != "en"} for k, row in table.items()}
    compact = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    lines = open(HTML, encoding="utf-8").read().splitlines(keepends=True)
    n = 0
    for i, l in enumerate(lines):
        if l.startswith("const I18N="):
            lines[i] = "const I18N=" + compact + ";\n"
            n += 1
    if n != 1:
        sys.exit(f"expected exactly one `const I18N=` line in index.html, found {n}")
    open(HTML, "w", encoding="utf-8").write("".join(lines))
    print(f"injected {len(payload)} strings into {HTML}")

if __name__ == "__main__":
    main()
