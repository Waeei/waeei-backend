# data/extract_urls_improved.py
import json, re, pathlib, sys

INPUT = pathlib.Path("data/malicious-urls.ipynb")
OUTPUT = pathlib.Path("data/malicious_urls.txt")
url_re = re.compile(r"https?://[^\s\"'\\<>]+", re.IGNORECASE)

def gather_strings(obj):
    """Recursively collect all string values from a JSON-like structure."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from gather_strings(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from gather_strings(item)
    # ignore other types

# quick sanity checks
if not INPUT.exists():
    print(f"ERROR: Input file not found: {INPUT}", file=sys.stderr)
    sys.exit(2)

text = INPUT.read_text(encoding="utf-8", errors="replace")
# detect HTML (common error when raw url wrong)
if text.lstrip().startswith("<") and ("<!doctype html" in text.lower() or "<html" in text.lower()):
    print("WARNING: The downloaded file looks like an HTML page, not a raw .ipynb JSON. Check the RAW URL you used.", file=sys.stderr)

try:
    nb = json.loads(text)
except Exception as e:
    print("WARNING: Failed to parse JSON from .ipynb file:", e, file=sys.stderr)
    # fallback: search the raw text for URLs
    urls = set(re.findall(url_re, text))
else:
    urls = set()
    # search all strings recursively
    for s in gather_strings(nb):
        for u in url_re.findall(s):
            urls.add(u.strip())

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
with open(OUTPUT, "w", encoding="utf-8") as out:
    for u in sorted(urls):
        out.write(u + "\n")

print(f"Extracted {len(urls)} URLs to {OUTPUT}")
if len(urls) == 0:
    print("Tip: If 0, open the file 'data\\malicious-urls.ipynb' in a text editor and check whether it begins with '{' (JSON) or '<' (HTML).", file=sys.stderr)
