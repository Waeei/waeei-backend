 


import json, re, pathlib

INPUT = pathlib.Path("data/malicious-urls.ipynb")
OUTPUT = pathlib.Path("data/malicious_urls.txt")

url_re = re.compile(r"https?://[^\s\"'\\<>]+", re.IGNORECASE)

with open(INPUT, "r", encoding="utf-8") as f:
    nb = json.load(f)

urls = set()
for cell in nb.get("cells", []):
    for src in cell.get("source", []):
        for u in url_re.findall(src):
            urls.add(u.strip())

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
with open(OUTPUT, "w", encoding="utf-8") as out:
    for u in sorted(urls):
        out.write(u + "\n")

print(f"Extracted {len(urls)} URLs to {OUTPUT}")
