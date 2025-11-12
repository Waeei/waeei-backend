# data/import_to_sqlite.py
import sqlite3, os
DB = "data/malicious_urls.db"
TXT = "data/malicious_urls.txt"
os.makedirs("data", exist_ok=True)
conn = sqlite3.connect(DB)
conn.execute("""CREATE TABLE IF NOT EXISTS malicious_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE,
    domain TEXT,
    source TEXT,
    added_at TEXT DEFAULT (datetime('now'))
)""")
with open(TXT, encoding="utf-8") as f:
    for line in f:
        url = line.strip()
        if not url:
            continue
        domain = url.split("://")[-1].split("/")[0]
        conn.execute("INSERT OR IGNORE INTO malicious_urls(url,domain,source) VALUES(?,?,?)",
                     (url, domain, "github"))
conn.commit()
conn.close()
print("✅ Imported URLs into database")
