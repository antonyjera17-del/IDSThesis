import requests
import csv

# modify base URL if running elsewhere
BASE = "http://127.0.0.1:5000"

# small list of sample URLs
urls = [
    "https://www.google.com/search?q=hello",
    "http://example.com/index.php?id=1' OR '1'='1",
    "http://test.local/login?user=<script>alert(1)</script>",
    "http://localhost/test?param=1; DROP TABLE users;",
]

# create CSV
with open("test_urls.csv", "w", newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["url"])
    for u in urls:
        writer.writerow([u])

# POST CSV to bulk_test
with open("test_urls.csv", "rb") as f:
    r = requests.post(f"{BASE}/bulk_test", files={"file": ("test_urls.csv", f, "text/csv")})
    print("Status:", r.status_code)
    print(r.text[:1000])
