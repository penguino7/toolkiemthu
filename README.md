# Tool Recon Kiểm Thử Web

Đây là tool recon tổng quát để thu thập endpoint, form, tham số URL/body/JSON và chuẩn hóa tất cả về một schema chung. Tool không hardcode theo một website cụ thể, có thể dùng cho NewsHub lab hoặc các web khác nếu cấu hình đúng `base_url`, `scope` và `seeds`.

## Ý Tưởng

Tool đi theo pipeline:

```text
static crawler
playwright dynamic crawler
HAR importer
manual seed importer
        ↓
normalize
        ↓
enrich
        ↓
dedupe
        ↓
export inventory
```

Mục tiêu là gom dữ liệu từ nhiều nguồn nhưng xuất ra cùng một dạng:

```text
inventory.json
inventory.md
params.txt
```

## Cấu Trúc File

```text
.
├── README.md
├── requirements.txt
├── config.example.json
├── seeds.example.txt
└── recontool/
    ├── __main__.py
    ├── cli.py
    ├── config.py
    ├── models.py
    ├── normalizer.py
    ├── enrich.py
    ├── dedupe.py
    ├── exporters.py
    ├── http_client.py
    ├── scope.py
    ├── crawlers/
    │   ├── static_html.py
    │   └── playwright_dynamic.py
    └── importers/
        ├── har.py
        └── manual_seed.py
```

## Tính Năng Hiện Có

### Static HTML crawler

Không chạy JavaScript. Dùng để lấy:

```text
link <a href>
form action/method
input name
textarea name
select name
query params
status code
response content-type
```

### Playwright dynamic crawler

Chạy browser thật, phù hợp SPA. Dùng để lấy:

```text
fetch/XHR API
route SPA
request sinh ra bởi JavaScript
status code
response content-type
POST body
JSON body
```

Phần này là tùy chọn. Nếu chưa cài Playwright, tool vẫn chạy static/importer bình thường.

### HAR importer

Đọc file `.har` export từ:

```text
Chrome DevTools
Firefox DevTools
Playwright
ZAP
proxy khác có hỗ trợ HAR
```

### Manual seed importer

Đọc danh sách endpoint do bạn tự viết trong file text hoặc JSON. Hữu ích khi crawler không tự thấy endpoint ẩn.

### Normalize

Chuẩn hóa request về schema chung:

```text
method
url
scheme
host
port
path
canonical_path
query params
body params
json params
auth_context
content-type
status
source_tool
```

### Enrich

Suy luận candidate test:

```text
sqli
sqli_json
reflected_xss_candidate
stored_xss_candidate
api_xss_source
form_endpoint
```

### Dedupe

Gom endpoint trùng bằng fingerprint:

```text
method + host + canonical_path + query param names + body param names + content-type + auth_context
```

Ví dụ:

```text
GET /news.php?id=1
GET /news.php?id=2
```

được gom thành:

```text
GET /news.php?id={int}
```

## Cài Đặt

Tool core dùng Python standard library. Cần Python 3.11+.

Kiểm tra:

```bash
python --version
```

Nếu muốn dùng Playwright dynamic crawler:

```bash
pip install -r requirements.txt
python -m playwright install chromium
```

Nếu chỉ dùng static crawler, manual seed và HAR importer thì không cần cài thêm package.

Nếu trên Windows gặp lỗi quyền với `__pycache__`, xóa thư mục cache rồi chạy lại:

```powershell
Get-ChildItem -Recurse -Directory -Filter __pycache__ | Remove-Item -Recurse -Force
```

## Chạy Nhanh Với NewsHub Lab

Giả sử NewsHub đang chạy tại:

```text
http://127.0.0.1:8080
```

### Cách khuyến nghị: chạy một lệnh

Trên Kali/Linux:

```bash
bash run_recon.sh http://127.0.0.1:8080
```

Lệnh trên sẽ tự tạo `.venv` nếu chưa có, đọc `config.example.json`, chạy crawler/importer, dedupe/enrich và xuất kết quả.

Nếu muốn bật dynamic crawler cho SPA:

```bash
bash run_recon.sh http://127.0.0.1:8080 --dynamic
```

Nếu Kali chưa cài Playwright:

```bash
bash run_recon.sh http://127.0.0.1:8080 --dynamic --install-playwright
```

Đổi thư mục output:

```bash
bash run_recon.sh http://127.0.0.1:8080 --out recon-newshub
```

Trên Windows PowerShell:

```powershell
.\run_recon.ps1 -BaseUrl http://127.0.0.1:8080
```

### Cách chạy trực tiếp bằng Python

```bash
python -B -m recontool -c config.example.json
```

Output:

```text
recon-output/inventory.json
recon-output/inventory.md
recon-output/params.txt
```

## Chạy Static Crawler

```bash
python -m recontool \
  --base-url http://127.0.0.1:8080 \
  --seed / \
  --seed /search.php?q=test \
  --seed /spa/search \
  --out recon-output
```

Trên PowerShell có thể viết một dòng:

```powershell
python -m recontool --base-url http://127.0.0.1:8080 --seed / --seed /search.php?q=test --seed /spa/search --out recon-output
```

## Chạy Playwright Dynamic Crawler

Bật trong config:

```json
"dynamic": {
  "enabled": true,
  "max_pages": 30,
  "timeout_ms": 15000,
  "headless": true,
  "storage_state": ""
}
```

Hoặc bật bằng CLI:

```bash
python -m recontool -c config.example.json --dynamic
```

Dynamic crawler sẽ mở browser thật, vào seed URL, bắt request/response sinh ra bởi JavaScript rồi normalize thành endpoint record.

## Import HAR

Export HAR từ DevTools hoặc proxy, sau đó:

```bash
python -m recontool \
  --base-url http://127.0.0.1:8080 \
  --har traffic.har \
  --no-static
```

Hoặc cấu hình trong `config.example.json`:

```json
"imports": {
  "har_files": ["traffic.har"],
  "manual_seed_files": []
}
```

## Import Manual Seed

File text:

```text
GET http://127.0.0.1:8080/search.php?q=test
GET http://127.0.0.1:8080/api/spa/news.php?id=1
POST http://127.0.0.1:8080/api/spa/comment_add.php news_id=1&author_name=manual&content=hello
```

Chạy:

```bash
python -m recontool --manual seeds.example.txt --no-static
```

## Config Quan Trọng

### base_url

Target chính:

```json
"base_url": "http://127.0.0.1:8080"
```

### scope

Giới hạn host/path được crawl:

```json
"scope": {
  "include_hosts": ["127.0.0.1", "localhost"],
  "exclude_paths": ["/user/logout.php"]
}
```

### seeds

URL khởi đầu:

```json
"seeds": [
  "/",
  "/search.php?q=test",
  "/spa/search"
]
```

### auth_context

Đánh dấu context:

```json
"auth_context": "anonymous"
```

Khi crawl bằng session admin, đổi thành:

```json
"auth_context": "admin"
```

## Authenticated Crawl

Bản hiện tại chưa tự login form. Có 2 cách thực tế:

### Cách 1: Playwright storage_state

Tạo storage state bằng Playwright riêng, rồi cấu hình:

```json
"dynamic": {
  "enabled": true,
  "storage_state": "admin-state.json"
}
```

### Cách 2: Dùng HAR/Burp/ZAP

Đăng nhập thủ công bằng browser/proxy, export HAR hoặc traffic history, rồi import vào tool.

## Output Schema Rút Gọn

Mỗi endpoint record có dạng:

```json
{
  "method": "GET",
  "url": "http://127.0.0.1:8080/search.php?q=test",
  "scheme": "http",
  "host": "127.0.0.1",
  "port": 8080,
  "path": "/search.php",
  "canonical_path": "/search.php",
  "auth_context": "anonymous",
  "response_content_type": "text/html",
  "statuses": [200],
  "params": [
    {
      "name": "q",
      "location": "query",
      "type_hint": "string",
      "sample_values": ["test"],
      "reflected": true,
      "candidate_tests": ["reflected_xss_candidate", "sqli"]
    }
  ],
  "source_tools": ["static_html_crawler"],
  "candidate_tests": ["reflected_xss_candidate", "sqli"]
}
```

## Dedupe Mode

Strict:

```bash
python -m recontool -c config.example.json --dedupe-mode strict
```

Smart:

```bash
python -m recontool -c config.example.json --dedupe-mode smart
```

Khác biệt:

```text
strict: ít gom nhầm hơn
smart: gom /news/1 và /news/2 thành /news/{int}
```

## Gợi Ý Workflow

1. Chạy static crawler trước.
2. Chạy dynamic crawler nếu web có SPA/JS.
3. Import HAR từ browser/proxy nếu có.
4. Thêm manual seed cho endpoint ẩn.
5. Xem `inventory.md`.
6. Dùng `params.txt` để lên test plan XSS/SQLi.

## Giới Hạn Hiện Tại

- Chưa tự login form.
- Chưa tự submit form để tránh gây thay đổi dữ liệu ngoài ý muốn.
- Chưa có active scanner XSS/SQLi, mới dừng ở recon và gợi ý candidate tests.
- Burp/ZAP importer riêng chưa có, ưu tiên HAR importer trước vì dễ dùng chung.

## Kiểm Tra Cú Pháp

```bash
python -m compileall recontool
```

Kiểm tra nhanh không cần target đang chạy:

```bash
python -B -m recontool --manual seeds.example.txt --no-static --out test-output
```

Nếu chạy đúng sẽ sinh ra:

```text
test-output/inventory.json
test-output/inventory.md
test-output/params.txt
```
