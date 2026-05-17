# Tool Recon Kiểm Thử Web

Tool này chỉ tập trung vào **recon web**: thu thập endpoint, form, URL param, body param, JSON param, request SPA/API và chuẩn hóa chúng về một schema chung. Tool không scan tự động, không gửi giá trị kiểm thử và không cố chứng minh lỗ hổng.

Code đã được tổ chức lại theo OOP để dễ đọc hơn:

```text
crawl/import -> normalize -> enrich metadata -> dedupe -> export
```

## Chức Năng Chính

### Static Crawl

Đọc HTML không chạy JavaScript để lấy:

```text
link <a href>
form action/method
input/textarea/select name
URL param
status code
response content-type
```

### Dynamic Crawl Cho SPA

Dùng Playwright để chạy browser thật và bắt request do JavaScript sinh ra:

```text
route SPA
fetch/XHR API endpoint
POST body nếu browser gửi
JSON response content-type
status code
```

Ví dụ browser vào:

```text
/spa/search?q=AI
```

nhưng JavaScript gọi:

```text
GET /api/spa/search.php?q=AI
```

thì dynamic crawler có thể ghi nhận API này.

### Auth Profile

Hỗ trợ crawl theo context:

```text
anonymous
admin
user
```

Nếu cấu hình form login, tool đăng nhập để nhìn thấy endpoint sau đăng nhập. Đây vẫn là recon, không phải kiểm thử lỗ hổng.

### Normalize, Enrich, Dedupe

Mọi dữ liệu được đưa về `EndpointRecord`, sau đó:

```text
normalize   chuẩn hóa URL, param, body, JSON, content-type
enrich      gắn nhãn candidate như sqli/reflected_xss_candidate
dedupe      gom endpoint trùng
export      sinh inventory và test_plan
```

`candidate_tests` chỉ là gợi ý recon, không phải kết luận có lỗ hổng.

## Cấu Trúc File

```text
.
├── README.md
├── config.example.json
├── requirements.txt
├── run_recon.sh
├── seeds.example.txt
└── recontool/
    ├── __main__.py
    ├── auth.py
    ├── cli.py
    ├── config.py
    ├── dedupe.py
    ├── enrich.py
    ├── exporters.py
    ├── http_client.py
    ├── models.py
    ├── normalizer.py
    ├── scope.py
    ├── crawlers/
    │   ├── playwright_dynamic.py
    │   └── static_html.py
    └── importers/
        ├── har.py
        └── manual_seed.py
```

## Class Chính Theo Từng File

`cli.py`

- `CliArgumentParser`: tạo command-line options.
- `ReconApplication`: điều phối toàn pipeline từ load config đến export.

`config.py`

- `ConfigLoader`: đọc `config.example.json` và merge với config mặc định.

`models.py`

- `Param`: mô tả một tham số như `query:q`, `body:content`, `json:user.id`.
- `EndpointRecord`: object trung tâm đại diện cho một endpoint đã chuẩn hóa.

`normalizer.py`

- `ReconNormalizer`: chuẩn hóa URL, suy luận type, parse query/body/JSON và tạo `EndpointRecord`.

`scope.py`

- `ScopePolicy`: quyết định URL nào được phép crawl theo `include_hosts` và `exclude_paths`.

`http_client.py`

- `HttpResult`: kết quả HTTP rút gọn.
- `ResponseDecoder`: giải mã response text theo content-type.
- `HttpSession`: HTTP client có cookie jar, dùng cho static crawl và auth.

`auth.py`

- `AuthManager`: chọn auth profile, tạo session và login form cơ bản.

`crawlers/static_html.py`

- `HtmlDiscoveryParser`: parse link/form/input từ HTML.
- `StaticHtmlCrawler`: crawl HTML tĩnh và tạo `EndpointRecord`.

`crawlers/playwright_dynamic.py`

- `DynamicCrawler`: chạy Playwright, bắt request/response SPA/API và tạo `EndpointRecord`.

`importers/manual_seed.py`

- `ManualSeedImporter`: đọc endpoint do bạn tự ghi trong file text/JSON.

`importers/har.py`

- `HarImporter`: đọc HAR file và chuyển request thành `EndpointRecord`.

`enrich.py`

- `RecordEnricher`: gắn nhãn candidate XSS/SQLi dựa trên metadata đã quan sát được.

`dedupe.py`

- `EndpointDeduplicator`: gom endpoint trùng theo fingerprint.

`exporters.py`

- `ReconExporter`: xuất `inventory.json`, `inventory.md`, `params.txt`, `test_plan.md`.

## Chạy Trên Kali/Linux

Giả sử lab chạy tại:

```text
http://127.0.0.1:8080
```

Chạy recon tĩnh:

```bash
bash run_recon.sh http://127.0.0.1:8080
```

Chạy thêm dynamic crawler cho SPA/API:

```bash
bash run_recon.sh http://127.0.0.1:8080 --dynamic
```

Cài Playwright nếu Kali chưa có:

```bash
bash run_recon.sh http://127.0.0.1:8080 --dynamic --install-playwright
```

Đổi thư mục output:

```bash
bash run_recon.sh http://127.0.0.1:8080 --out recon-newshub
```

## Output

```text
inventory.json  dữ liệu đầy đủ cho tool khác đọc tiếp
inventory.md    bảng endpoint dễ đọc
params.txt      danh sách param ngắn gọn
test_plan.md    nhóm candidate XSS/SQLi để test thủ công sau
```

## Cấu Hình Quan Trọng

### Scope

```json
"scope": {
  "include_hosts": ["127.0.0.1", "localhost"],
  "exclude_paths": ["/user/logout.php"]
}
```

### Seeds

```json
"seeds": [
  "/",
  "/search.php?q=test",
  "/news.php?id=1",
  "/spa/search",
  "/spa/article/1"
]
```

### Auth Profiles

Mặc định chỉ crawl anonymous:

```json
"auth_profiles": [
  {
    "name": "anonymous",
    "type": "none",
    "enabled": true
  }
]
```

Nếu muốn recon sau đăng nhập, bật profile admin và sửa đúng thông tin form:

```json
{
  "name": "admin",
  "type": "form",
  "enabled": true,
  "login_url": "/user/login.php",
  "method": "POST",
  "data": {
    "username": "admin",
    "password": "admin123"
  },
  "success_check": {
    "url": "/admin/index.php",
    "contains": "admin"
  }
}
```

Chỉ chạy một profile:

```bash
python -B -m recontool -c config.example.json --auth-profile admin
```

### Dynamic Crawler

```json
"dynamic": {
  "enabled": false,
  "max_pages": 30,
  "timeout_ms": 15000,
  "headless": true,
  "storage_state": "",
  "click_selectors": [],
  "max_clicks_per_page": 0
}
```

Nếu SPA cần click tab/nút mới sinh API:

```json
"click_selectors": ["button[data-load]", ".tab-comments"],
"max_clicks_per_page": 3
```

## Kiểm Tra Nhanh Không Cần Target

```bash
python -B -m recontool --manual seeds.example.txt --no-static --out test-output
```

Kiểm tra cú pháp không ghi cache:

```bash
python - <<'PY'
from pathlib import Path
import ast
for path in Path("recontool").rglob("*.py"):
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
print("AST syntax check passed")
PY
```

## Giới Hạn Hiện Tại

- Không scan tự động.
- Không gửi giá trị kiểm thử.
- Không tự chứng minh XSS/SQLi.
- Dynamic crawler chỉ click selector được cấu hình.
- Importer mở rộng cho Burp/ZAP riêng chưa làm trong giai đoạn này.
