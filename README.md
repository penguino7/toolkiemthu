# Tool Kiểm Thử Web

Repo này gồm hai tool tách riêng nhưng dùng chung một luồng làm việc:

```text
recontool/  thu thập endpoint, form, param, SPA/API và xuất inventory
fuzztool/   đọc inventory từ recontool để kiểm thử XSS/SQLi có kiểm soát
```

Luồng sử dụng chính:

```text
recontool -> recon-output/inventory.json -> fuzztool -> fuzz-output/findings.json
```

`recontool` chỉ làm recon, không gửi giá trị kiểm thử. `fuzztool` mới là phần gửi payload/marker kiểm thử, có `--dry-run`, giới hạn scope, giới hạn request và mặc định không fuzz POST/body/json nếu chưa bật `--include-post`.

## Cài Đặt Trên Kali/Linux

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Nếu dùng dynamic crawler hoặc DOM XSS scanner:

```bash
python -m playwright install chromium
```

Nếu Kali thiếu thư viện hệ thống cho Chromium:

```bash
python -m playwright install-deps chromium
```

## Chạy Recon

Giả sử lab chạy tại:

```text
http://127.0.0.1:8080
```

Chạy static recon:

```bash
bash run_recon.sh http://127.0.0.1:8080
```

Chạy cả static và dynamic recon:

```bash
bash run_recon.sh http://127.0.0.1:8080 --dynamic
```

Cài Playwright trong lúc chạy nếu chưa cài:

```bash
bash run_recon.sh http://127.0.0.1:8080 --dynamic --install-playwright
```

Output recon:

```text
recon-output/inventory.json
recon-output/inventory.md
recon-output/params.txt
recon-output/test_plan.md
```

## Chạy Fuzz

Fuzztool đọc file `inventory.json` sinh bởi recontool.

Xem target trước, không gửi request:

```bash
bash run_fuzz.sh recon-output/inventory.json --xss --sqli --dry-run
```

Chạy XSS:

```bash
bash run_fuzz.sh recon-output/inventory.json --xss
```

Chạy SQLi:

```bash
bash run_fuzz.sh recon-output/inventory.json --sqli
```

Chạy cả XSS và SQLi:

```bash
bash run_fuzz.sh recon-output/inventory.json --xss --sqli
```

Cho phép fuzz POST body/json:

```bash
bash run_fuzz.sh recon-output/inventory.json --xss --sqli --include-post
```

Giới hạn số request:

```bash
bash run_fuzz.sh recon-output/inventory.json --xss --sqli --max-requests 50
```

Output fuzz:

```text
fuzz-output/findings.json
fuzz-output/findings.md
```

## Cấu Trúc Repo

```text
.
├── README.md
├── RECON_FLOW.md
├── config.example.json
├── fuzz.config.example.json
├── requirements.txt
├── run_recon.sh
├── run_fuzz.sh
├── seeds.example.txt
├── recontool/
│   ├── __main__.py
│   ├── auth.py
│   ├── cli.py
│   ├── config.py
│   ├── dedupe.py
│   ├── enrich.py
│   ├── exporters.py
│   ├── http_client.py
│   ├── models.py
│   ├── normalizer.py
│   ├── scope.py
│   ├── crawlers/
│   │   ├── playwright_dynamic.py
│   │   └── static_html.py
│   └── importers/
│       ├── har.py
│       └── manual_seed.py
└── fuzztool/
    ├── __main__.py
    ├── cli.py
    ├── config.py
    ├── http_client.py
    ├── inventory_loader.py
    ├── models.py
    ├── mutator.py
    ├── reporter.py
    └── plugins/
        ├── xss/
        │   ├── runner.py
        │   ├── reflected.py
        │   ├── stored.py
        │   ├── dom.py
        │   └── detector.py
        └── sqli/
            ├── runner.py
            ├── error_based.py
            ├── boolean_based.py
            ├── time_based.py
            └── detector.py
```

## ReconTool

Recontool làm các việc:

```text
static crawl
dynamic crawl bằng Playwright
auth profile
manual seed / HAR import
normalize EndpointRecord
enrich candidate metadata
dedupe endpoint
export inventory
```

Các class trọng tâm:

```text
ReconApplication      điều phối pipeline recon
EndpointRecord        dữ liệu trung tâm của recon
ReconNormalizer       chuẩn hóa URL, param, body, JSON
StaticHtmlCrawler     crawl HTML tĩnh
DynamicCrawler        bắt SPA/API request
RecordEnricher        gắn candidate_tests
EndpointDeduplicator  gom endpoint trùng
ReconExporter         xuất inventory/test_plan
```

## FuzzTool

Fuzztool làm các việc:

```text
đọc recon-output/inventory.json
lọc target theo candidate_tests
mutate query/body/json param
gửi request fuzz có giới hạn
detector phân tích response
export findings
```

Các class trọng tâm:

```text
FuzzApplication    điều phối pipeline fuzz
InventoryLoader    đọc inventory và tạo FuzzTarget
FuzzTarget         một param cụ thể sẽ được fuzz
RequestMutator     thay sample value bằng payload/marker
FuzzHttpClient     gửi request và đo response
XssRunner          chạy nhóm XSS
SqliRunner         chạy nhóm SQLi
FuzzReporter       xuất findings
```

## Cấu Hình Recon

File chính:

```text
config.example.json
```

Phần scope:

```json
"scope": {
  "include_hosts": ["127.0.0.1", "localhost"],
  "exclude_paths": ["/user/logout.php"]
}
```

Phần dynamic crawler:

```json
"dynamic": {
  "enabled": false,
  "resource_types": ["document", "xhr", "fetch"],
  "auto_scroll": false,
  "click_selectors": [],
  "max_clicks_per_page": 0,
  "debug": false
}
```

## Cấu Hình Fuzz

File chính:

```text
fuzz.config.example.json
```

Phần safety:

```json
"safety": {
  "include_post": false,
  "max_requests": 100,
  "delay_seconds": 0.05,
  "dry_run": false
}
```

Phần XSS:

```json
"xss": {
  "enabled": false,
  "reflected": true,
  "stored": false,
  "dom": false
}
```

Phần SQLi:

```json
"sqli": {
  "enabled": false,
  "error_based": true,
  "boolean_based": false,
  "time_based": false
}
```

## Kiểm Tra Nhanh

Kiểm tra recon không cần target đang chạy:

```bash
python -B -m recontool --manual seeds.example.txt --no-static --out test-output
```

Kiểm tra fuzz không gửi request:

```bash
python -B -m fuzztool test-output/inventory.json --xss --sqli --dry-run --out test-fuzz-output
```

Kiểm tra cú pháp:

```bash
python - <<'PY'
from pathlib import Path
import ast
for path in list(Path("recontool").rglob("*.py")) + list(Path("fuzztool").rglob("*.py")):
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
print("AST syntax check passed")
PY
```

## Giới Hạn Hiện Tại

Recontool:

- Dynamic crawler chỉ click selector được cấu hình.
- Importer mở rộng cho Burp/ZAP riêng chưa làm.

Fuzztool:

- Finding là candidate, vẫn cần xác minh thủ công.
- Stored XSS cần cấu hình `stored_check_paths`.
- DOM XSS cần Playwright.
- Boolean/time SQLi mặc định tắt vì dễ nhiễu hoặc chậm.
- POST/body/json mặc định tắt để tránh thay đổi dữ liệu ngoài ý muốn.
