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

`recontool` chỉ làm recon, không gửi giá trị kiểm thử. `fuzztool` mới là phần gửi payload kiểm thử, có `--dry-run`, giới hạn scope, giới hạn request và mặc định không fuzz POST/body/json nếu chưa bật `--include-post`.

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

Lệnh trên chạy đủ reflected XSS, DOM XSS và Stored XSS. Tool tự bật POST/body/json cho nhóm XSS vì Stored XSS cần gửi dữ liệu.

Stored XSS dùng `stored_check_paths` trong `fuzz.config.example.json` để biết URL nào cần mở lại sau khi submit payload. File mẫu đã để sẵn path cho lab local, khi test web khác thì sửa lại danh sách này.

```json
"stored_check_paths": ["/news.php?id=1", "/spa/comments/1", "/spa/logs"]
```

Chạy SQLi:

```bash
bash run_fuzz.sh recon-output/inventory.json --sqli
```

Payload SQLi nằm trong `fuzztool/plugins/sqli/payloads.txt`, chia theo nhóm error-based, boolean-based và time-based. Scanner sẽ tự thay `{sample}` bằng giá trị mẫu của param và `{sleep}` bằng số giây delay trong config.

Chạy cả XSS và SQLi:

```bash
bash run_fuzz.sh recon-output/inventory.json --xss --sqli
```

Đây là lệnh fuzz đầy đủ cho lab: reflected XSS, DOM XSS, Stored XSS, SQLi error-based, SQLi boolean-based và SQLi time-based. `--include-post` vẫn còn được hỗ trợ nhưng không cần thêm khi đã dùng `--xss` hoặc `--sqli`.

Giới hạn số request:

```bash
bash run_fuzz.sh recon-output/inventory.json --xss --sqli --max-requests 50
```

Output fuzz:

```text
fuzz-output/findings.json
fuzz-output/findings.md
```

`findings` chỉ chứa kết quả đã có bằng chứng. Với XSS, tool dùng Playwright mở URL trong browser thật và chỉ ghi khi bắt được `alert()`/dialog chứa marker của payload. Payload chỉ được phản xạ trong HTML/JSON hoặc chỉ render ra DOM nhưng không thực thi sẽ không được ghi vào `findings`.

## Cấu Trúc Repo

```text
.
├── README.md
├── config.example.json
├── fuzz.config.example.json
├── requirements.txt
├── run_recon.sh
├── run_fuzz.sh
├── seeds.example.txt
├── recontool/
│   ├── __main__.py
│   ├── RECON_FLOW.md
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
RequestMutator     thay sample value bằng payload kiểm thử
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
  "max_requests": 800,
  "delay_seconds": 0.05,
  "dry_run": false
}
```

Phần XSS:

```json
"xss": {
  "enabled": false,
  "payload_mode": "proof",
  "reflected": true,
  "stored": false,
  "dom": false,
  "dom_headless": true,
  "dom_timeout_ms": 8000,
  "post_load_wait_ms": 500
}
```

`payload_mode` mặc định là `proof`, tức là XSS scanner dùng payload thật như:

```text
<script>alert("FUZZXSS_xxxxxxxx")</script>
"><svg/onload=alert("FUZZXSS_xxxxxxxx")>
<img src=x onerror=alert("FUZZXSS_xxxxxxxx")>
```

Marker `FUZZXSS_xxxxxxxx` vẫn được giữ bên trong payload để tool truy vết finding.

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

- XSS finding là kết quả đã được browser xác nhận bằng dialog có marker, không còn là candidate phản xạ đơn thuần.
- SQLi finding vẫn nên được đọc cùng evidence vì boolean/time có thể nhiễu nếu target phản hồi không ổn định.
- Stored XSS cần cấu hình `stored_check_paths`.
- DOM XSS cần Playwright.
- Boolean/time SQLi mặc định tắt vì dễ nhiễu hoặc chậm.
- POST/body/json mặc định tắt để tránh thay đổi dữ liệu ngoài ý muốn.
