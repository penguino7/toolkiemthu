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

## Chạy Bằng Menu CLI

Nếu không muốn gõ lệnh dài, dùng launcher terminal:

```bash
bash run_tool.sh
```

Menu sẽ hiện các lựa chọn bằng số:

```text
1. Chạy recon tĩnh
2. Chạy recon tĩnh + dynamic Playwright
3. Chạy fuzz XSS
4. Chạy fuzz SQLi
5. Chạy fuzz XSS + SQLi
6. Dry-run fuzz all
7. Xem tóm tắt inventory
8. Xem tóm tắt findings
9. Cài đặt
0. Thoát
```

Mặc định launcher bật `Trace log`. Khi chạy fuzz/recon, terminal sẽ hiện log realtime:

```text
[PAYLOAD ] GET /search.php query:q
           value: test'
[REQUEST ] GET /search.php?q=test'
[RESPONSE] status=500 time=0.041s size=923B
```

Log mỗi lần chạy được lưu vào thư mục:

```text
runs/
```

## Chạy Recon

Giả sử lab chạy tại:

```text
http://127.0.0.1:12001
```

Chạy static recon:

```bash
bash run_recon.sh http://127.0.0.1:12001
```

Chạy cả static và dynamic recon:

```bash
bash run_recon.sh http://127.0.0.1:12001 --dynamic
```

Cài Playwright trong lúc chạy nếu chưa cài:

```bash
bash run_recon.sh http://127.0.0.1:12001 --dynamic --install-playwright
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
├── run_tool.sh
├── seeds.example.txt
├── toolcli/
│   ├── __main__.py
│   ├── menu.py
│   ├── runner.py
│   └── trace_runner.py
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

## Cách Đọc Source Nhanh

Khi mới đọc code, không cần mở tất cả file cùng lúc. Nên đọc theo thứ tự này:

```text
run_recon.sh
recontool/cli.py
recontool/crawlers/static_html.py
recontool/crawlers/playwright_dynamic.py
recontool/normalizer.py
recontool/enrich.py
recontool/dedupe.py
recontool/exporters.py

run_fuzz.sh
fuzztool/cli.py
fuzztool/inventory_loader.py
fuzztool/mutator.py
fuzztool/plugins/xss/runner.py
fuzztool/plugins/sqli/runner.py
fuzztool/reporter.py
```

Khi đọc fuzz scanner, mở `runner.py` trước để biết scanner nào được gọi, sau đó mở từng file cụ thể:

```text
fuzztool/plugins/xss/reflected.py      reflected XSS
fuzztool/plugins/xss/stored.py         stored XSS
fuzztool/plugins/xss/dom.py            DOM XSS
fuzztool/plugins/sqli/error_based.py   SQLi error-based
fuzztool/plugins/sqli/boolean_based.py SQLi boolean-based
fuzztool/plugins/sqli/time_based.py    SQLi time-based
```

Các hàm `scan()` trong những file này được viết theo kiểu tuyến tính:

```text
1. tạo payload
2. tạo request/URL tấn công
3. gửi request hoặc mở browser
4. kiểm tra evidence
5. ghi Finding nếu có bằng chứng
```

Các hàm recon chính cũng theo kiểu tương tự:

```text
StaticHtmlCrawler.crawl()   lấy seed -> request page -> parse link/form -> đưa link mới vào queue
DynamicCrawler.crawl()      mở browser -> login nếu có -> nghe response -> tạo EndpointRecord
ReconNormalizer.make_record() normalize URL -> tạo record -> thêm params -> gắn evidence
RecordEnricher.enrich_one() đọc evidence/param -> gắn candidate_tests
EndpointDeduplicator.dedupe() tạo fingerprint -> merge record trùng
```

Trọng tâm cần hiểu trước:

```text
ReconApplication.run()  luồng chính của recon
FuzzApplication.run()   luồng chính của fuzz
EndpointRecord          một endpoint sau khi recon
FuzzTarget              một param sẽ được fuzz
RequestMutator          thay giá trị param bằng payload
Finding                 kết quả fuzz đã có bằng chứng
```

Các file có thể đọc sau:

```text
http_client.py          chi tiết gửi HTTP request
scope.py                luật giới hạn domain/path
auth.py                 login/auth profile
payloads.txt            danh sách payload
detector.py             luật nhận diện evidence
browser_verifier.py     xác minh XSS bằng Playwright
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
