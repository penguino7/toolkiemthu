# Tool Kiểm Thử Web

Repo này gồm các module tách riêng nhưng dùng chung một luồng làm việc:

```text
recontool/  thu thập endpoint, form, param, SPA/API và xuất inventory
fuzztool/   đọc inventory từ recontool để kiểm thử XSS/SQLi có kiểm soát
aitest/     AI-assisted iterative testing, chạy riêng và xuất session log riêng
```

Luồng sử dụng chính:

```text
recontool -> recon-output/inventory.json -> fuzztool -> fuzz-output/findings.json
```

`recontool` chỉ làm recon, không gửi giá trị kiểm thử. `fuzztool` mới là phần gửi payload kiểm thử, có `--dry-run`, giới hạn scope, giới hạn request và mặc định không fuzz POST/body/json nếu chưa bật `--include-post`.

`aitest` là module thử nghiệm riêng: AI đề xuất payload theo từng vòng, tool kiểm tra an toàn rồi mới gửi request. Kết quả ghi vào `aitest-output/`, không làm thay đổi finding chính.

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
9. Chạy AI analysis
10. Xem tóm tắt AI report
11. Cài đặt recon/fuzz
12. Cài đặt AI
13. Kiểm tra AI provider/API key
14. Chạy AI iterative test
0. Thoát
```

Mặc định launcher bật `Trace log`. Khi chạy fuzz/recon, terminal sẽ hiện log realtime:

```text
┌──────────────────────────────────────────────────────────────────────
│ PAYLOAD  GET /search.php query:q
│          test'
│
│ REQUEST  GET /search.php?q=test'
│ RESPONSE status=500 time=0.041s size=923B
└──────────────────────────────────────────────────────────────────────
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

Chạy static recon: mở menu bằng `bash run_tool.sh`, sau đó chọn `1`.

Chạy cả static và dynamic recon: mở menu bằng `bash run_tool.sh`, sau đó chọn `2`.

Nếu chưa cài Playwright, cài trước bằng:

```bash
python -m playwright install chromium
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

Nếu inventory được tạo ở port cũ, dùng `--base-url` để ép fuzztool gọi đúng lab hiện tại. Khi chạy bằng menu, Base URL trong phần settings sẽ được truyền tự động cho fuzz.

Trong menu, dùng `11. Cài đặt recon/fuzz` để chỉnh `Base URL`, `Inventory path`, `Fuzz output` và `Max requests`.

Mặc định fuzztool không dùng proxy từ biến môi trường để tránh trường hợp Python đi qua proxy khác với `curl`. Nếu muốn cố tình đi qua Burp/ZAP, bật `use_environment_proxy` trong `fuzz.config.example.json`.

Xem target trước, không gửi request: chọn `6. Dry-run fuzz all`.

Chạy XSS: chọn `3. Chạy fuzz XSS`.

Lệnh trên chạy đủ reflected XSS, DOM XSS và Stored XSS. Tool tự bật POST/body/json cho nhóm XSS vì Stored XSS cần gửi dữ liệu.

Stored XSS dùng `stored_check_paths` trong `fuzz.config.example.json` để biết URL nào cần mở lại sau khi submit payload. File mẫu đã để sẵn path cho lab local, khi test web khác thì sửa lại danh sách này.

```json
"stored_check_paths": ["/news.php?id=1", "/spa/comments/1", "/spa/logs"]
```

Chạy SQLi: chọn `4. Chạy fuzz SQLi`.

Payload SQLi nằm trong `fuzztool/payloads/sqli.txt`, chia theo nhóm error-based, boolean-based và union-based. Scanner sẽ tự thay `{sample}` bằng giá trị mẫu của param; riêng union-based sẽ tự sinh `{columns}` để thử số cột UNION SELECT.

Chạy cả XSS và SQLi: chọn `5. Chạy fuzz XSS + SQLi`.

Đây là lệnh fuzz đầy đủ cho lab: reflected XSS, DOM XSS, Stored XSS, SQLi error-based, SQLi boolean-based và SQLi union-based. `--include-post` vẫn còn được hỗ trợ nhưng không cần thêm khi đã dùng `--xss` hoặc `--sqli`.

Giới hạn số request: vào `11. Cài đặt recon/fuzz`, nhập giá trị ở dòng `Max requests`, rồi chạy lại lựa chọn fuzz cần dùng.

Output fuzz:

```text
fuzz-output/findings.json
fuzz-output/findings.md
```

`findings` chỉ chứa kết quả đã có bằng chứng. Với XSS, tool dùng Playwright mở URL trong browser thật và chỉ ghi khi bắt được `alert()`/dialog chứa marker của payload. Payload chỉ được phản xạ trong HTML/JSON hoặc chỉ render ra DOM nhưng không thực thi sẽ không được ghi vào `findings`.

## Chạy AI Iterative Test

Module này chạy riêng để AI gợi ý payload theo nhiều vòng. Tool vẫn kiểm soát payload, scope và request.

Trong menu, chọn `14. Chạy AI iterative test`.

Muốn đổi số endpoint hoặc số vòng test thì vào `12. Cài đặt AI`, chỉnh `AI test max targets` và `AI test rounds`.

Output:

```text
aitest-output/sessions.json
aitest-output/sessions.md
```

`aitest` không sửa `fuzz-output/findings.json`; đây là session log để đọc quá trình AI đề xuất payload và response từng vòng.

## Chạy AI Analysis

AI tool là bước hậu xử lý, chỉ đọc `findings.json` và sinh report riêng. Nó không sửa `recontool` hoặc `fuzztool`.

Chạy mặc định bằng chế độ `offline`:

```bash
python -B -m aitool fuzz-output/findings.json
```

Output:

```text
ai-output/ai-report.json
ai-output/ai-report.md
```

Cấu hình AI nằm ở:

```text
ai.config.example.json
```

Config mẫu hiện đang dùng provider `openai_compatible` theo router API:

```json
"provider": {
  "name": "openai_compatible",
  "base_url": "https://ravavct.abc-tunnel.us/v1",
  "model": "gc/gemini-3-pro-preview",
  "api_key_env": "AI_API_KEY"
}
```

Set API key trước khi chạy:

```bash
export AI_API_KEY="your_router_api_key"
```

## Cấu Trúc Repo

```text
.
├── README.md
├── ai.config.example.json
├── recon.config.example.json
├── fuzz.config.example.json
├── requirements.txt
├── run_tool.sh
├── seeds.example.txt
├── toolcli/
│   ├── __main__.py
│   ├── menu.py
│   ├── runner.py
│   └── trace_runner.py
├── aitool/
│   ├── __main__.py
│   ├── ai_client.py
│   ├── analyzer.py
│   ├── cli.py
│   ├── config.py
│   ├── prompts.py
│   ├── providers.py
│   ├── redactor.py
│   ├── reporter.py
│   └── schemas.py
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
    ├── xss_scanner.py
    ├── sqli_scanner.py
    └── payloads/
        ├── xss.txt
        └── sqli.txt
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
run_tool.sh
toolcli/menu.py
recontool/cli.py
recontool/crawlers/static_html.py
recontool/crawlers/playwright_dynamic.py
recontool/normalizer.py
recontool/enrich.py
recontool/dedupe.py
recontool/exporters.py

fuzztool/cli.py
fuzztool/inventory_loader.py
fuzztool/mutator.py
fuzztool/xss_scanner.py
fuzztool/sqli_scanner.py
fuzztool/reporter.py
```

Khi đọc fuzz scanner, mở `xss_scanner.py` và `sqli_scanner.py`. Mỗi file vẫn chia hàm riêng cho từng loại lỗ hổng:

```text
fuzztool/xss_scanner.py   scan_reflected_xss(), scan_stored_xss(), scan_dom_xss()
fuzztool/sqli_scanner.py  scan_error_based_sqli(), scan_boolean_based_sqli(), scan_union_based_sqli()
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
payloads/               danh sách payload XSS/SQLi
xss_scanner.py          scanner XSS và xác minh bằng Playwright
sqli_scanner.py         scanner SQLi và luật nhận diện evidence
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
XssScanner         chạy nhóm XSS
SqliScanner        chạy nhóm SQLi
FuzzReporter       xuất findings
```

## Cấu Hình Recon

File chính:

```text
recon.config.example.json
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
  "union_based": false,
  "union_max_columns": 12
}
```

## Cấu Hình AI

File chính:

```text
ai.config.example.json
```

Các provider đang hỗ trợ:

```text
offline              không gọi API, dùng fallback nội bộ
ollama               gọi API local kiểu Ollama /api/chat
openai_compatible    gọi API tương thích /chat/completions
```

AI tool chỉ nhận dữ liệu đã lọc từ `findings.json`. Mặc định nó có `redaction.enabled=true` để ẩn các key nhạy cảm như `authorization`, `cookie`, `password`, `token` trước khi gửi sang provider.

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
- SQLi finding vẫn nên được đọc cùng evidence vì boolean-based có thể nhiễu nếu target phản hồi không ổn định, còn union-based chỉ ghi khi marker xuất hiện trong response.
- Stored XSS cần cấu hình `stored_check_paths`.
- DOM XSS cần Playwright.
- Boolean/union SQLi mặc định tắt trong config, nhưng sẽ được bật khi chạy `--sqli`.
- POST/body/json mặc định tắt để tránh thay đổi dữ liệu ngoài ý muốn.
