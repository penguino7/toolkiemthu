# AiTool

`aitool` là bước hậu xử lý cho `fuzztool`.

Nó đọc file:

```text
fuzz-output/findings.json
```

Sau đó sinh report:

```text
ai-output/ai-report.json
```

`aitool` không gửi payload, không crawl, không fuzz và không sửa logic của `recontool` hoặc `fuzztool`.

## Chạy Nhanh

```bash
python -B -m aitool fuzz-output/findings.json
```

Chọn output folder khác:

```bash
python -B -m aitool fuzz-output/findings.json --out ai-output-new
```

Chọn config khác:

```bash
python -B -m aitool fuzz-output/findings.json --config ai.config.example.json
```

## Luồng Hoạt Động

```text
findings.json
-> analyzer.py lọc và rút gọn dữ liệu
-> redactor.py ẩn token/cookie/password nếu có
-> api_client.py gọi API /chat/completions
-> analyzer.py kiểm tra JSON AI trả về
-> reporter.py ghi ai-report.json
```

## Cấu Hình AI

File cấu hình mẫu nằm ở repo root:

```text
ai.config.example.json
```

Config mẫu hiện tại dùng API tương thích `/chat/completions`.

## Dùng API Tương Thích OpenAI

Config mẫu hiện tại dùng router API tương thích `/chat/completions`:

```json
"provider": {
  "name": "openai_compatible",
  "base_url": "https://ravavct.abc-tunnel.us/v1",
  "model": "gc/gemini-3-pro-preview",
  "api_key_env": "AI_API_KEY"
}
```

Set API key:

```bash
export AI_API_KEY="your_router_api_key"
```

Rồi chạy:

```bash
python -B -m aitool fuzz-output/findings.json
```

## Dữ Liệu Gửi Sang AI

`aitool` không gửi toàn bộ response thô. Nó chỉ gửi dữ liệu đã được `fuzztool` ghi trong finding, ví dụ:

```text
vuln_type
subtype
method
url
param
payload
status
evidence
details
```

Trước khi gửi, `redactor.py` sẽ ẩn các key nhạy cảm như:

```text
authorization
cookie
password
token
secret
api_key
```

## JSON AI Cần Trả Về

Provider AI phải trả về JSON theo dạng:

```json
{
  "confirmed": true,
  "vulnerability_type": "sqli",
  "subtype": "error_based",
  "cwe": "CWE-89",
  "possible_cve": null,
  "severity": "high",
  "confidence": 0.9,
  "reason_vi": "Response có dấu hiệu lỗi SQL sau khi inject dấu nháy.",
  "false_positive_note_vi": "Cần kiểm tra thêm response snippet nếu có.",
  "remediation_vi": "Dùng prepared statements và không nối chuỗi SQL trực tiếp."
}
```

Nếu AI trả sai JSON hoặc API lỗi, `aitool` vẫn ghi report nhưng đánh dấu `confirmed=false` và nêu rõ AI analysis chưa thành công.

## Ý Nghĩa Các File

```text
__main__.py       entrypoint khi chạy python -m aitool
cli.py            parse tham số dòng lệnh và điều phối tool
config.py         đọc ai.config.example.json và merge config mặc định
api_client.py     gọi API tương thích OpenAI /chat/completions
analyzer.py       đọc findings.json, gọi AI và parse JSON kết quả
prompts.py        prompt/schema gửi sang AI
redactor.py       ẩn dữ liệu nhạy cảm trước khi gửi AI
reporter.py       xuất ai-report.json
```

## Thứ Tự Đọc Code

Nếu mới đọc source, nên đọc theo thứ tự:

```text
cli.py
config.py
analyzer.py
api_client.py
prompts.py
reporter.py
```

## Giới Hạn Hiện Tại

- AI chỉ phân tích `findings.json`, chưa đọc full response.
- Chưa có fingerprint công nghệ để map CVE tự động.
- `possible_cve` chỉ nên có khi finding chứa dữ liệu về sản phẩm/phiên bản cụ thể.
- Kết luận cuối vẫn phải dựa trên evidence của fuzztool, không dựa mù vào AI.
