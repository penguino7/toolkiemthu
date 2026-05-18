# AiTool

`aitool` là bước hậu xử lý cho `fuzztool`.

Nó đọc file:

```text
fuzz-output/findings.json
```

Sau đó sinh report:

```text
ai-output/ai-report.json
ai-output/ai-report.md
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
-> ai_client.py gọi provider đã cấu hình
-> schemas.py kiểm tra JSON AI trả về
-> reporter.py ghi ai-report.json và ai-report.md
```

## Cấu Hình AI

File cấu hình mẫu nằm ở repo root:

```text
ai.config.example.json
```

Provider mặc định là:

```json
"provider": {
  "name": "offline"
}
```

Chế độ `offline` không gọi API. Nó dùng fallback nội bộ để gán CWE cơ bản:

```text
xss  -> CWE-79
sqli -> CWE-89
```

## Dùng Ollama

Ví dụ cấu hình Ollama local:

```json
"provider": {
  "name": "ollama",
  "base_url": "http://127.0.0.1:11434",
  "model": "llama3.1:8b",
  "timeout_seconds": 60,
  "temperature": 0.1
}
```

Chạy Ollama trước:

```bash
ollama serve
ollama pull llama3.1:8b
```

Sau đó chạy:

```bash
python -B -m aitool fuzz-output/findings.json
```

## Dùng API Tương Thích OpenAI

Nếu có một API hỗ trợ endpoint `/chat/completions`, cấu hình:

```json
"provider": {
  "name": "openai_compatible",
  "base_url": "https://your-ai-api.example/v1",
  "model": "your-model",
  "api_key_env": "AI_API_KEY"
}
```

Set API key:

```bash
export AI_API_KEY="your_api_key_here"
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

Nếu AI trả sai JSON hoặc API lỗi, `aitool` dùng fallback nội bộ để vẫn sinh report.

## Ý Nghĩa Các File

```text
__main__.py       entrypoint khi chạy python -m aitool
cli.py            parse tham số dòng lệnh và điều phối tool
config.py         đọc ai.config.example.json và merge config mặc định
ai_client.py      client chung, không phụ thuộc provider cụ thể
providers.py      các provider: offline, ollama, openai_compatible
analyzer.py       đọc findings.json và phân tích từng finding
prompts.py        prompt/schema gửi sang AI
schemas.py        parse/validate JSON AI trả về, fallback khi lỗi
redactor.py       ẩn dữ liệu nhạy cảm trước khi gửi AI
reporter.py       xuất ai-report.json và ai-report.md
```

## Thứ Tự Đọc Code

Nếu mới đọc source, nên đọc theo thứ tự:

```text
cli.py
config.py
analyzer.py
ai_client.py
providers.py
prompts.py
schemas.py
reporter.py
```

## Giới Hạn Hiện Tại

- AI chỉ phân tích `findings.json`, chưa đọc full response.
- Chưa có fingerprint công nghệ để map CVE tự động.
- `possible_cve` chỉ nên có khi finding chứa dữ liệu về sản phẩm/phiên bản cụ thể.
- Kết luận cuối vẫn phải dựa trên evidence của fuzztool, không dựa mù vào AI.

