# AITest

`aitest` là module AI-assisted SQL Injection testing cho lab được phép kiểm thử. Module này tách riêng khỏi `fuzztool`, không ghi vào `fuzz-output/findings.json`.

Mục tiêu của module không phải lấy dữ liệu thật, mà là thử nghiệm khả năng AI đọc response và đề xuất payload SQLi theo nhiều vòng:

- SQLi: đi từ SQL error -> ORDER BY/UNION -> marker xuất hiện trong dữ liệu thật hoặc HTML.
- XSS không chạy trong `aitest`; nhóm này được fuzztool kiểm thử và xác minh bằng Playwright.

## Luồng chính

```text
inventory.json
-> chọn tối đa vài target
-> gửi baseline request
-> AI đọc baseline/previous_rounds/response_context rồi đề xuất 1 payload
-> payload_guard kiểm tra an toàn
-> gửi request
-> detector tách evidence/signals khách quan
-> AI đọc response thật + signals để đưa verdict
-> nếu mới có SQL error thì tiếp tục, chưa dừng
-> nếu AI verdict là confirmed thì dừng target
-> nếu AI tự trả stop=true hoặc API AI lỗi thì dừng target
-> xuất aitest-output/sessions.json
```

Payload trong luồng chính chỉ do AI sinh dựa trên ngữ cảnh từng vòng. Tool không có payload fallback. Nếu API lỗi, AI trả JSON sai hoặc trả payload không thuộc SQLi thì target sẽ dừng và ghi `ai_error`.

## Response context gửi cho AI

`ResponseSummarizer` không chỉ gửi `status/signals` nữa. Nó dùng chế độ smart:

- response nhỏ: gửi `raw_response` để AI đọc gần như toàn bộ nội dung.
- JSON nhỏ: cho phép gửi dài hơn HTML vì JSON thường sát dữ liệu API hơn.
- response lớn: gửi `raw_head`, `raw_tail` và `signal_windows` quanh marker hoặc lỗi SQL.

Cấu hình nằm trong `ai.config.example.json`:

```json
"aitest": {
  "full_raw_under_chars": 4000,
  "json_raw_under_chars": 8000,
  "raw_head_chars": 2000,
  "raw_tail_chars": 2000,
  "signal_window_chars": 700,
  "text_preview_chars": 1200
}
```

## Evidence Và AI Verdict

Detector không tự kết luận lỗ hổng. Nó chỉ tách evidence để AI đọc dễ hơn:

```json
{
  "sql_error_confirmed": true,
  "union_marker_in_output": false,
  "objective_proof": false
}
```

Sau mỗi payload, AI đọc `response_context` và signals để trả verdict:

```json
{
  "status": "no_issue|suspicious|confirmed",
  "vuln_type": "none|sqli",
  "confidence": "low|medium|high",
  "reason": "giải thích ngắn gọn",
  "next_step": "hướng test tiếp nếu chưa confirmed"
}
```

`sql_error_confirmed=true` chỉ là tín hiệu nghi vấn. Module chỉ nên coi là confirmed khi AI thấy đủ bằng chứng, ví dụ:

- UNION marker xuất hiện trong dữ liệu thật hoặc HTML, không chỉ nằm trong debug SQL.
## Chạy

```bash
bash run_tool.sh
```

Sau đó chọn:

```text
5. Chạy AI SQLi test
```

Output:

```text
aitest-output/sessions.json
```

## Giới hạn an toàn

- AI không gửi request trực tiếp.
- Tool luôn kiểm tra payload bằng `PayloadGuard` trước khi gửi.
- Payload phá hoại như `DROP`, `DELETE`, `UPDATE`, `INSERT`, `OUTFILE`, `LOAD_FILE`, `curl`, `wget` sẽ bị chặn.
- Module chỉ tạo proof bằng marker trong response, không tự động trích xuất dữ liệu thật.
