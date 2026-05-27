# AITest

`aitest` là module AI-assisted exploit proof cho lab XSS/SQLi. Module này tách riêng khỏi `fuzztool`, không ghi vào `fuzz-output/findings.json`.

Mục tiêu của module không phải lấy dữ liệu thật, mà là tạo bằng chứng khai thác an toàn:

- SQLi: đi từ SQL error -> ORDER BY/UNION -> marker xuất hiện trong dữ liệu thật hoặc HTML.
- XSS: payload được phản chiếu -> Playwright mở trình duyệt -> alert/dialog chứa marker.

## Luồng chính

```text
inventory.json
-> chọn tối đa vài target
-> gửi baseline request
-> AI đề xuất 1 payload
-> payload_guard kiểm tra an toàn
-> gửi request
-> detector tách signal
-> nếu mới có SQL error thì tiếp tục, chưa dừng
-> nếu có exploit_proof thì dừng target
-> xuất aitest-output/sessions.json
```

## Các signal quan trọng

```json
{
  "sql_error_confirmed": true,
  "union_marker_confirmed": false,
  "xss_reflection": false,
  "xss_executed": false,
  "exploit_proof": false
}
```

`sql_error_confirmed=true` chỉ là tín hiệu nghi vấn. Module chỉ coi là proof khi:

- `union_marker_confirmed=true`, hoặc
- `xss_executed=true`.

## Chạy

```bash
bash run_tool.sh
```

Sau đó chọn:

```text
5. Chạy AI exploit proof
```

Output:

```text
aitest-output/sessions.json
```

## Giới hạn an toàn

- AI không gửi request trực tiếp.
- Tool luôn kiểm tra payload bằng `PayloadGuard` trước khi gửi.
- Payload phá hoại như `DROP`, `DELETE`, `UPDATE`, `INSERT`, `OUTFILE`, `LOAD_FILE`, `curl`, `wget` sẽ bị chặn.
- Module chỉ tạo proof bằng marker/alert, không tự động trích xuất dữ liệu thật.
