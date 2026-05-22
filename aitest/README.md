# AITest

`aitest` là module thử nghiệm AI-assisted iterative testing. Module này tách riêng khỏi `fuzztool`, không ghi vào `fuzz-output/findings.json`.

Luồng chính:

```text
inventory.json
-> chọn tối đa vài target
-> gửi baseline request
-> AI đề xuất 1 payload
-> payload_guard kiểm tra an toàn
-> gửi request
-> rút gọn response + detector signal
-> lặp lại vài vòng
-> xuất sessions.json / sessions.md
```

Chạy mẫu:

```bash
bash run_tool.sh
```

Sau đó chọn `9. Chạy AI iterative test`.

Muốn đổi số endpoint hoặc số vòng test thì vào `7. Cài đặt AI`.

Khi chạy, terminal sẽ in log realtime:

```text
========================================================================
TARGET   1/5
POINT    GET /api/spa/news.php query:id
MARKER   AITEST_xxxxxxxx
========================================================================

------------------------------------------------------------------------
BASELINE REQUEST
------------------------------------------------------------------------
REQUEST  GET http://127.0.0.1:12001/api/spa/news.php?id=1
RESPONSE status=200 time=0.012s size=49B
------------------------------------------------------------------------

========================================================================
ROUND    1/4
STEP     Asking AI for next payload
========================================================================
PAYLOAD  1'
------------------------------------------------------------------------
ATTACK   REQUEST
------------------------------------------------------------------------
REQUEST  GET http://127.0.0.1:12001/api/spa/news.php?id=1%27
RESPONSE status=200 time=0.014s size=2.1KB
SIGNAL   confirmed=False sql_error=- marker_in_data=False matched=- ignored=-
------------------------------------------------------------------------
```

Nếu muốn tắt log chi tiết khi chạy trực tiếp bằng module thì thêm `--quiet`.

Output:

```text
aitest-output/sessions.json
aitest-output/sessions.md
```

Giới hạn an toàn:

- AI không gửi request trực tiếp.
- Tool luôn kiểm tra payload trước khi gửi.
- Payload phá hoại như `DROP`, `DELETE`, `UPDATE`, `INSERT`, `OUTFILE`, `LOAD_FILE`, `curl`, `wget` sẽ bị chặn.
- Module chỉ ghi session log riêng, không tự động thêm finding chính.
