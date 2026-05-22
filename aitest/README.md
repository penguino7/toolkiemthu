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

Sau đó chọn `14. Run AI iterative test`.

Muốn đổi số endpoint hoặc số vòng test thì vào `12. AI settings`.

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
