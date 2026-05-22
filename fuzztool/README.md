# FuzzTool

`fuzztool` nằm cùng repo với `recontool`. Recon tool sinh `inventory.json`; fuzztool đọc file đó để kiểm thử XSS/SQLi có kiểm soát.

## Luồng Dùng

```bash
bash run_tool.sh
```

Trong menu, chọn `1` để chạy recon, rồi chọn `4` để fuzz cả XSS và SQLi.

`Base URL` trong menu giúp fuzztool rewrite host/port từ inventory sang lab đang chạy hiện tại. Mặc định fuzztool không dùng proxy từ biến môi trường; muốn đi qua proxy thì bật `use_environment_proxy` trong `fuzz.config.example.json`.

## Chế Độ An Toàn

Mặc định fuzztool:

- `--xss` hoặc `--sqli` sẽ tự bật POST/body/json để quét đủ lab.
- Không fuzz `password`, `csrf`, `token`, `session`.
- Giới hạn số request bằng `max_requests`.
- POST/body/json vẫn có thể bật thủ công bằng `--include-post` khi chạy trực tiếp bằng CLI.
- XSS dùng payload proof-of-execution như `<script>alert("FUZZXSS_xxxxxxxx")</script>`.
- XSS chỉ được ghi vào `findings` khi Playwright bắt được dialog chứa marker, không ghi các payload chỉ phản xạ/render nhưng chưa thực thi.
- `--xss` chạy reflected XSS, DOM XSS và Stored XSS.
- `--sqli` chạy error-based, boolean-based và union-based SQLi.

## Lệnh Mẫu

Chạy đủ nhóm XSS, gồm reflected XSS, DOM XSS và Stored XSS: chọn `2. Chạy fuzz XSS` trong menu.

Stored XSS dùng `stored_check_paths` trong `fuzz.config.example.json`, vì tool phải biết sau khi submit payload thì nên mở URL nào để xác minh payload đã được lưu và thực thi. File mẫu đã để sẵn path cho lab local, khi test web khác thì sửa lại danh sách này.

```json
"stored_check_paths": ["/news.php?id=1", "/spa/comments/1", "/spa/logs"]
```

Payload XSS mặc định là payload thật có marker bên trong:

```text
<script>alert("FUZZXSS_xxxxxxxx")</script>
"><svg/onload=alert("FUZZXSS_xxxxxxxx")>
<img src=x onerror=alert("FUZZXSS_xxxxxxxx")>
```

Chạy đủ nhóm SQLi, gồm error-based, boolean-based và union-based: chọn `3. Chạy fuzz SQLi` trong menu.

Payload SQLi được đọc từ:

```text
fuzztool/payloads/sqli.txt
```

File này chia payload theo nhóm `error`, `boolean` và `union`. Có thể thêm payload mới bằng template `{sample}`; riêng union-based dùng `{columns}` do scanner tự sinh.

Chạy đầy đủ cả XSS và SQLi: chọn `4. Chạy fuzz XSS + SQLi` trong menu.

## Output

```text
fuzz-output/findings.json
```

`findings` là kết quả đã có bằng chứng. Với XSS, bằng chứng hợp lệ là browser thật chạy payload và tạo `alert()`/dialog có marker tương ứng. Nếu payload chỉ xuất hiện trong HTML/JSON/DOM nhưng không thực thi JavaScript thì tool bỏ qua, không ghi vào `findings`.

## Cấu Trúc Chính

```text
fuzztool/
├── cli.py
├── config.py
├── models.py
├── inventory_loader.py
├── http_client.py
├── mutator.py
├── reporter.py
├── xss_scanner.py
├── sqli_scanner.py
└── payloads/
    ├── xss.txt
    └── sqli.txt
```

`xss_scanner.py` vẫn chia hàm `scan_reflected_xss()`, `scan_stored_xss()`, `scan_dom_xss()`.
`sqli_scanner.py` vẫn chia hàm `scan_error_based_sqli()`, `scan_boolean_based_sqli()`, `scan_union_based_sqli()`.
