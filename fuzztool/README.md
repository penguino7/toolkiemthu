# FuzzTool

`fuzztool` nằm cùng repo với `recontool`. Recon tool sinh `inventory.json`; fuzztool đọc file đó để kiểm thử XSS/SQLi có kiểm soát.

## Luồng Dùng

```bash
bash run_recon.sh http://127.0.0.1:12001 --dynamic
bash run_fuzz.sh recon-output/inventory.json --base-url http://127.0.0.1:12001 --xss --sqli
```

`--base-url` giúp fuzztool rewrite host/port từ inventory sang lab đang chạy hiện tại. Mặc định fuzztool không dùng proxy từ biến môi trường; muốn đi qua proxy thì bật `use_environment_proxy` trong `fuzz.config.example.json`.

## Chế Độ An Toàn

Mặc định fuzztool:

- `--xss` hoặc `--sqli` sẽ tự bật POST/body/json để quét đủ lab.
- Không fuzz `password`, `csrf`, `token`, `session`.
- Giới hạn số request bằng `max_requests`.
- Có `--dry-run` để liệt kê target mà không gửi request.
- POST/body/json vẫn có thể bật thủ công bằng `--include-post` khi chạy scanner riêng lẻ.
- XSS dùng payload proof-of-execution như `<script>alert("FUZZXSS_xxxxxxxx")</script>`.
- XSS chỉ được ghi vào `findings` khi Playwright bắt được dialog chứa marker, không ghi các payload chỉ phản xạ/render nhưng chưa thực thi.
- `--xss` chạy reflected XSS, DOM XSS và Stored XSS.
- `--sqli` chạy error-based, boolean-based và time-based SQLi.

## Lệnh Mẫu

Chỉ xem target, không gửi request:

```bash
bash run_fuzz.sh recon-output/inventory.json --xss --sqli --dry-run
```

Chạy đủ nhóm XSS, gồm reflected XSS, DOM XSS và Stored XSS:

```bash
bash run_fuzz.sh recon-output/inventory.json --xss
```

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

Chạy đủ nhóm SQLi, gồm error-based, boolean-based và time-based:

```bash
bash run_fuzz.sh recon-output/inventory.json --sqli
```

Payload SQLi được đọc từ:

```text
fuzztool/plugins/sqli/payloads.txt
```

File này chia payload theo nhóm `error`, `boolean` và `time`. Có thể thêm payload mới bằng template `{sample}` và `{sleep}` mà không cần sửa code scanner.

Chạy đầy đủ cả XSS và SQLi:

```bash
bash run_fuzz.sh recon-output/inventory.json --xss --sqli
```

Chạy riêng DOM XSS:

```bash
bash run_fuzz.sh recon-output/inventory.json --xss-dom
```

Chạy riêng SQLi boolean/time:

```bash
bash run_fuzz.sh recon-output/inventory.json --sqli --sqli-boolean --sqli-time
```

## Output

```text
fuzz-output/findings.json
fuzz-output/findings.md
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
