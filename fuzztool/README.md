# FuzzTool

`fuzztool` nằm cùng repo với `recontool`. Recon tool sinh `inventory.json`; fuzztool đọc file đó để kiểm thử XSS/SQLi có kiểm soát.

## Luồng Dùng

```bash
bash run_recon.sh http://127.0.0.1:8080 --dynamic
bash run_fuzz.sh recon-output/inventory.json --xss --sqli
```

## Chế Độ An Toàn

Mặc định fuzztool:

- Chỉ fuzz query param.
- Không fuzz `password`, `csrf`, `token`, `session`.
- Giới hạn số request bằng `max_requests`.
- Có `--dry-run` để liệt kê target mà không gửi request.
- POST/body/json chỉ chạy khi bật `--include-post`.
- XSS dùng payload proof-of-execution như `<script>alert("FUZZXSS_xxxxxxxx")</script>`.
- XSS chỉ được ghi vào `findings` khi Playwright bắt được dialog chứa marker, không ghi các payload chỉ phản xạ/render nhưng chưa thực thi.
- Stored XSS, DOM XSS, boolean/time SQLi là tùy chọn.

## Lệnh Mẫu

Chỉ xem target, không gửi request:

```bash
bash run_fuzz.sh recon-output/inventory.json --xss --sqli --dry-run
```

Chạy XSS reflected mặc định:

```bash
bash run_fuzz.sh recon-output/inventory.json --xss
```

Payload XSS mặc định là payload thật có marker bên trong:

```text
<script>alert("FUZZXSS_xxxxxxxx")</script>
"><svg/onload=alert("FUZZXSS_xxxxxxxx")>
<img src=x onerror=alert("FUZZXSS_xxxxxxxx")>
```

Chạy SQLi error-based mặc định:

```bash
bash run_fuzz.sh recon-output/inventory.json --sqli
```

Cho phép fuzz POST body/json:

```bash
bash run_fuzz.sh recon-output/inventory.json --xss --sqli --include-post
```

Chạy thêm DOM XSS:

```bash
bash run_fuzz.sh recon-output/inventory.json --xss --xss-dom
```

Chạy thêm SQLi boolean/time:

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
