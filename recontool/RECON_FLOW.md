# Biểu Đồ Hoạt Động Recon Tool

File này mô tả luồng hoạt động của `recontool` bằng Mermaid. Recon chỉ thu thập và chuẩn hóa dữ liệu đã quan sát được, không gửi payload kiểm thử và không tự gợi ý loại lỗ hổng cần test.

## 1. Luồng Tổng Quan

```mermaid
flowchart TD
    A[Người dùng chạy run_tool.sh và chọn recon] --> B[ReconApplication]
    B --> C[ConfigLoader đọc recon.config.example.json]
    C --> D[Áp dụng tham số CLI như base-url, seed]

    D --> E{Nguồn dữ liệu}
    E -->|Static crawl| F[StaticHtmlCrawler]
    E -->|Dynamic crawl| G[DynamicCrawler Playwright]

    F --> I[ReconNormalizer]
    G --> I

    I --> J[EndpointRecord]
    J --> K[EndpointDeduplicator gom trùng]
    K --> L[ReconExporter xuất file]

    L --> M[inventory.json]
    L --> N[params.txt]
```

## 2. Luồng CLI

```mermaid
flowchart TD
    A[__main__.py gọi main] --> B[ReconApplication.run]
    B --> C[Parse tham số CLI]
    C --> D[Đọc config]
    D --> E[Thu thập record từ crawler/importer]
    E --> F[Gom trùng endpoint]
    F --> G[Xuất inventory]
```

## 3. Static Crawler

Static crawler đọc HTML thuần, lấy link và form nhưng không chạy JavaScript.

```mermaid
flowchart TD
    A[Đọc seed URL] --> B[Đưa seed vào queue]
    B --> C{Queue còn URL?}
    C -->|Không| Z[Trả danh sách record]
    C -->|Có| D[Lấy URL tiếp theo]
    D --> E{Trong scope và chưa thăm?}
    E -->|Không| C
    E -->|Có| F[Gửi GET bằng HttpSession]
    F --> G[Tạo EndpointRecord cho trang]
    G --> H{Response là HTML?}
    H -->|Không| C
    H -->|Có| I[Parse link và form]
    I --> J[Tạo record cho form]
    I --> K[Đưa link mới vào queue]
    J --> C
    K --> C
```

## 4. Dynamic Crawler

Dynamic crawler mở Chromium bằng Playwright để bắt request sinh bởi JavaScript, fetch hoặc XHR của SPA.

```mermaid
flowchart TD
    A[Mở Chromium] --> B[Tạo browser context]
    B --> E[Mở seed URL]
    E --> F[JavaScript gọi API]
    F --> G[Bắt response]
    G --> H{Resource type cần giữ?}
    H -->|Không| I[Bỏ qua image, css, font, media]
    H -->|Có| J{URL trong scope?}
    J -->|Không| I
    J -->|Có| K[Đọc method, URL, header, body, status]
    K --> L[ReconNormalizer tạo EndpointRecord]
```

## 5. Chuẩn Hóa Dữ Liệu

`ReconNormalizer` biến dữ liệu thô từ mọi nguồn thành cùng một format `EndpointRecord`.

```mermaid
flowchart TD
    A[Request/response thô] --> B[Chuẩn hóa URL]
    B --> C[Bỏ cache-buster params]
    C --> D[Chuẩn hóa path để dedupe]

    A --> E[Parse query params]
    A --> F[Parse body form-urlencoded]
    A --> G[Parse JSON body]

    A --> H[Lưu status, content-type và headers]

    D --> J[EndpointRecord]
    E --> J
    F --> J
    G --> J
    H --> J
```

## 6. Gom Trùng Endpoint

`EndpointDeduplicator` tạo fingerprint cho từng endpoint. Nếu fingerprint giống nhau, record được merge để tránh trùng dữ liệu.

```mermaid
flowchart TD
    A[Danh sách EndpointRecord] --> B[Tạo fingerprint]
    B --> C[method]
    B --> D[scheme, host, port]
    B --> E[canonical_path]
    B --> F[tên query/body/json param]
    B --> G[request content-type]

    B --> I{Fingerprint đã có?}
    I -->|Chưa| J[Thêm record mới]
    I -->|Rồi| K[Merge record]
    K --> L[Gộp status, params, samples, sources, evidence]
    J --> M[Danh sách đã dedupe]
    L --> M
```

## 7. Xuất Kết Quả

```mermaid
flowchart TD
    A[Record sau dedupe] --> B[ReconExporter.export_all]
    B --> C[inventory.json đầy đủ cho tool khác đọc]
    B --> D[params.txt danh sách param nhanh]
```

## 8. Class Chính

```mermaid
classDiagram
    class ReconApplication {
        +run(argv)
        -_load_config(args)
        -_collect_records(config)
        -_crawl(config)
        -_dedupe_records(records, config)
    }

    class ConfigLoader {
        +load(path)
    }

    class StaticHtmlCrawler {
        +crawl()
    }

    class DynamicCrawler {
        +crawl()
    }

    class ReconNormalizer {
        +make_record(...)
        +absolute_url(url, base_url)
        +parse_query_params(url)
        +parse_body_params(body, content_type)
    }

    class EndpointRecord {
        +method
        +url
        +params
        +evidence
        +add_param(param)
        +merge(other)
        +to_dict()
    }

    class EndpointDeduplicator {
        +dedupe(records)
        +fingerprint(record)
    }

    class ReconExporter {
        +export_all(records, output_dir)
        +export_json(records, output_path)
        +export_params(records, output_path)
    }

    ReconApplication --> ConfigLoader
    ReconApplication --> StaticHtmlCrawler
    ReconApplication --> DynamicCrawler
    ReconApplication --> EndpointDeduplicator
    ReconApplication --> ReconExporter
    StaticHtmlCrawler --> ReconNormalizer
    DynamicCrawler --> ReconNormalizer
    ReconNormalizer --> EndpointRecord
```
