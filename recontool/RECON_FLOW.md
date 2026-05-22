# Biểu Đồ Hoạt Động Recon Tool

File này mô tả luồng hoạt động của toàn bộ recon tool bằng Mermaid. GitHub có thể render trực tiếp các biểu đồ trong file Markdown này.

Ghi chú:

- Các tên class như `ReconApplication`, `StaticHtmlCrawler`, `EndpointRecord` được giữ nguyên để đối chiếu với source code.
- Các bước xử lý, điều kiện và nhãn mũi tên được viết bằng tiếng Việt.
- Tool này chỉ làm recon: thu thập, chuẩn hóa, gắn metadata, gom trùng và xuất báo cáo.

## 1. Luồng Tổng Quan

Biểu đồ này cho thấy toàn bộ pipeline từ lúc người dùng chạy tool đến lúc sinh file kết quả.

```mermaid
flowchart TD
    A[Người dùng chạy run_tool.sh và chọn recon] --> B[Ứng dụng chính: ReconApplication]
    B --> C[Đọc cấu hình bằng ConfigLoader]
    C --> D[Áp dụng tham số từ dòng lệnh]
    D --> E{Nguồn dữ liệu nào được bật?}

    E -->|Crawler tĩnh| F[StaticHtmlCrawler]
    E -->|Crawler động| G[DynamicCrawler]
    E -->|Importer| H[ManualSeedImporter hoặc HarImporter]

    F --> I[Chuẩn hóa bằng ReconNormalizer]
    G --> I
    H --> I

    I --> J[EndpointRecord]
    J --> K[Gắn metadata bằng RecordEnricher]
    K --> L[Gom trùng bằng EndpointDeduplicator]
    L --> M[Xuất file bằng ReconExporter]

    M --> N[inventory.json]
    M --> O[inventory.md]
    M --> P[params.txt]
    M --> Q[test_plan.md]
```

## 2. Luồng CLI Chính

Biểu đồ này mô tả file `cli.py`. Đây là nơi điều phối các bước chính của tool.

```mermaid
flowchart TD
    A[__main__.py gọi hàm main] --> B[ReconApplication.run]
    B --> C[Tạo parser tham số dòng lệnh]
    C --> D[Đọc tham số người dùng nhập]
    D --> E[Đọc file cấu hình]
    E --> F[Ghi đè cấu hình bằng tham số CLI]
    F --> G[Thu thập record]
    G --> H[Chạy crawler]
    G --> I[Chạy importer]
    H --> J[Danh sách record thô]
    I --> J
    J --> K[Gắn nhãn candidate]
    K --> L[Gom endpoint trùng]
    L --> M[Xuất toàn bộ kết quả]
```

## 3. Luồng Static Crawler

Static crawler đọc HTML không chạy JavaScript. Nó phù hợp với trang server-rendered, link HTML và form HTML.

```mermaid
flowchart TD
    A[Bắt đầu StaticHtmlCrawler.crawl] --> B[Đọc seed từ config]
    B --> C[Đưa seed vào hàng đợi]
    C --> D{Hàng đợi còn URL?}
    D -->|Không| Z[Trả về danh sách record]
    D -->|Có| E[Lấy URL tiếp theo]

    E --> F{URL đã thăm, quá sâu, hoặc ngoài scope?}
    F -->|Có| D
    F -->|Không| G[Gửi GET bằng HttpSession]

    G --> H[Tạo record cho trang hiện tại]
    H --> I{Response có phải HTML?}

    I -->|Không| D
    I -->|Có| J[Parse HTML bằng HtmlDiscoveryParser]
    J --> K[Lấy danh sách form]
    J --> L[Lấy danh sách link]

    K --> M[Tạo record cho form]
    L --> N[Chuẩn hóa link]
    N --> O{Link còn trong scope và chưa thăm?}
    O -->|Có| P[Đưa link vào hàng đợi]
    O -->|Không| D
    P --> D
```

## 4. Luồng Dynamic Crawler

Dynamic crawler chạy Chromium bằng Playwright. Nó dùng để bắt request sinh ra bởi JavaScript, đặc biệt là fetch/XHR của SPA.

```mermaid
flowchart TD
    A[Bắt đầu DynamicCrawler.crawl] --> B[Nạp Playwright]
    B --> C[Mở Chromium]
    C --> D[Tạo browser context]
    D --> E[Đăng ký sự kiện bắt response]
    E --> F{Có cấu hình login form?}

    F -->|Có| G[Đăng nhập bằng form]
    F -->|Không| H[Crawl các seed URL]
    G --> H

    H --> I[Đi tới seed bằng page.goto]
    I --> J[JavaScript trên trang gọi API]
    J --> K[Bắt response trong _on_response]

    K --> L{Loại resource có cần giữ?}
    L -->|Không| X[Bỏ qua image, font, css, media]
    L -->|Có| M{URL có nằm trong scope?}

    M -->|Không| Y[Bỏ qua URL ngoài phạm vi]
    M -->|Có| N[Đọc method, URL, header, body, status]
    N --> O[Tạo EndpointRecord]
    O --> P[Lưu record vào danh sách]

    I --> Q{Có bật auto scroll?}
    Q -->|Có| R[Scroll để kích hoạt lazy-load API]
    Q -->|Không| S[Click selector đã cấu hình]
    R --> S
    S --> T[Lấy thêm link a href]
    T --> U[Đưa URL mới vào hàng đợi]
```

## 5. Luồng Chuẩn Hóa Dữ Liệu

`ReconNormalizer` là nơi biến dữ liệu thô từ crawler/importer thành `EndpointRecord`.

```mermaid
flowchart TD
    A[Dữ liệu thô từ crawler hoặc importer] --> B[ReconNormalizer.make_record]
    B --> C[Chuẩn hóa URL tuyệt đối]
    C --> D[Bỏ tham số gây nhiễu như cache, timestamp, utm]
    D --> E[Sắp xếp query param]
    E --> F[Chuẩn hóa path để phục vụ dedupe]

    B --> G[Parse query param]
    B --> H[Parse body param]
    H --> I{Body có phải JSON?}
    I -->|Có| J[Flatten JSON thành json param]
    I -->|Không| K[Parse body dạng form-urlencoded]

    B --> L[Kiểm tra reflection từ sample value]
    L --> M{Sample value có xuất hiện trong response?}
    M -->|Có| N[Ghi nhận reflected và context]
    M -->|Không| O[Không có metadata reflection]

    F --> P[EndpointRecord]
    G --> P
    J --> P
    K --> P
    N --> P
    O --> P
```

## 6. Luồng Lọc Dữ Liệu

Biểu đồ này mô tả các lớp lọc dữ liệu: lọc scope, lọc resource, lọc tham số gây nhiễu và gom trùng endpoint.

```mermaid
flowchart TD
    A[recon.config.example.json] --> B[ScopePolicy]
    B --> C[Lọc host và path được phép crawl]

    C --> D[StaticHtmlCrawler]
    C --> E[DynamicCrawler]

    D --> F[Lọc URL đã thăm, độ sâu, số trang, content-type]
    E --> G[Lọc resource type và scope]

    F --> H[ReconNormalizer]
    G --> H

    H --> I[Bỏ cache-buster param]
    H --> J[Chuẩn hóa URL và path]
    H --> K[Parse query, body, json param]

    I --> L[EndpointRecord]
    J --> L
    K --> L

    L --> M[RecordEnricher]
    M --> N[Gắn metadata candidate]
    N --> O[EndpointDeduplicator]
    O --> P[Gom endpoint trùng]
    P --> Q[ReconExporter]
```

## 7. Luồng Gom Trùng Endpoint

`EndpointDeduplicator` tạo fingerprint cho từng endpoint. Nếu fingerprint giống nhau, record sẽ được merge.

```mermaid
flowchart TD
    A[Danh sách EndpointRecord] --> B[EndpointDeduplicator]
    B --> C[Tạo fingerprint]

    C --> D[HTTP method]
    C --> E[scheme, host, port]
    C --> F[canonical_path]
    C --> G[tên query, body, json param]
    C --> H[request content-type]
    C --> I[auth_context]

    C --> J{Fingerprint đã tồn tại?}
    J -->|Chưa| K[Thêm record mới]
    J -->|Rồi| L[Gộp record]

    L --> M[Gộp status code]
    L --> N[Gộp param và sample value]
    L --> O[Gộp nguồn phát hiện]
    L --> P[Gộp URL mẫu và evidence]
    L --> Q[Gộp candidate_tests]

    K --> R[Danh sách đã gom trùng]
    Q --> R
```

## 8. Luồng Gắn Nhãn Candidate

`RecordEnricher` chỉ gắn metadata gợi ý. Nó không kết luận có lỗ hổng và không gửi giá trị kiểm thử.

```mermaid
flowchart TD
    A[EndpointRecord] --> B[RecordEnricher]
    B --> C[Duyệt từng Param]

    C --> D{Param giống candidate SQLi?}
    D -->|Có| E[Thêm nhãn sqli hoặc sqli_json]
    D -->|Không| F[Không thêm nhãn SQLi]

    C --> G{Param giống candidate XSS?}
    G -->|Có| H[Thêm nhãn reflected, stored hoặc api_xss_source]
    G -->|Không| I[Không thêm nhãn XSS]

    B --> J{Endpoint có form?}
    J -->|Có| K[Thêm nhãn form_endpoint]
    J -->|Không| L[Không thêm nhãn form_endpoint]

    E --> M[EndpointRecord đã enrich]
    H --> M
    K --> M
    F --> M
    I --> M
    L --> M
```

## 9. Luồng Xuất Kết Quả

`ReconExporter` tạo các file kết quả từ danh sách record đã enrich và dedupe.

```mermaid
flowchart TD
    A[Record sau enrich và dedupe] --> B[ReconExporter.export_all]

    B --> C[Xuất JSON đầy đủ]
    B --> D[Xuất Markdown dễ đọc]
    B --> E[Xuất danh sách param]
    B --> F[Xuất kế hoạch kiểm thử thủ công]

    C --> G[inventory.json]
    D --> H[inventory.md]
    E --> I[params.txt]
    F --> J[test_plan.md]

    F --> K[Nhóm SQLi]
    F --> L[Nhóm Reflected XSS]
    F --> M[Nhóm Stored XSS]
    F --> N[Nhóm API hoặc DOM XSS Source]
    F --> O[Nhóm Forms]
```

## 10. Sơ Đồ Class Chính

Biểu đồ này giữ tên class/method bằng tiếng Anh vì chúng trùng với source code. Phần quan hệ thể hiện class nào gọi hoặc phụ thuộc class nào.

```mermaid
classDiagram
    class ReconApplication {
        +run(argv)
        -_load_config(args)
        -_collect_records(config, auth_profile_names)
        -_crawl(config, auth_profile_names)
        -_import(config)
        -_enrich_and_dedupe(records, config)
    }

    class ConfigLoader {
        +load(path)
        +deep_merge(base, override)
    }

    class ScopePolicy {
        +allows(url)
    }

    class StaticHtmlCrawler {
        +crawl()
        -_crawl_one_page(url, parent)
        -_make_page_record(...)
        -_make_form_records(...)
    }

    class DynamicCrawler {
        +crawl()
        -_login_with_form(page)
        -_crawl_pages(page, seeds)
        -_on_response(response)
    }

    class ReconNormalizer {
        +make_record(...)
        +absolute_url(url, base_url)
        +parse_query_params(url)
        +parse_body_params(body, content_type)
        +canonicalize_path(path)
    }

    class EndpointRecord {
        +method
        +url
        +params
        +candidate_tests
        +add_param(param)
        +merge(other)
        +to_dict()
    }

    class Param {
        +name
        +location
        +type_hint
        +sample_values
        +add_value(value)
        +merge(other)
        +to_dict()
    }

    class RecordEnricher {
        +enrich_many(records)
        +enrich_one(record)
    }

    class EndpointDeduplicator {
        +dedupe(records)
        +fingerprint(record)
    }

    class ReconExporter {
        +export_all(records, output_dir)
        +export_json(records, output_path)
        +export_markdown(records, output_path)
        +export_params(records, output_path)
        +export_test_plan(records, output_path)
    }

    ReconApplication --> ConfigLoader
    ReconApplication --> StaticHtmlCrawler
    ReconApplication --> DynamicCrawler
    ReconApplication --> RecordEnricher
    ReconApplication --> EndpointDeduplicator
    ReconApplication --> ReconExporter
    StaticHtmlCrawler --> ScopePolicy
    DynamicCrawler --> ScopePolicy
    StaticHtmlCrawler --> ReconNormalizer
    DynamicCrawler --> ReconNormalizer
    ReconNormalizer --> EndpointRecord
    EndpointRecord --> Param
```

## 11. Luồng Dữ Liệu Rút Gọn

Biểu đồ cuối cùng là bản rút gọn để nhớ nhanh: mọi nguồn dữ liệu đều được chuẩn hóa thành `EndpointRecord`, sau đó enrich, dedupe và export.

```mermaid
flowchart LR
    A[URL, form, API, HAR, manual seed] --> B[Chuẩn hóa dữ liệu]
    B --> C[EndpointRecord]
    C --> D[Gắn metadata]
    D --> E[Gom trùng]
    E --> F[Xuất kết quả]
    F --> G[inventory.json]
    F --> H[test_plan.md]
```
