# Biểu Đồ Hoạt Động Recon Tool

File này mô tả luồng hoạt động của toàn bộ recon tool bằng Mermaid. Có thể xem trực tiếp trên GitHub vì GitHub hỗ trợ render Mermaid trong Markdown.

## 1. Luồng Tổng Quan

```mermaid
flowchart TD
    A[User chạy run_recon.sh] --> B[ReconApplication trong cli.py]
    B --> C[ConfigLoader đọc config.example.json]
    C --> D[Áp dụng CLI options]
    D --> E{Chạy nguồn dữ liệu nào?}

    E -->|Static| F[StaticHtmlCrawler]
    E -->|Dynamic| G[DynamicCrawler]
    E -->|Importer| H[ManualSeedImporter / HarImporter]

    F --> I[ReconNormalizer.make_record]
    G --> I
    H --> I

    I --> J[EndpointRecord]
    J --> K[RecordEnricher]
    K --> L[EndpointDeduplicator]
    L --> M[ReconExporter]

    M --> N[inventory.json]
    M --> O[inventory.md]
    M --> P[params.txt]
    M --> Q[test_plan.md]
```

## 2. Luồng CLI Chính

```mermaid
flowchart TD
    A[__main__.py gọi main] --> B[ReconApplication.run]
    B --> C[CliArgumentParser.build]
    C --> D[Parse arguments]
    D --> E[ConfigLoader.load]
    E --> F[Apply CLI overrides]
    F --> G[Collect records]
    G --> H[Run crawlers]
    G --> I[Run importers]
    H --> J[Raw records]
    I --> J
    J --> K[RecordEnricher.enrich_many]
    K --> L[EndpointDeduplicator.dedupe]
    L --> M[ReconExporter.export_all]
```

## 3. Luồng Static Crawler

```mermaid
flowchart TD
    A[StaticHtmlCrawler.crawl] --> B[Load seeds từ config]
    B --> C[Đưa seed vào queue]
    C --> D{Queue còn URL?}
    D -->|Không| Z[Trả về records]
    D -->|Có| E[Lấy URL tiếp theo]

    E --> F{visited/depth/scope hợp lệ?}
    F -->|Không| D
    F -->|Có| G[HttpSession.get URL]

    G --> H[ReconNormalizer.make_record cho page]
    H --> I{Response là HTML?}

    I -->|Không| D
    I -->|Có| J[HtmlDiscoveryParser parse HTML]
    J --> K[Lấy forms]
    J --> L[Lấy links]

    K --> M[Tạo EndpointRecord cho form]
    L --> N[Normalize link]
    N --> O{Link in scope và chưa visited?}
    O -->|Có| P[Đưa link vào queue]
    O -->|Không| D
    P --> D
```

## 4. Luồng Dynamic Crawler

```mermaid
flowchart TD
    A[DynamicCrawler.crawl] --> B[Load Playwright]
    B --> C[Mở Chromium]
    C --> D[Tạo browser context]
    D --> E[Đăng ký page.on response]
    E --> F{Có auth form?}

    F -->|Có| G[Login form]
    F -->|Không| H[Crawl seeds]
    G --> H

    H --> I[page.goto seed URL]
    I --> J[JavaScript trên trang gọi API]
    J --> K[_on_response bắt response]

    K --> L{Resource type hợp lệ?}
    L -->|Không| X[Bỏ qua image/font/css/media]
    L -->|Có| M{URL in scope?}

    M -->|Không| Y[Bỏ qua ngoài scope]
    M -->|Có| N[Đọc method/url/headers/body/status]
    N --> O[ReconNormalizer.make_record]
    O --> P[Thêm EndpointRecord vào records]

    I --> Q{auto_scroll bật?}
    Q -->|Có| R[Scroll để kích hoạt lazy-load]
    Q -->|Không| S[Run configured click actions]
    R --> S
    S --> T[Lấy a href mới]
    T --> U[Đưa URL mới vào queue]
```

## 5. Luồng Normalize Dữ Liệu

```mermaid
flowchart TD
    A[Dữ liệu thô từ crawler/importer] --> B[ReconNormalizer.make_record]
    B --> C[absolute_url]
    C --> D[Bỏ cache-buster params]
    D --> E[Sort query params]
    E --> F[canonicalize_path]

    B --> G[parse_query_params]
    B --> H[parse_body_params]
    H --> I{Content-Type JSON?}
    I -->|Có| J[Flatten JSON thành json params]
    I -->|Không| K[Parse form-urlencoded body]

    B --> L[mark_reflections]
    L --> M{Sample value xuất hiện trong response?}
    M -->|Có| N[Đánh dấu reflected/context]
    M -->|Không| O[Không có reflection metadata]

    F --> P[EndpointRecord]
    G --> P
    J --> P
    K --> P
    N --> P
    O --> P
```

## 6. Luồng Lọc Dữ Liệu

```mermaid
flowchart TD
    A[config.example.json] --> B[ScopePolicy]
    B --> C[Lọc host/path]

    C --> D[StaticHtmlCrawler]
    C --> E[DynamicCrawler]

    D --> F[Lọc visited/max_depth/max_pages/content-type]
    E --> G[Lọc resource_types và scope]

    F --> H[ReconNormalizer]
    G --> H

    H --> I[Bỏ cache-buster params]
    H --> J[Chuẩn hóa URL/path]
    H --> K[Parse query/body/json params]

    I --> L[EndpointRecord]
    J --> L
    K --> L

    L --> M[RecordEnricher]
    M --> N[Gắn candidate metadata]
    N --> O[EndpointDeduplicator]
    O --> P[Gom endpoint trùng]
    P --> Q[ReconExporter]
```

## 7. Luồng Dedupe

```mermaid
flowchart TD
    A[Danh sách EndpointRecord] --> B[EndpointDeduplicator]
    B --> C[Tạo fingerprint]

    C --> D[method]
    C --> E[scheme/host/port]
    C --> F[canonical_path]
    C --> G[query/body/json param names]
    C --> H[request content-type]
    C --> I[auth_context]

    C --> J{Fingerprint đã tồn tại?}
    J -->|Chưa| K[Thêm record mới]
    J -->|Rồi| L[Merge record]

    L --> M[Gộp statuses]
    L --> N[Gộp params/sample_values]
    L --> O[Gộp source_tools]
    L --> P[Gộp examples/evidence]
    L --> Q[Gộp candidate_tests]

    K --> R[Danh sách đã dedupe]
    Q --> R
```

## 8. Luồng Enrich Candidate

```mermaid
flowchart TD
    A[EndpointRecord] --> B[RecordEnricher]
    B --> C[Duyệt từng Param]

    C --> D{Param giống SQLi candidate?}
    D -->|Có| E[Thêm sqli hoặc sqli_json]
    D -->|Không| F[Không gắn SQLi]

    C --> G{Param giống XSS candidate?}
    G -->|Có| H[Thêm reflected/stored/api_xss_source]
    G -->|Không| I[Không gắn XSS]

    B --> J{Có form?}
    J -->|Có| K[Thêm form_endpoint]
    J -->|Không| L[Không thêm form_endpoint]

    E --> M[EndpointRecord đã enrich]
    H --> M
    K --> M
    F --> M
    I --> M
    L --> M
```

## 9. Luồng Export

```mermaid
flowchart TD
    A[Records sau enrich và dedupe] --> B[ReconExporter.export_all]

    B --> C[export_json]
    B --> D[export_markdown]
    B --> E[export_params]
    B --> F[export_test_plan]

    C --> G[inventory.json đầy đủ]
    D --> H[inventory.md dễ đọc]
    E --> I[params.txt danh sách param]
    F --> J[test_plan.md nhóm candidate]

    F --> K[SQLi]
    F --> L[Reflected XSS]
    F --> M[Stored XSS]
    F --> N[API/DOM XSS Source]
    F --> O[Forms]
```

## 10. Sơ Đồ Class Chính

```mermaid
classDiagram
    class ReconApplication {
        +run(argv)
        -_apply_cli_overrides(config, args)
        -_collect_records(config, args)
        -_run_crawlers(config, args)
        -_run_importers(config)
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

```mermaid
flowchart LR
    A[URL/Form/API/HAR/Manual seed] --> B[ReconNormalizer]
    B --> C[EndpointRecord]
    C --> D[Enrich]
    D --> E[Dedupe]
    E --> F[Export]
    F --> G[inventory.json]
    F --> H[test_plan.md]
```
