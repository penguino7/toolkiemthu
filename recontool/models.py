from __future__ import annotations  # Cho phép dùng type hint của class ngay trong file này.

from dataclasses import dataclass, field  # dataclass giúp tạo class lưu dữ liệu ngắn gọn.
from typing import Any, Dict, List  # Các kiểu dữ liệu dùng cho type hint.


def _unique(values: List[Any]) -> List[Any]:
    """Giữ thứ tự ban đầu nhưng loại bỏ phần tử trùng.

    Hàm này dùng khi merge nhiều record/param lại với nhau. Ví dụ crawler thấy
    cùng một endpoint nhiều lần thì ta chỉ muốn giữ mỗi URL mẫu một lần.
    """
    seen = set()  # Lưu "dấu vết" của phần tử đã gặp để kiểm tra trùng.
    output = []  # Danh sách kết quả sau khi bỏ trùng.
    for value in values:  # Duyệt từng phần tử trong danh sách đầu vào.
        marker = repr(value)  # Biến object thành chuỗi ổn định để đưa vào set.
        if marker in seen:  # Nếu đã gặp phần tử này rồi thì bỏ qua.
            continue
        seen.add(marker)  # Đánh dấu phần tử này là đã gặp.
        output.append(value)  # Giữ lại phần tử chưa trùng.
    return output  # Trả về danh sách đã loại trùng.


@dataclass
class Param:
    """Đại diện cho một tham số của endpoint.

    Ví dụ:
    - `/search.php?q=test` có param `q` nằm ở `query`.
    - POST form `content=hello` có param `content` nằm ở `body`.
    - JSON `{"user": {"id": 1}}` có param `user.id` nằm ở `json`.
    """

    name: str  # Tên tham số, ví dụ: q, id, news_id, content.
    location: str  # Vị trí tham số: query, body hoặc json.
    type_hint: str = "string"  # Kiểu suy luận từ sample value: string, int, float, bool...
    sample_values: List[str] = field(default_factory=list)  # Giá trị mẫu đã quan sát được, không phải giá trị tool tự sinh.
    reflected: bool = False  # True nếu sample value xuất hiện lại trong response.
    candidate_tests: List[str] = field(default_factory=list)  # Gợi ý kiểm thử sau này, ví dụ: sqli, reflected_xss_candidate.

    @property
    def key(self) -> str:
        """Khóa duy nhất của param trong một endpoint.

        Cần cả `location` và `name` vì một endpoint có thể có `query:id` và
        `body:id`; hai param này không nên bị xem là một.
        """
        return f"{self.location}:{self.name}"  # Ví dụ: query:q, body:content, json:user.id.

    def add_value(self, value: Any) -> None:
        """Thêm sample value cho param.

        Sample value là giá trị tool đã nhìn thấy khi crawl/import, ví dụ `q=test`.
        Tool recon không tự sinh payload ở đây.
        """
        if value is None:  # Không lưu giá trị None vì không có ý nghĩa làm sample.
            return
        text = str(value)  # Chuyển mọi kiểu về string để export JSON/Markdown đơn giản.
        if text not in self.sample_values:  # Chỉ thêm nếu giá trị này chưa có.
            self.sample_values.append(text)
        if len(self.sample_values) > 8:  # Giới hạn số sample để file output không quá dài.
            self.sample_values = self.sample_values[:8]

    def merge(self, other: "Param") -> None:
        """Gộp thông tin của param trùng nhau.

        Dùng khi dedupe endpoint. Ví dụ cùng `query:q` được thấy ở nhiều URL
        hoặc nhiều crawler khác nhau.
        """
        self.type_hint = self.type_hint if self.type_hint != "string" else other.type_hint  # Ưu tiên type cụ thể hơn string.
        self.sample_values = _unique(self.sample_values + other.sample_values)[:8]  # Gộp sample và bỏ trùng.
        self.reflected = self.reflected or other.reflected  # Chỉ cần một lần reflected thì giữ True.
        self.candidate_tests = sorted(set(self.candidate_tests + other.candidate_tests))  # Gộp nhãn candidate và sort cho dễ đọc.

    def to_dict(self) -> Dict[str, Any]:
        """Chuyển Param thành dict để ghi ra inventory.json."""
        return {
            "name": self.name,  # Tên param.
            "location": self.location,  # Vị trí param.
            "type_hint": self.type_hint,  # Kiểu suy luận.
            "sample_values": self.sample_values,  # Các sample value đã quan sát.
            "reflected": self.reflected,  # Có reflected trong response hay không.
            "candidate_tests": self.candidate_tests,  # Các gợi ý kiểm thử liên quan param này.
        }


@dataclass
class EndpointRecord:
    """Một endpoint đã được chuẩn hóa.

    Đây là object trung tâm của tool. Static crawler, dynamic crawler, HAR importer
    và manual seed importer đều tạo ra EndpointRecord để các bước sau xử lý thống nhất.
    """

    method: str  # HTTP method: GET, POST, PUT, PATCH, DELETE...
    url: str  # URL đầy đủ đã normalize, ví dụ: http://127.0.0.1:12001/search.php?q=test.
    scheme: str  # Giao thức: http hoặc https.
    host: str  # Host/domain, ví dụ: 127.0.0.1, localhost, example.com.
    port: int | None  # Port nếu URL có ghi rõ, ví dụ: 12001; nếu không có thì None.
    path: str  # Path thật của URL, ví dụ: /search.php hoặc /api/spa/news.php.
    canonical_path: str  # Path dùng để dedupe, ví dụ: /news/{int} thay cho /news/1.
    auth_context: str = "anonymous"  # Context khi phát hiện endpoint: anonymous, admin, user...
    request_content_type: str = ""  # Content-Type của request body, ví dụ: application/json.
    response_content_type: str = ""  # Content-Type của response, ví dụ: text/html hoặc application/json.
    request_headers: Dict[str, str] = field(default_factory=dict)  # Header của request, ví dụ: user-agent, content-type, cookie.
    response_headers: Dict[str, str] = field(default_factory=dict)  # Header của response, ví dụ: content-type, set-cookie, location.
    statuses: List[int] = field(default_factory=list)  # Các HTTP status đã thấy, ví dụ: 200, 302, 404.
    params: Dict[str, Param] = field(default_factory=dict)  # Danh sách param, key dạng query:q hoặc body:content.
    forms: List[Dict[str, Any]] = field(default_factory=list)  # Form HTML đã parse được: action, method, inputs.
    source_tools: List[str] = field(default_factory=list)  # Nguồn phát hiện: static_html_crawler, playwright_dynamic_crawler...
    discovered_from: List[str] = field(default_factory=list)  # URL cha dẫn tới endpoint này, dùng để truy vết.
    examples: List[str] = field(default_factory=list)  # Một vài URL mẫu thật đã quan sát được.
    seen_count: int = 1  # Số lần endpoint này được thấy trước/sau dedupe.
    evidence: Dict[str, Any] = field(default_factory=dict)  # Metadata bổ sung, ví dụ: reflection_contexts, db_error_pattern.
    candidate_tests: List[str] = field(default_factory=list)  # Gợi ý kiểm thử cấp endpoint, ví dụ: sqli, form_endpoint.

    def add_param(self, param: Param) -> None:
        """Thêm param vào endpoint.

        Nếu param đã tồn tại thì merge thay vì ghi đè, để không mất sample value
        hoặc candidate_tests đã thu thập trước đó.
        """
        if param.key in self.params:  # Nếu đã có param cùng location:name.
            self.params[param.key].merge(param)  # Gộp thông tin param mới vào param cũ.
        else:
            self.params[param.key] = param  # Nếu chưa có thì thêm mới.

    def merge(self, other: "EndpointRecord") -> None:
        """Gộp endpoint trùng nhau sau bước dedupe."""
        self.seen_count += other.seen_count  # Cộng số lần nhìn thấy endpoint.
        self.statuses = sorted(set(self.statuses + other.statuses))  # Gộp HTTP status và bỏ trùng.
        if not self.response_content_type and other.response_content_type:  # Nếu record hiện tại thiếu response content-type.
            self.response_content_type = other.response_content_type  # Lấy response content-type từ record khác.
        if not self.request_content_type and other.request_content_type:  # Nếu record hiện tại thiếu request content-type.
            self.request_content_type = other.request_content_type  # Lấy request content-type từ record khác.
        self.request_headers.update({k: v for k, v in other.request_headers.items() if v})  # Gộp request headers có giá trị.
        self.response_headers.update({k: v for k, v in other.response_headers.items() if v})  # Gộp response headers có giá trị.
        for param in other.params.values():  # Duyệt toàn bộ param của record khác.
            self.add_param(param)  # Thêm hoặc merge param vào record hiện tại.
        self.forms = _unique(self.forms + other.forms)  # Gộp form đã thấy và bỏ trùng.
        self.source_tools = sorted(set(self.source_tools + other.source_tools))  # Gộp nguồn phát hiện.
        self.discovered_from = _unique(self.discovered_from + other.discovered_from)[:20]  # Giữ tối đa 20 URL cha.
        self.examples = _unique(self.examples + other.examples)[:10]  # Giữ tối đa 10 URL mẫu.
        self.candidate_tests = sorted(set(self.candidate_tests + other.candidate_tests))  # Gộp candidate test.
        self.evidence.update({k: v for k, v in other.evidence.items() if v})  # Gộp evidence có giá trị truthy.

    def to_dict(self) -> Dict[str, Any]:
        """Chuyển EndpointRecord thành dict để ghi ra inventory.json."""
        return {
            "method": self.method,  # HTTP method.
            "url": self.url,  # URL đầy đủ.
            "scheme": self.scheme,  # http hoặc https.
            "host": self.host,  # Host/domain.
            "port": self.port,  # Port.
            "path": self.path,  # Path thật.
            "canonical_path": self.canonical_path,  # Path đã chuẩn hóa để dedupe.
            "auth_context": self.auth_context,  # Context đăng nhập khi phát hiện.
            "request_content_type": self.request_content_type,  # Content-Type của request.
            "response_content_type": self.response_content_type,  # Content-Type của response.
            "request_headers": self.request_headers,  # Header request đã ghi nhận.
            "response_headers": self.response_headers,  # Header response đã ghi nhận.
            "statuses": self.statuses,  # Danh sách HTTP status đã thấy.
            "params": [p.to_dict() for p in sorted(self.params.values(), key=lambda p: p.key)],  # Param đã sort cho output ổn định.
            "forms": self.forms,  # Form HTML đã phát hiện.
            "source_tools": self.source_tools,  # Crawler/importer nào phát hiện endpoint.
            "discovered_from": self.discovered_from,  # URL cha.
            "examples": self.examples,  # URL mẫu.
            "seen_count": self.seen_count,  # Số lần thấy endpoint.
            "evidence": self.evidence,  # Metadata bằng chứng quan sát được.
            "candidate_tests": self.candidate_tests,  # Gợi ý kiểm thử cấp endpoint.
        }
