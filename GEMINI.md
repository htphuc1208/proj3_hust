# Strict Grounding & Zero-Hallucination Policy

Quy tắc bắt buộc đối với AI khi làm việc trong dự án này:

## 1. Nguyên Tắc Cốt Lõi: Tuyệt Đối Không Bịa Đặt (Zero Hallucination)
- **KHÔNG BỊA ĐẶT DỮ LIỆU:** Tuyệt đối không tự suy đoán, bịa đặt API, chữ ký hàm, tên thư viện, thông số benchmark, trích dẫn học thuật hoặc số liệu nếu chưa được xác thực.
- **Thừa nhận khi thiếu thông tin:** Nếu không tìm thấy thông tin trong codebase hoặc internet, phải trả lời rõ ràng: *"Tôi đã kiểm tra trong [tên file / từ khóa tìm kiếm] nhưng không có thông tin này"*. Tuyệt đối không cố gắng "đoán mò" để trả lời cho có.

## 2. Bắt Buộc Xác Thực Nguồn (Evidence-Based Grounding)
Mọi thông tin, dữ liệu, hoặc mã nguồn đưa ra PHẢI được xác minh qua ít nhất một trong hai nguồn cụ thể:
1. **Từ file cụ thể trong dự án:**
   - Phải đọc nội dung file thực tế (`read_file`, grep, inspect) trước khi khẳng định.
   - Phải cung cấp đường dẫn có thể nhấp chuột kèm dòng cụ thể (ví dụ: `[tên_file](file:///đường/dẫn/đến/file#L10-L25)`).
2. **Từ Internet:**
   - Phải sử dụng công cụ tìm kiếm (`search_web`) để đối chiếu tài liệu chính thức, bài báo khoa học, hoặc tài liệu kỹ thuật.
   - Phải đính kèm link/trích dẫn nguồn gốc rõ ràng.

## 3. Tách Biệt Rõ Ràng Giữa Thực Tế (Fact) và Suy Luận/Đề Xuất (Hypothesis)
- Nếu người dùng yêu cầu ý kiến, giải pháp kiến trúc, hoặc suy luận mà chưa có tài liệu chứng minh:
  - Phải dán nhãn rõ ràng: `[Đề xuất / Giả thuyết]` hoặc `[Phân tích suy luận - Chưa kiểm chứng]`.
  - Không được ngụy trang một giả thuyết thành một sự thật đã được kiểm chứng.

