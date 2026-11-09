# Kết quả triển khai và quyết định nghiên cứu V2

## Kết luận hiện tại

Đã triển khai đối soát có chứng cứ, checker riêng, CLI, đối chứng và pipeline
development cách ly oracle. **Chưa có bằng chứng V2 vượt đối chứng ngữ nghĩa mạnh
về độ đúng.** Gate `NOT_MET_EQUAL_STRONG_CONTROL` ngăn việc dùng phiên bản này để
chạy held-out với claim accuracy-superiority.

Nguồn kết quả chính là [run development v4](../runs/certified-development-v4/REPORT.md)
và [summary](../runs/certified-development-v4/summary.json). Có 20 dự án development
cũ, ba điều kiện, năm phương pháp: 60 ca ghép cặp và 300 lượt phương pháp.
Số dự án độc lập vẫn là 20. Không dùng dự án held-out, không gọi LLM/API.

## Kết quả đo

Điều kiện đủ metadata và ngữ cảnh:

| Phương pháp | F1 cạnh, cùng 11 dự án có cạnh reference | FP trên toàn bộ 20 dự án | FN trên toàn bộ 20 dự án |
| --- | ---: | ---: | ---: |
| Quan sát | 0,8702 | 42 | 4 |
| Legacy additive | 0,8813 | 42 | 0 |
| Legacy additive + reconciliation | 0,9464 | 17 | 0 |
| Đối chứng ngữ nghĩa mạnh | 1,0000 | 1 | 0 |
| Certified V2 | 1,0000 | 1 | 0 |

F1 bằng 1 ở panel này **không có nghĩa toàn bộ 20 dự án hoàn hảo**. Một FP còn ở
dự án có reference rỗng nên không nằm trong mẫu số F1 của panel. Cụ thể, metadata
pyserial khai báo `Metadata-Version: 2.0`, nằm ngoài tập phiên bản metadata đầy đủ
được V2 hỗ trợ; V2 giữ quan hệ chưa chứng minh được thay vì tự coi đó là âm tính.
Baseline v1 vốn chấp nhận metadata lịch sử này và được giữ đúng hành vi đó.

V2 thực hiện 45 thay đổi có nhãn xác định trong điều kiện đủ thông tin: thêm bốn
cạnh và rút 41 cạnh. Ở điều kiện giấu ngữ cảnh, V2 thêm bốn cạnh; ở điều kiện che
50% metadata, V2 không thay đổi cạnh nào. Tổng 49 là **số lần thay đổi qua các điều
kiện**, không phải 49 cạnh độc lập hoặc 49 dự án. Reference hiện tại không chấm sai
thay đổi nào trong số này. Điều đó không tạo bảo đảm sai số bằng 0 ngoài mẫu.

V2 và đối chứng mạnh có **cùng tập cạnh trong 60/60 ca**. Hai phương pháp chia sẻ
parser, binding và ngữ nghĩa marker/activation. Đối chứng trực tiếp diễn giải các
khai báo, không dùng proposal generator hoặc certificates. Kết quả hòa không phải
một phép so sánh độc lập với toàn bộ SOTA; nó chỉ ra rằng certificates không tự
tạo thêm thông tin suy luận. Không được chuyển cải thiện trước baseline cũ thành
claim AI hay claim thuật toán mới.

Hai điều kiện giấu thông tin là can thiệp có kiểm soát; không chứng minh lỗi
metadata ngoài thực tế tuân theo cùng cơ chế hoặc có cùng tỷ lệ. Mọi thất bại và
điều kiện legacy không hỗ trợ vẫn nằm trong dữ liệu. Báo cáo theo điều kiện và
kiểm định ghép cặp theo dự án được lưu riêng; mẫu số không xác định giữ `null`.

## Đã hoàn thành về phần mềm

- `ContextKnowledgeV2`, `CompletenessClaim`, `ReconciliationDecisionV2` và
  certificate có binding tới input/context/evidence.
- Binding theo occurrence vật lý từ native locations; không ghép chỉ theo PURL.
- Marker ba giá trị, extra seeds rõ mức đầy đủ, lower derivation và upper
  activation invariant; parent chưa đọc không bị tự coi là không liên quan.
- Ba rule cho khai báo hoạt động, không có khai báo khớp trong parent đầy đủ và
  mọi khai báo khớp đều bất hoạt.
- Checker riêng kiểm tra rule, trích dẫn, điều kiện đầy đủ, stale inputs và
  activation witness trước khi áp dụng thay đổi.
- CLI thu thập/đối soát, SBOM gốc bất biến, bản dẫn xuất, assessments và seal.
- Docker worker không có network, target đầy đủ, oracle, metadata bị che hoặc
  context bị giấu trong mounts; tất cả prediction được niêm phong trước chấm.
- Frozen source chứa cả thay đổi working tree; thêm `pyproject.toml` làm dấu root
  để source bundle không nhận nhầm `.git` của thư mục cha khi tái lập.
- Kiểm tra 432 mô hình fixed-point nhỏ bằng liệt kê các thế giới phù hợp, kiểm
  tra marker, giả mạo chứng cứ, CLI và ranh giới dữ liệu.

Kiểm tra cuối: `368 tests`, `OK (skipped=2)` — 366 đạt và hai bỏ qua.
Chạy ngoài sandbox để các test HTTP localhost có thể mở socket. CLI replay trên
ca requests cho prediction cùng hash với bản chạy trong container. Unit tests
và chứng cứ thực thi không được dùng thay cho bằng chứng novelty.

## Tính hợp lệ và các phiên bản artifact

- `certified-development-v2`: adapter chưa nhận Syft `sourceInfo`, không có
  binding; chỉ là engineering run. Có `VALIDITY_NOTE.md`.
- `certified-development-v3`: đã sửa binding; báo cáo cũ dùng số cạnh native
  reference có application-root nhân tạo để chọn mẫu số. Sealed predictions
  được giữ nguyên.
- `certified-analysis-v1`: sửa mẫu số bằng chấm lại sealed predictions v3, không
  chạy suy luận. Adapter legacy lúc đó còn nhận hạn chế Metadata-Version của V2.
- `certified-development-v4`: run cuối với mẫu số đúng và test hồi quy bảo toàn
  hành vi legacy đối với metadata 2.0. Đây là nguồn dùng cho bảng kết quả trên.

Oracle cũ là reference cho installed declarations, có giới hạn coordinate-level
và vẫn chia sẻ metadata/standards libraries với phương pháp. Thay đổi trên
occurrence mơ hồ không nhận nhãn đúng/sai chỉ vì trùng PURL. Chưa có đánh giá
executable contents, runtime reachability, exploitability hoặc lợi ích triage.

## Công việc nghiên cứu còn lại và quyết định

[Packet review](../runs/certified-development-v4/review-packet.json) có 88 task:
chọn tối đa 40 task ở mỗi nhóm thêm/rút/từ chối; không đủ 120 vì nhóm thêm có ít
quyết định. Số review human hoàn tất là **0**. Đây là packet single-author;
không tuyên bố double annotation, independent review hoặc inter-rater agreement.

Các so sánh mới với CycloneDX Python environment, SIT và unifier theo đúng scope
chưa hoàn thành. Cohort mới chưa bị tiêu thụ. Các hạng mục này không được báo là
đã xong chỉ vì đã có code/protocol.

Theo điều kiện dừng đã chốt, **không triển khai held-out accuracy-superiority cho
phiên bản này**. Trước một nghiên cứu mới cần xác lập giá trị phân biệt của việc
kiểm tra chứng cứ: chẳng hạn giảm cơ sở phải tin hoặc giảm công sức kiểm toán,
với đối chứng đã có và đánh giá độc lập thích hợp. Đây là câu hỏi cần nghiên cứu,
chưa phải đóng góp đã chứng minh. Nền tảng certain answers và query completeness
đã có trong literature; việc đặt tên mới cho chúng không đủ cho bài A*.

Protocol, lập luận tính đúng có điều kiện và nguồn literature nằm trong
[hướng dẫn V2](CERTIFIED_RECONCILIATION.md).
