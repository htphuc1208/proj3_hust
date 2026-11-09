# Dàn ý báo cáo tiến độ — SBOM Recovery

Cập nhật theo mã nguồn và artifact có trong repo ngày 09/11/2026. Đề xuất **11 slide**, khoảng 10–12 phút. Các kết quả dưới đây thuộc những đợt thử nghiệm khác nhau; mỗi trang ghi rõ tập dữ liệu và phạm vi.

Thông điệp xuyên suốt: **Đã xây dựng hệ thống khôi phục và đối soát đồ thị SBOM có bằng chứng, hoàn thành một số đánh giá thực nghiệm; đóng góp riêng của AI và khả năng tổng quát hóa vẫn cần kiểm chứng tiếp.**

## Slide 1 — Đề tài và mục tiêu giai đoạn

**Tiêu đề:** Khôi phục đồ thị phụ thuộc SBOM dựa trên bằng chứng và ngữ cảnh môi trường.

- Mục tiêu: phát hiện thiếu/sai thông tin package và quan hệ phụ thuộc trong SBOM.
- Đầu ra: đồ thị dẫn xuất, danh sách thay đổi và bằng chứng cho từng thay đổi.
- Tiến độ chính: đã có bộ xử lý, benchmark, agent lựa chọn bằng chứng và giao diện demo.

**Hình gợi ý:** một đồ thị nhỏ trước/sau khôi phục; đánh dấu cạnh bổ sung và cạnh bị đối soát loại bỏ.

## Slide 2 — Bài toán cần giải quyết và phạm vi

- SBOM quan sát có thể vừa thiếu cạnh vừa chứa cạnh không phù hợp với môi trường đích.
- Quan hệ phụ thuộc thay đổi theo phiên bản Python, hệ điều hành và extras; không thể chỉ ghép theo tên package.
- Phạm vi chính hiện tại: các distribution Python đã cài và phụ thuộc trực tiếp được khai báo; mục tiêu hạ nguồn là hỗ trợ truy vết đường phụ thuộc đến package có advisory.

**Điểm cần nói:** có đường phụ thuộc chưa chứng minh khai thác được; không thấy đường đi vẫn là `UNKNOWN`.

**Hình gợi ý:** `Ứng dụng → A → B`, với một cạnh thiếu và một cạnh chỉ có hiệu lực khi bật extra.

Nguồn: [mô hình bài toán](ARCHITECTURE.md), [ngữ nghĩa resolver](sbom_recovery/core/resolver.py).

## Slide 3 — Kiến trúc và luồng xử lý đã xây dựng

Trình bày một sơ đồ ngang:

```text
SBOM CycloneDX/SPDX + ngữ cảnh môi trường
                    ↓
Chuẩn hóa danh tính, occurrence và phạm vi
                    ↓
Thu thập bằng chứng được phép
                    ↓
Resolver / chính sách xác định / AI Agent
                    ↓
Cổng kiểm chứng bằng luật + đối soát mâu thuẫn
                    ↓
SBOM dẫn xuất + evidence + audit + giao diện
```

- Giữ nguyên bản quan sát; quản lý riêng đồ thị ứng viên và đồ thị dẫn xuất.
- Tám nhóm nghiệp vụ: `core`, `evidence`, `agents`, `baselines`, `gold`, `campaign`, `metrics`, `reconciliation`; `bridge` giữ các công cụ/demo tương thích.
- Nhãn tham chiếu độc lập chỉ phục vụ khâu chuẩn bị benchmark và chấm điểm; worker suy luận không được đọc oracle.

Nguồn: [cấu trúc package](sbom_recovery), [điều phối thử nghiệm](sbom_recovery/campaign/campaign.py), [cách ly worker](sbom_recovery/campaign/isolated.py).

## Slide 4 — Các chức năng đã hoàn thành

| Nhóm | Chức năng hiện có |
| --- | --- |
| Nhập và chuẩn hóa | CycloneDX/SPDX, PURL, giữ bản gốc và dấu vết chuyển đổi |
| Khôi phục | Ràng buộc phiên bản, PEP 508 markers, extras; `MUST` / `MAY_ONLY` / `UNKNOWN` |
| Kiểm chứng | Kiểm tra bằng chứng, hash, ngữ cảnh; ghi nhận khai báo mâu thuẫn |
| Đối soát | Bổ sung cạnh được hỗ trợ; loại cạnh có bằng chứng khai báo không hoạt động khỏi bản dẫn xuất |
| Vận hành nghiên cứu | CLI, Docker worker, đóng băng source/evidence, niêm phong dự đoán và báo cáo |

**Dòng cuối trang:** bộ test hiện tại: **329 test, 327 đạt, 2 bỏ qua**. Đây là kiểm tra phần mềm, không phải thước đo độ chính xác thực nghiệm.

Nguồn: [định dạng](sbom_recovery/core/formats.py), [resolver](sbom_recovery/core/resolver.py), [verifier](sbom_recovery/metrics/verifier.py), [đối soát](sbom_recovery/reconciliation/reconciliation.py), [test suite](tests).

## Slide 5 — Dữ liệu và thiết kế đánh giá

- Benchmark Python M2.5: 100 dự án, chia **20 development / 20 calibration / 60 test** theo cửa sổ thời gian; có reference từ cài đặt độc lập và metadata thực tế.
- Hai nhánh riêng: SBOM nguyên bản từ scanner và dữ liệu che có kiểm soát ở mức **10/30/50/70%**, seed **11/23/42**. Không lấy kết quả che ngẫu nhiên để kết luận về mọi lỗi scanner thực tế.
- Gold pilot bổ sung: **9 ca Python/npm/Java**, ba lớp claim về source, resolved graph và artifact; **3.161 phép dẫn xuất provenance** đã qua bộ đọc kiểm tra độc lập, phần review của con người còn chờ.

**Hình gợi ý:** sơ đồ chia 20–20–60 và hai nhánh “raw scanner” / “controlled masking”.

**Ghi chú người trình bày:** bộ 100 dự án mới cho nghiên cứu tiếp theo là một cohort khác, trình bày ở slide 11.

Nguồn: [protocol M2.5](research/AGENT_PROTOCOL.md), [cohort M2.5](runs/m25-cohort-buildable-v4/cohort.json), [gold pilot v3](runs/gold-pilot-v3/REPORT.md).

## Slide 6 — Kết quả đã đo trên 60 dự án kiểm thử

**Điều kiện hiển thị:** nhánh raw scanner, bằng chứng cố định (`fixed`), trung bình F1 cạnh theo dự án, gộp ba lần lặp trong từng dự án.

| Phương pháp | F1 toàn bộ cạnh |
| --- | ---: |
| SBOM quan sát | 0,5393 |
| Khôi phục xác định | **0,5818** |
| Single agent | 0,5551 |
| Multi agent | 0,5534 |

- Đã audit đủ **360 ca ghép cặp**, **2.520 lượt phương pháp**, trên **60 dự án**; số lần lặp không làm tăng số dự án độc lập.
- Bản khôi phục chỉ thêm cạnh vẫn giữ **474 cạnh sai có sẵn trong đầu vào** ở panel fixed một lần lặp; đây là động lực xây dựng bước đối soát.
- Kết quả của phiên bản đã đo chưa cho thấy agent vượt đối chứng xác định; giữ cả kết quả lỗi trong đánh giá.

**Hình có sẵn:** [biểu đồ F1](runs/m25-raw-final-audit-v1/report/direct-edge-f1.svg).

Nguồn: [báo cáo raw track hoàn tất](runs/m25-raw-final-audit-v1/report/REPORT.md).

## Slide 7 — Cải tiến: khôi phục kết hợp đối soát cạnh

**Tập đánh giá:** 20 dự án development cũ, ba phương pháp dùng cùng quyền truy cập metadata đầy đủ.

| Phương pháp | F1 cạnh | Cạnh sai FP | Cạnh thiếu FN |
| --- | ---: | ---: | ---: |
| SBOM quan sát | 0,8702 | 42 | 4 |
| Chỉ khôi phục bổ sung | 0,8813 | 42 | 0 |
| Khôi phục + đối soát | **0,9464** | **17** | **0** |

- Bổ sung đúng **4 cạnh**; đối soát loại **25 cạnh sai**, không loại cạnh đúng đã xác định trong lần đo này.
- Vẫn còn **17 FP** và nhiều đánh giá `UNKNOWN`; kết quả này chưa chứng minh khả năng tổng quát hóa sang tập mới.

**Chú thích bắt buộc:** F1 là trung bình trên **11 dự án có cạnh tham chiếu**, dùng cùng mẫu số giữa ba phương pháp. FP/FN cộng trên toàn bộ **20 dự án**. Không so sánh trực tiếp mức F1 ở đây với slide 6 vì khác tập dữ liệu.

**Hình có sẵn:** [so sánh ba phương pháp](runs/paired-reconciliation-development-v1/comparison.svg).

Nguồn: [báo cáo development](runs/paired-reconciliation-development-v1/REPORT.md), [số liệu chi tiết](runs/paired-reconciliation-development-v1/summary.json).

## Slide 8 — Tiến độ nhánh AI Agent và lựa chọn bằng chứng

- Đã triển khai single agent, Planner/Reconciler/Critic và agent chọn nguồn bằng chứng; mọi thay đổi phải qua cổng kiểm chứng xác định.
- Đã chạy đủ **120 lượt đối chứng xác định** trên 20 dự án development: ba chiến lược chọn nguồn × hai ngân sách 4/16; có thêm chế độ thu thập không giới hạn quota trong phiên bản sau.
- Vấn đề quan sát được: study raw cũ có **217/360 lượt single agent gặp `MODEL_ERROR`**; cần phân biệt lỗi timeout/transport/response với năng lực thuật toán.

**Điểm chốt:** công cụ agent đã hoạt động; hiệu quả riêng của AI vẫn cần đánh giá với cùng bằng chứng và điều kiện chạy. Kiểm tra tích hợp unrestricted hiện có cho agent và control cho cùng hash dự đoán, chưa phải kết quả trên tập kiểm thử mới.

Nguồn: [agent chọn nguồn](sbom_recovery/agents/budget_agent.py), [120 lượt đối chứng](runs/budget-controls-development-v2/summary.json), [study raw](runs/m25-raw-final-audit-v1/report/REPORT.md), [kiểm tra unrestricted](runs/unrestricted-agent-validation-v1/comparison.json).

## Slide 9 — Sản phẩm demo và khả năng kiểm tra kết quả

- Web UI chọn target/scanner hoặc nhập SBOM, chọn phương pháp và xem lịch sử chạy.
- So sánh đồ thị trước/sau, xem cạnh bổ sung hoặc loại bỏ, nguồn bằng chứng và nhật ký công cụ.
- Xuất SBOM dẫn xuất; xem advisory và đường phụ thuộc ở cấp package. Có thêm workbench offline để xem báo cáo đã lưu.

**Bố cục gợi ý:** ảnh giao diện chiếm khoảng 2/3 trang, bên cạnh là ba thao tác demo: chọn input → xem thay đổi → mở evidence.

**Ảnh có sẵn:** [giao diện đồ thị](runs/budget-ui-check-v5/desktop.png), [bảng rủi ro](runs/budget-ui-check-v5/risk.png), [workbench](results/research_workbench/graph_screenshot.png).

Nguồn: [UI](ui/agent.html), [API](ui/budget_api.py), [kiểm tra trình duyệt đã lưu](runs/budget-ui-check-v5/verification.json).

## Slide 10 — Reachability: đã thử nghiệm đến đâu?

- Đã có truy vết đường phụ thuộc cấp package và PoC call graph Python đơn giản.
- Pilot kiểm soát PyYAML: **20 ca runtime**, **2 ca quan sát được witness lỗi bằng đầu vào vô hại**, 18 ca không quan sát witness với đầu vào đó.
- Phân tích tĩnh PyCG của pilot gặp lỗi ở **10/10 ca**; các kết luận đường gọi tương ứng giữ `UNKNOWN`.

**Điểm cần nói:** đây là pilot kiểm soát cơ chế của CVE, chưa phải bằng chứng về khai thác trên ứng dụng thực tế. Trong raw benchmark, VRR chỉ có mẫu số hợp lệ ở **1/60 dự án**, nên giá trị an ninh hạ nguồn còn thiếu dữ liệu đánh giá.

**Hình gợi ý:** bốn mức package hiện diện → đường phụ thuộc → đường gọi hàm → quan sát runtime; ghi trạng thái thực tế ở từng mức.

Nguồn: [kết quả pilot](runs/level23-pilot-v7/summary.json), [giới hạn PyCG](runs/level23-pilot-v7/KNOWN_LIMITATIONS.md), [phạm vi VRR](runs/m25-raw-final-audit-v1/report/REPORT.md).

## Slide 11 — Việc còn lại và kế hoạch giai đoạn tiếp theo

| Hạng mục | Trạng thái và đầu ra cần đạt |
| --- | --- |
| Cohort mới | Đã có **100 dự án build hợp lệ**, chia 20/20/60; artifact hiện ghi **chưa chạy dự đoán phương pháp** |
| Đánh giá agent | Đóng băng phương pháp và đối chứng, hiệu chuẩn riêng, rồi chạy so sánh trên tập mới với cùng quyền bằng chứng |
| Controlled benchmark M2.5 | Chưa có báo cáo hoàn tất toàn bộ; checkpoint lưu ngày 02/11 là 227/12.960 ca |
| Chất lượng gold | Hoàn thành review độc lập; packet đã có 675 claim được lấy mẫu, hiện chưa có review A/B hoàn tất |
| Giá trị an ninh | Khắc phục hoặc thay PyCG; bổ sung các ca có advisory-path để đo tác động hạ nguồn |

**Câu kết trình bày:** “Giai đoạn hiện tại đã có hệ thống chạy được và kết quả thực nghiệm về khôi phục/đối soát. Giai đoạn tiếp theo tập trung kiểm chứng trên tập mới và đo đóng góp riêng của AI.”

**Lưu ý chuẩn bị báo cáo:** checkpoint cũ ghi `RUNNING` không xác nhận tiến trình đang chạy hôm nay. Không gộp cohort mới với 60 dự án đã có kết quả ở slide 6.

Nguồn: [cohort mới đã kiểm tra build](runs/unrestricted-cohort-replacement-v3/cohort.json), [validation](runs/unrestricted-cohort-validation-v3.json), [checkpoint controlled](runs/m25-agent-study-v2/test/controlled/progress.json), [review gold](runs/gold-pilot-v3/final-review-status/review-status.json).

## Cách rút xuống 10 slide

Gộp slide 8 vào slide 6: giữ vai trò agent, kết quả F1 và vấn đề độ ổn định; bỏ chi tiết ma trận 120 lượt khỏi phần trình chiếu. Các nguồn và số liệu chi tiết để trong ghi chú người thuyết trình.

## Những phần khác đã có trong repo, chỉ đưa vào ghi chú nếu cần

- Tái hiện một phần nghiên cứu DSN 2024; đối chứng package-manager B4, deps.dev B6 và phân tích topology B5.
- Tái hiện bộ đo 39 trường của sbom-unifier; báo cáo field presence khác với độ đúng của inventory/edge. Không gộp hai loại thước đo thành một chỉ số chất lượng.
- Hạ tầng gold G1/G2/G3, scope/instance matching, packet discovery và review độc lập cho Python/npm/Java.
- Bộ thu nhận artifact có kiểm tra hash, wheel snapshot, manifest, audit provenance và bộ công cụ phân tích/báo cáo kết quả.

**Kiểm tra phần mềm trong lần rà soát này:** `.venv/bin/python -B -m unittest discover -s tests -q`, kết quả `Ran 329 tests … OK (skipped=2)`. Chạy ngoài sandbox để test HTTP localhost có thể mở socket. Không chạy lại benchmark hoặc gọi LLM để tạo dàn ý.
