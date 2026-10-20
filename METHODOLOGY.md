# Tier-1 Academic Standards & Methodological Contract
# Tiêu Chuẩn Nghiên Cứu Khoa Học Cấp Cao (A* Tier-1 Academic Standard)
# Scope: Software Supply Chain Security, SBOM Graph Reconstruction & Vulnerability Reachability

Tài liệu này định hình phong cách làm việc, tư duy phương pháp luận và nguyên tắc thực nghiệm bắt buộc cho nghiên cứu này, tuân thủ tiêu chuẩn của một **Nhà nghiên cứu khoa học chuyên sâu (A* Senior Researcher / Principal Investigator)** tại các hội nghị đầu ngành (ACM CCS, IEEE S&P, USENIX Security, NDSS, ICSE, FSE, ASE, ISSTA, ACM TOSEM, IEEE TSE).

---

## 1. Tư Duy Cốt Lõi & Liêm Chính Khoa Học (Scientific Integrity)

1. **Tuyệt đối không Overclaiming (Chống Thổi phồng Kết quả):**
   * Phân biệt rạch ròi giữa **dữ liệu tổng hợp (synthetic fixture)** và **thực nghiệm thực tế (empirical benchmark)**.
   * Đạt 100% precision/recall trên dữ liệu fixture tạo có chủ đích **chỉ chứng minh tính thông suốt của đường ống dữ liệu (pipeline validity)**, hoàn toàn **không có giá trị chứng minh hiệu năng thuật toán trong thực tế**.
   * Luôn gắn nhãn mọi kết quả tái cấu trúc là *ứng viên suy luận (candidate)*, tuyệt đối không đồng nhất với *gói đã được cài đặt thực tế (verified installed artifact)*.

2. **Nguyên tắc "Fail-Closed" & "No Path ≠ Safe":**
   * Nếu không tìm thấy đường đi trong đồ thị phụ thuộc hoặc không tìm thấy đường gọi hàm (call path): Trạng thái bắt buộc phải là **`UNKNOWN`** hoặc **`NOT_OBSERVED`**, tuyệt đối **không được kết luận là `SAFE` hay `PROVEN_UNREACHABLE`**.
   * Dựa trên Định lý Rice (Rice's Theorem), mọi phân tích tĩnh (Static Analysis) về hành vi chương trình đều mang tính xấp xỉ (soundness vs. completeness trade-off). Phân tích AST luôn có giới hạn lý thuyết trước dynamic import, reflection, runtime dispatch và eval.

3. **Chống Rò rỉ Dữ liệu Tuyệt đối (Anti-Data / Anti-Label Leakage):**
   * Không được lấy nguồn suy luận (ví dụ: `deps.dev`) làm *Ground Truth* nếu chính `deps.dev` đang được dùng làm bằng chứng (*evidence*) tái cấu trúc. Điều này gây rò rỉ nhãn (label leakage) làm sai lệch toàn bộ kết quả nghiên cứu.
   * Ground truth thực nghiệm bắt buộc phải được tạo độc lập từ môi trường thực tế (pinned build lockfiles, installed virtualenv, wheels).

---

## 2. Nguồn Gốc Khoa Học Của Mọi Findings (Literature & Evidence Provenance)

Mọi nhận định, định nghĩa bài toán, thuật toán và phân loại rủi ro **bắt buộc phải có xuất xứ khoa học chính thống**:

1. **Căn cứ từ Tài liệu Khoa học Đầu ngành (Peer-Reviewed Literature):**
   * Mọi định nghĩa khái niệm, mô hình hóa bài toán (problem formulation), nhận định thuật toán phải tham chiếu từ các công trình được bình duyệt tại các hội nghị/tạp chí uy tín (Top-tier Software Engineering & Security venues: IEEE S&P, USENIX Security, ACM CCS, NDSS, ICSE, FSE, ASE, ISSTA, ACM TOSEM, IEEE TSE).
   * Tuyệt đối không dùng blog cá nhân hoặc diễn đàn không được bình duyệt làm căn cứ khoa học cho các kết luận cốt lõi.

2. **Tuân thủ Đặc tả & Tiêu chuẩn Công nghiệp Chính thống (Accredited Standards & Specifications):**
   * **SBOM Format:** CycloneDX Specification (OWASP/ECMA), SPDX Specification (ISO/IEC 5962).
   * **Tuyên bố khả năng khai thác lỗ hổng:** OpenVEX Specification, CSAF (OASIS).
   * **Bảo mật chuỗi cung ứng:** NIST SP 800-218 (SSDF), NIST SP 800-161, SLSA Framework.
   * **Dữ liệu bảo mật chuẩn hóa:** OSV (Open Source Vulnerabilities Schema), NVD/CVE (NIST/MITRE), CWE (Common Weakness Enumeration), CISA KEV Catalog.
   * **Nhận diện gói:** Package URL Specification (purl-spec).

3. **Cấm Suy đoán Vô Căn cứ (No Unsubstantiated Claims):**
   * Mọi finding (phát hiện bảo mật, cấu trúc đồ thị, phân loại rủi ro) phải có **địa chỉ chứng minh (provenance)**:
     - Hoặc là kết quả đo lường trực tiếp từ thực nghiệm độc lập (có log, file artifact, seed).
     - Hoặc viện dẫn trực tiếp từ bài báo khoa học / đặc tả chuẩn tương ứng `[Tác giả/Tổ chức, Năm, Tên tài liệu/Hội nghị/Spec]`.

---

## 3. Mô Hình Hóa Toán Học & Ngữ Nghĩa Phụ Thuộc (Formal Rigor & Semantics)

1. **Mô hình hóa bài toán (Formal Problem Formulation):**
   * Đồ thị phụ thuộc mục tiêu (Ground Truth Graph): $G^* = (V^*, E^*, \mu^*, \mathcal{E})$, trong đó:
     - $V^*$: Tập hợp các package chính xác được giải quyết và tải trong môi trường thực thi.
     - $E^*$: Tập các cạnh phụ thuộc trực tiếp giữa các artifact.
     - $\mathcal{E}$: Ngữ cảnh môi trường thực thi gồm $(\text{os}, \text{arch}, \text{runtime\_version}, \text{wheel\_tags}, \text{active\_extras})$.
   * Đồ thị quan sát được (Observed SBOM): $G_{\text{obs}} = (V_{\text{obs}}, E_{\text{obs}}) \subseteq G^*$.
   * Hàm mục tiêu: Học ánh xạ $f: (G_{\text{obs}}, \mathcal{E}, \text{Evidence}) \to (\hat{G}, \mathcal{C})$, trong đó $\hat{G}$ là đồ thị tái cấu trúc và $\mathcal{C}$ là độ tin cậy được hiệu chuẩn (calibrated confidence score).

2. **Cấm Suy luận Phụ thuộc Phi Ngữ cảnh (Context-Free Resolution is Prohibited):**
   * Không được coi quan hệ phụ thuộc là đồ thị tĩnh cố định. Trong hệ sinh thái PyPI, quan hệ phụ thuộc là một hàm phụ thuộc môi trường theo **Environment Markers (PEP 508)** và **Extras** (ví dụ: `requests[security]`).
   * Mọi cạnh phụ thuộc suy luận khi thiếu ngữ cảnh môi trường $\mathcal{E}$ bắt buộc phải gắn cờ `Context-Uncertain` và biểu diễn dưới dạng xác suất có điều kiện $P(e \mid \mathcal{E})$.

3. **Cơ chế Khuyết thiếu (Missingness Mechanisms):**
   * Luôn phân loại rõ dữ liệu khuyết thiếu trong nghiên cứu thuộc cơ chế nào:
     - **MCAR (Missing Completely at Random):** Xóa ngẫu nhiên nhân tạo (chỉ dùng để stress-test đường ống).
     - **MAR (Missing at Random):** Thiếu do các thuộc tính quan sát được (ví dụ: công cụ quét tự động bỏ qua dev-dependencies hoặc optional packages).
     - **MNAR (Missing Not at Random):** Thiếu do thuộc tính ẩn (ví dụ: dynamic code generation trong `setup.py` hoặc conditional builds khiến parser không thể đọc được).
   * Nghiêm cấm lấy kết quả thử nghiệm trên MCAR để khẳng định thuật toán giải quyết được MNAR trên thực tế.

---

## 4. Kim Tự Tháp Khả Năng Tiếp Cận 4 Cấp Độ (The 4-Tier Reachability Hierarchy)

Nghiêm cấm đánh đồng hoặc suy diễn bắc cầu giữa 4 cấp độ tiếp cận sau:

```
  [Level 3] Dynamic Exploitability (Dữ liệu đầu vào kích hoạt được lỗi tại runtime)
      ▲   (Yêu cầu: Dynamic taint analysis, Symbolic execution, Runtime monitoring)
  [Level 2] Static Call-Graph Reachability (Hàm entry-point gọi tới hàm dính lỗi)
      ▲   (Yêu cầu: Inter-procedural call graph, CHA/RTA/Points-to analysis)
  [Level 1] Dependency Graph Path (Tồn tại đường đi u rightsquigarrow v trong đồ thị gói)
      ▲   (Tái cấu trúc SBOM chỉ giải quyết cấp độ này!)
  [Level 0] Package Co-occurrence (Package cùng có mặt trong SBOM)
```

* **Quy tắc bất biến:**
  - `Level 1 ≠ Level 2`: Có đường đi trong đồ thị phụ thuộc **không đồng nghĩa** hàm chứa mã độc được gọi.
  - `Level 2 ≠ Level 3`: Tìm thấy call path tĩnh **không đồng nghĩa** lỗ hổng có thể khai thác được (Exploitable) vì có thể bị chặn bởi điều kiện logic (path condition infeasibility) hoặc sanitizer.
  - `No Path tại Level 2`: Bắt buộc ghi nhận là **`UNKNOWN`**, tuyệt đối **không kết luận là `SAFE`**.

---

## 5. Định Lượng Bất Định & Từ Chối Dự Đoán (Uncertainty & Selective Classification)

1. **Chiến lược Từ chối Dự đoán (Calibrated Abstention / Selective Classification):**
   * Trong an ninh phần mềm, một **False Negative** (bỏ sót thư viện có lỗ hổng RCE) gây ra thảm họa bảo mật; nhưng quá nhiều **False Positive** gây tê liệt quy trình vận hành và kiệt quệ đội ngũ bảo mật (alert fatigue).
   * Mô hình phải hỗ trợ cơ chế từ chối đưa ra kết luận (Abstain / UNKNOWN) khi độ bất định vượt ngưỡng $\tau$ (sử dụng Conformal Prediction hoặc Bayesian Credible Intervals).
   * Báo cáo đánh giá phải luôn đi kèm đường cong đánh đổi: **Coverage vs. Selective Risk**.

2. **Kháng Công Kích Chuỗi Cung Ứng (Adversarial Robustness & Provenance):**
   * Đánh giá rủi ro mô hình bị đánh lừa bởi metadata độc hại (Dependency Confusion, Typosquatting packages trong Registry).
   * Mọi cạnh dự đoán phải truy vết được nguồn gốc bằng chứng: Suy ra từ Registry Metadata, Cấu trúc Topo đồ thị, hay Ngữ nghĩa mã nguồn?

---

## 6. Thiết Kế Thực Nghiệm Chuẩn A* (Rigorous Benchmark Design)

1. **Phân chia Dữ liệu theo Mốc Thời Gian (Strict Chronological / Temporal Splitting):**
   * Tuyệt đối không dùng k-fold cross-validation ngẫu nhiên trên toàn bộ tập package vì gây rò rỉ dữ liệu xuyên thời gian (Temporal Look-Ahead Leakage).
   * Dữ liệu huấn luyện: Các package/release phát hành trước thời điểm $T_0$.
   * Dữ liệu kiểm thử: Các package/release phát hành sau thời điểm $T_0$.

2. **Benchmark Đối Chuẩn Kép (Dual-Track Benchmark):**
   * **Track 1 (Controlled Synthetic Benchmark):** Masking có chủ đích với các tỷ lệ khuyết thiếu khác nhau (10%, 30%, 50%, 70%), cố định `seed`, lưu vết `mask.json` trên tập Ground Truth độc lập (pinned build lockfiles: `poetry.lock`, `Pipfile.lock`, installed virtualenvs).
   * **Track 2 (In-the-wild Generator Discrepancy Benchmark):** So sánh độ chênh lệch thực tế giữa các công cụ sinh SBOM hàng đầu (Syft, Trivy, cdxgen, cyclonedx-cli) trên cùng một tập dự án mã nguồn mở thực tế.

3. **Thước Đo Giá Trị An Ninh Hạ Nguồn (Downstream Security Utility Metrics):**
   Không dừng lại ở các chỉ số topo đồ thị thuần túy (Node/Edge Precision, Recall, F1), bắt buộc phải đo lường tác động an ninh thực tế:
   * **Vulnerability Recovery Rate (VRR):** Tỷ lệ các CVE/Advisories thực sự được tìm thấy nhờ các cạnh/node được khôi phục.
   * **Triage Delta ($\Delta \text{Triage}$):** Số lượng trạng thái OpenVEX (ví dụ: chuyển từ `under_investigation` sang `affected`) được cập nhật chính xác sau khi tái cấu trúc.
   * **False Assurance Reduction:** Giảm thiểu bao nhiêu trường hợp ứng dụng bị ngộ nhận là an toàn do SBOM thiếu cạnh.

---

## 7. Phân Loại Lỗi & Mối Đe Dọa Tính Hợp Lệ (Failure Taxonomy & Threats to Validity)

1. **Bảng Phân loại Nguyên nhân Thất bại (Failure Taxonomy):**
   Mọi trường hợp dự đoán sai (False Positives, False Negatives) phải được phân loại định lượng theo 5 nhóm nguyên nhân:
   * *(A) Namespace / PURL Normalization Error:* Lỗi chuẩn hóa tên gói hoặc hệ sinh thái.
   * *(B) Dynamic Installation Script:* Phụ thuộc động sinh ra trong runtime của `setup.py`.
   * *(C) Optional Extras / Environment Markers Mismatch:* Không khớp cờ môi trường hoặc tính năng tùy chọn.
   * *(D) Registry Ambiguity:* Xung đột phiên bản hoặc thiếu metadata trên Registry.
   * *(E) Topological Graph Sparsity:* Đồ thị phụ thuộc quá thưa thớt, không đủ tín hiệu liên kết.

2. **Báo cáo Minh bạch 3 Mối Đe Dọa (Threats to Validity):**
   * **Construct Validity:** Thước đo cạnh khôi phục có phản ánh đúng khả năng khai thác thực tế không?
   * **Internal Validity:** Có rò rỉ nhãn giữa Registry metadata và Ground Truth không? Pipeline parsing có thiên vị (bias) với các package phổ biến không?
   * **External Validity:** Khả năng tổng quát hóa kết quả từ PyPI sang các hệ sinh thái khác (npm, Maven, Go, Rust Crates) với cơ chế giải quyết phụ thuộc hoàn toàn khác nhau.

---

## 8. Chuẩn Mực Báo Cáo & Giao Tiếp Học Thuật (Academic Communication)

Khi trình bày phát hiện, tư vấn hoặc báo cáo nghiên cứu:
1. **Ngôn ngữ:** Học thuật, súc tích, logic, sử dụng thuật ngữ chuyên ngành chính xác.
2. **Cấu trúc Báo cáo Chuẩn:**
   * **Context & Problem Formulation:** Đặt vấn đề và mô hình hóa toán học.
   * **Theoretical Background & Sourcing:** Cơ sở lý thuyết, chuẩn IEEE/ACM/ISO/NIST tham chiếu.
   * **Hypothesis & Experimental Design:** Giả thuyết nghiên cứu, baseline đối sánh, cấu hình thực nghiệm.
   * **Empirical Evidence & Downstream Metrics:** Kết quả đo đếm, biểu đồ, bảng so sánh metrics (Precision, Recall, F1, VRR).
   * **Failure Taxonomy & Threats to Validity:** Phân loại ca lỗi và chỉ rõ giới hạn nội tại.
   * **Actionable Next Steps:** Kế hoạch thực nghiệm tiếp theo có mục tiêu định lượng cụ thể.
