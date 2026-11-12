> Draft artifact-only trước khi chọn A+B+E. Tài liệu này chỉ làm phụ lục cho adapter evidence theo artifact; đề bài chính hiện tại ở [PROBLEM_FORMULATION.md](../../../PROBLEM_FORMULATION.md).

# Đề bài V3: Khôi phục SBOM theo artifact từ bằng chứng không đầy đủ

Trạng thái **thiết kế**, ngày 12-11-2026. Engine Python hiện có vẫn là V2; V3 chưa có pipeline end-to-end. [Kiến trúc](../../../ARCHITECTURE.md), [kế hoạch](../../ARTIFACT_RECONCILIATION_PLAN.md), [khảo sát](../../SBOM_VULNERABILITY_SURVEY_VI.md), [thực nghiệm khám phá](../../../runs/cross-ecosystem-probe-v1/REPORT.md).

## 1. Phát biểu đề bài

**Cho một SBOM được cung cấp cùng một artifact phát hành cụ thể, ngữ cảnh đích có thể chưa đầy đủ và một tập evidence tùy chọn, hãy xác định sai lệch về component, identity, version, phạm vi và quan hệ; áp dụng thay đổi được evidence hỗ trợ; giữ rõ phần chưa xác định; đo ảnh hưởng tới vulnerability matching trên cùng consumer/advisory snapshot.**

Người dùng đầu tiên là đội bảo mật nhận JAR từ nhà cung cấp, có thể không có source hoặc khả năng tái dựng đúng môi trường build. Evidence có thể được CI/nhà cung cấp giao cùng sản phẩm hoặc được người nhận trích từ artifact.

Đầu ra là SBOM dẫn xuất và lời giải thích cho các kết luận/thay đổi. Sửa topology khi vẫn gắn sai package/version, hoặc coi dependency build là bytecode được ship, chưa giải quyết đầy đủ đề bài.

## 2. Phạm vi

Một lần phân tích gắn với **một target artifact có SHA-256 cụ thể**. MVP nhận một JAR; archive lồng bên trong thuộc phạm vi khi đã được duyệt. Classpath ngoài JAR, plugin tải thêm và môi trường runtime nằm ngoài phạm vi mặc định. Release nhiều file sẽ dùng manifest artifact ở giai đoạn sau.

| Lớp | Câu hỏi | Evidence |
| --- | --- | --- |
| Khai báo | Source/metadata khai báo gì? | manifest, METADATA, POM |
| Được chọn | Resolver chọn gì cho target/build? | native tree, record của đúng build |
| Có trong artifact | Component/phần mã nào được giao? | archive entries, class hashes, output contributions |
| Ảnh hưởng runtime | Mã liên quan advisory có thể được gọi/khai thác không? | phân tích riêng, ngoài MVP |

Các lớp không đồng nhất. `selected(B)=true` và `code_present(B)=false` có thể cùng đúng sau tối ưu đóng gói. `code_present(B)=true` và `declared_dependency(A,B)=unknown` có thể cùng đúng khi vendoring.

## 3. Đầu vào

\[
I=(A,S_0,C_o,E_o,\Pi),\qquad h_A=\operatorname{SHA256}(A).
\]

- \(A\): bytes artifact; filename không thay cho hash.
- \(S_0\): SBOM gốc, giữ nguyên bytes; có thể thiếu/chứa khai báo sai.
- \(C_o\): ngữ cảnh biết một phần: OS, architecture, runtime/toolchain, profile, feature/extras, entrypoint. Thiếu/null là chưa biết; danh sách rỗng là biết không chọn mục nào.
- \(E_o\): evidence tùy chọn: manifest/lockfile, artifact metadata, native resolution, file/class observations, build receipt, esbuild metafile, package archive upstream hoặc SBOM khác.
- \(\Pi\): policy về scope, evidence admissibility, giới hạn collector và export profile.

Đánh giá matching cần thêm \((K,\theta,D)\): consumer/phiên bản \(K\), cấu hình \(\theta\), advisory snapshot \(D\). Không bắt buộc có scanner để thực hiện mọi bước reconciliation.

Registry metadata tự thân không chứng minh package được chọn/có trong target. Record cùng tên/version dự án nhưng không nối tới \(h_A\) vẫn chưa ràng buộc với target này.

## 4. Identity, occurrence và footprint

\[
i=(ecosystem,namespace,name,version,origin,artifact\_digest).
\]

Các chiều có thể chưa biết. PURL có thể không mang đầy đủ origin/digest. Alias, tên hiển thị và tên advisory database không tự là canonical identity.

Occurrence \(o\) là một thực thể **trong target \(h_A\)**, có locators tới archive members, class files, bundle contributions hoặc nhóm bytes. Cùng name/version chưa đủ gộp hai occurrence. \(F(o)\) là footprint quan sát được: units có location/hash/loại, kèm coverage. Metadata của B có mặt không có nghĩa bytecode của B có mặt.

\[
\operatorname{Bind}(o)=(\mathcal K_o,resolution).
\]

Candidates \(\mathcal K_o\); resolution thuộc `UNRESOLVED`, `UNIQUE`, `AMBIGUOUS`, `CONFLICT`. Một candidate duy nhất tìm trong kho không tự chứng minh UNIQUE vì kho có thể thiếu. Class hashes dùng chung giữa nhiều release phải giữ các version khả dĩ.

## 5. Claims có scope

\[
q=(subject,predicate,object,\sigma),\quad
\sigma=(h_A,phase,context\_id,unit\_domain).
\]

Predicate chính: `identity`, `selected`, `metadata_present`, `code_present`, `unit_present`, `direct_dependency`, `contains`, `build_input_of`, `source_contributes`.

Evidence trái nhau chỉ là conflict khi đánh giá **cùng claim/scope**. Dependency có trong declared graph nhưng không được chọn cho Linux không mâu thuẫn giữa hai lớp.

Sau policy, \(P_q,N_q\) là evidence admissible hỗ trợ/phản bác q:

| \(P_q\) | \(N_q\) | Status |
| --- | --- | --- |
| Có | Không | `SUPPORTED` |
| Không | Có | `REFUTED` |
| Có | Có | `CONFLICT` |
| Không | Không | `UNKNOWN` |

Status không phải xác suất hoặc chứng minh nguồn đúng. Admissibility phụ thuộc collector/binding/scope và giả định tin cậy công khai trong \(\Pi\); không lấy số nguồn đồng ý thay cho các điều kiện này.

Scanner không thấy package không tự tạo \(N_q\). Phản bác presence cần coverage đầy đủ cho **đúng miền units**, cách định danh phù hợp và không có phần bỏ qua. Duyệt hết ZIP entry names chỉ đủ kết luận literal paths; chưa đủ phủ định class đã relocation/obfuscation.

Archive lỗi, thiếu mapping cần thiết hoặc đạt giới hạn recursion làm kết quả âm tính của miền liên quan trở thành UNKNOWN. Không dùng phần chưa quan sát để xóa package/edge.

## 6. Phép toán khôi phục và đầu ra

\[
R_\Pi(I)=(S^*,\mathcal Q,\Delta,U).
\]

- \(S^*\): SBOM dẫn xuất theo export profile công bố.
- \(\mathcal Q\): claims/status/scope/evidence explanations.
- \(\Delta\): changes kèm before/after, rule và claim IDs.
- \(U\): unresolved bindings, conflicts, coverage gaps, input issues.

\(S^*\) không mặc định là ground truth. Profile MVP giữ observation chưa đủ cơ sở sửa; assessment tách dữ liệu gốc với facts được hệ thống xác nhận. Field giữ lại không tự thành verified.

Thay đổi dự kiến: thêm component có binding phù hợp; sửa identity/version; thêm/rút direct edge đúng scope; tạo identity projection riêng cho consumer. Containment chỉ tạo `contains`, không cấp quyền thêm `direct_dependency`.

Điều kiện áp dụng:

1. Claims đúng target/scope; evidence có binding/policy phù hợp.
2. Binding cần thiết phân giải; edge endpoints xác định duy nhất.
3. Claims có status đúng hướng thay đổi; UNKNOWN/CONFLICT chỉ cho report/defer.
4. Before-value còn khớp; format/reference integrity được giữ.

Rút edge khỏi selected view không xóa khai báo source. Metadata-only không tự cấp quyền xóa component: metadata/build dependency có thể vẫn đúng. Quan hệ không biểu diễn trung thực được trong format giữ ở assessment.

MVP xuất `sbom.cdx.json`, `assessment.json`; đánh giá consumer thêm input projection và `comparison.json`. Không có certificate/checker độc lập hoặc conformal fitting trong luồng mới.

## 7. Mục tiêu và giới hạn hình thức

Tăng facts đúng xác định được trong scope; giảm khai báo sai và identity-induced missed/incorrect advisory matches; đo lỗi do changes mới riêng. Chưa gộp identity/graph/footprint/security bằng trọng số tùy ý.

Thuộc tính mong muốn:

- **Scope preservation:** facts của A không áp dụng cho A' vì cùng tên/version.
- **Conservative change:** thiếu evidence/conflict không cấp quyền thay đổi.
- **Relation separation:** containment/build input không thành dependency/call edge.
- **Traceability:** changes nối tới rule/evidence; dữ liệu gốc không đổi.
- **Determinism:** cùng input/policy/tool snapshots cho cùng facts/changes; tách metadata thời gian chạy.
- **No safety promotion:** no-path/no-match/missing observation không suy ra ứng dụng an toàn.

Đây là yêu cầu kiểm thử, chưa có định lý soundness cho collectors hoặc pipeline.

Nếu hai thế giới thực cùng phù hợp mọi evidence nhưng khác q, input đó không xác định q luôn đúng. Giữ unknown thay vì ép SBOM hoàn chỉnh. Candidates hữu hạn tìm được không mặc định phủ mọi khả năng.

## 8. Matching và applicability

Với profile \(\pi\):

\[
M_0=\operatorname{Match}_{K,\theta,D}(\pi(S_0)),\quad
M_1=\operatorname{Match}_{K,\theta,D}(\pi(S^*)).
\]

So matches thêm/mất/giữ sau chuẩn hóa advisory aliases. Record mới không tự là true positive; cần labels đúng scope.

Tách kết quả:

1. **Match correctness:** identity/version ghép đúng advisory package-level của snapshot?
2. **Artifact observation:** units liên quan advisory quan sát ở đâu, coverage nào?
3. **Runtime applicability/exploitability:** ngoài MVP; `NOT_ASSESSED`.

Footprint một phần vẫn giữ component. Scanner package/version có thể tiếp tục báo advisory; artifact observation không tự suppress. Mapping `std` → `stdlib` chỉ áp dụng consumer projection của instance đã nhận diện là Go standard library.

## 9. RQs và đánh giá

| RQ | Kiểm tra |
| --- | --- |
| RQ1: Sai lệch nào còn tồn tại trên release thực với đúng mode? | Corpus artifact hashes/context; giữ thành công/thất bại. |
| RQ2: Reconciliation giúp gì theo mức evidence? | SBOM-only, +artifact, +manifest/lock, +matched build; baseline cùng thông tin. |
| RQ3: Changes nào cải thiện matching? | Cùng consumer/config/snapshot; identity/scope/footprint/graph ablations riêng. |
| RQ4: Chi phí và unresolved coverage? | Unknown/conflict, thời gian/bytes, lỗi do changes, labels chưa rõ. |

Precision/recall theo facts/changes có labels độc lập ở từng lớp. Báo denominators/coverage/labels chưa rõ riêng; mẫu số 0 trả null. Full-output và incremental-change accuracy riêng vì observation giữ lại có thể sai.

Reference: native resolution đúng context, artifact entries/class/file hashes, review ca xung đột. Oracle chỉ vào scorer. Discovery cases không là held-out; split theo project/release lineage, controls cùng artifact cùng split.

Baseline: native CycloneDX/regeneration; Syft/Trivy đúng mode/resolver; cdxgen; rule/union đơn giản; JBomAudit cho Java; SBOMit/OmniBOR khi có build evidence; cargo-auditable cho Rust. Control nhiều thông tin hơn ở regime riêng. Scanner disagreement không tự xác định ai sai.

Alias rename, bỏ metadata giữ class bytes, minimize giữ metadata, record thuộc build khác, graph removal là mechanism controls; không là prevalence/exploitability labels.

## 10. MVP và claim nghiên cứu

MVP: Java JAR + CycloneDX 1.6 JSON; metadata/class-entry inspection, binding, explanations; chưa giải quyết toàn relocation/obfuscation. JS bundle/esbuild receipt tiếp theo. SPDX 2.3, Go/Rust, multi-artifact release là adapters sau; V2 phục vụ installed Python.

Contribution ứng viên là reconciliation của evidence thiếu/xung đột qua các giai đoạn, scope tường minh, utility đo trên consumer. Novelty/vượt strong baselines chưa chứng minh. JBomAudit, SBOMit, OmniBOR và native tools giải quyết các phần gần bài toán; phải so trực tiếp. LLM không phải điều kiện của mô hình/MVP.

## Nguồn

- [Khảo sát](../../SBOM_VULNERABILITY_SURVEY_VI.md), [thử nghiệm](../../../runs/cross-ecosystem-probe-v1/REPORT.md).
- [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/): dependency trực tiếp, lifecycle, uncertainty; missing record không đồng nghĩa dependency-free.
- [SPDX 2.3.1 relationships](https://spdx.github.io/spdx-spec/v2.3.1/relationships-between-SPDX-elements/): containment/dependency khác nghĩa; cơ sở adapter sau MVP.
