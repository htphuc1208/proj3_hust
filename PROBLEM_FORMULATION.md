# Đề bài V3 — Evidence-Based SBOM Metadata and Dependency Graph Reconciliation

Ngày 12-11-2026. Hướng chính được chọn: **A + B + E**. A xử lý identity/metadata, B xử lý quan hệ trên các component đã căn chỉnh, E đo tác động downstream. Artifact là evidence tùy chọn; nghiên cứu binary recovery đầy đủ chưa thuộc MVP.

Trạng thái: đã có engine đa SBOM, frozen evidence collectors npm/Cargo, single-agent investigation có budget, export và evaluator riêng trong `sbom_recovery/investigation`. [Hướng dẫn chạy và giới hạn](research/EAGER_SBOM_IMPLEMENTATION.md). Corpus/pilot thực độc lập và lợi ích trước strong baselines chưa được chứng minh. Python V2 vẫn hoạt động riêng. [Kiến trúc](ARCHITECTURE.md), [kế hoạch](research/RECONCILIATION_PLAN_V3.md), [khảo sát](research/SBOM_VULNERABILITY_SURVEY_VI.md).

## 1. Phát biểu đề bài

**Cho nhiều SBOM mô tả cùng một bản phần mềm trong phạm vi phân tích được khai báo, ngữ cảnh đích có thể thiếu và các nguồn evidence tùy chọn, hãy căn chỉnh component, xử lý identity/version mâu thuẫn và khôi phục dependency graph bằng evidence; biểu diễn phần chưa xác định; đánh giá correctness/completeness và ảnh hưởng tới vulnerability matching trên cùng consumer/advisory snapshot.**

Đầu ra gồm SBOM hợp nhất dẫn xuất, provenance/explanations theo field và edge, cùng conflicts/unknowns. Không lấy nhiều field hoặc nhiều edges hơn làm định nghĩa correctness. Không mặc định có thể cải thiện correctness mà không giảm field completeness trong mọi tình huống.

## 2. A, B, E là một phương pháp

| Phần | Câu hỏi | Vai trò |
| --- | --- | --- |
| A | Những records nào nói về cùng component/instance, và identity/version nào có cơ sở? | nền cho alignment và field reconciliation |
| B | Cạnh nào thuộc đúng graph/scope và có evidence? | dùng alignment của A, không union edges vô điều kiện |
| E | Thay đổi nào cải thiện package–advisory matching hoặc dependency-path analysis? | đánh giá outcome, không phải một engine AI khác |

Tên tiếng Anh làm việc: **Evidence-Based Reconciliation of SBOM Metadata and Dependency Graphs for Vulnerability Analysis**. Novelty/vượt strong baselines chưa được chứng minh.

## 3. Target và đầu vào

\[
\tau=(project,revision,context,view,boundary),\quad
I=(\tau,\mathcal S,E_o,\Pi),\quad \mathcal S=\{S_1,\ldots,S_n\},\ n\ge2.
\]

- \(\tau\): một comparison target. Revision cần được freeze; context gồm OS/architecture/runtime/profile/feature nếu biết. View phân biệt declared dependencies, resolved dependencies và artifact contents.
- \(S_j\): SBOM gốc có bytes/hash, format, producer/version/config, source scope. Native refs chỉ có ý nghĩa trong document đó.
- \(E_o\): lockfile, native resolution, installed metadata, registry/package archive, artifact metadata/hash hoặc build record, tùy khả năng thu thập.
- \(\Pi\): policy về alignment, admissibility, scope và export.

Target ID là grouping key, không phải proof các SBOM cùng mô tả một build. Scope binder phải kiểm tra nguồn/context; thiếu thông tin thì compatibility chưa xác định. Source/build/artifact views khác nhau giữ riêng, không chấm cùng một graph reference. Artifact không bắt buộc trong input chung; muốn kết luận về bytes đã ship thì phải có evidence tương ứng.

Thiếu/null context là unknown; [] là known-empty. Registry metadata không chứng minh installed/selected presence. Lockfile/resolver mô tả resolution của context nào phải được chỉ rõ; không tự biến thành shipped-artifact truth.

Đánh giá E cần thêm \((K,\theta,D)\): consumer/phiên bản, cấu hình và advisory snapshot cố định. Số lượng tools đồng ý không thay evidence độc lập; lỗi dùng chung parser có thể tương quan.

## 4. Observation identity và alignment

Observation key:

\[
o=(\operatorname{SHA256}(S_j),native\_ref).
\]

Duplicate refs trong cùng document là input issue. Hai docs dùng cùng bom-ref không được gộp vì trùng chuỗi ID.

Canonical package identity có các chiều `(ecosystem, namespace, name, version, origin, digest)` có thể thiếu. Một identity có thể có nhiều occurrence. **Package identity và physical occurrence không được gộp làm một.**

Alignment là partial mapping:

\[
\alpha(o)\in V\cup\{\text{UNRESOLVED}\}.
\]

Candidate blocking có thể dùng PURL/name/namespace/locators, nhưng xác nhận same-instance cần evidence phù hợp. Version là một phần identity: hai PURL chỉ khác version không tự là một conflict. Chúng có thể là hai bản cài hợp lệ. Cùng PURL cũng chưa chứng minh cùng physical occurrence hoặc cùng scope.

Một candidate tìm thấy duy nhất trong reference cache không có nghĩa candidate universe đầy đủ. Hash file/class dùng chung giữa releases không đủ tự chọn exact version. Các records chưa align vẫn được giữ với provenance; không loại bỏ để làm chỉ số đẹp hơn.

## 5. Reconciliation theo nhận định

\[
q=(subject,predicate,value,scope),
\quad scope=(\tau,phase,occurrence/context,domain).
\]

MVP tập trung identity/name/version/PURL/origin/digest và direct-dependency facts. License/supplier giữ nguyên observation nhưng chưa nhận claim xác minh toàn bộ field. Checksum luôn gắn đối tượng bytes cụ thể; không so hash archive với hash installed directory như cùng một field.

Sau policy, \(P_q,N_q\) là evidence admissible hỗ trợ/phản bác đúng claim:

| Positive | Negative | Status |
| --- | --- | --- |
| Có | Không | `SUPPORTED` |
| Không | Có | `REFUTED` |
| Có | Có | `CONFLICT` |
| Không | Không | `UNKNOWN` |

Status không phải calibrated probability hoặc proof của input truth. Giả định tin cậy của collector/binding phải công khai. Consensus chỉ là observed agreement. Không dùng majority hoặc fixed producer priority để gọi một giá trị là verified.

Conflict chỉ tồn tại trong cùng claim/scope. Maven chọn B cho build và JAR chỉ giữ metadata của B có thể đồng thời đúng. Absence từ scanner không là negative evidence; refutation cần closed coverage/rule đủ điều kiện cho đúng domain. Unknown candidate/context không cấp quyền xóa component hoặc edge.

## 6. Dependency graph và quan hệ

Reference graph theo view \(G^*_{\tau}=(V^*_{\tau},E^*_{\tau},\mu^*_{\tau})\). Nó là target của đánh giá, không được cung cấp cho inference.

Một source edge chỉ được chuyển sang aligned graph khi endpoints đủ xác định và relationship semantics/scope tương thích. Giữ source provenance và trạng thái quan sát. Edge được tool xuất không tự là verified direct dependency.

Phân biệt `direct_dependency`, `contains`, `build_input_of` và call relation. Trường hợp App→A→B ở tool 1 và App→B ở tool 2 không tự chứng minh shortcut sai: cả hai có thể đúng, hoặc tool 2 đang trình bày flattened inventory. Phải xét producer mode và native declaration/resolution.

Evidence cho bổ sung/rút direct edge: metadata declaration/conditional rule đúng context hoặc native resolved tree của cùng target. Rút khỏi selected view không xóa declared fact. Endpoint ambiguity khiến edge defer; không chọn occurrence tùy ý hoặc tạo path xuyên các scope không tương thích.

MVP không làm full call graph, runtime tracing, exploit generation hoặc VEX not-affected inference. No dependency path không là kết luận safe.

## 7. Hàm reconciliation và output

\[
R_\Pi(I)=(S^*,\mathcal A,\mathcal Q,\Delta,U).
\]

- \(S^*\): SBOM hợp nhất dẫn xuất theo export policy.
- \(\mathcal A\): alignment mapping và candidates còn mơ hồ.
- \(\mathcal Q\): field/edge claims có scope/status/evidence.
- \(\Delta\): decisions có before/after, source refs, rule/evidence IDs.
- \(U\): conflicts, unknowns, incompatible scopes và coverage/input issues.

Không quảng bá toàn bộ S* là verified. Policy phải ghi rõ giá trị nào là supported, retained observation hoặc unresolved; nhiều giá trị mâu thuẫn giữ trong assessment. Không điền một version tùy ý chỉ để tăng completeness.

Changes được áp dụng khi alignment/claim/evidence/scope đủ điều kiện, preconditions còn khớp và format/ref integrity giữ được. Original docs bất biến. Fields/relations chưa biểu diễn lossless được giữ trong assessment. Không tự thêm root→mọi component hoặc `dependsOn: []` cho unknown graph.

Output MVP: unified SBOM + assessment. Optional consumer evaluation thêm projections/comparison. Không có certificate/checker riêng hoặc conformal fitting.

## 8. E — Đánh giá security outcome

\[
M_j=Match_{K,\theta,D}(\pi(S_j)),\quad
M^*=Match_{K,\theta,D}(\pi(S^*)).
\]

So sánh cùng consumer/mapping policy/snapshot; dedup advisory aliases. Record mới không tự là TP, record biến mất không tự là FP đã sửa. Cần labels đúng version/context và advisory snapshot.

Tách:

1. Component/identity-induced advisory matching accuracy.
2. Dependency-path correctness/utility khi consumer sử dụng graph.
3. Artifact-unit observation nếu có evidence.
4. Runtime applicability/exploitability: `NOT_ASSESSED` trong MVP.

OSV package matching trong probe đã chạy không đổi khi chỉ xóa edges. Vì vậy B không được mặc định phải tăng CVE recall của một consumer không dùng graph. Đo đóng góp B bằng edge/path metrics và downstream tasks thực sự sử dụng relationships.

## 9. RQs và metrics

| RQ | Metrics/đối chứng |
| --- | --- |
| RQ1: Conflicts/alignment errors nào còn tồn tại trên release thực? | taxonomy, false merge/split, field/version accuracy, breakdown scope/ecosystem |
| RQ2: Evidence giúp A+B bao nhiêu trước strong baselines cùng thông tin? | package/edge precision-recall, conflict-resolution precision/coverage, incorrect-change rate |
| RQ3: Changes nào cải thiện E? | matching P/R theo labels, added/lost correct matches, path accuracy/triage utility riêng |
| RQ4: Correctness/completeness/cost trade-off? | verified vs unverified completeness, unknown/conflict rate, time/bytes, oracle-label coverage |

Mẫu số 0 trả null. Báo full output và incremental changes riêng. Không chỉ chấm phần đã chọn chắc mà giấu tỷ lệ abstention/unknown. Bootstrap/CI theo project, không coi hàng nghìn edges cùng repo là mẫu độc lập.

Reference dựa trên native metadata/resolution đúng scope, artifact observations khi phù hợp và review ca khó. Oracle chỉ vào scorer. Discovery cases không là held-out; split theo project/release lineage, controls cùng artifact cùng split. Corpus 90 repo của sbom-unifier là điểm chọn subjects, không tự là graph/field truth cho nghiên cứu này.

Baselines: từng scanner, naive union, fixed-priority sbom-unifier, majority/agreement rule; **native CycloneDX/regeneration và semantic metadata control**; JBomAudit/SBOMit/OmniBOR khi cùng evidence/task. Không chỉ thắng priority merge rồi suy ra vượt mọi generator.

## 10. MVP và giới hạn claim

Pilot feasibility ở Java/Maven và npm, ưu tiên subjects từ artifact paper; freeze release, context, generator và advisory snapshot. Chưa cam kết 150–300 repo trước khi biết tỷ lệ build/reference feasibility. Không dùng lại bộ 20 dev cũ làm corpus độc lập.

Artifact inspector của draft trước được giữ như adapter evidence tùy chọn, có [contracts/examples riêng](research/design/artifact-reconciliation-v3/README.md). Nó không còn là điều kiện bắt buộc của đề bài chính. Python V2, graph semantics và hạ tầng format/evidence/scoring là nguồn tái sử dụng.

Hypothesis contribution: joint alignment/metadata/edge reconciliation dưới evidence thiếu/xung đột, có uncertainty tường minh và utility đo được. Chưa xác lập novelty; tên hướng A+B+E không tự là contribution. Không giả định LLM cần thiết.

## Nguồn

- [Khảo sát](research/SBOM_VULNERABILITY_SURVEY_VI.md), [probe](runs/cross-ecosystem-probe-v1/REPORT.md).
- [sbom-unifier paper](https://arxiv.org/html/2608.30708v1): field completeness, PURL alignment, priority complementation.
- [Merger đã xem ở commit 521f3b8](https://github.com/MoriwakiYusuke/sbom-unifier/blob/521f3b8ee6e301e847f7cb113517ba46831e2b28/src/sbom_unifier/merge/merger.py): đã có conflict annotations và package-to-package relationship merging; verified graph correctness là mục tiêu khác.
