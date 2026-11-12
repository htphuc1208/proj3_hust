# Kế hoạch V3 — A + B + E

Ngày 12-11-2026. [Đề bài](../PROBLEM_FORMULATION.md), [kiến trúc](../ARCHITECTURE.md). Hướng chính là multi-SBOM metadata/graph reconciliation; artifact là evidence tùy chọn. V2 giữ riêng.

Runtime đã triển khai: xem [hướng dẫn](EAGER_SBOM_IMPLEMENTATION.md) và package `sbom_recovery/investigation`. Có controlled tests npm/Cargo, chưa hoàn thành empirical gates P1/P5 hoặc chứng minh accuracy/agent superiority. Các acceptance bên dưới giữ nguyên cho nghiên cứu thực.

## P0 — Đặc tả và contracts

Đề bài, models/schemas input multi-SBOM, provenance và scope contract; giữ artifact contracts như adapter draft. Engine/CLI đa SBOM hiện có trong lệnh `investigation`.

Acceptance: source/context/view khác không trộn; doc refs namespace theo document; input không tự cấp trust; null/[] khác nghĩa; schema examples hợp lệ. Contract checks không chứng minh accuracy.

## P1 — Pilot disagreement và reference feasibility

Chọn Java/Maven và npm subjects từ artifact paper; freeze revision/context/toolchain. Chưa mở ngay 150–300 repo. Bộ 20 dev cũ không là corpus độc lập.

Phân loại: missing field, conflicting field, ambiguous alignment, duplicate/split occurrence, wrong-scope edge, missing edge và unsupported semantics. Chạy native CycloneDX/resolver baseline trước. Giữ failed/unsupported/unlabeled cases.

Acceptance: có ca thực được adjudicate và biết strong baselines sai/tie ở regime nào; không dùng overlap scanners làm labels.

## P2 — A: Alignment và identity/version

Namespace original refs; candidate blocking rộng, confirmation có evidence; giữ hai-version hypothesis. Resolve field theo claim, không theo global tool priority. Bảo toàn optional fields chưa verify với status phù hợp.

Acceptance: giữ versions hợp lệ riêng; không merge chỉ vì name; shared coordinates không collapse occurrences; conflict/unknown có explanations. So naive union, fixed priority, majority, semantic/native controls cùng evidence.

## P3 — B: Direct dependency reconciliation

Bind endpoints từ A; phân view/context; đối chiếu declaration/native resolution. Typed relationships giữ riêng. Add/refute edges khi đủ scope/evidence; defer unresolved endpoints.

Acceptance: edge P/R và false-merge/path errors theo independent graph reference; producer flattened graph không tự thành direct edges; missing record không thành empty deps; không suppress từ no-path.

## P4 — E: Security evaluation và ablations

Cùng consumer/config/advisory snapshot, dedup alias records. So single tools, union/priority, A-only và A+B. Đo matching delta theo labels, graph/path utility riêng và uncertainty/cost.

Acceptance: biết thay đổi identity/component/edge nào tạo tác động, biết consumer có dùng graph không. Record mới không tự là TP; không đánh đồng dependency CVE với exploitability. Báo CI theo project, không theo repeated edges.

## P5 — Corpus độc lập

Split project/lineage trước tuning; controls cùng release cùng split. Mở quy mô theo build/reference feasibility, không theo số repo mặc định. Full output và incremental changes đều có metrics/coverage.

Tiếp tục claim phương pháp mới khi có lợi ích trên ca thực độc lập trước strong baselines cùng evidence. Nếu tie với native regeneration, báo tie; regression benchmark/upstream fixes vẫn có giá trị.

## Adapter không phải trọng tâm đầu tiên

[Artifact design](design/artifact-reconciliation-v3/README.md) giữ contracts/coverage boundaries hữu ích. Java binary recovery đầy đủ, relocation/obfuscation, JS source-map reconstruction, license/supplier verification, temporal maintenance và LLM acquisition không nằm trong MVP A+B+E.
