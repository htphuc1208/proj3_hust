> Draft artifact-only trước khi chọn A+B+E. Tài liệu này chỉ làm phụ lục cho adapter evidence theo artifact; đề bài chính hiện tại ở [PROBLEM_FORMULATION.md](../../../PROBLEM_FORMULATION.md).

# Kế hoạch triển khai V3

Ngày 12-11-2026. [Đề bài](../../../PROBLEM_FORMULATION.md), [kiến trúc](../../../ARCHITECTURE.md). Python V2 và các runs trước giữ riêng; [protocol M2.3](../../PROTOCOL.md) là nghiên cứu lịch sử.

## Quyết định

| Quyết định | Lý do |
| --- | --- |
| Một artifact hash/lần; Java JAR + CycloneDX 1.6 trước | Phạm vi cụ thể, có artifact paper và shade/minimize controls |
| Context/evidence được thiếu | Không đòi luôn có đúng môi trường build |
| Facts typed, coverage, native adapters | Giữ semantics theo ecosystem, không viết lại mọi resolver |
| SBOM dẫn xuất + explanations | Certificate/conformal không trở lại |
| Matching/applicability riêng; baseline cùng evidence | Không dùng cạnh làm proxy CVE recall hoặc lợi thế đầu vào làm lợi thế thuật toán |

## P0 — Đề bài và contracts

Deliverables: PROBLEM_FORMULATION.md, ARCHITECTURE.md, contracts_v3.py, schemas/examples và boundary tests. Bước này chỉ triển khai design/contracts; chưa có CLI/engine V3.

Acceptance: tách scope/status/identity resolution; null feature khác []; UNKNOWN/CONFLICT không apply; containment không là dependency; refutation presence cần coverage đúng miền; schemas/examples round-trip. Data checks không chứng minh evidence đúng.

## P1 — Java inspection

JAR + SBOM → metadata/class observations, locators/hashes, issues và per-domain coverage. Collector dự kiến `artifact_java.py`: đọc ZIP có giới hạn, giữ archive chain, multi-release entries/duplicates, không chạy JAR. Không thấy entry khác với archive đọc lỗi.

Acceptance: JBomAudit sample, shade, stripped metadata, minimize; metadata-only và literal missing paths; không whole-app not-affected/direct edges từ containment. So Syft/Trivy rootfs, giữ raw outputs.

## P2 — Identity/component reconciliation

Nhận thêm evidence đã bind target; candidates → claims → changes đủ điều kiện. Policy versioned, unbound/mismatched sources không cấp quyền target changes.

Acceptance: thêm component khi occurrence/identity hỗ trợ; sửa version khi bind đủ; class hashes dùng chung giữ ambiguity; conflict không tự chọn nguồn; input không đổi; output schema/refs hợp lệ; missing dependency record còn unknown.

Baseline: native CycloneDX, Syft/Trivy, cdxgen, metadata-rule/union cùng evidence. So JBomAudit trên contract Java phù hợp trước claim code-aware novelty.

## P3 — Quan hệ và matching

Native selected graph phải thuộc đúng build/output. Selected edges, declared graph, containment giữ riêng. Consumer namespace adapter theo role; freeze consumer/config/database hoặc recorded-response evaluation có ghi giới hạn.

Acceptance: graph removal có thể không đổi matching; identity-induced delta có giải thích; advisory aliases dedup; metadata-only không suppress; package người dùng tên `std` không bị đổi; full-output/incremental metrics riêng.

## P4 — JS bundle

esbuild output-specific contributions + bound package metadata. Zero bytes/external imports có nghĩa riêng; thiếu receipt/output binding/input identity giữ unknown.

Acceptance: alias, hai versions, tree-shaken input, external package, record của output khác. Native/regeneration và SBOMit khi có Witness evidence là controls.

## P5 — Đánh giá độc lập

Release thực ngoài discovery; split project/lineage trước tuning. Tách regimes SBOM-only, +artifact, matched build; giữ failed/unsupported/unlabeled cases. Quy mô corpus chọn sau pilot feasibility.

Đo identity, selection, footprint, direct edges, matching riêng. Applicability labels review riêng. Oracle không tham gia chọn repairs; overlap scanners không là truth.

Tiếp tục phương pháp mới khi có lợi ích trên ca thực độc lập trước strong baselines cùng evidence. Nếu native regeneration/adapter đơn giản giải quyết đủ, ưu tiên regression benchmark/upstream fixes. Novelty chưa xác lập.

## Sau MVP

SPDX 2.3, Python V2 integration, Go/Rust, multi-artifact manifest và acquisition ranking xem sau P1–P4. Chỉ đánh giá LLM nếu xuất hiện tác vụ evidence discovery/interpretation mà control tất định chưa giải quyết tốt; không mặc định dùng quyết identity/binding.
