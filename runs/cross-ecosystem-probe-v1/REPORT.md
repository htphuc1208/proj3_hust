# Thử nghiệm bổ sung: SBOM phục vụ quét lỗ hổng

Ngày khảo sát: 11-11-2026. Đây là thử nghiệm khám phá cơ chế, chọn mẫu có chủ đích. Chưa đánh giá một thuật toán khôi phục mới và chưa ước lượng tỷ lệ lỗi trong cộng đồng.

**Kết quả đáng theo đuổi:** sai danh tính/phiên bản, chọn sai tập dependency cho artifact, và mất thông tin sau đóng gói ảnh hưởng rõ đến vulnerability matching. Số cạnh sửa được không đủ làm thước đo chính. Thiết kế đề xuất nằm trong [khảo sát và hướng thiết kế](../../research/SBOM_VULNERABILITY_SURVEY_VI.md).

## Phạm vi và công cụ

Đã thử JavaScript/npm, Java/Maven, Go và Rust/Cargo. Ba nguồn thực bổ sung:

| Nguồn | Cách sử dụng | Giới hạn |
| --- | --- | --- |
| `code-genome/jbomaudit`, `aaa-cli-jar:0.15.2` | Quét đúng JAR/SBOM mẫu công khai của paper; kiểm tra class trong JAR với Maven Central | Một artifact, không đại diện 25.882 JAR trong paper |
| `withspectrum/spectrum` | Quét source và Yarn lock đã commit; đây là một tên dự án xuất hiện trong Mind the Gap | Checkout ghi commit trong acquisition.json; không khẳng định đúng revision paper; không dựng deployment |
| `rustls/webpki-roots` | Quét workspace và đối chiếu `cargo tree --locked` | Ca kiểm tra tính phổ biến của cú pháp rename; không dựng toàn bộ workspace hoặc xác nhận CVE |

Các ca npm alias/bundle, Java shade/minimize, Go build và Rust alias/target được tạo để cô lập cơ chế, sử dụng package upstream thật. Biến thể của cùng ca không được tính thành ứng dụng độc lập. Bộ 20 development Python không được dùng. Kết quả Python trước đó vẫn ở [paper-corpus-probe-v1](../paper-corpus-probe-v1/REPORT.md).

| Công cụ | Phiên bản |
| --- | --- |
| Syft | 1.57.1 |
| Trivy | 0.76.2 |
| cdxgen | 12.9.1 |
| CycloneDX npm | 7.0.0 |
| CycloneDX Maven plugin | 2.9.3 |
| CycloneDX Go | 1.12.0 |
| Cargo CycloneDX | 0.5.10 |
| cargo-auditable | 0.7.7 |
| OSV-Scanner | 2.7.1 |
| Node / npm / esbuild | 22.23.2 / 10.9.8 / 0.28.2 |
| Go / Rust | 1.27.4 / 1.99.1 |

Go 1.23.0 được dùng thêm làm đối chứng dương cho việc ghép advisory thư viện chuẩn. Java build dùng Maven 3.9.9/JDK 17 trong image đã ghi ID/digest. Release metadata, checksum và lệnh nằm ở tool-metadata/, versions/ và các execution.json. Các phiên bản được cố định tại lần chạy này.

## 1. Rust rename làm mất package có advisory

Ca gốc có khai báo:

```toml
[dependencies]
regex_alias = { package = "regex", version = "=1.5.4" }
```

Ứng dụng thực sự dùng `regex_alias::Regex`. `cargo tree` cho build Linux production có bốn crate upstream: regex, regex-syntax, aho-corasick, memchr.

| Đầu vào/công cụ | Có `regex@1.5.4` | OSV ghép được CVE-2022-24713 |
| --- | --- | --- |
| Trivy `fs`, khai báo alias | Không | Không |
| Trivy `fs`, bỏ alias | Có | Có |
| Trivy `fs --include-dev-deps`, giữ alias | Không | Không |
| CycloneDX Cargo, target mặc định | Có | Có |
| Syft, binary build bằng cargo-auditable | Có | Có |

Đối chứng thay khai báo thành `regex = "=1.5.4"` và đổi tên import tương ứng. **Cargo.lock giống từng byte; tập dependency production của Cargo giữ nguyên.** Trivy nhận lại cả bốn crate sau thay đổi này. Đây là bất đồng có kiểm soát giữa scanner và package manager, vượt khỏi khác biệt scope đơn thuần.

OSV trả hai record `RUSTSEC-2022-0013` và `GHSA-m5pq-gvj9-9vr8`; chúng cùng alias **một CVE**, không phải hai lỗ hổng độc lập. Chưa kiểm tra khai thác hoặc điều kiện đầu vào gây lỗi.

Ở repo thực webpki-roots, cả Syft, Trivy và cdxgen nhận diện được `rustls-pki-types` qua workspace alias `pki-types`. Vì vậy chưa có bằng chứng lỗi rename xuất hiện trong repo thực này, hoặc mọi dạng rename đều hỏng. Cần mở rộng theo dạng khai báo inline, workspace và feature.

Bằng chứng: rust-build/, scans/rust-source/, scans/rust-no-alias/, mechanism-controls/rust-alias-control.json và consumers/rust-*/.

## 2. Go: replace không còn áp dụng vẫn đổi phiên bản scanner

Sau `go mod tidy`, Go chọn:

```go
require golang.org/x/text v0.14.0
replace golang.org/x/text v0.3.0 => golang.org/x/text v0.3.8
```

Theo ngữ nghĩa Go, dòng replace chỉ áp dụng cho **v0.3.0**. Nó không thay v0.14.0. Native `go list`, buildinfo của binary, Trivy và CycloneDX Go đều ghi v0.14.0; Syft quét source mặc định ghi v0.3.8.

Xóa riêng dòng replace không hoạt động giữ nguyên tập module của `go list`, nhưng làm Syft trở lại v0.14.0. Bật `SYFT_GOLANG_USE_PACKAGES_LIB=true` cũng cho v0.14.0. Mã Syft v1.57.1 đã lưu: nhánh applyReplaceDirectives phù hợp với hiện tượng ghi đè theo path khi không có kết quả native resolver.

Đây là lỗi phiên bản trong ca kiểm soát. **Hai phiên bản này hiện ghép cùng hai record OSV**, nên chưa đo được CVE delta từ riêng lỗi replace. Không suy diễn sai phiên bản luôn làm sai số CVE. Source còn chứa dependency Windows/test; chúng hợp lệ trong inventory nguồn nhưng không thuộc binary Linux đã build.

Bằng chứng: go-build/, scans/go-source/, scans/go-binary/, scans/go-no-inactive-replace/, mechanism-controls/go-* và syft-v1.57.1-parse_go_mod.go.

## 3. Đối chứng mạnh vẫn gặp vấn đề tương thích danh tính Go

CycloneDX Go `bin -std` xuất `pkg:golang/std@go1.23.0`; Syft xuất danh tính `stdlib`. Cùng một binary:

| SBOM chuyển cho cùng OSV-Scanner | Record advisory ghép cho thư viện chuẩn |
| --- | --- |
| CycloneDX Go nguyên bản: `std` | 0 |
| Syft: `stdlib` | 164 |
| Bản CycloneDX chỉ đổi name/PURL `std` → `stdlib` | 164, cùng tập ID với Syft |

Đây là **164 record khớp theo package/version trong database hiện tại**, không phải 164 lỗ hổng đã xác nhận ảnh hưởng ứng dụng. Không chấm reachability hay exploitability. Bản đối chứng không sửa phiên bản hoặc dependency edges.

Vấn đề đã được [maintainer Trivy thảo luận từ năm 2025](https://github.com/aquasecurity/trivy/discussions/8350). Đây là tái hiện khoảng trống tương thích producer–consumer đã biết, không phải phát hiện mới. Một tên có ý nghĩa với module system vẫn cần ánh xạ sang danh tính mà advisory database dùng.

Bằng chứng: go123/, scans/go123-binary/, consumers/go123-*/ và tool-metadata/go123.json.

## 4. Java: metadata còn nhưng bytecode thư viện đã bị loại

Ca Maven khai báo commons-compress 1.20, chương trình chỉ in `SBOM`, và Maven Shade chạy `minimizeJar=true`. JAR cuối chỉ có **một class ứng dụng**, không có class commons-compress; pom.properties/pom.xml của thư viện vẫn còn.

CycloneDX Maven vẫn liệt kê commons-compress; Syft và Trivy rootfs cũng nhận diện nó từ metadata. OSV ghép năm record advisory cho commons-compress. Dependency được khai báo và dùng trong quá trình build là thông tin đúng; suy từ đó rằng JAR chứa bytecode dễ bị lỗi là bước suy luận không được bằng chứng này hỗ trợ.

Một ví dụ thực xuất hiện ngay trong JAR mẫu JBomAudit: 21 class `commons-text` giống từng byte với upstream 1.9, nhưng thiếu `StringSubstitutor` và `StringLookupFactory`. OSV vẫn ghép CVE-2022-42889 từ version 1.9. [Apache xác định điều kiện liên quan API StringSubstitutor và đầu vào không tin cậy](https://commons.apache.org/proper/commons-text/security.html).

Kết luận được giới hạn ở **nội dung JAR này**. Chưa biết classpath ngoài JAR, plugin hoặc class được nạp lúc chạy. Không phát hành kết luận SAFE/NOT_AFFECTED cho cả ứng dụng. Phiên bản chính xác dựa thêm vào metadata upstream; 21 class match không tự chứng minh không có phiên bản khác chứa cùng bytecode.

Bằng chứng: java-minimized/, java-jbomaudit/commons-text-class-evidence.json, commons-text-symbol-observation.json và consumers/java-*/.

## 5. Mất metadata sau đóng gói cần bằng chứng khác để khôi phục

| Artifact | Quan sát | Đối chứng có ích |
| --- | --- | --- |
| JS bundle minify chỉ dùng `lodash-vulnerable` | Syft/Trivy/cdxgen không liệt kê package từ riêng app.js | esbuild metafile nối được file đầu vào với metadata bản lodash 4.17.20 đã cài; bản alias 4.17.21 không đi vào bundle |
| JAR shade giữ metadata | Syft và Trivy rootfs thấy commons-compress 1.20 | CycloneDX Maven xác nhận resolved dependency |
| Cùng JAR, bỏ META-INF | Syft/Trivy/cdxgen không thấy package; mọi class giữ nguyên hash | Receipt build và upstream class evidence là nguồn bổ sung có thể dùng |
| Rust binary thường | Các chế độ đã thử không nhận diện crate | Cùng chương trình build bằng cargo-auditable: Syft/Trivy rootfs thấy đủ bốn crate upstream |

cargo-auditable đã giải quyết trường hợp có thể thay đổi build, bằng metadata nhúng vào binary. Thiết kế mới phải có nó làm đối chứng. Các ca bị bỏ metadata là biến thể kiểm soát, không chứng minh đó là cấu hình phát hành phổ biến. JS metafile ở ngoài thư mục bundle nên scanner artifact không được thấy; không coi việc công cụ thiếu đầu vào này là bug parser.

## 6. Repo thực và khác biệt chế độ cần giữ rõ

- Spectrum: Syft có 2.649 component entries, Trivy 2.842; số lượng này không cho biết ai chính xác hơn. cdxgen 12.9.1 thất bại khi parse Yarn với lỗi `purl is missing the required name component`. Chưa cô lập minimal reproducer hoặc chứng minh alias là nguyên nhân crash; giữ log, không tự gán cơ chế.
- JAR aaa-cli-jar: Syft có 27 package PURL; Trivy rootfs có cùng 27; cdxgen `-t jar` và `--deep` trả một component triemap. Có 21 class commons-text đối chiếu upstream độc lập hỗ trợ sự hiện diện của component mà cdxgen bỏ qua. JBomAudit đã nghiên cứu bài toán này, nên không gọi đó là novelty.
- `trivy fs` trả zero cho các thư mục binary/JAR trong thử nghiệm, còn `trivy rootfs` nhận diện được Go/JAR/Rust auditable. Điểm này là lựa chọn chế độ; kết luận chính dùng rootfs cho artifact.
- Syft directory mặc định đọc lockfile; package fsevents dành Darwin có thể xuất hiện trong inventory nguồn dù không cài trên Linux. Chế độ `--override-default-catalogers installed` nhận đúng package đã cài. Không gán tất cả package từ lockfile thành false positives của scanner nguồn.

Một lần cấu hình Syft dùng `--select-catalogers installed` trên tập mặc định directory đã bỏ cataloger JavaScript installed; đã sửa sang override và giữ log cũ trong attempts/. OSV từ chối tên file SBOM gốc của tác giả Java; bản sao .cdx.json giống hash đã được dùng để đọc thành công. Các lỗi dựng/cấu hình này không được tính là scanner false negatives.

## 7. Cạnh có thể không đổi vulnerability matching

Giữ nguyên components, metadata và versions của CycloneDX npm production, xóa riêng dependencies. OSV-Scanner với `--no-resolve`, không call analysis, cho **cùng tập package–advisory**. Kết quả này giới hạn ở consumer/configuration đã chạy.

Đồ thị vẫn có ích cho giải thích đường dependency, cập nhật và reachability khi consumer thật sự sử dụng nó. Thử nghiệm hiện tại không hỗ trợ luận điểm “thêm cạnh sẽ tăng recall CVE” cho scanner ghép theo danh sách package. Không có đường phụ thuộc không được biến thành bằng chứng an toàn.

## Tái lập và kiểm tra

93 tài liệu .cdx.json được tổng hợp; đây là số tài liệu từ nhiều chế độ/biến thể, không phải số dự án. 92 tài liệu hợp lệ với schema đã cache; SBOM tác giả Java 1.4 chưa được kiểm tra schema do cache hiện chỉ có 1.5–1.7. Kiểm tra schema không xác nhận nội dung đúng. 20/20 kiểm tra tích hợp về cơ chế và tính nguyên vẹn input đều qua, xem validation.json. Các response OSV nguyên bản được giữ; database là snapshot theo lần truy vấn, không cam kết response tương lai giống nhau.

Mã chạy:

```bash
# Dùng release metadata đã đóng băng trong tool-metadata/ để cài đúng tool.
python3 scripts/setup_cross_ecosystem_tools.py
python3 scripts/setup_cross_ecosystem_tools.py --rust
# Clone các repo và checkout commit trong acquisition.json trước khi chạy.
python3 scripts/run_cross_ecosystem_probe.py all
python3 scripts/probe_sbom_mechanisms.py all
.venv/bin/python scripts/analyze_cross_ecosystem_probe.py
```

Payload, compiler, node_modules và cache ở research/.work/cross-ecosystem-probe-v1, không đưa vào git. Cần Docker image theo java-shade/image.json và source checkout theo acquisition.json. Runner ghi lệnh, stdout/stderr, native tree, SHA và source snapshot; một số lượt sửa cấu hình ban đầu được lưu trong attempts/. executed-source/ giữ các snapshot runner từ những lượt sau khi bật cơ chế đóng băng source; không khẳng định mọi lượt thử ban đầu có đầy đủ source snapshot. Không gọi LLM, thuật toán sửa của repo, hoặc checker certificate. Chưa có kết luận vượt đối chứng mạnh trên corpus độc lập.
