# Paper-corpus probe: finding dependency-graph failure mechanisms

## Kết luận

Đã quét **26 ca source**: bốn ca Python DSN, toàn bộ 12 template Cofano và toàn bộ mười repo Python trong artifact sbom-unifier. Dựng được **22 môi trường**. Trạng thái còn lại: {'COMPLETE': 22, 'FAILED': 1, 'NOT_ATTEMPTED': 2, 'RESOURCE_LIMIT': 1}. Không dùng target hoặc reference từ bộ 20 development của repo.

Có vấn đề tái lập được: **Syft 1.54.1 nhận diện đủ package nhưng bỏ cạnh khai báo bằng URL/VCS**. Tám template Cofano mất hai cạnh/template, tổng 16 lượt cạnh thiếu; không coi 16 lượt này là 16 lỗi độc lập. Đối chứng đổi cách biểu diễn sang name==version khôi phục đủ hai cạnh với cùng inventory.

**CycloneDX Python 8.0.1 chế độ environment không thiếu cạnh hoạt động trên 22/22 môi trường đã dựng**, theo reference từ declared Requires-Dist và ngữ cảnh. Nó có 129 lượt cạnh thêm so với đồ thị hoạt động, chủ yếu là marker/extras bất hoạt. Đây chưa phải bằng chứng thuật toán repo vượt đối chứng mạnh, cũng chưa phải novelty đã chứng minh.

## 1. Dữ liệu và chế độ thông tin

- DSN: `DeepBitsTechnology/sbom-benchmark`, commit trong plan.json; source scan chỉ thấy entrypoint và các file được tham chiếu, không thấy groundtruth tác giả hoặc entrypoint khác.
- Cofano: `serenacofano/SBOM-python-ecosystem`, commit trong plan.json; đủ 12 template. Chúng chia sẻ phần lớn dependency, không phải 12 dự án độc lập đại diện PyPI.
- Repo thực: mười tên trong subjects.csv của sbom-unifier; clone HEAD và ghi commit. Đây là contemporary probes trên cùng tên repo, không phải tái lập đúng phiên bản paper.
- Source scans: Syft 1.54.1 `scan dir`, Trivy 0.76.1 `fs`, CycloneDX Python native requirements/poetry/pipenv khi có mode phù hợp. Không tạo lockfile giả khi artifact không có lockfile.
- Installed scans: build wheel từ source sạch trong Docker, cài production dependencies, không yêu cầu root extras. Ngoại lệ DSN có `requests[security]` trong literal input nên seed security được giữ. Sau cài, quét target chỉ đọc bằng CycloneDX environment, Syft dir và Trivy rootfs.
- Không so source với installed bằng cùng một F1. Source được báo số ingredient identities có mặt; installed mới chấm cạnh theo ngữ cảnh. Không đếm GitHub Actions, file nodes hay metadata vendored là package Python cài độc lập.

Mốc cạnh được tính bằng mã phân tích riêng từ METADATA mới đọc, có marker/extras propagation. URL/VCS phải khớp direct_url.json hoặc tag→commit đã lưu. Không gọi hàm sửa SBOM của repo, nhưng vẫn chia sẻ ngữ nghĩa khai báo và thư viện packaging. Đây không phải ground truth runtime hay kiểm chứng con người độc lập.

## 2. Cofano: source và installed là hai bài toán khác nhau

| Template | Syft source: tên trong 6 ingredient | Trivy source: tên trong 6 | Cài được | Syft installed: cạnh thiếu | CycloneDX env: cạnh thiếu |
| --- | --- | --- | --- | --- | --- |
| hatch-hatchling | 0 | 0 | COMPLETE | 2 | 0 |
| hatch-pdm | 0 | 0 | COMPLETE | 2 | 0 |
| hatch-setuptools | 0 | 0 | COMPLETE | 2 | 0 |
| pdm-flit | 6 | 0 | COMPLETE | 2 | 0 |
| pdm-hatchling | 6 | 0 | COMPLETE | 2 | 0 |
| pdm-pdm | 6 | 0 | COMPLETE | 2 | 0 |
| pdm-setuptools | 6 | 0 | COMPLETE | 2 | 0 |
| pip-hatchling | 1 | 1 | COMPLETE | 0 | 0 |
| pip-pdm | 1 | 1 | COMPLETE | 0 | 0 |
| pip-setuptools | 1 | 1 | COMPLETE | 0 | 0 |
| pipenv-pdm | 6 | 6 | COMPLETE | 0 | 0 |
| poetry-poetry | 6 | 6 | COMPLETE | 2 | 0 |

Ba template hatch không có lockfile cho cả hai scanner nguồn trong lệnh đã thử nên trả về zero packages. Bốn template PDM có lockfile: Syft thấy đủ sáu ingredient; Trivy không xuất package trong lệnh fs đã thử. Ba template pip chỉ có seaborn được pin thông thường nên Syft/Trivy chỉ nhận diện một trong sáu ingredient; CycloneDX requirements nhận diện năm tên và có component `unknown` cho bare docopt URL. Đây là coverage/identity observations, không tự là sáu lỗi scanner trong một mẫu đại diện.

Sau cài, hai dependency direct URL/VCS trên tám root có Requires-Dist tương ứng được xác minh là:

```text
root → black   (git+https://github.com/psf/black.git@21.10b0)
root → docopt  (https://.../docopt-0.6.2.tar.gz)
```

Syft vẫn liệt kê black và docopt với version, nhưng không có hai cạnh. Không đếm bốn template pip/pipenv là thành công root-graph tương đương: các template đó cài thêm requirement từ file/lock bên ngoài nhưng metadata root không khai báo dependency. Inventory đầy đủ không tự chứng minh có đồ thị application root đầy đủ.

Một lỗi artifact cũng được giữ rõ: template tên `pip-setuptools` thực tế khai báo backend hatchling. Không dùng tên thư mục để gán hành vi cho setuptools.

## 3. Repo thực từ sbom-unifier

| Repo của paper | Trạng thái dựng | Package đã cài | Cạnh hoạt động | Syft: thiếu | CycloneDX env: thiếu |
| --- | --- | --- | --- | --- | --- |
| thefuck | COMPLETE | 7 | 6 | 0 | 0 |
| flask | COMPLETE | 7 | 8 | 0 | 0 |
| keras | COMPLETE | 13 | 14 | 0 | 0 |
| rich | COMPLETE | 4 | 3 | 0 | 0 |
| requests | COMPLETE | 5 | 4 | 0 | 0 |
| gym | COMPLETE | 4 | 3 | 0 | 0 |
| pytorch-lightning | RESOURCE_LIMIT | — | — | — | — |
| python-fire | COMPLETE | 2 | 1 | 0 | 0 |
| cookiecutter | COMPLETE | 20 | 20 | 0 | 0 |
| loguru | COMPLETE | 1 | 0 | 0 | 0 |

Trên chín repo dựng được, Syft và CycloneDX environment không thiếu cạnh hoạt động. PyTorch Lightning bị giới hạn vì wheel torch tương thích vượt 512 MiB; không thay ngầm bằng CPU build hoặc phiên bản khác. Source SBOM có thể chứa dependency của docs, test, examples và GitHub workflows; chúng không tự là false positives của source inventory. Ví dụ source scan requests trả về các thành phần docs/workflow nhưng không thể xem đó là inventory deployment chính.

## 4. DSN Python

| Ca DSN | Lượt dựng môi trường | Syft/Trivy source | CycloneDX source |
| --- | --- | --- | --- |
| requirements | COMPLETE | 0 tên package Python | 8 tên |
| continuations | FAILED | 0 tên package Python | 3 tên |
| poetry | NOT_ATTEMPTED | 0 tên package Python | không chạy được do thiếu lockfile |
| pipenv | NOT_ATTEMPTED | 0 tên package Python | không chạy được do thiếu lockfile |

`requirements` dựng thành công ở thời điểm hiện tại: 55 package, 66 cạnh hoạt động. Không so package/version mới với danh sách cài đặt năm 2024 như một ground truth lịch sử. Syft/Trivy source không nhận diện package trong input nguyên văn đã chọn; CycloneDX requirements đọc được nhiều cú pháp hơn, bao gồm file tham chiếu và line continuation. Ca `r.txt` bị uv 0.12.4 từ chối ngay ở parser với cú pháp line continuation nguyên bản. Đối chứng trực tiếp xác nhận pip 26.3 đọc thành `numpy ==1.26.2`, còn uv từ chối cả khi đọc trực tiếp file. Chỉ nối các dòng continuation thành một dòng tương đương thì uv resolve thành công. Đây là parser disagreement của pipeline cài đặt, không được gán thành FN của scanner. CycloneDX requirements cũng đọc được numpy 1.26.2 từ bản nguyên văn. Các lệnh, stdout/stderr và input dẫn xuất nằm trong mechanism-controls/continuation-control.json và các file pip26-/uv-*. Hai fixture Poetry/Pipfile không có lockfile tác giả và không có root package để build, nên không có installed-edge scores.

## 5. Kiểm tra cơ chế và ảnh hưởng tới đường phụ thuộc

`mechanism-controls/url-vs-pin.json` là đối chứng metadata-only dẫn xuất từ một ca Cofano:

| Cách khai báo | Package inventory | Cạnh Syft |
| --- | --- | --- |
| URL/VCS nguyên bản | root, black, docopt | 0 |
| name==version, giữ nguyên inventory | cùng ba package | 2 |

Không tính control dẫn xuất này thành dự án mới hay kiểm chứng code thực thi. Mã Syft ở tag v1.54.1 được lưu trong `syft-dependency.go`: extractPackageName tách theo extras/version/marker delimiters nhưng không tách ký tự `@`, phù hợp với kết quả quan sát. Phần comment của upstream còn nói rõ wheel/egg relationships hiện có thể nối extra dependency nếu endpoint đã cài; vì vậy gọi mọi cạnh dư là bug chuẩn CycloneDX sẽ vượt bằng chứng.

Ở môi trường hatch-hatchling thật, reference từ khai báo có đường đến black; Syft không có đường đó và bỏ sót tám package reachable từ root: black, click, docopt, mypy-extensions, pathspec, platformdirs, regex, tomli. CycloneDX environment giữ đường đến black.

Query OSV hiện tại cho black 21.10b0 có advisory liên quan CVE-2024-21503, cùng các record/alias khác trong `mechanism-controls/black-osv.json`. Điều này minh họa: consumer sai lầm dùng no-path như bộ lọc âm tính có thể che advisory dù package vẫn xuất hiện trong SBOM. Không chạy exploit, không chứng minh lỗ hổng được kích hoạt, không đo lợi ích triage trên sản phẩm; dữ liệu advisory là retrospective và không đếm các alias thành CVE độc lập.

## 6. Các quan sát bổ sung

Đối chứng DSN parser còn tái hiện một cơ chế lỗi đã biết của paper trên một công cụ cài đặt hiện tại:

```text
numpy \
==\
1.26.2
```

pip 26.3 parse được và giữ phân biệt requirement/constraint; uv 0.12.4 báo lỗi. Bản nối dòng tương đương được uv resolve. Kết quả này quan trọng cho reference builder: một pipeline chỉ dùng uv có thể loại nhầm ca hợp lệ theo pip. Đây là case hồi quy có thể báo upstream, không tự là thuật toán SBOM mới.


- Thêm `--pyproject` vào CycloneDX environment làm root mất version ở 6 ca: cofano/hatch-hatchling, cofano/hatch-pdm, cofano/hatch-setuptools, real/keras, real/requests, real/loguru. Đây là identity-fidelity observation; topology theo tên được chấm riêng để không đếm nhầm thành cạnh thiếu. Root application metadata có thể có chủ đích khác với installed distribution, nên cần đánh giá contract trước khi gọi là bug.
- Trivy rootfs nhận diện package nhưng không xuất cạnh package-to-package trong 22 môi trường này; quan hệ file/root không được tính là Requires-Dist edge. Đây là giới hạn chế độ đã thử, không phải bằng chứng registry/package bị thiếu.
- Các cạnh marker/extras bất hoạt có thể tạo cycle/shortcut không thuộc đồ thị kích hoạt. Pilot chưa đo độc lập ảnh hưởng triage hoặc exploitability của các cạnh này.

## 7. Có gì đáng nghiên cứu tiếp?

**Đáng điều tra nhất:** package inventory đúng nhưng đồ thị mất cạnh do dependency origin/representation (tên + pin so với archive URL/VCS), và ảnh hưởng tới các consumer dùng đường phụ thuộc. Có ca gốc, control giữ inventory và ví dụ advisory. Bước tiếp theo cần ca repo thực có dependency URL/VCS, đối chứng CycloneDX/PIP-sbom/semantic extractor, và metric graph correctness riêng với component correctness.

**Chưa đủ cho novelty mạnh:** vá regex tách `@`, đọc thêm PEP 621 hoặc lọc marker/extras bằng quy tắc. Các paper đã bàn về remote dependencies và metadata; không tuyên bố đây là phát hiện đầu tiên. Chưa tìm được failure về thiếu cạnh của CycloneDX environment khi đầy đủ installed metadata trên corpus chạy được. LLM không được chứng minh cần thiết.

**Nếu giữ hướng khôi phục:** phải xác lập use case mà người dùng chỉ có SBOM cùng evidence rời rạc, không thể quét lại đúng môi trường. Đó là một regime thông tin mới cần chứng minh bằng dữ liệu thực; không được lấy thắng lợi trước scanner nguồn rồi quy thành vượt CycloneDX với đầy đủ môi trường.

## 8. Tái lập và giới hạn kỹ thuật

Source inputs được giữ nguyên. Lượt đầu thiếu Git trong image build được lưu trong `attempts/`; sau đó thêm Git và dùng build constraint setuptools==80.9.0 để hỗ trợ các setup.py cũ dùng pkg_resources. Đây là compatibility variant được công khai, không phải lỗi SBOM. Pipenv cài production bằng export từ default lock entries; Poetry/PEP 621 root được build qua PEP 517 và resolve mới, không khẳng định đã replay nguyên frontend hay lock lịch sử.

`plan.json`, `build-image.json`, input-manifest.json, các *.execution.json, build-steps.json, prediction-seal.json và executed-source/ ghi nguồn, lệnh và snapshot mã. Target environments và wheel payload được gitignore vì lớn. `source-summary.json`, `installed-summary.json` và `summary.json` giữ đủ ca thành công/thất bại. Kiểm thử parser/reference boundaries nằm trong tests/test_paper_corpus_probe.py; validation.json xác minh hashes, provenance và nhận diện missing edge có kiểm soát.

```bash
.venv/bin/python -B scripts/run_paper_corpus_probe.py --phase source --out runs/paper-corpus-probe-new
.venv/bin/python -B scripts/run_paper_corpus_probe.py --phase installed --out runs/paper-corpus-probe-new --build-image sbom-paper-corpus:py311-git --build-constraint research/.work/paper-corpus-probe-v1/legacy-build-constraints.txt
.venv/bin/python -B scripts/analyze_paper_corpus_probe.py runs/paper-corpus-probe-new
```

Acquisition snapshots ở research/.work/paper-corpus-probe-v1; tái tạo từ URL + commit trong plan.json. Source clone phải đúng commit; source-mount chỉ đọc; network chỉ dùng khi acquisition/build. Không tái sử dụng bộ 20 development, không gọi LLM/API mô hình, không dùng held-out để tune.

Nguồn: [DSN artifact](https://github.com/DeepBitsTechnology/sbom-benchmark), [Cofano artifact](https://github.com/serenacofano/SBOM-python-ecosystem), [sbom-unifier subjects](https://github.com/MoriwakiYusuke/sbom-unifier-replication/blob/main/SUBJECTS.md), [Syft dependency implementation](https://github.com/anchore/syft/blob/v1.54.1/syft/pkg/cataloger/python/dependency.go), [CycloneDX environment](https://github.com/CycloneDX/cyclonedx-python/blob/v8.0.1/cyclonedx_py/_internal/environment.py).
