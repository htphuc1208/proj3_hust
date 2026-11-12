# CycloneDX Python 8.0.1 — pilot trên môi trường đã cài

| Dự án | Gói đã cài | Cạnh reference | Cạnh CycloneDX | Thiếu | Dư/bất hoạt |
| --- | ---: | ---: | ---: | ---: | ---: |
| requests 2.32.5 | 7 | 4 | 5 | 0 | 1 |
| typer 0.21.0 | 10 | 7 | 8 | 0 | 1 |
| nox 2025.11.12 | 13 | 11 | 18 | 0 | 7 |
| django-debug-toolbar 6.1.0 | 6 | 4 | 5 | 0 | 1 |
| imbalanced-learn 0.14.1 | 9 | 12 | 14 | 0 | 2 |
| pyserial 3.5 | 3 | 0 | 1 | 0 | 1 |

Chạy lệnh `environment` trên Linux/CPython 3.11.16, CycloneDX 1.6 JSON, validation bật. Công cụ được cài riêng; target chỉ đọc; container quét không có network hoặc oracle. Không truyền pyproject để tránh thay metadata của gói gốc bằng một nguồn khác.

Reference là declared direct requirements của toàn bộ gói cài trực tiếp trong site-packages, bao gồm pip/setuptools; loại metadata vendored lồng trong setuptools. Không yêu cầu root extras; extras từ khai báo con được lan truyền đến fixed point. Đối chiếu độc lập từ metadata target mới đọc với reference cài đặt đã lưu: tập gói/phiên bản và tập cạnh phải trùng trước khi chấm. Reference được tính lại bằng mã riêng nhưng vẫn chia sẻ ngữ nghĩa khai báo và thư viện packaging; đây không phải kiểm chứng độc lập về mã thực thi.

## Kết quả riêng cho ứng dụng

| Dự án | Cạnh hoạt động trong closure ứng dụng | Thiếu | Dư có parent trong closure |
| --- | ---: | ---: | ---: |
| requests | 4 | 0 | 0 |
| typer | 7 | 0 | 0 |
| nox | 11 | 0 | 2 |
| django-debug-toolbar | 4 | 0 | 0 |
| imbalanced-learn | 12 | 0 | 1 |
| pyserial | 0 | 0 | 0 |

Không thấy cạnh thiếu trên sáu môi trường. Có 13 lượt cạnh dư/bất hoạt trên toàn bộ môi trường: 10 có parent setuptools, ba có parent nằm trong closure ứng dụng. Không phải 13 cạnh độc lập.

- nox: `virtualenv → packaging` và `virtualenv → setuptools` chỉ được khai báo cho extra `test`. Extra này không được yêu cầu. Cạnh thứ hai làm setuptools và pip trở nên reachable từ nox trong đồ thị xuất ra, dù không nằm trong closure khai báo hoạt động của ứng dụng.
- imbalanced-learn: `scipy → threadpoolctl` chỉ dành cho extra `test`. Gói threadpoolctl vẫn reachable qua đường hợp lệ khác, nên cạnh dư này không tạo thêm package reachable.
- Cả sáu môi trường: `setuptools → pip` dành cho extra `test` vẫn xuất hiện. Cạnh này có parent nằm ngoài closure hoạt động của ứng dụng, nên không tính là lỗi cạnh trực tiếp của ứng dụng.

Trong mã nguồn 8.0.1 được lưu kèm (`cyclonedx-environment-source.py`), `__finalize_dependencies` liên kết Requires-Dist với gói đã cài theo tên, không đánh giá marker. Điều này phù hợp với các cạnh extra bất hoạt quan sát được. Xem [mã nguồn upstream](https://github.com/CycloneDX/cyclonedx-python/blob/v8.0.1/cyclonedx_py/_internal/environment.py) và [hướng dẫn environment](https://cyclonedx-bom-tool.readthedocs.io/en/latest/usage.html).

Đây là sáu dự án development cũ, không phải held-out hay mẫu đại diện PyPI. Các cạnh dư là khác biệt so với đồ thị kích hoạt theo ngữ cảnh đã định nghĩa; không tự chứng minh công cụ vi phạm đặc tả CycloneDX. Kết quả không đo runtime, exploitability hoặc novelty. Chưa có bằng chứng từ pilot này rằng cần một thuật toán khôi phục cạnh thiếu tốt hơn CycloneDX Python; khác biệt đang thấy là lọc cạnh theo ngữ cảnh extras. Xem assessment.json cho từng cạnh và khai báo nguồn.

## Tái lập

Cài `cyclonedx-bom==8.0.1` vào venv công cụ riêng trên image đã ghi trong plan.json. tool-inventory.json ghi phiên bản tất cả dependency của công cụ. Sau đó chạy:

```bash
.venv/bin/python -B scripts/run_cyclonedx_python_pilot.py --out runs/cyclonedx-python-pilot-new
```

Các file scan.execution.json lưu đầy đủ lệnh Docker và thời gian; scan.stderr giữ cảnh báo. scan-seal.json và scan-seals.json ghi hash SBOM, inventory và metadata gốc.
