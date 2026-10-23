# Primary Research Literature & Benchmarks

This directory contains peer-reviewed primary literature and benchmark definitions required for empirical reproduction and scientific baselines in `sbom_security_poc`:

## 1. DSN 2024: Metadata-Based SBOM Differential Analysis
- **Title:** *On the Correctness of Metadata-Based SBOM Generation: A Differential Analysis Approach*
- **Authors:** Sheng Yu, Wei Song, Xunchao Hu, Heng Yin (University of California, Riverside)
- **Venue:** 54th Annual IEEE/IFIP International Conference on Dependable Systems and Networks (DSN 2024)
- **Artifacts:**
  - Paper: `sbom-dsn24.pdf`
  - Metadata: `dsn2024.json`
  - Benchmark Repository: [DeepBitsTechnology/sbom-benchmark](https://github.com/DeepBitsTechnology/sbom-benchmark)
  - License: `DSN_BENCHMARK_LICENSE`
- **Relevance:** Serves as the independent benchmark for generator omission reproduction (`scripts/run_paper_reproduction.py`).

## 2. Pinned External Peer-Reviewed References (Referenced in AGENTS.md)
- **Moriwaki et al., 2026:** *sbom-unifier: Integration Framework for Heterogeneous SBOMs*, IEEE International Conference on Software Maintenance and Evolution (ICSME) Tool Demonstrations: <https://arxiv.org/abs/2608.30708>.
- **Bouzenia et al., 2025:** *RepairAgent: Autonomous Program Repair Agent*, IEEE/ACM International Conference on Software Engineering (ICSE 2025): <https://doi.org/10.1109/ICSE55347.2025.00157>.

