# Superseded by final development v4

This analysis correctly excludes artificial native reference-root edges from
F1-panel eligibility and preserves the sealed v3 predictions. Its legacy
comparator still uses v3's adapter, which inherited V2's metadata-completeness
restriction for historical Metadata-Version 2.0. The final run
`runs/certified-development-v4` restores the exact v1 behavior for that case.
Use v4 for the final comparison; V2 and strong-control graphs are unchanged.
