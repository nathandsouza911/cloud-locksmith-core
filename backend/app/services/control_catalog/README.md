# Compliance Mapping Catalog (Phase 1)

Read-only overlay mapping the **17 canonical Cloud Locksmith controls** to external
framework references. **Not consumed by any report yet** — Phase 2 wires it into
finding detail, the insurance evidence report, and CSV export.

## Files

| File | Owner | Authority |
|---|---|---|
| `frameworks.json` | security eng | Framework registry (IDs validation references) |
| `compliance_mappings.json` | security eng | `control_id → [mapping]` — **the file to review** |
| `crosswalks.json` | security eng | NIST CSF 2.0 → ISO 27001 (derived frameworks) |
| `schema.py` | — | Enums + `CatalogValidationError` |
| `loader.py` | — | Fail-closed load + `validate_catalog()` + accessors |

## How to validate after editing

```bash
python -m pytest tests/test_control_catalog.py -q
```

The loader also validates at import, so a malformed catalog crashes app startup
(intended — never silently degrade reports).

## Source authority of `reference_id` values — READ BEFORE REVIEW

| Framework | Authority | Shown in reports/CSV |
|---|---|---|
| **cisa-scuba** (`MS.AAD.*`, `MS.EXO.*`) | Every ID and `report_label` must match `scuba_statements.json`, which quotes cisagov/ScubaGear (`main`, read 2026-11-15) verbatim. The loader refuses anything else. Until 2026-11-15 several IDs were wrong (3.3v1, 7.3v1, 7.4v1 cited with invented text); `tests/test_scuba_references.py` pins the corrected table. | yes |
| **cyber-insurance** (`MFA-ADMIN`, etc.) | Product-owned taxonomy. | yes |
| **nist-csf** functions (`PR.AA-03`, etc.) | Derived; real NIST CSF 2.0 subcategory IDs, choice per control is a judgement. | yes |
| **cis-m365** (`5.2.2.4`, `1.1.3`, etc.) | **Unverified.** Numbers were inferred, not taken from a licensed CIS benchmark. `frameworks.json` marks it `"verified": false`, so the references stay here for review but are not shown anywhere. Check every `reference_id` against your licensed copy, then set `verified` to `true`. | **no** |

`IDENTITY_PASSWORD_NEVER_EXPIRES` has no SCuBA mapping on purpose: MS.AAD.6.1v1 says user
passwords SHALL NOT expire, the opposite of what that control flags.

## Coverage

The SCuBA mapping per control is generated into `docs/controls.md` (column *CISA SCuBA*);
that file and `tests/test_scuba_references.py` are the current view. Every control has at
least one mapping (test-enforced).

## When a new control lands later
Add its `control_id → [mapping]` block here. `test_every_baseline_control_has_at_least_one_mapping` fails CI until it is mapped.
