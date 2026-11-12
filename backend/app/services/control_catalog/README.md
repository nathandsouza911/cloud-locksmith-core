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

| Framework | Authority | Action for reviewer |
|---|---|---|
| **cisa-scuba** (`MS.AAD.*`) | **Authoritative.** Pulled from the vendored `reference_repos/ScubaGear-main/.../baselines/aad.md` policy IDs. | Spot-check only. |
| **cyber-insurance** (`MFA-ADMIN`, etc.) | **Product-owned taxonomy.** We define these. | Confirm the category names read well to underwriters. |
| **nist-csf** functions (`PR.AA-03`, etc.) | Derived; real NIST CSF 2.0 subcategory IDs. | Spot-check the function choice per control. |
| **cis-m365** (`5.2.2.4`, `1.1.3`, etc.) | ⚠️ **BEST-EFFORT — VERIFY.** Numbers were inferred, not pulled from a licensed CIS benchmark (CIS M365 numbering shifts across versions). The **`report_label` titles are accurate**; the **numeric `reference_id`s need confirmation** against your CIS M365 Foundations Benchmark v5.0 copy. | **Verify every `cis-m365` `reference_id`.** |

`frameworks.json` pins `cis-m365` to `v5.0` — change the version and IDs together if you reconcile against a different benchmark edition.

## Coverage summary (every control has ≥1 mapping; test-enforced)

| Control | CIS | SCuBA | Insurance | NIST CSF (derived) |
|---|---|---|---|---|
| IDENTITY_USER_NO_MFA | 5.2.2.1 ⚠️ | MS.AAD.3.2v2 | MFA-USERS | PR.AA-03 |
| IDENTITY_ADMIN_NO_MFA | 5.2.2.4 ⚠️ | MS.AAD.3.6v1 | MFA-ADMIN | PR.AA-03 |
| IDENTITY_UNUSED_ACCOUNT | 1.1.4 ⚠️ | — | ACCOUNT-LIFECYCLE | PR.AA-01 |
| IDENTITY_ADMIN_COUNT_EXCESS | 1.1.3 ⚠️ | MS.AAD.7.1v1 | ADMIN-COUNT | PR.AA-05 |
| IDENTITY_OVERPRIVILEGED_USER | 1.1.1 ⚠️ | MS.AAD.7.2v1 | PRIV-ACCESS | PR.AA-05 |
| IDENTITY_BREAK_GLASS_ACCOUNT | — | — | EMERGENCY-ACCESS | PR.AA-01 |
| IDENTITY_BREAK_GLASS_USAGE | — | — | EMERGENCY-ACCESS-MONITOR | DE.CM-03 |
| IDENTITY_GUEST_INVITES_OPEN | 1.1.7 ⚠️ | MS.AAD.8.2v1 | EXTERNAL-ACCESS | PR.AA-05 |
| IDENTITY_USER_CONSENT_POLICY | 5.1.5.1 ⚠️ | MS.AAD.5.2v1 | APP-CONSENT | PR.AA-05 / PR.PS-01 |
| IDENTITY_ILLICIT_CONSENT_GRANTS | 5.1.5.2 ⚠️ | MS.AAD.5.2v1 | APP-CONSENT | DE.CM-03 |
| CA_MFA_ALL_USERS | 5.2.2.6 ⚠️ | MS.AAD.3.2v2 | MFA-USERS | PR.AA-03 |
| CA_MFA_ADMINS | 5.2.2.4 ⚠️ | MS.AAD.3.6v1 | MFA-ADMIN | PR.AA-03 |
| CA_LEGACY_AUTH_BLOCK | 5.2.2.10 ⚠️ | MS.AAD.1.1v1 | LEGACY-AUTH | PR.AA-03 / PR.PS-01 |
| CA_DEVICE_CODE_FLOW_BLOCK | — | MS.AAD.3.9v1 | LEGACY-AUTH | PR.AA-03 / PR.PS-01 |
| CA_AUTHENTICATION_TRANSFER_BLOCK | — | — | AUTH-HARDENING | PR.PS-01 |
| CA_GUEST_MFA | 5.2.2.7 ⚠️ | MS.AAD.3.2v2 | EXTERNAL-ACCESS | PR.AA-03 |
| CA_BREAK_GLASS_EXCLUSION | — | — | EMERGENCY-ACCESS | PR.AA-01 |

⚠️ = `cis-m365` reference number to verify.

### Controls intentionally lacking SCuBA/CIS mappings (not gaps)
- **Break-glass (3 controls)** and **CA_AUTHENTICATION_TRANSFER_BLOCK**: no verified SCuBA/CIS policy exists; mapped to the product insurance taxonomy + derived NIST. These satisfy coverage by design — do not invent SCuBA/CIS IDs for them.
- **IDENTITY_UNUSED_ACCOUNT**: SCuBA has no inactive-account policy; CIS + insurance cover it.

## When a new control lands later
Add its `control_id → [mapping]` block here. `test_every_baseline_control_has_at_least_one_mapping` fails CI until it is mapped.
