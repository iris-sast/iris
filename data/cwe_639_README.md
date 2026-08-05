# CWE-639 IDOR cases — candidate contribution to iris-sast/iris

## What this is

12 IDOR (Insecure Direct Object Reference / CWE-639, "Authorization Bypass
Through User-Controlled Key") findings, hand-verified against source at a
pinned commit, formatted to match iris-sast's `project_info.csv` /
`fix_info.csv` schema.

- **No CVE IDs.** These are unlabeled vulnerabilities: real access-control
  gaps located by our static analysis tool (Chanakya) in public open-source
  repositories, then manually verified against the actual source at the
  pinned commit — not sourced from any CVE, GHSA advisory, or public
  disclosure. `cve_id` uses a placeholder (`CHANAKYA-IDOR-001` ...
  `CHANAKYA-IDOR-012`), matched consistently between the two CSVs and
  embedded in `project_slug`.
- **Found by:** Chanakya static analysis (control/data-flow source→sink
  tracing over Spring MVC handler methods, looking for a client-controlled
  identifier reaching a resource lookup/mutation with no ownership check
  dominating the call) followed by manual line-by-line source verification
  of every case below — including checking the service-layer implementation
  each controller method delegates to, not just the controller.
- **All repos are public**, cloned at the exact pinned commit referenced in
  `buggy_commit_id`:
  - `shopizer-ecommerce/shopizer` @ `6a4a0a65a3408ee8f62597b51d1b3aac24b77dee`
  - `SelimHorri/ecommerce-microservice-backend-app` @
    `695a6d49a8fb5559b025e22017df1ec657104309`
- **Tool:** Chanakya. Reported precision/recall (0.719 / 0.885) is measured
  against Chanakya's own internal labeled corpus
  (`chanakya-core/benchmarks/labeled_corpus/labels.yaml`, A01+A03 combined,
  260 labeled cases) — **not** against IRIS/CWE-Bench-Java. Treat it as
  provenance context for how the tool that surfaced these cases performs on
  its own held-out set, not as a claim about performance on this dataset.

## Selection rule (stated explicitly — this is a judgment call, not something
the corpus schema encodes directly)

The source corpus (`labels.yaml`) labels each case `vulnerable` / `safe` /
`disputed`, plus an `engine_verdict_known` field recorded at adjudication
time. For "verified true positive, not uncertain, not FP" I applied:

```
category == A01
AND label == vulnerable          (excludes safe + disputed/UNCERTAIN)
AND engine_verdict_known == VULNERABLE   (Chanakya actually flagged it —
                                           consistent with "found by static
                                           analysis + manual verification")
AND provenance_tier == independent_real_world (real third-party app, not one
                                           of our teaching/CTF fixtures)
```

The `provenance_tier` filter excludes label=vulnerable cases from
VulnerableApp (SasanLabs), WebGoat, CentralBankSecLand, and JavaSecLab.
Those are **deliberately-vulnerable teaching/CTF applications** — their IDOR
lessons are the documented, intended content of the app, not an
undisclosed bug we found. Presenting those as "vulnerabilities we found" in
a real-world CWE dataset would misrepresent already-public, intentional
teaching content as original findings, so I left them out. If you want the
teaching-app cases included too (they're legitimate CWE-639 examples, just
not "found" in the same sense), say so and I'll add a separate batch.

I also excluded `engine_verdict_known: NONE` cases (e.g. the SelimHorri
`findById`-with-no-downstream-sink misses, `orders_customer_order_persist`,
the JavaSecLab horizontal-IDOR case) — those are real, hand-verified bugs
too, but Chanakya's engine currently misses them (a documented return-value
taint gap), so calling them "found by static analysis" would be false.

## Correction made to your CWE-639 name

You asked for `cwe_name: Improper Authorization` — that's actually CWE-285's
title. **CWE-639's official title is "Authorization Bypass Through
User-Controlled Key"** (this dataset's actual CWE, an IDOR-shaped
authorization bypass). I used the correct official name in the CSV rather
than the one you specified, since this is headed into an external PR where
a wrong CWE title would be an obvious, easily-checked error. Flag if you
intended something else.

## One case pulled after re-verification: `shopizer_cart_total_idor`

The labeled corpus has a 13th A01 case matching the filter above
(`shopizer_cart_total_idor`, `OrderTotalApi.java` — `GET
/auth/cart/{id}/total`). Re-reading the actual source at the pinned commit
(not just trusting the old label) shows this method **does** have a
post-fetch ownership check:

```java
ShoppingCart shoppingCart = shoppingCartFacade.getShoppingCartModel(id, merchantStore);
...
if (shoppingCart.getCustomerId().longValue() != customer.getId().longValue()) {
    response.sendError(404, "Cart id " + id + " does not exist for exist for user " + userName);
    return null;
}
```

This is the exact "genuine post-fetch ownership check" shape the same
corpus already treats as `safe` elsewhere (e.g. `shopizer_order_get_order`,
the `ContentApi` delete cluster) — Chanakya's dominance analysis doesn't see
it because the check happens after the facade call, not before it. I did
not find a way to bypass it (the one real bug in this method — a missing
`return` after an early `sendError(503)` when `customer == null` — leads to
a `NullPointerException` on the next line, not an authorization bypass).

This label looks stale/wrong as-is, so I excluded it rather than ship a
probably-mislabeled "true positive" into an external submission. This needs
re-adjudication in `labels.yaml` independent of this task — flagging here
rather than silently fixing the corpus, since you said not to touch the
CHANAKYA repo this session.

## Files

- `cwe_639_project_info.csv` — 12 rows, one per finding (`id` 1–12,
  `cve_id` `CHANAKYA-IDOR-001..012`)
- `cwe_639_fix_info.csv` — 12 rows, one per finding, joined to
  `project_info.csv` by `project_slug` (and `cve_id`)
- `cwe_639_README.md` — this file

`class_start/class_end` and `method_start/method_end` in `fix_info.csv` are
exact line numbers from the pinned-commit source (verified by direct
brace-counted reading of each file, not estimated from the labels.yaml
`source_line`, which points at the `@*Mapping` annotation rather than the
method declaration).

## Not done / left for you

- No commits, no branch, nothing written back into the CHANAKYA repo or the
  `labeled_corpus/labels.yaml` file — per instruction, everything above is
  in `/tmp` only.
- `labels.yaml`'s `shopizer_cart_total_idor` entry needs re-adjudication
  (see above) — separate task.
- If iris-sast expects `github_tag` to be an actual release tag/branch
  rather than a commit SHA, note that both source repos are pinned by SHA
  in Chanakya's own checkpoint harness
  (`chanakya-core/scripts/fetch_checkpoints.py`), not by a version tag, so I
  used the short SHA as the tag value.
