"""Ensure project_slug values in fix_info.csv are well formed.

A slug looks like::

    <username>__<repo>_<CVE-id>_<tag>

for example ``perwendel__spark_CVE-2018-9159_2.7.1`` or
``apache__incubator-dubbo_CVE-2021-30181_2.6.8``.

"""

import re

# <username>__<...>_CVE-YYYY-NNNN_<tag>
SLUG_RE = re.compile(r"^[A-Za-z0-9.\-]+__\S+_CVE-\d{4}-\d{3,}_\S+$")
CVE_RE = re.compile(r"CVE-\d{4}-\d{3,}")


def test_slugs_match_canonical_format(fix_info):
    _fieldnames, rows = fix_info

    offenders = []
    for lineno, row in rows:
        slug = row.get("project_slug") or ""
        if not SLUG_RE.match(slug):
            offenders.append(f"  line {lineno}: malformed slug {slug!r}")

    assert not offenders, (
        f"{len(offenders)} fix_info.csv slug(s) are not in "
        f"<username>__<repo>_<CVE>_<tag> form:\n" + "\n".join(offenders)
    )


def test_slug_cve_matches_cve_id_column(fix_info):
    _fieldnames, rows = fix_info

    offenders = []
    for lineno, row in rows:
        slug = row.get("project_slug") or ""
        cve_id = (row.get("cve_id") or "").strip()
        match = CVE_RE.search(slug)
        if not match:
            offenders.append(f"  line {lineno}: no CVE id in slug {slug!r}")
        elif match.group(0) != cve_id:
            offenders.append(
                f"  line {lineno}: slug CVE {match.group(0)!r} "
                f"!= cve_id column {cve_id!r} ({slug!r})"
            )

    assert not offenders, (
        f"{len(offenders)} fix_info.csv row(s) have a slug CVE that "
        f"disagrees with the cve_id column:\n" + "\n".join(offenders)
    )
