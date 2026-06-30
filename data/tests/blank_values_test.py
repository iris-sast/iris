# Ensure fix_info.csv rows have no blank values in required columns.

# Columns that must always carry a value for a row to be usable.
REQUIRED_COLUMNS = [
    "project_slug",
    "cve_id",
    "github_username",
    "github_repository_name",
    "commit",
    "file",
]


def test_required_columns_are_not_blank(fix_info):
    _fieldnames, rows = fix_info

    offenders = []
    for lineno, row in rows:
        blank = [col for col in REQUIRED_COLUMNS if not (row.get(col) or "").strip()]
        if blank:
            offenders.append(
                f"  line {lineno}: blank {blank} "
                f"(project_slug={row.get('project_slug')!r})"
            )

    assert not offenders, (
        f"{len(offenders)} fix_info.csv row(s) have blank required values:\n"
        + "\n".join(offenders)
    )
