# Ensure every project in build_info / project_info appears in fix_info.

def _slug_set(loaded):
    _fieldnames, rows = loaded
    return {(row.get("project_slug") or "").strip() for _lineno, row in rows}


def _missing(source_loaded, fix_slugs):
    _fieldnames, rows = source_loaded
    missing = []
    for lineno, row in rows:
        slug = (row.get("project_slug") or "").strip()
        if slug not in fix_slugs:
            missing.append(f"  line {lineno}: {slug!r}")
    return missing


def test_build_info_projects_are_in_fix_info(build_info, fix_info):
    fix_slugs = _slug_set(fix_info)
    missing = _missing(build_info, fix_slugs)
    assert not missing, (
        f"{len(missing)} build_info.csv project(s) have no row in fix_info.csv:\n"
        + "\n".join(missing)
    )


def test_project_info_projects_are_in_fix_info(project_info, fix_info):
    fix_slugs = _slug_set(fix_info)
    missing = _missing(project_info, fix_slugs)
    assert not missing, (
        f"{len(missing)} project_info.csv project(s) have no row in fix_info.csv:\n"
        + "\n".join(missing)
    )
