# Shared fixtures for the data-quality tests.

import csv
import pathlib

import pytest

# data/tests/conftest.py -> the CSVs live one directory up, in data/.
DATA_DIR = pathlib.Path(__file__).resolve().parent.parent


def _load(name):
    """Load ``data/<name>.csv`` as a list of dict rows.

    Each row is paired with its 1-based line number in the file (accounting
    for the header) so failure messages can point at the offending row.
    """
    path = DATA_DIR / f"{name}.csv"
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        fieldnames = reader.fieldnames
        # line 1 is the header, so the first data row is line 2.
        rows = [(lineno, row) for lineno, row in enumerate(reader, start=2)]
    return fieldnames, rows


@pytest.fixture(scope="session")
def fix_info():
    """(fieldnames, [(lineno, row), ...]) for fix_info.csv."""
    return _load("fix_info")


@pytest.fixture(scope="session")
def build_info():
    """(fieldnames, [(lineno, row), ...]) for build_info.csv."""
    return _load("build_info")


@pytest.fixture(scope="session")
def project_info():
    """(fieldnames, [(lineno, row), ...]) for project_info.csv."""
    return _load("project_info")
