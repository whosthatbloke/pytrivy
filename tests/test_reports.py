import os

import pyexcel
import pytest

from src.trivy.classes import TrivyClient
from src.trivy.enums import TrivyScanCommandEnum
from src.trivy.exceptions import TrivyClientNotScanned
from src.trivy.reports import generate_excel_report
from tests.helpers import MONGODB_2_11_LITERAL, MONGODB_2_11_RESULTS


@pytest.fixture
def mock_client() -> TrivyClient:
    """
    Returns a client pre-loaded with mock data.
    """
    return TrivyClient.from_file(str(MONGODB_2_11_RESULTS))


def test_raises_if_not_scanned():
    client = TrivyClient(MONGODB_2_11_LITERAL, TrivyScanCommandEnum.Image)
    with pytest.raises(TrivyClientNotScanned):
        generate_excel_report(client)


def test_returns_filename(mock_client: TrivyClient, tmp_path):
    filename = str(tmp_path / "report.xlsx")
    result = generate_excel_report(mock_client, filename=filename)
    assert result == filename


def test_creates_file(mock_client: TrivyClient, tmp_path):
    filename = str(tmp_path / "report.xlsx")
    generate_excel_report(mock_client, filename=filename)
    assert os.path.exists(filename)


def test_default_filename_format(mock_client: TrivyClient, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    result = generate_excel_report(mock_client)
    assert result.endswith(".xlsx")
    assert "percona__percona-backup-mongodb:2.11.0" in result
    assert os.path.exists(result)


def test_sheet_names(mock_client: TrivyClient, tmp_path):
    filename = str(tmp_path / "report.xlsx")
    generate_excel_report(mock_client, filename=filename)
    book = pyexcel.get_book(file_name=filename)
    assert set(book.sheet_names()) == {
        "Severity Summary",
        "Vulnerabilities",
        "Packages",
        "Targets",
    }


def test_severity_summary_sheet(mock_client: TrivyClient, tmp_path):
    filename = str(tmp_path / "report.xlsx")
    generate_excel_report(mock_client, filename=filename)
    rows = pyexcel.get_book(file_name=filename)["Severity Summary"].to_array()
    assert rows[0] == ["Severity", "Count"]
    # header + 5 severities + total
    assert len(rows) == 7
    totals_row = rows[-1]
    assert totals_row[0] == "Total"
    assert totals_row[1] == 289


def test_vulnerabilities_sheet_row_count(mock_client: TrivyClient, tmp_path):
    filename = str(tmp_path / "report.xlsx")
    generate_excel_report(mock_client, filename=filename)
    rows = pyexcel.get_book(file_name=filename)["Vulnerabilities"].to_array()
    # header + one row per vulnerability
    assert len(rows) == 290


def test_vulnerabilities_sheet_headers(mock_client: TrivyClient, tmp_path):
    filename = str(tmp_path / "report.xlsx")
    generate_excel_report(mock_client, filename=filename)
    headers = pyexcel.get_book(file_name=filename)["Vulnerabilities"].to_array()[0]
    assert headers[0] == "VulnerabilityID"
    assert headers[1] == "Severity"
    assert "Description" in headers
    assert "PkgName" in headers


def test_packages_sheet_row_count(mock_client: TrivyClient, tmp_path):
    filename = str(tmp_path / "report.xlsx")
    generate_excel_report(mock_client, filename=filename)
    rows = pyexcel.get_book(file_name=filename)["Packages"].to_array()
    # header + one row per package
    assert len(rows) == 470


def test_packages_sheet_headers(mock_client: TrivyClient, tmp_path):
    filename = str(tmp_path / "report.xlsx")
    generate_excel_report(mock_client, filename=filename)
    headers = pyexcel.get_book(file_name=filename)["Packages"].to_array()[0]
    assert headers == ["Target", "Type", "ID", "Name", "Version", "Licenses", "PURL"]


def test_targets_sheet_row_count(mock_client: TrivyClient, tmp_path):
    filename = str(tmp_path / "report.xlsx")
    generate_excel_report(mock_client, filename=filename)
    rows = pyexcel.get_book(file_name=filename)["Targets"].to_array()
    # header + one row per target
    assert len(rows) == 8
