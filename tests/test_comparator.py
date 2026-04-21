import pytest

from src.trivy.classes import TrivyClient, TrivyComparator
from src.trivy.enums import TrivyScanCommandEnum

from tests.helpers import *


@pytest.fixture
def mock_client_old_version() -> TrivyClient:
    """
    Returns a client pre-loaded with mock data.
    """
    return TrivyClient.from_file(str(MONGODB_2_10_RESULTS))


@pytest.fixture
def mock_client_new_version() -> TrivyClient:
    """
    Returns a client pre-loaded with mock data.
    """
    return TrivyClient.from_file(str(MONGODB_2_11_RESULTS))


@pytest.fixture
def mock_client(mock_client_old_version, mock_client_new_version) -> TrivyClient:
    return TrivyComparator(mock_client_old_version, mock_client_new_version)


def test_initialization():
    # Tests unscanned clients are scanned once initialised by the compartor class
    old_version = TrivyClient(MONGODB_2_11_LITERAL, TrivyScanCommandEnum.Image)
    new_version = TrivyClient(MONGODB_2_11_LITERAL, TrivyScanCommandEnum.Image)
    comp = TrivyComparator(old_version, new_version)
    assert comp.old_version.scan_results() != {}
    assert comp.new_version.scan_results() != {}


def test_fixed_vulnerabilities(mock_client: TrivyComparator):
    fixed = mock_client.fixed_vulnerabilities()
    conflicts = []
    for vuln in fixed:
        in_old = vuln in mock_client.old_version.vulnerabilities()
        in_new = vuln in mock_client.new_version.vulnerabilities()
        if in_old and in_new:
            conflicts.append(vuln)

    assert len(conflicts) == 0


def test_persisting_vulnerabilities(mock_client: TrivyComparator):
    fixed = mock_client.persisting_vulnerabilities()
    conflicts = []
    for vuln in fixed:
        in_old = vuln in mock_client.old_version.vulnerabilities()
        in_new = vuln in mock_client.new_version.vulnerabilities()
        if in_old and in_new:
            conflicts.append(vuln)

    assert len(conflicts) != 0
