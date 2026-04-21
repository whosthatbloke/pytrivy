import pytest

from src.trivy.classes import TrivyClient, TrivyComparator, TrivyAnalyzer
from src.trivy.enums import TrivyScanCommandEnum, SeverityEnum

from tests.helpers import *


@pytest.fixture
def mock_client() -> TrivyAnalyzer:
    """
    Returns an analyzer pre-loaded with mock data.
    """
    return TrivyAnalyzer(
        [
            TrivyClient.from_file(str(MONGODB_2_10_RESULTS)),
            TrivyClient.from_file(str(MONGODB_2_11_RESULTS)),
            TrivyClient.from_file(str(OPENSEARCH_2_19_RESULTS)),
        ]
    )


def test_initialization():
    # Tests unscanned clients are scanned once initialised by the compartor class
    mongo_210 = TrivyClient(MONGODB_2_10_LITERAL, TrivyScanCommandEnum.Image)
    mongo_211 = TrivyClient(MONGODB_2_11_LITERAL, TrivyScanCommandEnum.Image)
    opensearch_219 = TrivyClient(OPENSEARCH_2_19_LITERAL, TrivyScanCommandEnum.Image)
    result = TrivyAnalyzer([mongo_210, mongo_211, opensearch_219])
    assert mongo_210.scan_results() != {}
    assert mongo_211.scan_results() != {}
    assert opensearch_219.scan_results() != {}


def test_vulnerabilities(mock_client: TrivyAnalyzer):
    result = mock_client.vulnerabilities()
    # I know this CVE is in one of the results. So this confirms it works
    assert "CVE-2025-47914" in result


def test_unique_vulnerabilities(mock_client: TrivyAnalyzer):
    result = mock_client.unique_vulnerabilities()
    # I know this CVE is in one of the results. So this confirms it works
    assert "CVE-2025-47914" in result
    assert len(result) < len(mock_client.vulnerabilities())


def test_most_common_cves(mock_client: TrivyAnalyzer):
    result = mock_client.most_common_cves()
    assert len(result) == 5


def test_most_common_cves_custom_limit(mock_client: TrivyAnalyzer):
    assert len(mock_client.most_common_cves(limit=1)) == 1
    assert len(mock_client.most_common_cves(limit=10)) == 10


def test_severities(mock_client: TrivyAnalyzer):
    result = mock_client.severities()
    for severity_enum in SeverityEnum:
        assert severity_enum.value in result.keys()


def test_find_images_with_cve(mock_client: TrivyAnalyzer):
    result = mock_client.find_images_with_cve("CVE-2025-47914")
    assert len(result) == 2
    targets = [client.trivy_target for client in result]
    assert "percona/percona-backup-mongodb:2.11.0" in targets
    assert "percona/percona-backup-mongodb:2.10.0" in targets


def test_number_of_clients(mock_client: TrivyAnalyzer):
    result = mock_client.number_of_clients()
    assert result == 3


def test_clients_with_highest_vulnerabilities():
    analyzer = TrivyAnalyzer(
        [
            TrivyClient.from_file(str(MONGODB_2_10_RESULTS)),
            TrivyClient.from_file(str(MONGODB_2_11_RESULTS)),
        ]
    )
    assert len(analyzer.clients_with_highest_vulnerabilities()) == 1
    analyzer = TrivyAnalyzer(
        [
            TrivyClient.from_file(str(MONGODB_2_10_RESULTS)),
            TrivyClient.from_file(str(MONGODB_2_10_RESULTS)),
        ]
    )
    assert len(analyzer.clients_with_highest_vulnerabilities()) == 2


def test_clients_with_lowests_vulnerabilities():
    analyzer = TrivyAnalyzer(
        [
            TrivyClient.from_file(str(MONGODB_2_10_RESULTS)),
            TrivyClient.from_file(str(MONGODB_2_11_RESULTS)),
        ]
    )
    assert len(analyzer.clients_with_lowest_vulnerabilities()) == 1
    analyzer = TrivyAnalyzer(
        [
            TrivyClient.from_file(str(MONGODB_2_10_RESULTS)),
            TrivyClient.from_file(str(MONGODB_2_10_RESULTS)),
        ]
    )
    assert len(analyzer.clients_with_lowest_vulnerabilities()) == 2


def test_bottlenecks(mock_client: TrivyAnalyzer):
    result = mock_client.bottlenecks()
    cve, count, client = result[0]
    assert count == 2
    assert [
        "percona/percona-backup-mongodb:2.10.0",
        "percona/percona-backup-mongodb:2.11.0",
    ] == [client[0].trivy_target, client[1].trivy_target]
