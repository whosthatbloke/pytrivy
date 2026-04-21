import json
import pytest

from src.trivy.classes import TrivyClient
from src.trivy.exceptions import (
    TargetDoesntExist,
    VulnerabilityDoesntExist,
    LicenseDoesntExist,
    PackageDoesntExist,
)
from src.trivy.enums import TrivyScanCommandEnum, TrivyResultsEnum
from tests.helpers import *


@pytest.fixture
def mock_client() -> TrivyClient:
    """
    Returns a client pre-loaded with mock data.
    """
    return TrivyClient.from_file(str(MONGODB_2_11_RESULTS))


def test_initialization():
    client = TrivyClient(MONGODB_2_11_LITERAL, TrivyScanCommandEnum.Image)
    assert client.scan_command == TrivyScanCommandEnum.Image
    assert client.trivy_target == MONGODB_2_11_LITERAL
    assert client.scan_results() == {}

    client = TrivyClient("/tmp", TrivyScanCommandEnum.FileSystem)
    # assert isinstance(client.scan_command, TrivyScanCommandEnum)
    assert client.scan_command == TrivyScanCommandEnum.FileSystem
    assert client.trivy_target == "/tmp"
    assert client.scan_results() == {}


def test_initialization_invalid_config_file_raises():
    with pytest.raises(FileNotFoundError):
        TrivyClient(
            MONGODB_2_11_LITERAL,
            TrivyScanCommandEnum.Image,
            config_file="/nonexistent/path/trivy.yaml",
        )


def test_repr(mock_client: TrivyClient):
    result = repr(mock_client)
    assert "percona/percona-backup-mongodb:2.11.0" in result
    assert "image" in result


def test_from_dict():
    with open(str(MONGODB_2_11_RESULTS)) as file:
        results = json.load(file)

    client = TrivyClient.from_dict(results)
    assert isinstance(client, TrivyClient)
    assert client.scan_results() != {}
    assert client.scan_command == TrivyScanCommandEnum.Image

    with open(TRAEFIK_CONFIG_RESULTS) as file:
        results = json.load(file)

    client = TrivyClient.from_dict(results)
    assert client.scan_command == TrivyScanCommandEnum.Config

    with open(SBOM_CYCLONEDX_RESULTS) as file:
        results = json.load(file)

    client = TrivyClient.from_dict(results)
    assert isinstance(client, TrivyClient)
    assert client.scan_command == TrivyScanCommandEnum.SBOM
    assert client.trivy_target == "my-image.cdx.json"

    with open(FILESYSTEM_RESULTS) as file:
        results = json.load(file)

    client = TrivyClient.from_dict(results)
    assert client.scan_command == TrivyScanCommandEnum.FileSystem


def test_from_file():
    client = TrivyClient.from_file(str(MONGODB_2_11_RESULTS))
    assert isinstance(client, TrivyClient)
    assert client.scan_results() != {}


#
# Scan
#
def test_scan():
    client = TrivyClient(MONGODB_2_11_LITERAL, TrivyScanCommandEnum.Image)
    assert client.scan_results() == {}
    client.scan()
    assert client.scan_results() != {}


#
# Targets
#
def test_raw_targets(mock_client):
    result = mock_client.raw_targets()
    assert len(result) > 0
    assert isinstance(result, list)
    assert isinstance(result[0], dict)


def test_targets(mock_client):
    result = mock_client.targets()
    assert len(result) > 0
    assert isinstance(result, list)
    assert isinstance(result[0], str)


def test_valid_target(mock_client):
    result = mock_client.target("usr/bin/pbm")
    assert isinstance(result, dict)
    assert result != {}


def test_invalid_target(mock_client):
    with pytest.raises(TargetDoesntExist):
        mock_client.target("INVALID/usr/bin/pbm")


def test_target_vulnerabilities(mock_client):
    result = mock_client.target_vulnerabilities("usr/bin/pbm")
    assert isinstance(result, list)
    assert isinstance(result[0], str)
    assert len(result) > 0
    assert result[0] == "CVE-2025-47914"


#
# Vulnerabilities
#
def test_raw_vulnerabilities(mock_client):
    result = mock_client.raw_vulnerabilities()
    assert len(result) > 0
    assert isinstance(result, list)
    assert isinstance(result[0], dict)


def test_vulnerabilities(mock_client):
    result = mock_client.vulnerabilities()
    assert len(result) == 289
    assert isinstance(result, list)
    assert isinstance(result[0], str)

    known_vuln_conut = 0
    for vuln in result:
        if vuln == "CVE-2025-61723":
            known_vuln_conut += 1

    assert known_vuln_conut == 4


def test_valid_vulnerability(mock_client):
    result = mock_client.vulnerability("CVE-2025-47914")
    assert isinstance(result, dict)
    assert result != {}


def test_vulnerability_lookup_is_case_insensitive(mock_client: TrivyClient):
    upper = mock_client.vulnerability("CVE-2025-47914")
    lower = mock_client.vulnerability("cve-2025-47914")
    mixed = mock_client.vulnerability("Cve-2025-47914")
    assert upper == lower == mixed


def test_invalid_vulnerability(mock_client):
    with pytest.raises(VulnerabilityDoesntExist):
        mock_client.vulnerability("INVALID-CVE-2025-47914")


def test_vulnerability_in_targets(mock_client):
    result = mock_client.vulnerability_in_targets("CVE-2025-47914")
    assert len(result) > 0
    assert result == ["usr/bin/pbm", "usr/bin/pbm-agent", "usr/bin/pbm-speed-test"]


def test_unique_vulnerabilities(mock_client):
    result = mock_client.unique_vulnerabilities()
    assert len(result) == 201

    # This CVE appears anumber of times in the .vulnerabilities() method
    # It should only appear once here
    known_vuln_conut = 0
    for vuln in result:
        if vuln == "CVE-2025-61723":
            known_vuln_conut += 1

    assert known_vuln_conut == 1


def test_criticals(mock_client):
    result = mock_client.criticals()
    assert isinstance(result, list)
    assert len(result) == 0


def test_highs(mock_client):
    result = mock_client.highs()
    assert isinstance(result, list)
    assert len(result) > 0


def test_mediums(mock_client: TrivyClient):
    result = mock_client.mediums()
    assert isinstance(result, list)
    assert len(result) > 0


def test_lows(mock_client: TrivyClient):
    result = mock_client.lows()
    assert isinstance(result, list)
    assert len(result) > 0


def test_unknowns(mock_client: TrivyClient):
    result = mock_client.unknowns()
    assert isinstance(result, list)
    assert len(result) == 0


#
# Licenses
#
def test_raw_licenses(mock_client: TrivyClient):
    result = mock_client.raw_licenses()
    assert len(result) == 2
    assert isinstance(result, list)
    assert isinstance(result[0], dict)
    assert result[0].get(TrivyResultsEnum.Class.value, "") == "license"


def test_licenses(mock_client):
    result = mock_client.licenses()
    assert len(result) == 182
    assert isinstance(result, list)
    assert isinstance(result[0], str)
    assert "BSD and GPLv2" in result


def test_valid_license(mock_client):
    result = mock_client.license("BSD and GPLv2")
    assert isinstance(result, dict)
    assert result != {}


def test_invalid_license(mock_client: TrivyClient):
    with pytest.raises(LicenseDoesntExist):
        mock_client.license("INVALID-BSD and GPLv2")


def test_unique_licenses(mock_client: TrivyClient):
    licenses = mock_client.licenses()
    unique_licenses = mock_client.unique_licenses()
    assert len(licenses) != len(unique_licenses)
    assert len(unique_licenses) == 61


def test_target_licenses(mock_client: TrivyClient):
    result = mock_client.target_licenses(
        "percona/percona-backup-mongodb:2.11.0 (redhat 9.6)"
    )
    assert isinstance(result, list)
    assert isinstance(result[0], str)
    assert len(result) == 141
    assert "MIT" in result


def test_license_in_targets(mock_client: TrivyClient):
    result = mock_client.license_in_targets("MIT")
    assert result == ["percona/percona-backup-mongodb:2.11.0 (redhat 9.6)"]


#
# Packages
#
def test_raw_packages(mock_client: TrivyClient):
    result = mock_client.raw_packages()
    assert isinstance(result, list)
    assert len(result) == 469
    assert isinstance(result[0], dict)
    assert result[0].get("Name") == "acl"


def test_packages(mock_client: TrivyClient):
    result = mock_client.packages()
    assert isinstance(result, list)
    assert len(result) == 469
    assert isinstance(result[0], str)
    assert "acl" in result


def test_packages_named_single_match(mock_client: TrivyClient):
    result = mock_client.packages_named("acl")
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0].get("Name") == "acl"
    assert result[0].get("Version") == "2.3.1"


def test_packages_named_multiple_matches(mock_client: TrivyClient):
    # gpg-pubkey appears 5 times across targets
    result = mock_client.packages_named("gpg-pubkey")
    assert isinstance(result, list)
    assert len(result) == 5
    assert all(p.get("Name") == "gpg-pubkey" for p in result)


def test_packages_named_no_match_returns_empty_list(mock_client: TrivyClient):
    result = mock_client.packages_named("INVALID-PACKAGE-XYZ")
    assert result == []


def test_package_by_id_valid(mock_client: TrivyClient):
    result = mock_client.package_by_id("acl@2.3.1-4.el9.x86_64")
    assert isinstance(result, dict)
    assert result.get("Name") == "acl"
    assert result.get("Version") == "2.3.1"


def test_package_by_id_invalid(mock_client: TrivyClient):
    with pytest.raises(PackageDoesntExist):
        mock_client.package_by_id("nonexistent@0.0.0")


def test_purl(mock_client: TrivyClient):
    result = mock_client.purl("acl@2.3.1-4.el9.x86_64")
    assert result == "pkg:rpm/redhat/acl@2.3.1-4.el9?arch=x86_64&distro=redhat-9.6"


def test_purl_raises_for_unknown_package(mock_client: TrivyClient):
    with pytest.raises(PackageDoesntExist):
        mock_client.purl("nonexistent@0.0.0")


def test_dependencies(mock_client: TrivyClient):
    result = mock_client.dependencies("acl@2.3.1-4.el9.x86_64")
    assert isinstance(result, list)
    assert "glibc@2.34-168.el9_6.23.x86_64" in result
    assert "libacl@2.3.1-4.el9.x86_64" in result


def test_dependencies_empty_for_package_with_none(mock_client: TrivyClient):
    # crypto-policies has no DependsOn field
    result = mock_client.dependencies("crypto-policies@20250128-1.git5269e22.el9.noarch")
    assert result == []


def test_dependencies_raises_for_unknown_package(mock_client: TrivyClient):
    with pytest.raises(PackageDoesntExist):
        mock_client.dependencies("nonexistent@0.0.0")


def test_unique_packages(mock_client: TrivyClient):
    all_packages = mock_client.packages()
    unique = mock_client.unique_packages()
    assert len(unique) == 246
    assert len(all_packages) != len(unique)
    assert "acl" in unique


def test_packages_in_target(mock_client: TrivyClient):
    result = mock_client.packages_in_target(
        "percona/percona-backup-mongodb:2.11.0 (redhat 9.6)"
    )
    assert isinstance(result, list)
    assert len(result) == 141
    assert isinstance(result[0], dict)
    assert result[0].get("Name") == "acl"
