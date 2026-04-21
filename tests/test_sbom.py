import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.trivy.classes import TrivyClient
from src.trivy.enums import SBOMFormatEnum, TrivyScanCommandEnum

CYCLONEDX_FIXTURE = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {"component": {"name": "test-image:latest"}},
    "components": [
        {
            "type": "library",
            "name": "openssl",
            "version": "3.0.2",
            "purl": "pkg:deb/ubuntu/openssl@3.0.2",
        }
    ],
}

SPDX_FIXTURE = {
    "spdxVersion": "SPDX-2.3",
    "name": "test-image:latest",
    "packages": [
        {"name": "openssl", "versionInfo": "3.0.2"},
    ],
}


@pytest.fixture
def client() -> TrivyClient:
    return TrivyClient("test-image:latest", TrivyScanCommandEnum.Image)


def _mock_subprocess(stdout: dict) -> MagicMock:
    """Returns a mock subprocess.CompletedProcess with the given dict as stdout."""
    mock = MagicMock()
    mock.stdout = json.dumps(stdout)
    return mock


#
# sbom_results()
#
def test_sbom_results_empty_before_generation(client: TrivyClient):
    assert client.sbom_results() == {}


#
# sbom() — CycloneDX
#
def test_sbom_returns_cyclonedx_dict(client: TrivyClient):
    with patch("subprocess.run", return_value=_mock_subprocess(CYCLONEDX_FIXTURE)):
        result = client.sbom()
    assert result["bomFormat"] == "CycloneDX"
    assert result["specVersion"] == "1.5"
    assert len(result["components"]) == 1


def test_sbom_defaults_to_cyclonedx(client: TrivyClient):
    with patch("subprocess.run", return_value=_mock_subprocess(CYCLONEDX_FIXTURE)) as mock_run:
        client.sbom()
    cmd = mock_run.call_args[0][0]
    assert "--format" in cmd
    assert cmd[cmd.index("--format") + 1] == "cyclonedx"


def test_sbom_stores_result_in_sbom_results(client: TrivyClient):
    with patch("subprocess.run", return_value=_mock_subprocess(CYCLONEDX_FIXTURE)):
        client.sbom()
    assert SBOMFormatEnum.CycloneDX in client.sbom_results()
    assert client.sbom_results()[SBOMFormatEnum.CycloneDX]["bomFormat"] == "CycloneDX"


def test_sbom_cached_result_not_rescanned(client: TrivyClient):
    with patch("subprocess.run", return_value=_mock_subprocess(CYCLONEDX_FIXTURE)) as mock_run:
        client.sbom()
        client.sbom()
    assert mock_run.call_count == 1


#
# sbom() — SPDX
#
def test_sbom_spdx_format(client: TrivyClient):
    with patch("subprocess.run", return_value=_mock_subprocess(SPDX_FIXTURE)) as mock_run:
        result = client.sbom(output_format=SBOMFormatEnum.SPDX)
    cmd = mock_run.call_args[0][0]
    assert cmd[cmd.index("--format") + 1] == "spdx-json"
    assert result["spdxVersion"] == "SPDX-2.3"


def test_sbom_caches_formats_independently(client: TrivyClient):
    with patch("subprocess.run", return_value=_mock_subprocess(CYCLONEDX_FIXTURE)):
        client.sbom(output_format=SBOMFormatEnum.CycloneDX)
    with patch("subprocess.run", return_value=_mock_subprocess(SPDX_FIXTURE)):
        client.sbom(output_format=SBOMFormatEnum.SPDX)

    assert SBOMFormatEnum.CycloneDX in client.sbom_results()
    assert SBOMFormatEnum.SPDX in client.sbom_results()
    assert client.sbom_results()[SBOMFormatEnum.CycloneDX]["bomFormat"] == "CycloneDX"
    assert client.sbom_results()[SBOMFormatEnum.SPDX]["spdxVersion"] == "SPDX-2.3"


#
# sbom() — output_file
#
def test_sbom_writes_to_file(client: TrivyClient, tmp_path: Path):
    output_file = tmp_path / "sbom.cdx.json"
    with patch("subprocess.run", return_value=_mock_subprocess(CYCLONEDX_FIXTURE)):
        client.sbom(output_file=output_file)

    assert output_file.exists()
    written = json.loads(output_file.read_text())
    assert written["bomFormat"] == "CycloneDX"


def test_sbom_file_not_written_when_output_file_is_none(client: TrivyClient, tmp_path: Path):
    with patch("subprocess.run", return_value=_mock_subprocess(CYCLONEDX_FIXTURE)):
        client.sbom()
    assert list(tmp_path.iterdir()) == []


#
# sbom() — subprocess command shape
#
def test_sbom_command_includes_target(client: TrivyClient):
    with patch("subprocess.run", return_value=_mock_subprocess(CYCLONEDX_FIXTURE)) as mock_run:
        client.sbom()
    cmd = mock_run.call_args[0][0]
    assert "test-image:latest" in cmd


def test_sbom_command_includes_scan_subcommand(client: TrivyClient):
    with patch("subprocess.run", return_value=_mock_subprocess(CYCLONEDX_FIXTURE)) as mock_run:
        client.sbom()
    cmd = mock_run.call_args[0][0]
    assert "image" in cmd


def test_sbom_command_includes_config_file(tmp_path: Path):
    config = tmp_path / "trivy.yaml"
    config.write_text("timeout: 5m\n")
    client = TrivyClient("test-image:latest", TrivyScanCommandEnum.Image, config_file=str(config))

    with patch("subprocess.run", return_value=_mock_subprocess(CYCLONEDX_FIXTURE)) as mock_run:
        client.sbom()
    cmd = mock_run.call_args[0][0]
    assert "--config" in cmd


#
# sbom() — error handling
#
def test_sbom_raises_on_subprocess_error(client: TrivyClient):
    with patch(
        "subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "trivy", stderr="some error"),
    ):
        with pytest.raises(Exception):
            client.sbom()


def test_sbom_does_not_require_prior_scan(client: TrivyClient):
    assert client.scan_results() == {}
    with patch("subprocess.run", return_value=_mock_subprocess(CYCLONEDX_FIXTURE)):
        result = client.sbom()
    assert result is not None
    assert client.scan_results() == {}
