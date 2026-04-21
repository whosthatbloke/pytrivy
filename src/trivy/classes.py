import json
import logging
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from typeguard import typechecked

from .enums import SeverityEnum, SBOMFormatEnum, TrivyResultsEnum, TrivyScanCommandEnum
from .exceptions import LicenseDoesntExist, PackageDoesntExist, TargetDoesntExist, VulnerabilityDoesntExist
from .helpers import handle_trivy_subprocess_command

logger = logging.getLogger(__name__)


class TrivyClient:
    """
    A programmatic SDK for the Trivy CLI to scan container images.

    Attributes:
        trivy_target (str): The name/tag of the container image or path to scan.
        config_file (Path | None): Path to a Trivy YAML/JSON configuration file.
    """

    def __init__(
        self,
        trivy_target: str,
        scan_command: TrivyScanCommandEnum,
        config_file: str | None = None,
    ):
        """
        Args:
            trivy_target (str): The name of the container image or path to scan.
            scan_command (TrivyScanCommandEnum): The Trivy scan subcommand to use.
            config_file (str | None, optional): Path to a Trivy YAML/JSON configuration file.

        Raises:
            FileNotFoundError: If a config file is passed but doesn't exist.
        """
        self.trivy_target = trivy_target
        self.scan_command = scan_command
        self.config_file = Path(config_file) if config_file else config_file
        if self.config_file:
            if not self.config_file.exists():
                raise FileNotFoundError(
                    f"Config file '{config_file}' passed but does not exist."
                )

        # Used to save the results of a scan
        self.__scan_results: dict[str, Any] = {}

        # Used to save generated SBOM results, keyed by SBOMFormatEnum
        self.__sbom_results: dict[SBOMFormatEnum, dict[str, Any]] = {}

        logger.debug(f"TrivyClient created: target='{trivy_target}', command='{scan_command.value}'")

    def __repr__(self) -> str:
        return f"{self.trivy_target} scanned with '{self.scan_command.value}' command"

    def scan_results(self) -> dict[str, Any]:
        """
        The results of scan().
        """
        return self.__scan_results

    def sbom_results(self) -> dict[SBOMFormatEnum, dict[str, Any]]:
        """
        The cached results of sbom(), keyed by SBOMFormatEnum.
        """
        return self.__sbom_results

    def sbom(
        self,
        output_format: SBOMFormatEnum = SBOMFormatEnum.CycloneDX,
        output_file: str | Path | None = None,
    ) -> dict[str, Any]:
        """
        Generates an SBOM for the target using Trivy and returns it as a dict.

        This is a separate Trivy invocation from scan() and does not affect
        scan_results(). The target does not need to have been scanned first.
        Results are cached per format — calling sbom() twice with the same
        format will return the cached result without re-running Trivy.

        Args:
            output_format (SBOMFormatEnum): The SBOM format to generate.
                Defaults to CycloneDX.
            output_file (str | Path | None): If provided, the generated SBOM
                is also written to this path as a JSON file.

        Returns:
            dict[str, Any]: The parsed SBOM as a Python dict.

        Raises:
            RuntimeError: If an unexpected error occurs during the Trivy call.
        """
        if output_format in self.__sbom_results:
            logger.debug(f"SBOM ({output_format.value}) already generated, returning cached result.")
            return self.__sbom_results[output_format]

        cmd = [
            "trivy",
            self.scan_command.value,
            "--format", output_format.value,
            "--quiet",
        ]
        if self.config_file:
            cmd += ["--config", str(self.config_file)]
        cmd.append(self.trivy_target)

        try:
            logger.info(f"Generating {output_format.value} SBOM for: {self.trivy_target}")
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            sbom_data = json.loads(result.stdout)
            self.__sbom_results[output_format] = sbom_data
            logger.info(f"SBOM generation complete for: {self.trivy_target}")

            if output_file:
                with open(output_file, "w") as f:
                    json.dump(sbom_data, f, indent=2)
                logger.info(f"SBOM written to: {output_file}")

            return sbom_data

        except subprocess.CalledProcessError as error:
            raise handle_trivy_subprocess_command(error.stderr, self.trivy_target)

        except json.JSONDecodeError as error:
            logger.error(f"Failed to parse Trivy SBOM output: {error}")
            return {"error": "Invalid JSON", "details": str(error)}

        except Exception as error:
            raise RuntimeError(f"An unexpected error occurred: {error}") from error

    def scan(self) -> dict[str, Any]:
        """
        Executes a Trivy scan using subprocess and loads the result.

        Returns:
            dict[str, Any]: The full JSON output from the Trivy scan.

        Raises:
            subprocess.CalledProcessError: If the Trivy binary returns a non-zero exit code.
            json.JSONDecodeError: If the output cannot be parsed as valid JSON.
        """
        if self.scan_results():
            logger.debug(f"'{self.trivy_target}' already scanned, returning cached results.")
            return self.scan_results()

        cmd = [
            "trivy",
            self.scan_command.value,
            "--format",
            "json",
            "--quiet",
        ]
        if self.config_file:
            cmd += ["--config", str(self.config_file)]
        cmd.append(self.trivy_target)
        try:
            logger.info(f"Scanning target: {self.trivy_target}")
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.__scan_results = json.loads(result.stdout)
            logger.info(f"Scan complete: {self.trivy_target}")
            return self.__scan_results

        except subprocess.CalledProcessError as error:
            raise handle_trivy_subprocess_command(error.stderr, self.trivy_target)

        except json.JSONDecodeError as error:
            logger.error(f"Failed to parse Trivy JSON output: {error}")
            return {"error": "Invalid JSON", "details": str(error)}

        except Exception as error:
            raise RuntimeError(f"An unexpected error occurred: {error}") from error

    def raw_targets(self) -> list[dict]:
        """
        Grabs all information about targets in its 'raw' format.
        """
        return self.scan_results().get(TrivyResultsEnum.Results.value, [])

    def targets(self) -> list[str]:
        """
        Returns a list of target names.
        """
        result = [
            target.get(TrivyResultsEnum.Target.value) for target in self.raw_targets()
        ]
        logger.debug(f"[{self.trivy_target}] targets(): {len(result)} targets")
        return result

    def target(self, name: str) -> dict:
        logger.debug(f"[{self.trivy_target}] target(): looking up '{name}'")
        targets = self.raw_targets()
        for target in targets:
            if name == target.get(TrivyResultsEnum.Target.value):
                return target

        logger.warning(f"[{self.trivy_target}] target(): '{name}' not found")
        raise TargetDoesntExist(f"Target '{name}' doesn't exist.")

    def target_vulnerabilities(self, name: str) -> list[str | None]:
        """
        Returns a list of vulnerability IDs found in a target.

        Args:
            name (str): Target name.

        Returns:
            list[str | None]: List of vulnerability IDs.
        """
        target = self.target(name)
        vulns = target.get(TrivyResultsEnum.Vulnerabilities.value)
        result = (
            [vuln[TrivyResultsEnum.VulnerabilityID.value] for vuln in vulns]
            if vulns
            else []
        )
        logger.debug(f"[{self.trivy_target}] target_vulnerabilities('{name}'): {len(result)} vulnerabilities")
        return result

    def target_licenses(self, name: str) -> list[str]:
        """
        Returns a list of license names found in a target.

        Args:
            name (str): Target name.

        Returns:
            list[str]: List of license names.
        """
        target = self.target(name)
        packages = target.get(TrivyResultsEnum.Packages.value, [])
        licenses = []
        for package in packages:
            if package.get("Licenses", None) is None:
                continue
            licenses.extend(package.get("Licenses"))

        logger.debug(f"[{self.trivy_target}] target_licenses('{name}'): {len(licenses)} licenses")
        return licenses

    def raw_vulnerabilities(self) -> list[dict]:
        vulnerabilities = []
        # TODO: This could be changed to self.raw_targets()
        results = self.scan_results().get(TrivyResultsEnum.Results.value, [])
        for target in results:
            vulnerability = target.get(TrivyResultsEnum.Vulnerabilities.value, [])
            if vulnerability:
                vulnerabilities.extend(vulnerability)

        return vulnerabilities

    def vulnerabilities(self) -> list[str]:
        """
        Returns all vulnerability IDs from the scan.
        """
        vulns = self.raw_vulnerabilities()
        result = [
            vulnerability.get(TrivyResultsEnum.VulnerabilityID.value)
            for vulnerability in vulns
        ]
        logger.debug(f"[{self.trivy_target}] vulnerabilities(): {len(result)} total")
        return result

    def vulnerability(self, vuln_id: str) -> dict:
        """
        Grabs a vulnerability's details. The passed ID is case insensitive.

        Args:
            vuln_id (str): The vulnerability ID to look up.

        Returns:
            dict: The vulnerability detail dict.

        Raises:
            VulnerabilityDoesntExist: If no matching vulnerability is found.
        """
        logger.debug(f"[{self.trivy_target}] vulnerability(): looking up '{vuln_id}'")
        vulns = self.raw_vulnerabilities()
        for vuln in vulns:
            if vuln_id.lower() == vuln.get(TrivyResultsEnum.VulnerabilityID.value).lower():
                return vuln

        logger.warning(f"[{self.trivy_target}] vulnerability(): '{vuln_id}' not found")
        raise VulnerabilityDoesntExist(f"Vulnerability '{vuln_id}' doesn't exist.")

    def vulnerability_in_targets(self, vuln_id: str) -> list[str]:
        """
        Returns a list of targets where the vulnerability is found.

        Args:
            vuln_id (str): The vulnerability ID to search for.

        Returns:
            list[str]
        """
        search_id = vuln_id.lower()
        result = [
            target
            for target in self.targets()
            if any(
                search_id == vulnerability.lower()
                for vulnerability in self.target_vulnerabilities(target)
            )
        ]
        logger.debug(f"[{self.trivy_target}] vulnerability_in_targets('{vuln_id}'): found in {len(result)} targets")
        return result

    def unique_vulnerabilities(self) -> list[str]:
        """
        Returns a list of unique vulnerabilities from the scan.

        Returns:
            list[str]
        """
        result = list(set(self.vulnerabilities()))
        logger.debug(f"[{self.trivy_target}] unique_vulnerabilities(): {len(result)} unique")
        return result

    #
    # Licenses
    #
    def raw_licenses(self) -> list[dict]:
        licenses = []
        results = self.raw_targets()
        for target in results:
            class_result = target.get(TrivyResultsEnum.Class.value)
            # Licenses appear in "results". Skip all non-license results.
            if class_result not in [
                TrivyResultsEnum.License.value,
                TrivyResultsEnum.LicenseFull.value,
            ]:
                continue

            licenses.append(target)

        return licenses

    def licenses(self) -> list[str]:
        """
        Returns all license names from the scan.
        """
        results = []
        raw_licenses = self.raw_licenses()
        for raw_license in raw_licenses:
            licenses = raw_license.get("Licenses")
            for license in licenses:
                results.append(license.get("Name"))

        logger.debug(f"[{self.trivy_target}] licenses(): {len(results)} total")
        return results

    def license(self, name: str) -> dict:
        """
        Returns a license's detail dict.

        NOTE: This is case sensitive.

        Args:
            name (str): The license name to look up.

        Returns:
            dict: The license detail dict.

        Raises:
            LicenseDoesntExist: If no matching license is found.
        """
        logger.debug(f"[{self.trivy_target}] license(): looking up '{name}'")
        raw_licenses = self.raw_licenses()
        for raw_license in raw_licenses:
            licenses = raw_license.get("Licenses")
            for license in licenses:
                if name == license.get("Name"):
                    return license

        logger.warning(f"[{self.trivy_target}] license(): '{name}' not found")
        raise LicenseDoesntExist(f"License '{name}' doesn't exist.")

    def unique_licenses(self) -> list[str]:
        """
        Returns a list of unique licenses from the scan.

        Returns:
            list[str]
        """
        result = list(set(self.licenses()))
        logger.debug(f"[{self.trivy_target}] unique_licenses(): {len(result)} unique")
        return result

    def license_in_targets(self, name: str) -> list[str]:
        """
        Returns a list of targets where the license is found.

        Args:
            name (str): The license name to search for.

        Returns:
            list[str]
        """
        result = [
            target
            for target in self.targets()
            if any(name in licenses for licenses in self.target_licenses(target))
        ]
        logger.debug(f"[{self.trivy_target}] license_in_targets('{name}'): found in {len(result)} targets")
        return result

    #
    # Packages (SBOM)
    #
    def raw_packages(self) -> list[dict]:
        """
        Returns all package dicts across all targets in their raw format.
        """
        packages = []
        for target in self.raw_targets():
            pkgs = target.get(TrivyResultsEnum.Packages.value, [])
            if pkgs:
                packages.extend(pkgs)
        return packages

    def packages(self) -> list[str]:
        """
        Returns all package names from the scan.
        """
        result = [pkg.get(TrivyResultsEnum.Name.value) for pkg in self.raw_packages()]
        logger.debug(f"[{self.trivy_target}] packages(): {len(result)} total")
        return result

    def packages_named(self, name: str) -> list[dict]:
        """
        Returns all packages matching a given name across all targets.

        Use this instead of a single-result lookup because the same package
        name can appear in multiple targets (e.g. a Go binary vendored
        alongside an OS package of the same name).

        Args:
            name (str): The package name to search for. Case sensitive.

        Returns:
            list[dict]: All matching package detail dicts. Empty list if none found.
        """
        result = [
            pkg
            for pkg in self.raw_packages()
            if name == pkg.get(TrivyResultsEnum.Name.value)
        ]
        logger.debug(f"[{self.trivy_target}] packages_named('{name}'): {len(result)} match(es)")
        return result

    def package_by_id(self, pkg_id: str) -> dict:
        """
        Returns a package by its unique Trivy ID (e.g. 'acl@2.3.1-4.el9.x86_64').

        This is the correct way to look up a single package without ambiguity,
        since package names are not unique across targets.

        Args:
            pkg_id (str): The Trivy package ID to look up.

        Returns:
            dict: The package detail dict.

        Raises:
            PackageDoesntExist: If no matching package is found.
        """
        logger.debug(f"[{self.trivy_target}] package_by_id(): looking up '{pkg_id}'")
        for pkg in self.raw_packages():
            if pkg_id == pkg.get(TrivyResultsEnum.ID.value):
                return pkg

        logger.warning(f"[{self.trivy_target}] package_by_id(): '{pkg_id}' not found")
        raise PackageDoesntExist(f"Package '{pkg_id}' doesn't exist.")

    def purl(self, pkg_id: str) -> str | None:
        """
        Returns the PURL (Package URL) for a package, identified by its Trivy ID.

        PURLs are the standard unique identifier used in SBOM formats such as
        CycloneDX and SPDX. Example: pkg:rpm/redhat/acl@2.3.1-4.el9?arch=x86_64

        Args:
            pkg_id (str): The Trivy package ID to look up.

        Returns:
            str | None: The PURL string, or None if the package has no identifier.

        Raises:
            PackageDoesntExist: If no matching package is found.
        """
        logger.debug(f"[{self.trivy_target}] purl(): looking up '{pkg_id}'")
        pkg = self.package_by_id(pkg_id)
        result = pkg.get(TrivyResultsEnum.Identifier.value, {}).get(
            TrivyResultsEnum.PURL.value
        )
        logger.debug(f"[{self.trivy_target}] purl('{pkg_id}'): {result}")
        return result

    def dependencies(self, pkg_id: str) -> list[str]:
        """
        Returns the list of package IDs that a given package directly depends on.

        Args:
            pkg_id (str): The Trivy package ID to look up.

        Returns:
            list[str]: List of dependency package IDs. Empty list if none.

        Raises:
            PackageDoesntExist: If no matching package is found.
        """
        logger.debug(f"[{self.trivy_target}] dependencies(): looking up '{pkg_id}'")
        pkg = self.package_by_id(pkg_id)
        result = pkg.get(TrivyResultsEnum.DependsOn.value) or []
        logger.debug(f"[{self.trivy_target}] dependencies('{pkg_id}'): {len(result)} dependencies")
        return result

    def unique_packages(self) -> list[str]:
        """
        Returns a list of unique package names from the scan.

        Returns:
            list[str]
        """
        result = list(set(self.packages()))
        logger.debug(f"[{self.trivy_target}] unique_packages(): {len(result)} unique")
        return result

    def packages_in_target(self, name: str) -> list[dict]:
        """
        Returns the raw package dicts for a specific target.

        Args:
            name (str): Target name.

        Returns:
            list[dict]: List of package detail dicts.
        """
        target = self.target(name)
        result = target.get(TrivyResultsEnum.Packages.value, [])
        logger.debug(f"[{self.trivy_target}] packages_in_target('{name}'): {len(result)} packages")
        return result

    #
    # Vulnerabilities by severity
    #

    def criticals(self) -> list[str]:
        """
        Returns IDs of all critical vulnerabilities.

        Returns:
            list[str]
        """
        result = self.__filter_by_severity(SeverityEnum.Critical)
        logger.debug(f"[{self.trivy_target}] criticals(): {len(result)}")
        return result

    def highs(self) -> list[str]:
        """
        Returns IDs of all high vulnerabilities.

        Returns:
            list[str]
        """
        result = self.__filter_by_severity(SeverityEnum.High)
        logger.debug(f"[{self.trivy_target}] highs(): {len(result)}")
        return result

    def mediums(self) -> list[str]:
        """
        Returns IDs of all medium vulnerabilities.

        Returns:
            list[str]
        """
        result = self.__filter_by_severity(SeverityEnum.Medium)
        logger.debug(f"[{self.trivy_target}] mediums(): {len(result)}")
        return result

    def lows(self) -> list[str]:
        """
        Returns IDs of all low vulnerabilities.

        Returns:
            list[str]
        """
        result = self.__filter_by_severity(SeverityEnum.Low)
        logger.debug(f"[{self.trivy_target}] lows(): {len(result)}")
        return result

    def unknowns(self) -> list[str]:
        """
        Returns IDs of all vulnerabilities with an unknown severity.

        Returns:
            list[str]
        """
        result = self.__filter_by_severity(SeverityEnum.Unknown)
        logger.debug(f"[{self.trivy_target}] unknowns(): {len(result)}")
        return result

    # TODO: Cache this
    def __filter_by_severity(self, severity: SeverityEnum) -> list[str]:
        """
        Generic filter to retrieve vulnerability IDs by their severity level.

        Args:
            severity (SeverityEnum): The severity level to filter by (e.g., CRITICAL).

        Returns:
            list[str]: A list of vulnerability IDs matching the given severity.
        """
        matches = [
            vulnerability
            for vulnerability in self.raw_vulnerabilities()
            if vulnerability.get(
                TrivyResultsEnum.Severity.value, SeverityEnum.Unknown.value
            )
            == severity.value
        ]
        return [
            vulnerability.get(TrivyResultsEnum.VulnerabilityID.value, None)
            for vulnerability in matches
        ]

    @classmethod
    def from_dict(
        cls, trivy_results: dict[str, Any], config_file: Path | None = None
    ) -> "TrivyClient":
        """
        Creates a TrivyClient instance by extracting the target name
        directly from the scan results.
        """

        class_args: dict[str, Any] = {
            "trivy_target": None,
            "scan_command": None,
            "config_file": config_file,
        }

        artifact_name = trivy_results.get(TrivyResultsEnum.ArtifactType.value, None)
        if not artifact_name:
            raise ValueError(
                f"Something has gone wrong with the file import. Unknown artifact name detected: {artifact_name}"
            )

        if artifact_name == "container_image":
            class_args["scan_command"] = TrivyScanCommandEnum.Image
        elif artifact_name == "repository":
            # We have to iterate over the results.
            # If someone used the 'config' command we'll get a match for config;
            # if not, its either repo or fs, which I think is the same.
            command = ""
            for result in trivy_results.get(TrivyResultsEnum.Results.value):
                if result.get("Class", "") == "config":
                    command = TrivyScanCommandEnum.Config
                    break

            class_args["scan_command"] = (
                TrivyScanCommandEnum.FileSystem if command == "" else command
            )
        elif artifact_name in ("cyclonedx", "spdx"):
            class_args["scan_command"] = TrivyScanCommandEnum.SBOM

        class_args["trivy_target"] = trivy_results.get(
            TrivyResultsEnum.ArtifactName.value
        )
        if class_args["scan_command"] in [
            TrivyScanCommandEnum.Config,
            TrivyScanCommandEnum.FileSystem,
        ]:
            class_args["trivy_target"] = Path(artifact_name).name

        logger.info(
            f"TrivyClient loaded from dict: target='{class_args['trivy_target']}', "
            f"artifact_type='{artifact_name}', command='{class_args['scan_command'].value}'"
        )

        # Create the instance
        instance = cls(**class_args)

        # Load the results into the private attribute
        instance._TrivyClient__scan_results = trivy_results

        return instance

    @classmethod
    def from_file(cls, file: str | Path, config_file: str | None = None) -> "TrivyClient":
        """
        Creates a TrivyClient instance by loading scan results from a JSON file.

        Args:
            file (str | Path): Path to the JSON file containing Trivy scan results.
            config_file (str | None, optional): Path to a Trivy configuration file.

        Returns:
            TrivyClient
        """
        logger.info(f"Loading scan results from file: {file}")
        with open(file) as f:
            results = json.load(f)

        return TrivyClient.from_dict(results, config_file)


class TrivyComparator:
    """
    Compares the same component across different versions.

    This class is useful if you want to know how many CVEs have been fixed
    between two different versions of the same component.
    """

    def __init__(self, old_version: TrivyClient, new_version: TrivyClient):
        self.old_version = old_version
        self.new_version = new_version

        for client in [self.old_version, self.new_version]:
            if not client.scan_results():
                client.scan()

        logger.info(
            f"TrivyComparator ready: '{old_version.trivy_target}' vs '{new_version.trivy_target}'"
        )

    def fixed_vulnerabilities(self) -> set[str]:
        """
        Returns vulnerabilities present in 'old' but GONE in 'new'.
        These are the CVEs that were successfully remediated.
        """
        old_vulns = set(self.old_version.unique_vulnerabilities())
        new_vulns = set(self.new_version.unique_vulnerabilities())
        result = old_vulns - new_vulns
        logger.debug(f"fixed_vulnerabilities(): {len(result)} CVEs remediated")
        return result

    def persisting_vulnerabilities(self) -> set[str]:
        """
        Returns vulnerabilities that exist in both versions.
        These are the 'carry-over' risks that still need attention.
        """
        old_vulns = set(self.old_version.unique_vulnerabilities())
        new_vulns = set(self.new_version.unique_vulnerabilities())
        result = old_vulns.intersection(new_vulns)
        logger.debug(f"persisting_vulnerabilities(): {len(result)} CVEs still present")
        return result


@typechecked
class TrivyAnalyzer:
    """
    Performs aggregate analysis across a large collection of Trivy scans.
    """

    def __init__(self, clients: list[TrivyClient]):
        for client in clients:
            if not client.scan_results():
                # TODO: Add error handling
                client.scan()
        self.clients: list[TrivyClient] = clients
        logger.info(f"TrivyAnalyzer ready with {len(clients)} client(s)")

    def clients_with_highest_vulnerabilities(self) -> list[TrivyClient]:
        """
        Returns the client(s) with the highest number of vulnerabilities.

        Returns:
            list[TrivyClient]
        """
        max_count = max(len(client.vulnerabilities()) for client in self.clients)
        result = [
            client
            for client in self.clients
            if len(client.vulnerabilities()) == max_count
        ]
        logger.debug(f"clients_with_highest_vulnerabilities(): {len(result)} client(s) with {max_count} vulnerabilities")
        return result

    def clients_with_lowest_vulnerabilities(self) -> list[TrivyClient]:
        """
        Returns the client(s) with the lowest number of vulnerabilities.

        Returns:
            list[TrivyClient]
        """
        min_count = min(len(client.vulnerabilities()) for client in self.clients)
        result = [
            client
            for client in self.clients
            if len(client.vulnerabilities()) == min_count
        ]
        logger.debug(f"clients_with_lowest_vulnerabilities(): {len(result)} client(s) with {min_count} vulnerabilities")
        return result

    def number_of_clients(self) -> int:
        """
        Returns the number of clients.

        Returns:
            int
        """
        return len(self.clients)

    def vulnerabilities(self) -> list[str]:
        """
        Returns all the vulnerabilities in the passed clients.

        Returns:
            list[str]
        """
        result = [
            vulnerability
            for client in self.clients
            for vulnerability in client.vulnerabilities()
        ]
        logger.debug(f"vulnerabilities(): {len(result)} total across {len(self.clients)} client(s)")
        return result

    def unique_vulnerabilities(self) -> list[str]:
        """
        Returns all the unique vulnerabilities in the passed clients.

        Returns:
            list[str]
        """
        result = list(set(self.vulnerabilities()))
        logger.debug(f"unique_vulnerabilities(): {len(result)} unique across fleet")
        return result

    def most_common_cves(self, limit: int = 5) -> list[tuple[str, int]]:
        """
        Returns the vulnerabilities that appear in the highest number of different targets.

        Returns:
            list[tuple[str, int]]: A list of (CVE-ID, count) sorted by frequency.
        """
        cves: Counter = Counter()
        for client in self.clients:
            cves.update(client.unique_vulnerabilities())

        result = cves.most_common(limit)
        logger.debug(f"most_common_cves(limit={limit}): top entry is {result[0] if result else 'none'}")
        return result

    def severities(self) -> dict[str, list[str]]:
        """
        Returns the unique set of CVE IDs for each severity across the entire fleet.

        Returns:
            dict[str, list[str]]
        """
        # TODO: Make this prettier. Also, perhaps make another func, or flag, to include the affected components.
        result = {
            f"{SeverityEnum.Critical.value}": list(set(
                vuln for client in self.clients for vuln in client.criticals()
            )),
            f"{SeverityEnum.High.value}": list(set(
                vuln for client in self.clients for vuln in client.highs()
            )),
            f"{SeverityEnum.Medium.value}": list(set(
                vuln for client in self.clients for vuln in client.mediums()
            )),
            f"{SeverityEnum.Low.value}": list(set(
                vuln for client in self.clients for vuln in client.lows()
            )),
            f"{SeverityEnum.Unknown.value}": list(set(
                vuln for client in self.clients for vuln in client.unknowns()
            )),
        }
        logger.debug(
            f"severities(): CRITICAL={len(result[SeverityEnum.Critical.value])}, "
            f"HIGH={len(result[SeverityEnum.High.value])}, "
            f"MEDIUM={len(result[SeverityEnum.Medium.value])}, "
            f"LOW={len(result[SeverityEnum.Low.value])}, "
            f"UNKNOWN={len(result[SeverityEnum.Unknown.value])}"
        )
        return result

    def find_images_with_cve(self, cve: str) -> list[TrivyClient]:
        """
        Returns a list of clients whose scan results contain a specific CVE.

        Args:
            cve (str)

        Returns:
            list[TrivyClient]
        """
        result = [
            client
            for client in self.clients
            if any(vuln == cve for vuln in client.vulnerabilities())
        ]
        logger.debug(f"find_images_with_cve('{cve}'): found in {len(result)} of {len(self.clients)} client(s)")
        return result

    def bottlenecks(self) -> list[tuple[str, int, list[TrivyClient]]]:
        """
        Identifies CVEs that appear across multiple images.
        NOTE: Fixing these usually involves updating a shared base image.
        """
        cve_map: dict[str, list[TrivyClient]] = {}
        for client in self.clients:
            for cve in client.unique_vulnerabilities():
                if cve not in cve_map:
                    cve_map[cve] = []
                cve_map[cve].append(client)

        result = sorted(
            [(cve, len(clients), clients) for cve, clients in cve_map.items()],
            key=lambda x: x[1],
            reverse=True,
        )
        multi_image = sum(1 for _, count, _ in result if count > 1)
        logger.debug(f"bottlenecks(): {len(result)} total CVEs, {multi_image} appear in more than one image")
        return result
