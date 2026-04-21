import logging
from time import time
from typing import Optional

import pyexcel

from .classes import TrivyClient
from .enums import SeverityEnum, TrivyResultsEnum, TrivyScanCommandEnum
from .exceptions import TrivyClientNotScanned
from .helpers import flatten_dict_for_excel_report

logger = logging.getLogger(__name__)


def generate_excel_report(client: TrivyClient, filename: Optional[str] = None) -> str:
    """
    Generate a complete summary of a client.

    If a name is not provided, one will be generated as
    {client.trivy_target}_{unix-timestamp}_report.xlsx.
    Any "/" in client.trivy_target will be replaced with "__".

    Args:
        client (TrivyClient): The scanned client to generate a report for.
        filename (Optional[str], optional): Output filename without extension.

    Raises:
        TrivyClientNotScanned: If the image has not been scanned.

    Returns:
        str: The filename of the generated report.
    """
    if not client.scan_results():
        raise TrivyClientNotScanned("Scan the client before generating the report.")

    if not filename:
        target_name = client.trivy_target.replace("/", "__")
        filename = f"{target_name}_{int(time())}_report.xlsx"

    logger.info(f"Generating report: {filename}")

    #
    # Severity summary sheet
    #
    summary_data = [["Severity", "Count"]]
    severities = {
        SeverityEnum.Critical.value: len(client.criticals()),
        SeverityEnum.High.value: len(client.highs()),
        SeverityEnum.Medium.value: len(client.mediums()),
        SeverityEnum.Low.value: len(client.lows()),
        SeverityEnum.Unknown.value: len(client.unknowns()),
        "Total": len(client.criticals()) + len(client.highs()) + len(client.mediums()) + len(client.lows()) + len(client.unknowns()),
    }

    for sev_name, count in severities.items():
        summary_data.append([sev_name, count])

    #
    # Vulnerabilities sheet
    #
    vuln_list = client.vulnerabilities()
    flattened_vulns = []
    all_headers: set[str] = set()

    # Flatten everything and collect all possible headers
    for vuln_id in vuln_list:
        raw_details = client.vulnerability(vuln_id)
        flat = flatten_dict_for_excel_report(raw_details)
        flattened_vulns.append(flat)
        all_headers.update(flat.keys())

    # Sort headers so some appear first, others are alphabetical
    _desired_ordered_headers = [
        TrivyResultsEnum.VulnerabilityID.value,
        TrivyResultsEnum.Severity.value,
        TrivyResultsEnum.Description.value,
        TrivyResultsEnum.PkgName.value,
        TrivyResultsEnum.InstalledVersion.value,
        TrivyResultsEnum.FixedVersion.value,
    ]
    headers = _desired_ordered_headers + sorted(
        [header for header in all_headers if header not in _desired_ordered_headers]
    )

    vuln_data = [headers]
    for flat_vuln in flattened_vulns:
        row = [flat_vuln.get(header, "") for header in headers]
        vuln_data.append(row)

    #
    # Targets summary
    #
    targets_data = [["Name"]]
    for target in client.targets():
        targets_data.append([target])

    #
    # Packages (SBOM) sheet
    #
    packages_data = [["Target", "Type", "ID", "Name", "Version", "Licenses", "PURL"]]
    for raw_target in client.raw_targets():
        target_name = raw_target.get(TrivyResultsEnum.Target.value, "")
        target_type = raw_target.get(TrivyResultsEnum.Type.value, "")
        for pkg in raw_target.get(TrivyResultsEnum.Packages.value) or []:
            pkg_id = pkg.get(TrivyResultsEnum.ID.value, "")
            pkg_name = pkg.get(TrivyResultsEnum.Name.value, "")
            pkg_version = pkg.get(TrivyResultsEnum.Version.value, "")
            pkg_licenses = ", ".join(pkg.get(TrivyResultsEnum.Licenses.value) or [])
            pkg_purl = pkg.get(TrivyResultsEnum.Identifier.value, {}).get(
                TrivyResultsEnum.PURL.value, ""
            )
            packages_data.append([target_name, target_type, pkg_id, pkg_name, pkg_version, pkg_licenses, pkg_purl])

    #
    # Write the contents to a spreadsheet
    #
    book_content = {
        "Severity Summary": summary_data,
        "Vulnerabilities": vuln_data,
        "Packages": packages_data,
        "Targets": targets_data,
    }
    pyexcel.save_book_as(bookdict=book_content, dest_file_name=filename)
    logger.info(f"Report generated: {filename}")
    return filename
