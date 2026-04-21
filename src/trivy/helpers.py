from typing import Any

from .exceptions import UnknownImage


def handle_trivy_subprocess_command(error: str, trivy_target: str) -> Exception:
    """
    Returns a reasonable Exception based on the output of an attempted trivy scan.

    Args:
        error (str): The stderr output from the failed Trivy subprocess call.
        trivy_target (str): The target that was being scanned.

    Returns:
        Exception: An appropriate exception to raise.
    """
    if "unable to find the specified image" in error:
        return UnknownImage(f"Image '{trivy_target}' doesn't exist.")

    return Exception(f"Unhandled Trivy error for target '{trivy_target}': {error}")


def flatten_dict_for_excel_report(
    data: dict[str, Any], separator: str = ":", prefix: str = ""
) -> dict[str, Any]:
    """
    Recursively flattens a nested dictionary into a single-level dictionary.

    Example:
        {'CVSS': {'nvd': {'V3Score': 9.8}}} -> {'CVSS:nvd:V3Score': 9.8}

    Args:
        data (dict[str, Any]): The nested dictionary to flatten.
        separator (str, optional): Character used to join nested key names. Defaults to ":".
        prefix (str, optional): Key prefix accumulated during recursion. Defaults to "".

    Returns:
        dict[str, Any]: A single-level dictionary with compound keys.
    """
    items = []
    for key, value in data.items():
        new_key = f"{prefix}{separator}{key}" if prefix else key
        if isinstance(value, dict):
            items.extend(
                flatten_dict_for_excel_report(
                    value, separator=separator, prefix=new_key
                ).items()
            )
        else:
            # For lists or other types, stringify them to avoid Excel errors
            items.append((new_key, str(value) if value is not None else ""))
    return dict(items)
