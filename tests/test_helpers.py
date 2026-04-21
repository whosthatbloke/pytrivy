import pytest

from src.trivy.exceptions import UnknownImage
from src.trivy.helpers import flatten_dict_for_excel_report, handle_trivy_subprocess_command


#
# handle_trivy_subprocess_command
#
def test_handle_unknown_image_returns_unknown_image_exception():
    result = handle_trivy_subprocess_command(
        "unable to find the specified image", "my-image:latest"
    )
    assert isinstance(result, UnknownImage)


def test_handle_unknown_image_message_contains_target():
    result = handle_trivy_subprocess_command(
        "unable to find the specified image", "my-image:latest"
    )
    assert "my-image:latest" in str(result)


def test_handle_unknown_image_is_raiseable():
    exc = handle_trivy_subprocess_command(
        "unable to find the specified image", "my-image:latest"
    )
    with pytest.raises(UnknownImage):
        raise exc


def test_handle_fallback_returns_generic_exception():
    result = handle_trivy_subprocess_command("some unexpected error", "my-image:latest")
    assert isinstance(result, Exception)
    assert not isinstance(result, UnknownImage)


def test_handle_fallback_message_contains_target_and_error():
    result = handle_trivy_subprocess_command("some unexpected error", "my-image:latest")
    assert "my-image:latest" in str(result)
    assert "some unexpected error" in str(result)


#
# flatten_dict_for_excel_report
#
def test_flatten_simple_dict():
    result = flatten_dict_for_excel_report({"key": "value"})
    assert result == {"key": "value"}


def test_flatten_nested_dict():
    result = flatten_dict_for_excel_report({"CVSS": {"nvd": {"V3Score": 9.8}}})
    assert result == {"CVSS:nvd:V3Score": "9.8"}


def test_flatten_custom_separator():
    result = flatten_dict_for_excel_report({"a": {"b": "c"}}, separator=".")
    assert result == {"a.b": "c"}


def test_flatten_none_value_becomes_empty_string():
    result = flatten_dict_for_excel_report({"key": None})
    assert result == {"key": ""}


def test_flatten_list_value_is_stringified():
    result = flatten_dict_for_excel_report({"key": [1, 2, 3]})
    assert result == {"key": "[1, 2, 3]"}


def test_flatten_mixed_dict():
    result = flatten_dict_for_excel_report(
        {"a": "flat", "b": {"c": "nested"}, "d": None}
    )
    assert result == {"a": "flat", "b:c": "nested", "d": ""}


def test_flatten_empty_dict():
    result = flatten_dict_for_excel_report({})
    assert result == {}


def test_flatten_preserves_prefix():
    result = flatten_dict_for_excel_report({"b": "val"}, prefix="a")
    assert result == {"a:b": "val"}
