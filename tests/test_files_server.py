import pytest

from tools.files_server import _safe_path


def test_inside_sandbox_is_allowed():
    assert _safe_path("docs/report.txt").name == "report.txt"


@pytest.mark.parametrize("bad", ["../secret.txt", "docs/../../pyproject.toml", "/etc/passwd"])
def test_escape_is_rejected(bad):
    with pytest.raises(ValueError):
        _safe_path(bad)
