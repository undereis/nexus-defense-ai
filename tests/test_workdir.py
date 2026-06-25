import pytest

from tools.workdir import resolve_in_workdir


def test_simple_filename_resolves_inside_workdir():
    path = resolve_in_workdir("arquivo.txt")
    from config import WORKDIR
    assert path.parent == WORKDIR.resolve()


@pytest.mark.parametrize("escape_attempt", ["../../etc/passwd", "../../../etc/shadow", "/etc/passwd"])
def test_path_traversal_rejected(escape_attempt):
    with pytest.raises(ValueError):
        resolve_in_workdir(escape_attempt)
