import pytest

from tools.cracking import crack_with_hashcat, crack_with_john


def test_hashcat_missing_hash_file_reports_clearly():
    result = crack_with_hashcat("nao-existe.hash", "0", "wordlist_teste.txt")
    assert "não encontrado" in result


def test_hashcat_path_traversal_rejected():
    result = crack_with_hashcat("../../etc/passwd", "0", "wordlist_teste.txt")
    assert "fora do diretório" in result


def test_hashcat_rejects_non_numeric_mode():
    result = crack_with_hashcat("teste.hash", "abc", "wordlist_teste.txt")
    assert "números" in result


def test_john_missing_hash_file_reports_clearly():
    result = crack_with_john("nao-existe.hash")
    assert "não encontrado" in result


def test_john_rejects_invalid_format():
    from tools.workdir import resolve_in_workdir
    path = resolve_in_workdir("dummy_for_test.hash")
    path.write_text("user:hash")
    result = crack_with_john("dummy_for_test.hash", hash_format="raw-md5; rm -rf /")
    assert "inválido" in result
    path.unlink()
