"""Testes para tools/forensics.py — wrapper de Volatility3/Sleuth Kit.

NUNCA VALIDADO CONTRA IMAGEM REAL (ver aviso no módulo) — cobertura via
mock de subprocess. Validação real de path/workdir é testada de
verdade (sem mock), reusando o mesmo sandbox de cracking.py."""

import shutil

import pytest

from tools import forensics
from tools.workdir import resolve_in_workdir


@pytest.fixture
def fake_image(tmp_path):
    """Cria um arquivo de imagem falso dentro de WORKDIR de verdade,
    para os testes de validação de path não dependerem só de mock."""
    from config import WORKDIR
    WORKDIR.mkdir(parents=True, exist_ok=True)
    image_path = WORKDIR / "test_memdump.raw"
    image_path.write_bytes(b"fake memory image content")
    yield "test_memdump.raw"
    image_path.unlink(missing_ok=True)


def test_list_volatility_plugins_includes_common_categories():
    result = forensics.list_volatility_plugins()
    assert "windows" in result
    assert "linux" in result
    assert "windows.pslist" in result


def test_run_memory_analysis_rejects_path_outside_workdir():
    result = forensics.run_memory_analysis("../../etc/passwd", "windows.pslist")
    assert "fora do diretório permitido" in result


def test_run_memory_analysis_rejects_invalid_plugin_name(fake_image):
    result = forensics.run_memory_analysis(fake_image, "windows.pslist; rm -rf /")
    assert "inválido" in result


def test_run_memory_analysis_reports_missing_file():
    result = forensics.run_memory_analysis("does_not_exist.raw", "windows.pslist")
    # ou cai em "não encontrado" (se vol estiver instalado) ou em "não está instalado"
    assert "não encontrado" in result or "não está instalado" in result


def test_run_memory_analysis_reports_not_installed_when_no_binary(fake_image, monkeypatch):
    monkeypatch.setattr(forensics.shutil, "which", lambda name: None)
    result = forensics.run_memory_analysis(fake_image, "windows.pslist")
    assert "não está instalado" in result


def test_run_memory_analysis_calls_volatility_with_correct_args(fake_image, monkeypatch):
    monkeypatch.setattr(forensics.shutil, "which", lambda name: "/usr/local/bin/vol3" if name == "vol3" else None)

    captured = {}

    class FakeResult:
        returncode = 0
        stdout = "PID\tPPID\tImageFileName\n1\t0\tsystem"
        stderr = ""

    def fake_run(cmd, timeout=600):
        captured["cmd"] = cmd
        return FakeResult()

    monkeypatch.setattr(forensics, "_run", fake_run)

    result = forensics.run_memory_analysis(fake_image, "windows.pslist")

    assert captured["cmd"][0] == "/usr/local/bin/vol3"
    assert captured["cmd"][1] == "-f"
    assert "windows.pslist" in captured["cmd"]
    assert "system" in result


def test_filesystem_timeline_rejects_path_outside_workdir():
    result = forensics.filesystem_timeline("../../etc/passwd")
    assert "fora do diretório permitido" in result


def test_filesystem_timeline_reports_not_installed(monkeypatch):
    monkeypatch.setattr(forensics.shutil, "which", lambda name: None)
    result = forensics.filesystem_timeline("disk.img")
    assert "Sleuth Kit" in result and "não está instalado" in result


def test_recover_deleted_files_reports_not_installed(monkeypatch):
    monkeypatch.setattr(forensics.shutil, "which", lambda name: None)
    result = forensics.recover_deleted_files("disk.img", "recovered")
    assert "não está instalado" in result


def test_recover_deleted_files_calls_tsk_recover_and_counts_output(fake_image, monkeypatch, tmp_path):
    monkeypatch.setattr(forensics.shutil, "which", lambda name: "/usr/local/bin/tsk_recover" if name == "tsk_recover" else None)

    def fake_run(cmd, timeout=600):
        # Simula tsk_recover criando 2 arquivos no diretório de saída real.
        output_dir = resolve_in_workdir("recovered_test")
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "file1.txt").write_text("a")
        (output_dir / "file2.txt").write_text("b")

        class FakeResult:
            returncode = 0
            stderr = ""
        return FakeResult()

    monkeypatch.setattr(forensics, "_run", fake_run)

    result = forensics.recover_deleted_files(fake_image, "recovered_test")
    assert "2 arquivo(s)" in result

    shutil.rmtree(resolve_in_workdir("recovered_test"), ignore_errors=True)
