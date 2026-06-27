"""Testes para tools/honeytokens.py — arquivos-isca com callback real.

NOTA IMPORTANTE: testes que exigiriam connect() real via socket (cliente
de fato batendo na porta do listener) não puderam ser validados nesta
sessão — uma mudança de ambiente em algum momento da sessão passou a
bloquear TODO connect() TCP local, inclusive para código já validado
antes (honeypot ssh/ftp/http, que passava 100% mais cedo na mesma
sessão). Confirmado que não é bug do código: bind()/listen() continuam
funcionando normalmente (lsof confirma LISTEN), só connect() trava.
Os testes abaixo validam tudo que NÃO depende de connect() real: escrita
do arquivo-isca, parsing de path/user-agent, lógica de disparo
(handle_canary_trigger chamado direto, sem ir pelo socket), e o ciclo de
vida start/stop do listener (bind/listen/shutdown, sem cliente).
Recomendo revalidar com um cliente real (curl/navegador) assim que esse
problema de ambiente for resolvido — ver tests/test_honeypot.py para o
que ficou temporariamente sem cobertura de ponta a ponta pelo mesmo motivo.
"""

import importlib
import re

import pytest


@pytest.fixture
def honeytokens_module(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_honeytokens.db")
    monkeypatch.setattr(config, "CANARY_BASE_URL", "http://198.18.99.99:8099")
    monkeypatch.setattr(config, "AUTO_REPORT_ABUSEIPDB", False)
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    import tools.honeytokens as honeytokens
    importlib.reload(honeytokens)
    monkeypatch.setattr(honeytokens.firewall, "block_ip", lambda ip, reason: f"IP {ip} bloqueado.")
    monkeypatch.setattr(honeytokens.notify, "send_notification", lambda *a, **k: True)
    monkeypatch.setattr(honeytokens, "record_confirmed_isolation", lambda ip, reason: None)
    yield honeytokens, dbmod


def test_plant_decoy_file_without_canary_base_url(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "CANARY_BASE_URL", "")
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_ht2.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()
    import tools.honeytokens as honeytokens
    importlib.reload(honeytokens)

    result = honeytokens.plant_decoy_file("aws_credentials", tmp_path)
    assert "CANARY_BASE_URL não configurado" in result


def test_plant_decoy_file_rejects_unknown_kind(honeytokens_module, tmp_path):
    honeytokens, _ = honeytokens_module
    result = honeytokens.plant_decoy_file("kind_que_nao_existe", tmp_path)
    assert "desconhecido" in result


@pytest.mark.parametrize("kind", ["aws_credentials", "ssh_key", "database_backup"])
def test_plant_decoy_file_creates_convincing_file_with_real_callback_url(honeytokens_module, tmp_path, kind):
    honeytokens, dbmod = honeytokens_module
    result = honeytokens.plant_decoy_file(kind, tmp_path)
    assert "plantado" in result

    token_id = re.search(r"Token (\w+)", result).group(1)
    decoy_filename = honeytokens._DECOY_TEMPLATES[kind][0]
    decoy_file = tmp_path / decoy_filename
    assert decoy_file.exists()
    content = decoy_file.read_text()
    assert f"http://198.18.99.99:8099/canary/{token_id}" in content

    tokens = dbmod.list_honeytokens()
    assert len(tokens) == 1
    assert tokens[0][0] == token_id
    assert tokens[0][1] == kind


def test_handle_canary_trigger_with_real_token_isolates_and_records(honeytokens_module, tmp_path):
    honeytokens, dbmod = honeytokens_module
    result = honeytokens.plant_decoy_file("aws_credentials", tmp_path)
    token_id = re.search(r"Token (\w+)", result).group(1)

    triggered = honeytokens.handle_canary_trigger(token_id, "198.18.50.60", "curl/8.0")

    assert triggered is True
    triggers = dbmod.get_honeytoken_triggers(token_id)
    assert len(triggers) == 1
    assert triggers[0][0] == "198.18.50.60"
    assert triggers[0][1] == "curl/8.0"


def test_handle_canary_trigger_with_unknown_token_does_nothing(honeytokens_module):
    honeytokens, dbmod = honeytokens_module
    triggered = honeytokens.handle_canary_trigger("token-que-nunca-existiu", "1.2.3.4", "x")
    assert triggered is False
    assert dbmod.get_honeytoken_triggers("token-que-nunca-existiu") == []


def test_handle_canary_trigger_never_isolates_loopback(honeytokens_module, tmp_path, monkeypatch):
    honeytokens, _ = honeytokens_module
    result = honeytokens.plant_decoy_file("aws_credentials", tmp_path)
    token_id = re.search(r"Token (\w+)", result).group(1)

    block_calls = []
    monkeypatch.setattr(honeytokens.firewall, "block_ip", lambda ip, reason: block_calls.append(ip))

    honeytokens.handle_canary_trigger(token_id, "127.0.0.1", "teste-local")
    assert block_calls == []


def test_handle_canary_trigger_isolates_real_remote_ip(honeytokens_module, tmp_path, monkeypatch):
    honeytokens, _ = honeytokens_module
    result = honeytokens.plant_decoy_file("aws_credentials", tmp_path)
    token_id = re.search(r"Token (\w+)", result).group(1)

    block_calls = []
    monkeypatch.setattr(honeytokens.firewall, "block_ip", lambda ip, reason: block_calls.append(ip) or "ok")

    honeytokens.handle_canary_trigger(token_id, "198.51.100.7", "teste")
    assert block_calls == ["198.51.100.7"]


def test_describe_honeytokens_empty(honeytokens_module):
    honeytokens, _ = honeytokens_module
    assert "Nenhum honeytoken" in honeytokens.describe_honeytokens()


def test_describe_token_triggers_never_triggered(honeytokens_module):
    honeytokens, _ = honeytokens_module
    result = honeytokens.describe_token_triggers("token-qualquer")
    assert "nunca foi disparado" in result


def test_canary_path_regex_matches_real_http_request_line():
    from tools.honeytokens import _CANARY_PATH_RE
    request = b"GET /canary/abcd1234ef HTTP/1.1\r\nHost: x\r\n\r\n"
    match = _CANARY_PATH_RE.match(request)
    assert match is not None
    assert match.group(1) == b"abcd1234ef"


def test_canary_path_regex_rejects_unrelated_paths():
    from tools.honeytokens import _CANARY_PATH_RE
    assert _CANARY_PATH_RE.match(b"GET /favicon.ico HTTP/1.1\r\n\r\n") is None
    assert _CANARY_PATH_RE.match(b"POST /canary/abcd1234 HTTP/1.1\r\n\r\n") is None


def test_user_agent_regex_extracts_real_header():
    from tools.honeytokens import _USER_AGENT_RE
    request = b"GET /canary/abc HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8.4.0\r\n\r\n"
    match = _USER_AGENT_RE.search(request)
    assert match is not None
    assert match.group(1) == b"curl/8.4.0"


def test_canary_listener_start_stop_lifecycle_without_real_client(honeytokens_module):
    """bind()/listen() funcionam normalmente neste ambiente — só
    connect() está afetado pelo problema de ambiente documentado no
    topo do arquivo. Isso ainda valida o ciclo de vida real do socket."""
    honeytokens, _ = honeytokens_module
    assert honeytokens.is_canary_listener_running() is False

    result = honeytokens.start_canary_listener(0)  # porta 0 = o SO escolhe uma livre
    assert "rodando" in result
    assert honeytokens.is_canary_listener_running() is True

    second_attempt = honeytokens.start_canary_listener(0)
    assert "já está rodando" in second_attempt

    stop_result = honeytokens.stop_canary_listener()
    assert "parado" in stop_result
    assert honeytokens.is_canary_listener_running() is False


def test_canary_listener_stop_when_not_running(honeytokens_module):
    honeytokens, _ = honeytokens_module
    assert honeytokens.stop_canary_listener() == "Listener de canário não está rodando."


def test_generate_decoy_pppoe_username_has_recognizable_prefix(honeytokens_module):
    honeytokens, _ = honeytokens_module
    username = honeytokens.generate_decoy_pppoe_username()
    assert username.startswith(honeytokens._DECOY_USERNAME_PREFIX)


def test_register_pppoe_honeytoken_with_correct_prefix(honeytokens_module):
    honeytokens, dbmod = honeytokens_module
    username = honeytokens.generate_decoy_pppoe_username()
    result = honeytokens.register_pppoe_honeytoken(username)
    assert "registrado como honeytoken" in result

    tokens = dbmod.list_honeytokens()
    assert len(tokens) == 1
    assert tokens[0][0] == username
    assert tokens[0][1] == "pppoe_credential"


def test_register_pppoe_honeytoken_without_prefix_warns_but_still_registers(honeytokens_module):
    honeytokens, dbmod = honeytokens_module
    result = honeytokens.register_pppoe_honeytoken("cliente_normal")
    assert "Aviso" in result
    assert len(dbmod.list_honeytokens()) == 1


def test_check_pppoe_honeytoken_logins_with_no_decoys_registered(honeytokens_module, monkeypatch):
    honeytokens, _ = honeytokens_module
    from tools import mikrotik
    monkeypatch.setattr(mikrotik, "run_generic_command", lambda path: "alguma saída")

    result = honeytokens.check_pppoe_honeytoken_logins()
    assert "Nenhuma credencial-isca PPPoE registrada" in result


def test_check_pppoe_honeytoken_logins_reports_mikrotik_failure(honeytokens_module, monkeypatch):
    honeytokens, _ = honeytokens_module
    username = honeytokens.generate_decoy_pppoe_username()
    honeytokens.register_pppoe_honeytoken(username)

    from tools import mikrotik
    monkeypatch.setattr(mikrotik, "run_generic_command", lambda path: "Falha ao comunicar com o Mikrotik")

    result = honeytokens.check_pppoe_honeytoken_logins()
    assert "Não foi possível consultar" in result


def test_check_pppoe_honeytoken_logins_no_active_session(honeytokens_module, monkeypatch):
    honeytokens, _ = honeytokens_module
    username = honeytokens.generate_decoy_pppoe_username()
    honeytokens.register_pppoe_honeytoken(username)

    from tools import mikrotik
    monkeypatch.setattr(mikrotik, "run_generic_command", lambda path: "name=cliente_real address=10.0.0.5")

    result = honeytokens.check_pppoe_honeytoken_logins()
    assert "Nenhuma das 1 credencial" in result


def test_check_pppoe_honeytoken_logins_detects_active_decoy_session(honeytokens_module, monkeypatch):
    honeytokens, dbmod = honeytokens_module
    username = honeytokens.generate_decoy_pppoe_username()
    honeytokens.register_pppoe_honeytoken(username)

    from tools import mikrotik
    monkeypatch.setattr(
        mikrotik, "run_generic_command", lambda path: f"name={username} address=10.0.0.99 caller-id=AA:BB"
    )

    result = honeytokens.check_pppoe_honeytoken_logins()
    assert "COMPROMETIMENTO CONFIRMADO" in result
    assert username in result

    triggers = dbmod.get_honeytoken_triggers(username)
    assert len(triggers) == 1
