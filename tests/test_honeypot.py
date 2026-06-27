import importlib
import socket
import time

import pytest


@pytest.fixture
def honeypot_module(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_honeypot.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    import tools.honeypot as honeypot
    importlib.reload(honeypot)
    monkeypatch.setattr(honeypot.firewall, "block_ip", lambda ip, reason: f"IP {ip} bloqueado.")
    monkeypatch.setattr(honeypot, "record_confirmed_isolation", lambda ip, reason="": None)
    monkeypatch.setattr(honeypot.notify, "send_notification", lambda *a, **k: True)
    yield honeypot, dbmod
    honeypot.stop()


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_not_running_initially(honeypot_module):
    honeypot, _ = honeypot_module
    assert honeypot.is_running() is False


def test_start_and_stop(honeypot_module):
    honeypot, _ = honeypot_module
    port = _free_port()
    result = honeypot.start("ssh", port)
    assert "iniciado" in result
    assert honeypot.is_running() is True

    stop_result = honeypot.stop("ssh", port)
    assert "parado" in stop_result.lower()
    time.sleep(0.2)
    assert honeypot.is_running() is False


def test_starting_twice_is_idempotent(honeypot_module):
    honeypot, _ = honeypot_module
    port = _free_port()
    honeypot.start("ssh", port)
    second = honeypot.start("ssh", port)
    assert "já está rodando" in second


def test_rejects_unsupported_service(honeypot_module):
    honeypot, _ = honeypot_module
    result = honeypot.start("telnet", 12345)
    assert "não suportado" in result


def test_multiple_services_run_simultaneously(honeypot_module):
    honeypot, _ = honeypot_module
    ssh_port, ftp_port = _free_port(), _free_port()
    honeypot.start("ssh", ssh_port)
    honeypot.start("ftp", ftp_port)
    running = set(honeypot.list_running())
    assert ("ssh", ssh_port) in running
    assert ("ftp", ftp_port) in running


def test_ssh_connection_is_recorded_and_isolated(honeypot_module):
    honeypot, dbmod = honeypot_module
    port = _free_port()
    honeypot.start("ssh", port)
    time.sleep(0.2)

    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    client.recv(64)
    client.close()
    time.sleep(0.3)

    hits = dbmod.list_honeypot_hits()
    assert len(hits) == 1
    assert hits[0][0] == "127.0.0.1"
    assert hits[0][1] == port
    assert hits[0][2] == "ssh"


def test_describe_hits_when_empty(honeypot_module):
    honeypot, _ = honeypot_module
    result = honeypot.describe_hits()
    assert "Nenhuma conexão" in result


def test_describe_hits_after_capture(honeypot_module):
    honeypot, dbmod = honeypot_module
    dbmod.record_honeypot_hit("9.9.9.9", 2222, "ssh")
    result = honeypot.describe_hits()
    assert "9.9.9.9" in result


@pytest.mark.parametrize("ip", ["127.0.0.1", "127.5.5.5", "::1"])
def test_loopback_never_isolated(ip):
    from tools.honeypot import _is_safe_to_isolate
    assert _is_safe_to_isolate(ip) is False


@pytest.mark.parametrize("ip", ["8.8.8.8", "192.168.1.50", "45.187.68.91"])
def test_non_loopback_can_be_isolated(ip):
    from tools.honeypot import _is_safe_to_isolate
    assert _is_safe_to_isolate(ip) is True


def test_loopback_connection_is_recorded_but_not_isolated(honeypot_module, monkeypatch):
    honeypot, dbmod = honeypot_module
    blocked = []
    monkeypatch.setattr(honeypot.firewall, "block_ip", lambda ip, reason: blocked.append(ip))

    port = _free_port()
    honeypot.start("ssh", port)
    time.sleep(0.2)

    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    client.recv(64)
    client.close()
    time.sleep(0.3)

    assert len(dbmod.list_honeypot_hits()) == 1
    assert blocked == []  # nunca chamou block_ip para loopback


def test_ftp_captures_credentials(honeypot_module):
    honeypot, dbmod = honeypot_module
    port = _free_port()
    honeypot.start("ftp", port)
    time.sleep(0.2)

    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    client.recv(256)  # banner 220
    client.sendall(b"USER admin\r\n")
    client.recv(256)  # 331 password required
    client.sendall(b"PASS senha123\r\n")
    client.recv(256)  # 530 login incorrect
    client.close()
    time.sleep(0.3)

    creds = dbmod.list_honeypot_credentials()
    assert len(creds) == 1
    ip, captured_port, service, username, password, _ts = creds[0]
    assert ip == "127.0.0.1"
    assert service == "ftp"
    assert username == "admin"
    assert password == "senha123"


def test_ftp_captures_credentials_sent_in_single_packet(honeypot_module):
    """Alguns clientes/scanners mandam USER e PASS de uma vez, sem esperar
    a resposta intermediária do servidor — o parser precisa lidar com
    múltiplas linhas chegando no mesmo recv()."""
    honeypot, dbmod = honeypot_module
    port = _free_port()
    honeypot.start("ftp", port)
    time.sleep(0.2)

    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    client.recv(256)  # banner 220
    client.sendall(b"USER root\r\nPASS toor\r\n")  # tudo de uma vez
    time.sleep(0.3)
    client.close()

    creds = dbmod.list_honeypot_credentials()
    assert len(creds) == 1
    assert creds[0][3] == "root"
    assert creds[0][4] == "toor"


def test_http_login_page_served_on_get(honeypot_module):
    honeypot, _ = honeypot_module
    port = _free_port()
    honeypot.start("http", port)
    time.sleep(0.2)

    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    client.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    response = client.recv(4096)
    client.close()

    assert b"200 OK" in response
    assert b"Admin Login" in response


def test_http_captures_credentials_on_post(honeypot_module):
    honeypot, dbmod = honeypot_module
    port = _free_port()
    honeypot.start("http", port)
    time.sleep(0.2)

    body = b"username=root&password=toor123"
    request = (
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    client.sendall(request)
    response = client.recv(4096)
    client.close()
    time.sleep(0.3)

    assert b"401" in response
    creds = dbmod.list_honeypot_credentials()
    assert len(creds) == 1
    assert creds[0][3] == "root"
    assert creds[0][4] == "toor123"


def test_describe_credentials_when_empty(honeypot_module):
    honeypot, _ = honeypot_module
    assert "Nenhuma credencial" in honeypot.describe_credentials()


def test_describe_credentials_after_capture(honeypot_module):
    honeypot, dbmod = honeypot_module
    dbmod.record_honeypot_credential("1.2.3.4", 21, "ftp", "admin", "1234")
    result = honeypot.describe_credentials()
    assert "1.2.3.4" in result
    assert "admin" in result


def test_stop_marks_service_as_manually_stopped(honeypot_module):
    honeypot, _ = honeypot_module
    port = _free_port()

    honeypot.start("ssh", port)
    assert honeypot.is_manually_stopped("ssh", port) is False

    honeypot.stop("ssh", port)
    assert honeypot.is_manually_stopped("ssh", port) is True


def test_start_again_clears_manually_stopped_flag(honeypot_module):
    """Regressão: depois de start() de novo (manual ou via watchdog), o
    serviço não deve continuar marcado como 'parado de propósito'."""
    honeypot, _ = honeypot_module
    port = _free_port()

    honeypot.start("ssh", port)
    honeypot.stop("ssh", port)
    assert honeypot.is_manually_stopped("ssh", port) is True

    honeypot.start("ssh", port)
    assert honeypot.is_manually_stopped("ssh", port) is False


def test_start_reports_real_failure_when_port_already_in_use(honeypot_module):
    """Regressão do bug real: porta já ocupada por outro processo fazia
    start() reportar sucesso mesmo com o bind falhando em background, e
    o watchdog ficava tentando 'curar' isso para sempre sem nunca
    conseguir de fato. Agora start() espera a confirmação real do bind."""
    honeypot, _ = honeypot_module
    port = _free_port()

    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("0.0.0.0", port))
    blocker.listen(1)
    try:
        result = honeypot.start("ssh", port)
        assert "Falha ao iniciar" in result
        assert port not in [p for _, p in honeypot.list_running()]
    finally:
        blocker.close()
