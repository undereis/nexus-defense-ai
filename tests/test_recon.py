"""Testes para tools/recon.py — validação de target e headers de segurança.

nmap/nikto exigem rede e binários externos, então aqui cobrimos a lógica
de validação (regressão do bug: check_security_headers rejeitava URLs
com esquema/porta) com um servidor HTTP real local, sem mock de rede.
"""

import http.server
import threading
import time

import pytest

from tools.recon import check_security_headers


@pytest.fixture
def local_http_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)
    yield port
    server.shutdown()


def test_check_security_headers_accepts_full_url_with_port(local_http_server):
    url = f"http://127.0.0.1:{local_http_server}"
    result = check_security_headers(url)
    assert "status 200" in result
    assert "Strict-Transport-Security" in result


def test_check_security_headers_accepts_bare_hostname(local_http_server):
    # Sem esquema, a função tenta https:// por padrão; o servidor de teste é
    # HTTP puro, então a conexão falha — mas a validação do hostname deve
    # passar (a função retorna mensagem de falha, não levanta ValueError).
    result = check_security_headers("127.0.0.1")
    assert "Falha ao conectar" in result


def test_check_security_headers_rejects_invalid_target():
    with pytest.raises(ValueError):
        check_security_headers("http://not a valid host!!")
