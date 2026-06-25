from tools.web_injection import test_injection as run_injection_test


def test_no_findings_on_clean_response(monkeypatch):
    class FakeResp:
        status_code = 200
        text = "<html><body>Página normal</body></html>"

    monkeypatch.setattr("tools.web_injection.requests.get", lambda *a, **k: FakeResp())
    result = run_injection_test("example.com", "q", "both")
    assert "Nenhum sinal" in result


def test_detects_reflected_xss(monkeypatch):
    def fake_get(url, params=None, timeout=10):
        class FakeResp:
            status_code = 200
            text = f"<html>{params['q']}</html>"
        return FakeResp()

    monkeypatch.setattr("tools.web_injection.requests.get", fake_get)
    result = run_injection_test("example.com", "q", "xss")
    assert "SUSPEITO" in result
    assert "XSS" in result


def test_detects_sql_error_signature(monkeypatch):
    def fake_get(url, params=None, timeout=10):
        class FakeResp:
            status_code = 500
            text = "You have an error in your SQL syntax near..."
        return FakeResp()

    monkeypatch.setattr("tools.web_injection.requests.get", fake_get)
    result = run_injection_test("example.com", "id", "sqli")
    assert "SUSPEITO" in result
    assert "SQLi" in result


def test_invalid_payload_type_rejected():
    result = run_injection_test("example.com", "q", "invalido")
    assert "deve ser" in result


def test_normalizes_url_without_scheme(monkeypatch):
    captured = {}

    def fake_get(url, params=None, timeout=10):
        captured["url"] = url
        class FakeResp:
            status_code = 200
            text = "ok"
        return FakeResp()

    monkeypatch.setattr("tools.web_injection.requests.get", fake_get)
    run_injection_test("example.com", "q", "sqli")
    assert captured["url"].startswith("https://")
