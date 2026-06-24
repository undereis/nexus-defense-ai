import time

from tools.network_monitor import DdosDetector


def test_no_suspects_below_threshold(monkeypatch):
    monkeypatch.setattr(
        "tools.network_monitor.get_active_remote_ips", lambda: ["1.1.1.1"] * 5
    )
    detector = DdosDetector(window_seconds=10, threshold=80)
    assert detector.sample() == []


def test_flags_ip_above_threshold(monkeypatch):
    monkeypatch.setattr(
        "tools.network_monitor.get_active_remote_ips", lambda: ["9.9.9.9"] * 100
    )
    detector = DdosDetector(window_seconds=10, threshold=80)
    suspects = detector.sample()
    assert "9.9.9.9" in suspects


def test_old_samples_expire_outside_window(monkeypatch):
    calls = {"n": 0}

    def fake_ips():
        calls["n"] += 1
        return ["5.5.5.5"] * 100 if calls["n"] == 1 else []

    monkeypatch.setattr("tools.network_monitor.get_active_remote_ips", fake_ips)
    detector = DdosDetector(window_seconds=1, threshold=80)
    assert "5.5.5.5" in detector.sample()
    time.sleep(1.1)
    assert detector.sample() == []


def test_snapshot_counts_reflects_samples(monkeypatch):
    monkeypatch.setattr(
        "tools.network_monitor.get_active_remote_ips", lambda: ["2.2.2.2", "3.3.3.3", "2.2.2.2"]
    )
    detector = DdosDetector(window_seconds=10, threshold=80)
    detector.sample()
    counts = detector.snapshot_counts()
    assert counts["2.2.2.2"] == 2
    assert counts["3.3.3.3"] == 1
