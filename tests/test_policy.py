from collections import Counter

from tools.policy import classify_threats


def test_disabled_multiplier_routes_everything_to_moderate():
    counts = Counter({"1.1.1.1": 500, "2.2.2.2": 80})
    severe, moderate = classify_threats(counts, threshold=80, severe_multiplier=0)
    assert severe == []
    assert sorted(moderate) == ["1.1.1.1", "2.2.2.2"]


def test_below_threshold_is_ignored():
    counts = Counter({"1.1.1.1": 10})
    severe, moderate = classify_threats(counts, threshold=80, severe_multiplier=3)
    assert severe == [] and moderate == []


def test_severe_above_multiplier_threshold():
    counts = Counter({"1.1.1.1": 500, "2.2.2.2": 90})
    severe, moderate = classify_threats(counts, threshold=80, severe_multiplier=3)
    assert severe == ["1.1.1.1"]
    assert moderate == ["2.2.2.2"]


def test_exactly_at_severe_boundary_counts_as_severe():
    counts = Counter({"1.1.1.1": 240})
    severe, moderate = classify_threats(counts, threshold=80, severe_multiplier=3)
    assert severe == ["1.1.1.1"]
    assert moderate == []
