"""RBAC mínimo (Prioridade 4) — core/rbac.py."""

from core import rbac


def test_admin_has_everything():
    assert rbac.has_permission("admin", "offense.exploit")
    assert rbac.has_permission("admin", "qualquer.coisa")


def test_readonly_only_read():
    assert rbac.has_permission("readonly", "read")
    assert not rbac.has_permission("readonly", "defense.block_ip")
    assert not rbac.has_permission("readonly", "noc.block_subscriber")


def test_auditor_read_and_audit():
    assert rbac.has_permission("auditor", "read")
    assert rbac.has_permission("auditor", "audit")
    assert not rbac.has_permission("auditor", "defense.block_ip")


def test_noc_operator_scope():
    assert rbac.has_permission("noc_operator", "noc.block_subscriber")
    assert rbac.has_permission("noc_operator", "defense.block_ip")
    assert not rbac.has_permission("noc_operator", "offense.exploit")
    assert not rbac.has_permission("noc_operator", "infra.asn_block")


def test_soc_analyst_defense_not_offense():
    assert rbac.has_permission("soc_analyst", "defense.block_ip")
    assert rbac.has_permission("soc_analyst", "audit")
    assert not rbac.has_permission("soc_analyst", "offense.exploit")


def test_prefix_wildcard():
    assert rbac.has_permission("noc_operator", "noc.device_check")  # noc.*


def test_unknown_role_falls_back_to_default():
    assert rbac.normalize_role("inexistente") == rbac.default_role()
    assert rbac.normalize_role(None) == rbac.default_role()


def test_empty_permission_is_allowed():
    # Ação sem permissão exigida (ex.: desconhecida) não é barrada pelo RBAC.
    assert rbac.has_permission("readonly", "")
