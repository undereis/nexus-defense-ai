"""Núcleo de governança do Nexus (Control Plane / Policy Engine / RBAC).

Camada que fica ENTRE a IA/API/usuário e as tools sensíveis: representa uma
ação como um pedido estruturado, avalia política de forma determinística,
verifica ativo autorizado e papel/permissão, decide allow/deny/require_approval/
dry_run, audita e só então delega a execução (com aprovação humana via
tools/risk.py quando necessário).

Ver docs/control_plane.md para a arquitetura e o roadmap das próximas fases.
"""
