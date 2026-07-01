"""Gerência de usuários da API REST (Fase 3 — RBAC rico).

Ferramenta de OPERADOR: cria usuários com papel, lista e revoga. O token de um
usuário aparece UMA vez, na criação — guarde-o na hora (só o hash fica no banco).

Uso:
    venv/bin/python scripts/nexus_users.py list
    venv/bin/python scripts/nexus_users.py create --name "Fulano" --role noc_operator
    venv/bin/python scripts/nexus_users.py revoke usr_xxxxxxxxxxxx
    venv/bin/python scripts/nexus_users.py roles
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import rbac  # noqa: E402
from core import users  # noqa: E402
from database.db import init_db  # noqa: E402


def _cmd_list() -> int:
    rows = users.list_users()
    if not rows:
        print("Nenhum usuário da API cadastrado. Crie com: create --name ... --role ...")
        return 0
    print(f"{'USER_ID':18} {'PAPEL':13} {'STATUS':9} {'TOKEN':9} NOME")
    print("-" * 70)
    for u in rows:
        status = "ativo" if u["enabled"] else "revogado"
        print(f"{u['user_id']:18} {u['role']:13} {status:9} {u['token_hint']:9} {u['name']}")
    return 0


def _cmd_create(name: str, role: str) -> int:
    try:
        u = users.create_user(name, role)
    except ValueError as exc:
        print(f"ERRO: {exc}")
        return 1
    print(f"Usuário criado: {u['user_id']} ({u['name']}, papel {u['role']}).\n")
    print("TOKEN (aparece só agora, guarde já — não é recuperável):\n")
    print(f"    {u['token']}\n")
    print("Use no header:  Authorization: Bearer <token>")
    return 0


def _cmd_revoke(user_id: str) -> int:
    if users.revoke_user(user_id):
        print(f"OK: {user_id} revogado (token deixa de valer imediatamente).")
        return 0
    print(f"Nada revogado: {user_id} não existe ou já estava revogado.")
    return 1


def _cmd_roles() -> int:
    print("Papéis disponíveis (e suas permissões):\n")
    for role in rbac.ROLES:
        print(f"  {rbac.describe_role(role)}")
    return 0


def main() -> int:
    init_db()
    parser = argparse.ArgumentParser(description="Gerência de usuários da API REST (RBAC).")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("list", help="lista usuários (sem revelar tokens)")
    sub.add_parser("roles", help="mostra os papéis e suas permissões")

    p_new = sub.add_parser("create", help="cria um usuário e emite um token")
    p_new.add_argument("--name", required=True)
    p_new.add_argument("--role", required=True, choices=rbac.ROLES)

    p_rev = sub.add_parser("revoke", help="revoga um usuário pelo user_id")
    p_rev.add_argument("user_id")

    args = parser.parse_args()
    if args.cmd == "create":
        return _cmd_create(args.name, args.role)
    if args.cmd == "revoke":
        return _cmd_revoke(args.user_id)
    if args.cmd == "roles":
        return _cmd_roles()
    return _cmd_list()


if __name__ == "__main__":
    sys.exit(main())
