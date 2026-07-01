"""Gerência de segredos no Keychain do macOS (Fase 1).

Ferramenta de OPERADOR para migrar os segredos do `.env` (em claro) para o
Keychain do macOS, ver de onde cada segredo está sendo lido, e definir/remover
itens. Rode no terminal — o valor NUNCA vai por argumento de linha de comando
(o `set` lê sem eco via getpass; o `migrate` lê do ambiente/.env já carregado).

Uso:
    venv/bin/python scripts/nexus_secrets.py status
    venv/bin/python scripts/nexus_secrets.py migrate [NOME ...] [--force]
    venv/bin/python scripts/nexus_secrets.py set NOME
    venv/bin/python scripts/nexus_secrets.py delete NOME [--yes]

Depois de migrar, REMOVA a linha correspondente do `.env` (o Keychain passa a
ser a fonte da verdade; enquanto a linha existir no .env ela é redundante, mas
o valor continua em claro no arquivo). Keychain-first: se o item existir no
Keychain, ele vence o .env.
"""

import argparse
import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

from core import secrets  # noqa: E402

load_dotenv()


def _cmd_status() -> int:
    print(f"Backend ativo: {secrets.resolve_backend()}  "
          f"(keychain disponível: {secrets.keychain_available()})\n")
    print(f"{'SEGREDO':30} {'ORIGEM':10} PRESENTE")
    print("-" * 52)
    for row in secrets.secret_status():
        print(f"{row['name']:30} {row['source']:10} {'sim' if row['present'] else 'não'}")
    print("\n'keychain' = já migrado · 'env' = ainda no .env/ambiente · "
          "'ausente' = não configurado")
    return 0


def _cmd_migrate(names: list[str], force: bool) -> int:
    if not secrets.keychain_available():
        print("ERRO: Keychain indisponível neste ambiente. Nada migrado.")
        return 1
    targets = names or list(secrets.SECRET_ENV_NAMES)
    unknown = [n for n in targets if n not in secrets.SECRET_ENV_NAMES]
    if unknown:
        print(f"ERRO: nome(s) desconhecido(s): {', '.join(unknown)}")
        print("Conhecidos:", ", ".join(secrets.SECRET_ENV_NAMES))
        return 1

    migrated, skipped = [], []
    for name in targets:
        env_val = os.getenv(name, "")
        already = secrets._keychain_get(name)
        if already and not force:
            skipped.append((name, "já no Keychain (use --force p/ sobrescrever)"))
            continue
        if not env_val:
            skipped.append((name, "sem valor no .env/ambiente"))
            continue
        if secrets.set_secret(name, env_val):
            migrated.append(name)
        else:
            skipped.append((name, "falha ao gravar no Keychain"))

    for name in migrated:
        print(f"  migrado -> Keychain: {name}")
    for name, why in skipped:
        print(f"  pulado ({why}): {name}")
    if migrated:
        print(f"\n{len(migrated)} segredo(s) migrado(s). "
              "AGORA remova as linhas correspondentes do .env "
              "(o valor ainda está em claro lá).")
    return 0


def _cmd_set(name: str) -> int:
    if name not in secrets.SECRET_ENV_NAMES:
        print(f"ERRO: nome desconhecido: {name}")
        print("Conhecidos:", ", ".join(secrets.SECRET_ENV_NAMES))
        return 1
    if not secrets.keychain_available():
        print("ERRO: Keychain indisponível neste ambiente.")
        return 1
    value = getpass.getpass(f"Valor de {name} (não será exibido): ")
    if not value:
        print("Valor vazio — nada gravado.")
        return 1
    if secrets.set_secret(name, value):
        print(f"OK: {name} gravado no Keychain.")
        return 0
    print(f"ERRO: falha ao gravar {name} no Keychain.")
    return 1


def _cmd_delete(name: str, yes: bool) -> int:
    if not secrets.keychain_available():
        print("ERRO: Keychain indisponível neste ambiente.")
        return 1
    if secrets._keychain_get(name) is None:
        print(f"{name} não está no Keychain — nada a remover.")
        return 0
    if not yes:
        resp = input(f"Remover {name} do Keychain? [s/N] ").strip().lower()
        if resp not in ("s", "sim", "y", "yes"):
            print("Cancelado.")
            return 0
    if secrets.delete_secret(name):
        print(f"OK: {name} removido do Keychain "
              "(se ainda houver valor no .env, ele volta a valer).")
        return 0
    print(f"ERRO: falha ao remover {name}.")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Gerência de segredos no Keychain do macOS.")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("status", help="mostra a origem de cada segredo (sem valores)")

    p_mig = sub.add_parser("migrate", help="migra segredos do .env para o Keychain")
    p_mig.add_argument("names", nargs="*", help="nomes específicos (padrão: todos)")
    p_mig.add_argument("--force", action="store_true", help="sobrescreve o que já está no Keychain")

    p_set = sub.add_parser("set", help="define um segredo no Keychain (lê sem eco)")
    p_set.add_argument("name")

    p_del = sub.add_parser("delete", help="remove um segredo do Keychain")
    p_del.add_argument("name")
    p_del.add_argument("--yes", action="store_true", help="não pede confirmação")

    args = parser.parse_args()
    if args.cmd == "status" or args.cmd is None:
        return _cmd_status()
    if args.cmd == "migrate":
        return _cmd_migrate(args.names, args.force)
    if args.cmd == "set":
        return _cmd_set(args.name)
    if args.cmd == "delete":
        return _cmd_delete(args.name, args.yes)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
