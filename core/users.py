"""Usuários da API REST com papel — RBAC rico (Fase 3).

Identidade real por trás de cada token da API: cada usuário tem id, nome, papel
(um de `rbac.ROLES`) e um token de acesso. O token é gravado apenas como HASH
(sha256); o valor cru é retornado UMA vez na criação e nunca mais — não fica no
DB nem em log. A resolução (token -> usuário/papel) é usada pelo `api/server`
DEPOIS do token principal e dos `NEXUS_ROLE_TOKENS` do `.env`, sem quebrá-los.

Não confundir com os "atores" padrão do RBAC (`local_admin`/`admin`): aqui são
credenciais emitidas para operadores/integrações reais, com papel granular. A
posse do token dá o PAPEL; a policy engine continua aplicando risco/toggle/modo/
aprovação por cima (ter o papel é necessário, não suficiente).
"""

import hashlib
import secrets
import uuid

from core import rbac
from database import db


def _hash_token(token: str) -> str:
    """sha256 hex do token — é isto (e só isto) que fica no banco."""
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def _token_hint(token: str) -> str:
    """Dica curta para identificar o token numa lista, sem revelá-lo."""
    if not token or len(token) < 10:
        return "***"
    return f"{token[:4]}…{token[-4:]}"


def new_token() -> str:
    return secrets.token_urlsafe(32)


def create_user(name: str, role: str) -> dict:
    """Cria um usuário e EMITE um token. Retorna {user_id, name, role, token}.

    O `token` cru aparece SÓ AQUI — entregue ao operador na hora; não é
    recuperável depois (só o hash fica no banco). Levanta ValueError se o papel
    for inválido (sem fallback silencioso para admin)."""
    role = (role or "").strip().lower()
    if role not in rbac.ROLES:
        raise ValueError(f"papel inválido: {role!r}. Válidos: {', '.join(rbac.ROLES)}")
    name = (name or "").strip()
    token = new_token()
    user_id = f"usr_{uuid.uuid4().hex[:12]}"
    db.create_api_user(user_id, name or user_id, role, _hash_token(token), _token_hint(token))
    return {"user_id": user_id, "name": name or user_id, "role": role, "token": token}


def resolve_user(token: str) -> dict | None:
    """Resolve token -> {user_id, name, role} se houver usuário ATIVO; None senão."""
    if not token:
        return None
    row = db.get_api_user_by_token_hash(_hash_token(token))
    if not row:
        return None
    return {"user_id": row[0], "name": row[1], "role": row[2]}


def list_users() -> list[dict]:
    """Metadados dos usuários (sem token/hash), com status."""
    out: list[dict] = []
    for r in db.list_api_users():
        user_id, name, role, hint, enabled, created_at, revoked_at = r
        out.append({
            "user_id": user_id, "name": name, "role": role, "token_hint": hint,
            "enabled": bool(enabled), "created_at": created_at, "revoked_at": revoked_at,
        })
    return out


def revoke_user(user_id: str) -> bool:
    return db.revoke_api_user(user_id)
