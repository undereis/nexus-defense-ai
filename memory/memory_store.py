"""Memória de conversa persistente da Nexus Defense AI."""

from database.db import get_recent_messages, save_message


def remember(role: str, content: str):
    save_message(role, content)


def load_history(limit: int = 20) -> list[dict]:
    rows = get_recent_messages(limit)
    return [{"role": role, "content": content} for role, content in rows]
