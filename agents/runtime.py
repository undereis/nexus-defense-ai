"""Runtime compartilhado do agente Nexus: usado tanto pelo CLI (main.py)
quanto pelo backend HTTP (api/server.py), para não duplicar a lógica de
montar histórico, invocar o agente e persistir a conversa em dois lugares."""

import threading

from agents.nexus_agent import build_agent
from core import control_plane as cp
from core import rbac
from memory import memory_store

_agent = None
_agent_lock = threading.Lock()
_invoke_lock = threading.Lock()


def get_agent():
    global _agent
    if _agent is None:
        with _agent_lock:
            if _agent is None:
                _agent = build_agent()
    return _agent


def ask_agent(user_text: str, principal=None) -> str:
    """Invoca o agente. `principal` (opcional) é a identidade EFETIVA da chamada.

    APENAS o CLI/local pode chamar SEM principal — nesse caso roda EXPLICITAMENTE
    como `local_admin`/`admin`. TODA entrada externa (API/integrações) DEVE passar
    um Principal explícito — ex.: a API `/chat` passa o Principal do token. Assim,
    entrada externa nunca cai em admin implícito.

    O Principal é propagado às tools/Control Plane via ContextVar durante a
    invocação e RESETADO ao final (mesmo em exceção)."""
    effective = principal if principal is not None else rbac.Principal(
        rbac.default_actor(), rbac.default_role()
    )
    agent = get_agent()
    history = memory_store.load_history(limit=20)
    messages = [(m["role"], m["content"]) for m in history] + [("user", user_text)]
    with _invoke_lock, cp.principal_context(effective):
        result = agent.invoke({"messages": messages})
    reply = result["messages"][-1].content
    memory_store.remember("user", user_text)
    memory_store.remember("assistant", reply)
    return reply
