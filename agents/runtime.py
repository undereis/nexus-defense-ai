"""Runtime compartilhado do agente Nexus: usado tanto pelo CLI (main.py)
quanto pelo backend HTTP (api/server.py), para não duplicar a lógica de
montar histórico, invocar o agente e persistir a conversa em dois lugares."""

import threading

from agents.nexus_agent import build_agent
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


def ask_agent(user_text: str) -> str:
    agent = get_agent()
    history = memory_store.load_history(limit=20)
    messages = [(m["role"], m["content"]) for m in history] + [("user", user_text)]
    with _invoke_lock:
        result = agent.invoke({"messages": messages})
    reply = result["messages"][-1].content
    memory_store.remember("user", user_text)
    memory_store.remember("assistant", reply)
    return reply
